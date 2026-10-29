package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/trace"

	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/signup"
	"github.com/anywaye/identity/internal/telemetry"
	"github.com/anywaye/identity/internal/users"
)

const (
	SessionCookieName = "__Host-session"

	RetryAfterHeader = "Retry-After"

	maxRequestBody = 4 << 10
)

// Auth is the part of auth.Service the v1 routes need. It is an interface
// declared here, at the consumer, so the handlers can be tested against a
// programmable double and so the HTTP layer has no dependency on the use cases'
// internals.
type Auth interface {
	Register(ctx context.Context, in auth.RegisterInput) (auth.RegisteredUser, error)
	Login(ctx context.Context, in auth.LoginInput) (auth.LoginResult, error)
	Authenticate(ctx context.Context, token string) (users.User, error)
	Logout(ctx context.Context, token string) error
	ListSessions(ctx context.Context, token string) ([]auth.Session, error)
	RevokeSession(ctx context.Context, token string, sessionID id.UUID) error
	CompleteSecondFactor(ctx context.Context, in auth.CompleteSecondFactorInput) (auth.LoginResult, error)

	Disable(ctx context.Context, in auth.DisableInput) error
	Enable(ctx context.Context, in auth.EnableInput) error

	SearchUsers(ctx context.Context, query string, limit int) ([]users.DirectoryEntry, error)

	UserCounts(ctx context.Context) (users.UserCounts, error)

	UpdateDisplayName(ctx context.Context, userID id.UUID, name *string) error

	UpdateTheme(ctx context.Context, userID id.UUID, theme *string) error
}

// WithAuth mounts the v1 routes.
//
// It is an Option rather than a constructor argument because the probes are the
// service's floor: a process with no DATABASE_URL has no auth service, and that
// process must still answer /healthz. Routes are simply absent when it is not
// given, so a misconfiguration shows up as a 404 rather than as a stack of 500s.
func WithAuth(a Auth) Option {
	return func(o *options) {
		if a != nil {
			o.auth = a
		}
	}
}

type userResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	DisplayName *string `json:"display_name,omitempty"`
	Theme *string `json:"theme,omitempty"`
}

type sessionResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type challengeResponse struct {
	MFARequired bool      `json:"mfa_required"`
	Challenge   string    `json:"challenge"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Website string `json:"website"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type updateMeRequest struct {
	DisplayName string `json:"display_name"`
	Theme *string `json:"theme"`
}

func (o options) registerRoutes(r chiRouter) {
	if o.auth == nil {
		return
	}

	r.Post("/v1/users", o.rateLimit("/v1/users", o.handleRegister))
	r.Post("/v1/session", o.rateLimit("/v1/session", o.handleLogin))
	r.Delete("/v1/session", o.sessionCredentialOnly(o.handleLogout))
	r.Get("/v1/me", o.handleMe)
	r.Patch("/v1/me", o.handleUpdateMe)

	r.Get("/v1/sessions", o.sessionCredentialOnly(o.handleListSessions))
	r.Delete("/v1/sessions/{sessionID}", o.sessionCredentialOnly(o.handleRevokeSession))

	o.registerDeletionRoute(r)

	r.Post("/v1/session/mfa", o.sessionCredentialOnly(o.handleCompleteSecondFactor))

	if o.oidc != nil && o.tenancy != nil {
		o.registerSessionTokenRoutes(r)
	}

	if o.tenancy != nil {
		o.registerTenancyRoutes(r)
	}

	o.registerAgentPublicRoutes(r)

	o.registerMFARoutes(r)

	if o.oidc != nil {
		o.registerOIDCRoutes(r)
	}

	o.registerIntrospectionRoute(r)

	o.registerRecoveryRoutes(r)

	o.registerSocialRoutes(r)

	o.registerSessionLinkRoutes(r)

	o.registerOperatorRoutes(r)

	o.registerStaffRoutes(r)
}

type chiRouter interface {
	Post(pattern string, h http.HandlerFunc)
	Delete(pattern string, h http.HandlerFunc)
	Get(pattern string, h http.HandlerFunc)
	Patch(pattern string, h http.HandlerFunc)
}

func traced(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		span := trace.SpanFromContext(r.Context())
		telemetry.Record(span, map[string]any{"http.route": routeTemplate(r)})
		h(w, r)
	}
}

type tracedRouter struct {
	chiRouter

	patterns []string
}

func (t *tracedRouter) Get(pattern string, h http.HandlerFunc) {
	t.patterns = append(t.patterns, pattern)
	t.chiRouter.Get(pattern, traced(h))
}

func (t *tracedRouter) Post(pattern string, h http.HandlerFunc) {
	t.patterns = append(t.patterns, pattern)
	t.chiRouter.Post(pattern, traced(h))
}

func (t *tracedRouter) Patch(pattern string, h http.HandlerFunc) {
	t.patterns = append(t.patterns, pattern)
	t.chiRouter.Patch(pattern, traced(h))
}

func (t *tracedRouter) Delete(pattern string, h http.HandlerFunc) {
	t.patterns = append(t.patterns, pattern)
	t.chiRouter.Delete(pattern, traced(h))
}

func (o options) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body *registerRequest
	if !decodeBody(w, r, &body) {
		return
	}

	if body.Website != "" {
		problemFor(w, r, http.StatusUnprocessableEntity, CodeValidationFailed,
			"the request has an invalid field")
		return
	}

	if o.signup != nil {
		if !o.signup.Verify(signup.Pair{Timestamp: body.Timestamp, Signature: body.Signature}, o.clk.Now()) {
			problemFor(w, r, http.StatusUnprocessableEntity, CodeValidationFailed,
				"the request has an invalid field")
			return
		}
	}

	created, err := o.auth.Register(r.Context(), auth.RegisterInput{
		Email:    body.Email,
		Password: body.Password,
	})
	if err != nil {
		o.writeAuthError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, userResponse{ID: created.ID.String(), Email: created.Email})
}

func (o options) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body *loginRequest
	if !decodeBody(w, r, &body) {
		return
	}

	result, err := o.auth.Login(r.Context(), auth.LoginInput{
		Email:     body.Email,
		Password:  body.Password,
		UserAgent: r.UserAgent(),
		IP:        remoteIP(r),
	})
	if err != nil {
		o.writeAuthError(w, r, err)
		return
	}

	if result.MFARequired {
		o.writeChallenge(w, r, result)
		return
	}

	o.setSessionCookie(w, result.Token, result.ExpiresAt)
	writeJSON(w, http.StatusOK, sessionResponse{Token: result.Token, ExpiresAt: result.ExpiresAt})
}

func (o options) writeChallenge(w http.ResponseWriter, r *http.Request, result auth.LoginResult) {
	if result.Challenge == nil || result.Challenge.Token == "" {
		unexpected(w, r, o.logger, errNoChallengeToken)
		return
	}

	o.setMFAChallengeCookie(w, result.Challenge.Token, result.Challenge.ExpiresAt)
	writeJSON(w, http.StatusAccepted, challengeResponse{
		MFARequired: true,
		Challenge:   result.Challenge.Token,
		ExpiresAt:   result.Challenge.ExpiresAt,
	})
}

var errNoChallengeToken = errors.New("a login reported that a second factor is required but returned no challenge")

func (o options) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := o.presentedToken(r)
	if token == "" {
		unauthorized(w, r)
		return
	}

	if err := o.auth.Logout(r.Context(), token); err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			o.clearSessionCookie(w)
			unauthorized(w, r)
			return
		}
		unexpected(w, r, o.logger, err)
		return
	}

	o.clearSessionCookie(w)
	noContent(w)
}

func (o options) handleMe(w http.ResponseWriter, r *http.Request) {
	token := o.presentedToken(r)
	if token == "" {
		unauthorized(w, r)
		return
	}

	user, err := o.auth.Authenticate(r.Context(), token)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			unauthorized(w, r)
			return
		}
		unexpected(w, r, o.logger, err)
		return
	}

	writeJSON(w, http.StatusOK, userResponse{
		ID:          user.ID.String(),
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Theme:       user.Preferences.Theme,
	})
}

func (o options) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	token := o.presentedToken(r)
	if token == "" {
		unauthorized(w, r)
		return
	}

	user, err := o.auth.Authenticate(r.Context(), token)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			unauthorized(w, r)
			return
		}
		unexpected(w, r, o.logger, err)
		return
	}

	var body *updateMeRequest
	if !decodeBody(w, r, &body) {
		return
	}

	name := strings.TrimSpace(body.DisplayName)
	if err := users.ValidateDisplayName(name); err != nil {
		var fe *users.FieldError
		if !errors.As(err, &fe) {
			unexpected(w, r, o.logger, err)
			return
		}
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fe.Field, Code: fe.Code}}))
		return
	}

	var set *string
	if name != "" {
		set = &name
	}

	var theme *string
	if body.Theme != nil {
		if err := users.ValidateTheme(*body.Theme); err != nil {
			var fe *users.FieldError
			if !errors.As(err, &fe) {
				unexpected(w, r, o.logger, err)
				return
			}
			writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
				withDetail("the request has an invalid field").
				withFieldErrors([]FieldError{{Field: fe.Field, Code: fe.Code}}))
			return
		}
		theme = body.Theme
	}

	if err := o.auth.UpdateDisplayName(r.Context(), user.ID, set); err != nil {
		unexpected(w, r, o.logger, err)
		return
	}

	if err := o.auth.UpdateTheme(r.Context(), user.ID, theme); err != nil {
		unexpected(w, r, o.logger, err)
		return
	}

	writeJSON(w, http.StatusOK, userResponse{ID: user.ID.String(), Email: user.Email, DisplayName: set, Theme: theme})
}

type sessionListItem struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UserAgent string    `json:"user_agent"`
	IP      string `json:"ip"`
	Current bool   `json:"current"`
}

type sessionListResponse struct {
	Sessions []sessionListItem `json:"sessions"`
}

func (o options) handleListSessions(w http.ResponseWriter, r *http.Request) {
	token := o.presentedToken(r)
	if token == "" {
		unauthorized(w, r)
		return
	}

	list, err := o.auth.ListSessions(r.Context(), token)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			unauthorized(w, r)
			return
		}
		unexpected(w, r, o.logger, err)
		return
	}

	items := make([]sessionListItem, 0, len(list))
	for _, s := range list {
		items = append(items, sessionListItem{
			ID:        s.ID.String(),
			CreatedAt: s.CreatedAt,
			ExpiresAt: s.ExpiresAt,
			UserAgent: s.UserAgent,
			IP:        ipString(s.IP),
			Current:   s.Current,
		})
	}

	writeJSON(w, http.StatusOK, sessionListResponse{Sessions: items})
}

func ipString(addr *netip.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

const sessionIDParam = "sessionID"

func (o options) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	token := o.presentedToken(r)
	if token == "" {
		unauthorized(w, r)
		return
	}

	sessionID, ok := sessionIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	if err := o.auth.RevokeSession(r.Context(), token, sessionID); err != nil {
		switch {
		case errors.Is(err, auth.ErrUnauthenticated):
			unauthorized(w, r)
		case errors.Is(err, auth.ErrSessionNotFound):
			notFound(w, r)
		default:
			unexpected(w, r, o.logger, err)
		}
		return
	}

	noContent(w)
}

func sessionIDFrom(r *http.Request) (id.UUID, bool) {
	parsed, err := id.Parse(chi.URLParam(r, sessionIDParam))
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}

func (o options) presentedToken(r *http.Request) string {
	if token := bearerToken(r); token != "" {
		return token
	}
	return cookieToken(r)
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "

	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

func cookieToken(r *http.Request) string {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (o options) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
	})
}

func (o options) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func remoteIP(r *http.Request) *netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	return &addr
}

func decodeBody[T any](w http.ResponseWriter, r *http.Request, dst **T) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		var syntax *json.SyntaxError
		var unmarshalType *json.UnmarshalTypeError

		switch {
		case bodyTooLarge(err):
			problemFor(w, r, http.StatusRequestEntityTooLarge, CodePayloadTooLarge,
				fmt.Sprintf("the request body is larger than the %d bytes this endpoint accepts", maxRequestBody))
		case errors.As(err, &syntax),
			errors.As(err, &unmarshalType),
			errors.Is(err, io.EOF),
			errors.Is(err, io.ErrUnexpectedEOF):
			problemFor(w, r, http.StatusBadRequest, CodeInvalidJSON,
				"the request body is not a JSON object this endpoint accepts")
		default:
			problemFor(w, r, http.StatusUnprocessableEntity, CodeValidationFailed,
				"the request body has a field this endpoint does not accept")
		}
		return false
	}

	if *dst == nil {
		problemFor(w, r, http.StatusBadRequest, CodeInvalidJSON,
			"the request body must be a JSON object, not null")
		return false
	}

	return true
}

func (o options) writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	var locked *auth.LockedError
	var disabled *auth.DisabledError
	var unverified *auth.EmailNotVerifiedError
	var fieldErr *users.FieldError

	switch {
	case errors.As(err, &disabled):
		problemFor(w, r, http.StatusForbidden, CodeForbidden,
			"this account is disabled; contact the person or organization that administers it")

	case errors.As(err, &unverified):
		problemFor(w, r, http.StatusForbidden, CodeEmailNotVerified,
			"this account's email address is not verified; verify it before signing in")

	case errors.As(err, &locked):
		seconds := retryAfterSeconds(locked.RetryAfter)
		w.Header().Set(RetryAfterHeader, seconds)
		problemFor(w, r, http.StatusLocked, CodeAccountLocked,
			"too many failed sign-in attempts for this account; retry after "+seconds+" seconds")

	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrUnauthenticated):
		unauthorized(w, r)

	case errors.Is(err, users.ErrEmailTaken):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an account already exists for that email address")

	case errors.As(err, &fieldErr):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}

func retryAfterSeconds(d time.Duration) string {
	if d <= 0 {
		return "0"
	}
	seconds := int64(d / time.Second)
	if d%time.Second != 0 {
		seconds++
	}
	return fmt.Sprintf("%d", seconds)
}
