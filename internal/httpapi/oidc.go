package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/mfa"
	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/users"
)


// OIDC is the part of the OIDC provider the routes need.
//
// Declared here, at the consumer, for the same reason Auth and Tenancy are: the
// handlers are then testable against a double, and this file has no dependency on
// the library's types beyond the discovery document's own shape.
type OIDC interface {
	Handler() http.Handler
	Discovery(r *http.Request) any
	JWKS() ([]byte, error)
	LoginBanner(ctx context.Context, requestID string) (oidc.LoginBanner, error)
	LoginRedirect(params oidc.LoginRedirectParams) string
	CompleteLogin(ctx context.Context, requestID string, subject id.UUID) error
	MintAccountToken(subject, accountID id.UUID, audience string, now time.Time) (oidc.MintedToken, error)
}

// OIDCClients is the client registration use cases, for the admin routes.
type OIDCClients interface {
	Register(ctx context.Context, in oidc.RegisterInput) (oidc.RegisteredClient, error)
	List(ctx context.Context, accountID id.UUID) ([]oidc.Client, error)
	Get(ctx context.Context, accountID, rowID id.UUID) (oidc.Client, error)
	Revoke(ctx context.Context, in oidc.RevokeInput) (oidc.Client, error)
}

// WithOIDC mounts the OIDC protocol surface and the login page.
//
// It is an Option for the reason WithAuth is: with no OIDC_SIGNING_KEY there is
// no key to sign with and no document to publish, and that process must still
// answer /healthz. The routes are absent rather than present-and-500.
func WithOIDC(p OIDC) Option {
	return func(o *options) {
		if p != nil {
			o.oidc = p
		}
	}
}

// WithOIDCClients mounts the client registration routes.
//
// Separate from WithOIDC because the registrations live in an account and are
// gated on the owner role, which is the tenancy router's business, and a process
// with a key but no tenancy service has no account to register against.
func WithOIDCClients(c OIDCClients) Option {
	return func(o *options) {
		if c != nil {
			o.oidcClients = c
		}
	}
}

const oidcRequestParam = "requestID"

const oidcClientParam = "clientID"

func (o options) registerOIDCRoutes(r chiRouter) {
	if o.oidc == nil {
		return
	}

	r.Get(oidc.PathAuthorize, o.handleOIDCAuthorize)
	r.Post(oidc.PathAuthorize, o.handleOIDCAuthorize)

	r.Get(oidc.PathAuthorizeCallback, o.delegateOIDC)
	r.Post(oidc.PathToken, o.delegateOIDC)
	r.Get(oidc.PathUserinfo, o.delegateOIDC)
	r.Post(oidc.PathUserinfo, o.delegateOIDC)

	r.Get(oidc.PathLogin+"/{"+oidcRequestParam+"}", o.handleOIDCLogin)
	r.Post(oidc.PathLogin+"/{"+oidcRequestParam+"}", o.handleOIDCLogin)
}

func (o options) registerOIDCWellKnownRoutes(r chiRouter) {
	if o.oidc == nil {
		return
	}
	r.Get(oidc.PathDiscovery, o.handleOIDCDiscovery)
	r.Get(oidc.PathOAuthAuthorizationServer, o.handleOIDCDiscovery)
	r.Get(oidc.PathJWKS, o.handleOIDCJWKS)
}

func (o options) delegateOIDC(w http.ResponseWriter, r *http.Request) {
	buffer := httptest.NewRecorder()
	o.oidc.Handler().ServeHTTP(buffer, r)

	header := w.Header()
	for name, values := range buffer.Header() {
		header[name] = values
	}

	if isRedirect(buffer.Code) {
		header.Del("Content-Type")
		header.Del("Content-Length")
		w.WriteHeader(buffer.Code)
		return
	}

	w.WriteHeader(buffer.Code)
	_, _ = w.Write(buffer.Body.Bytes())
}

func isRedirect(status int) bool { return status >= 300 && status < 400 }

func (o options) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, o.oidc.Discovery(r))
}

func (o options) handleOIDCJWKS(w http.ResponseWriter, _ *http.Request) {
	document, err := o.oidc.JWKS()
	if err != nil {
		unexpected(w, nil, o.logger, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(document)
}

func (o options) handleOIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest, "the authorization request could not be parsed")
		return
	}

	if detail, ok := checkAuthorizeParams(r.Form); !ok {
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest, detail)
		return
	}

	state, err := oauth.NewState(OIDCStateProvider)
	if err != nil {
		unexpected(w, r, o.logger, err)
		return
	}
	http.SetCookie(w, oidcFlowCookie(state))

	o.delegateOIDC(w, r)
}

func oidcFlowCookie(state string) *http.Cookie {
	return &http.Cookie{
		Name:     OIDCFlowCookieName,
		Value:    state,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(OIDCStateTTL / time.Second),
		Expires:  time.Now().Add(OIDCStateTTL),
	}
}

func checkAuthorizeParams(form url.Values) (string, bool) {
	scopes := strings.Fields(form.Get("scope"))
	if err := oidc.ValidateRequestedScopes(scopes); err != nil {
		return err.Error(), false
	}

	switch form.Get("code_challenge_method") {
	case string(oidcS256):
		if form.Get("code_challenge") == "" {
			return "code_challenge_method is S256 but no code_challenge was sent", false
		}
	case "":
		return "PKCE is required: send code_challenge with code_challenge_method=S256", false
	default:
		return fmt.Sprintf("code_challenge_method must be S256; this provider does not accept %q",
			form.Get("code_challenge_method")), false
	}

	for _, prompt := range form["prompt"] {
		switch prompt {
		case oidcPromptNone:
		default:
			return fmt.Sprintf("prompt=%s is not implemented; this provider has no consent screen and does not re-authenticate", prompt), false
		}
	}
	if form.Get("max_age") != "" {
		return "max_age is not implemented; this provider does not re-authenticate a signed-in user", false
	}

	return "", true
}

const (
	oidcS256       = "S256"
	oidcPromptNone = "none"
)


// OIDCStateProvider is the provider name this service's own state carries.
//
// oauth.NewState joins it to a random token, and oauth.VerifyState compares it
// against the route. Reusing internal/oauth's state rather than minting a second
// implementation is the brief's instruction and the right call anyway: the
// threat is identical — a browser following a URL the user did not choose — and
// two state implementations in one service is two chances to fix one of them
// wrongly.
const OIDCStateProvider = "oidc"

// OIDCStateCookiePrefix is the cookie the login form's state is sealed in.
//
// The __Host- prefix is the browser-enforced contract this service already uses
// for its session cookie: Secure, Path=/, and no Domain attribute, so a
// subdomain cannot set or overwrite it. The request id is in the name rather than
// only in the value, because one cookie for the whole service means two login
// tabs clobber each other's state and the first one to submit fails with a 400 —
// a real bug in the one interaction whose entire job is to work.
const OIDCStateCookiePrefix = "__Host-oidc-state-"

// OIDCStateTTL is how long a login form's state is worth accepting.
//
// It matches internal/oauth's state cookie Max-Age. A user who abandons the login
// and comes back tomorrow is not attacking anything, and a state that expired
// while they were away would be a form that cannot be submitted.
const OIDCStateTTL = 10 * time.Minute

// OIDCFlowCookieName marks a browser that has been handed an authorization
// request by THIS service.
//
// It is the proof that the browser holding it began the flow rather than arriving
// at a login URL somebody else chose, and it is set at handleOIDCAuthorize —
// which is the only point where the start of a flow is observable. This handler
// cannot set it, because by the time this handler runs the two cases are
// indistinguishable: a browser that legitimately followed the redirect from
// `/oidc/authorize` and a browser that followed a link to `/oidc/login/{id}` are
// the same GET with the same ambient session cookie.
//
// `__Host-`, so no other origin can write it. The property is entirely that the
// cookie could only have been set by this service on this deployment.
//
// It is deliberately NOT keyed by request id. The id does not exist until the
// library has created the row, which is after this cookie must already have been
// written, and binding it later would mean the cookie is set by the very endpoint
// the attack aims at. One cookie for the service answers "did a flow start here",
// which is a question about the browser and not about one request.
const OIDCFlowCookieName = "__Host-oidc-flow"

func (o options) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, oidcRequestParam)

	if r.Method == http.MethodPost {
		o.completeOIDCLogin(w, r, requestID)
		return
	}

	banner, err := o.oidc.LoginBanner(r.Context(), requestID)
	if err != nil {
		o.writeOIDCError(w, r, err)
		return
	}

	if user, ok := o.signedInUser(r); ok {
		if !o.browserStartedThisFlow(r) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this sign-in was not started in this browser; start again from the application")
			return
		}
		o.finishOIDCLogin(w, r, banner.RequestID, user.ID)
		return
	}

	o.beginOIDCInteraction(w, r, banner, oidc.LoginStepPassword, oidcInteraction{})
}

type oidcInteraction struct {
	code string
	detail string
	retryAfter string
}

func (o options) beginOIDCInteraction(w http.ResponseWriter, r *http.Request, banner oidc.LoginBanner, step string, failure oidcInteraction) {
	state, err := oauth.NewState(OIDCStateProvider)
	if err != nil {
		unexpected(w, r, o.logger, err)
		return
	}

	http.SetCookie(w, oidcStateCookie(banner.RequestID, state))

	oidcRedirect(w, o.oidc.LoginRedirect(oidc.LoginRedirectParams{
		RequestID:   banner.RequestID,
		State:       state,
		Step:        step,
		ClientName:  banner.ClientName,
		LoginHint:   banner.LoginHint,
		Error:       failure.code,
		ErrorDetail: failure.detail,
		RetryAfter:  failure.retryAfter,
	}))
}

func (o options) browserStartedThisFlow(r *http.Request) bool {
	cookie, err := r.Cookie(OIDCFlowCookieName)
	if err != nil {
		return false
	}
	return oauth.VerifyState(OIDCStateProvider, cookie.Value, cookie.Value)
}

func (o options) completeOIDCLogin(w http.ResponseWriter, r *http.Request, requestID string) {
	if err := r.ParseForm(); err != nil {
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest, "the login form could not be parsed")
		return
	}

	sealed, err := r.Cookie(oidcStateCookieName(requestID))
	if err != nil || !oauth.VerifyState(OIDCStateProvider, sealed.Value, r.Form.Get("state")) {
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code: oidc.LoginErrorInteractionExpired,
			detail: "this sign-in was not started in this browser, or it expired; " +
				"start again from the application",
		}, oidc.LoginStepPassword)
		return
	}
	clearOIDCStateCookie(w, requestID)

	if _, isChallenge := r.Form["code"]; isChallenge {
		o.completeOIDCChallenge(w, r, requestID)
		return
	}

	email, password := r.Form.Get("email"), r.Form.Get("password")
	if email == "" || password == "" {
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:   oidc.LoginErrorMissingCredentials,
			detail: "this sign-in needs both an email address and a password",
		}, oidc.LoginStepPassword)
		return
	}

	result, err := o.auth.Login(r.Context(), auth.LoginInput{
		Email:     email,
		Password:  password,
		UserAgent: r.UserAgent(),
		IP:        remoteIP(r),
	})
	if err != nil {
		o.failOIDCLogin(w, r, requestID, err)
		return
	}

	if result.MFARequired {
		o.beginOIDCChallenge(w, r, requestID, result)
		return
	}

	user, err := o.auth.Authenticate(r.Context(), result.Token)
	if err != nil {
		unexpected(w, r, o.logger, fmt.Errorf("resolving the user behind a session this request just created: %w", err))
		return
	}

	o.setSessionCookie(w, result.Token, result.ExpiresAt)
	o.finishOIDCLogin(w, r, requestID, user.ID)
}

func (o options) failOIDCLogin(w http.ResponseWriter, r *http.Request, requestID string, err error) {
	var (
		locked   *auth.LockedError
		fieldErr *users.FieldError
	)

	switch {
	case errors.As(err, &locked):
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:       oidc.LoginErrorAccountLocked,
			detail:     "too many failed sign-in attempts for this account",
			retryAfter: retryAfterSeconds(locked.RetryAfter),
		}, oidc.LoginStepPassword)

	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrUnauthenticated):
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:   oidc.LoginErrorInvalidCredentials,
			detail: "that email address and password were not accepted",
		}, oidc.LoginStepPassword)

	case errors.Is(err, users.ErrEmailTaken):
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:   CodeConflict,
			detail: "an account already exists for that email address",
		}, oidc.LoginStepPassword)

	case errors.As(err, &fieldErr):
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:   oidc.LoginErrorInvalidCredentials,
			detail: "that email address and password were not accepted",
		}, oidc.LoginStepPassword)

	default:
		unexpected(w, r, o.logger, err)
	}
}

func (o options) failOIDCInteraction(w http.ResponseWriter, r *http.Request, requestID string, failure oidcInteraction, step string) {
	banner, err := o.oidc.LoginBanner(r.Context(), requestID)
	if err != nil {
		o.writeOIDCError(w, r, err)
		return
	}
	o.beginOIDCInteraction(w, r, banner, step, failure)
}

// OIDCChallengeCookiePrefix is where the challenge token waits between the two
// steps of the interaction.
//
// __Host- and per-request-id, for the same reasons as the state cookie above and
// with the same reasoning about two tabs: the request id is in the NAME, because
// one cookie for the whole service means two login tabs clobber each other's
// challenge and the first to submit fails — a real bug in the one interaction
// whose entire job is to work.
const OIDCChallengeCookiePrefix = "__Host-oidc-mfa-"

func oidcChallengeCookieName(requestID string) string {
	return OIDCChallengeCookiePrefix + requestID
}

func (o options) beginOIDCChallenge(w http.ResponseWriter, r *http.Request, requestID string, result auth.LoginResult) {
	if result.Challenge == nil || result.Challenge.Token == "" {
		unexpected(w, r, o.logger, errNoChallengeToken)
		return
	}

	http.SetCookie(w, oidcChallengeCookie(requestID, result.Challenge.Token, result.Challenge.ExpiresAt))

	banner, err := o.oidc.LoginBanner(r.Context(), requestID)
	if err != nil {
		o.writeOIDCError(w, r, err)
		return
	}
	o.beginOIDCInteraction(w, r, banner, oidc.LoginStepChallenge, oidcInteraction{})
}

func (o options) completeOIDCChallenge(w http.ResponseWriter, r *http.Request, requestID string) {
	cookie, err := r.Cookie(oidcChallengeCookieName(requestID))
	if err != nil || cookie.Value == "" {
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:   oidc.LoginErrorInteractionExpired,
			detail: "this sign-in expired before the code was entered; start again from the application",
		}, oidc.LoginStepPassword)
		return
	}

	result, err := o.auth.CompleteSecondFactor(r.Context(), auth.CompleteSecondFactorInput{
		ChallengeToken: cookie.Value,
		Code:           r.Form.Get("code"),
	})
	if err != nil {
		o.failOIDCChallenge(w, r, requestID, err)
		return
	}

	clearOIDCChallengeCookie(w, requestID)

	user, err := o.auth.Authenticate(r.Context(), result.Token)
	if err != nil {
		unexpected(w, r, o.logger, fmt.Errorf("resolving the user behind a session this request just created: %w", err))
		return
	}
	o.setSessionCookie(w, result.Token, result.ExpiresAt)
	o.finishOIDCLogin(w, r, requestID, user.ID)
}

func (o options) failOIDCChallenge(w http.ResponseWriter, r *http.Request, requestID string, err error) {
	var locked *sessions.LockedError

	switch {
	case errors.As(err, &locked):
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:       oidc.LoginErrorAccountLocked,
			detail:     "too many failed attempts at the second factor",
			retryAfter: retryAfterSeconds(locked.RetryAfter),
		}, oidc.LoginStepChallenge)

	case errors.Is(err, mfa.ErrInvalidFactor), errors.Is(err, auth.ErrInvalidCredentials),
		errors.Is(err, auth.ErrUnauthenticated):
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code: oidc.LoginErrorChallengeRejected,
			detail: "that code was not accepted; codes change every 30 seconds, so use the " +
				"current one or a recovery code",
		}, oidc.LoginStepChallenge)

	default:
		o.writeMFAError(w, r, err)
	}
}

func oidcChallengeCookie(requestID, token string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     oidcChallengeCookieName(requestID),
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: oidcInteractionSameSite,
		Expires:  expiresAt,
	}
}

func clearOIDCChallengeCookie(w http.ResponseWriter, requestID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcChallengeCookieName(requestID),
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: oidcInteractionSameSite,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (o options) finishOIDCLogin(w http.ResponseWriter, r *http.Request, requestID string, subject id.UUID) {
	if err := o.oidc.CompleteLogin(r.Context(), requestID, subject); err != nil {
		o.writeOIDCError(w, r, err)
		return
	}

	target := oidc.PathAuthorizeCallback + "?" + url.Values{"id": []string{requestID}}.Encode()
	proxied, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		unexpected(w, r, o.logger, fmt.Errorf("building the authorize callback request: %w", err))
		return
	}
	for name, values := range r.Header {
		if name == "Cookie" || name == "Content-Type" || name == "Content-Length" {
			continue
		}
		proxied.Header[name] = values
	}

	o.delegateOIDC(w, proxied)
}

func (o options) signedInUser(r *http.Request) (users.User, bool) {
	token := o.presentedToken(r)
	if token == "" {
		return users.User{}, false
	}
	user, err := o.auth.Authenticate(r.Context(), token)
	if err != nil {
		return users.User{}, false
	}
	return user, true
}

func oidcStateCookieName(requestID string) string {
	return OIDCStateCookiePrefix + requestID
}

const oidcInteractionSameSite = http.SameSiteNoneMode

func oidcStateCookie(requestID, state string) *http.Cookie {
	return &http.Cookie{
		Name:     oidcStateCookieName(requestID),
		Value:    state,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: oidcInteractionSameSite,
		MaxAge:   int(OIDCStateTTL / time.Second),
		Expires:  time.Now().Add(OIDCStateTTL),
	}
}

func clearOIDCStateCookie(w http.ResponseWriter, requestID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName(requestID),
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: oidcInteractionSameSite,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (o options) writeOIDCError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, oidc.ErrAuthRequestNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"this sign-in link has expired or was never valid; start again from the application")
	default:
		unexpected(w, r, o.logger, err)
	}
}

func oidcRedirect(w http.ResponseWriter, location string) {
	header := w.Header()
	header.Set("Location", location)
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
}


type oidcClientResponse struct {
	ID           string     `json:"id"`
	ClientID     string     `json:"client_id"`
	Name         string     `json:"name"`
	RedirectURIs []string   `json:"redirect_uris"`
	GrantTypes   []string   `json:"grant_types"`
	Scopes       []string   `json:"scopes"`
	CreatedAt    time.Time  `json:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

type oidcClientCreatedResponse struct {
	oidcClientResponse
	ClientSecret string `json:"client_secret"`
}

type registerOIDCClientRequest struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scopes       []string `json:"scopes"`
}

func (o options) registerOIDCClientRoutes(r chiRouter) {
	if o.oidcClients == nil {
		return
	}
	r.Post("/v1/accounts/{accountID}/oidc-clients", o.requireAccountRole(accounts.RoleOwner, o.handleRegisterOIDCClient))
	r.Get("/v1/accounts/{accountID}/oidc-clients", o.requireAccountRole(accounts.RoleOwner, o.handleListOIDCClients))
	r.Get("/v1/accounts/{accountID}/oidc-clients/{clientID}",
		o.requireAccountRole(accounts.RoleOwner, o.handleGetOIDCClient))
	r.Delete("/v1/accounts/{accountID}/oidc-clients/{clientID}",
		o.requireAccountRole(accounts.RoleOwner, o.handleRevokeOIDCClient))
}

func (o options) handleRegisterOIDCClient(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}
	account, _ := accountFrom(r.Context())

	var body *registerOIDCClientRequest
	if !decodeBody(w, r, &body) {
		return
	}

	registered, err := o.oidcClients.Register(r.Context(), oidc.RegisterInput{
		AccountID:    account.ID,
		Name:         body.Name,
		RedirectURIs: body.RedirectURIs,
		GrantTypes:   body.GrantTypes,
		Scopes:       body.Scopes,
		RegisteredBy: user.ID,
	})
	if err != nil {
		o.writeOIDCClientError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, oidcClientCreatedResponse{
		oidcClientResponse: newOIDCClientResponse(registered.Client),
		ClientSecret:       registered.Secret,
	})
}

func (o options) handleListOIDCClients(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())

	list, err := o.oidcClients.List(r.Context(), account.ID)
	if err != nil {
		o.writeOIDCClientError(w, r, err)
		return
	}

	items := make([]oidcClientResponse, 0, len(list))
	for _, client := range list {
		items = append(items, newOIDCClientResponse(client))
	}
	writeJSON(w, http.StatusOK, items)
}

func (o options) handleGetOIDCClient(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())

	rowID, ok := oidcClientIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	client, err := o.oidcClients.Get(r.Context(), account.ID, rowID)
	if err != nil {
		o.writeOIDCClientError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newOIDCClientResponse(client))
}

func (o options) handleRevokeOIDCClient(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}
	account, _ := accountFrom(r.Context())

	rowID, ok := oidcClientIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	if _, err := o.oidcClients.Revoke(r.Context(), oidc.RevokeInput{
		AccountID: account.ID,
		ClientID:  rowID,
		RevokedBy: user.ID,
	}); err != nil {
		o.writeOIDCClientError(w, r, err)
		return
	}
	noContent(w)
}

func oidcClientIDFrom(r *http.Request) (id.UUID, bool) {
	parsed, err := id.Parse(chi.URLParam(r, oidcClientParam))
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}

func newOIDCClientResponse(c oidc.Client) oidcClientResponse {
	return oidcClientResponse{
		ID:           c.ID.String(),
		ClientID:     c.ClientID,
		Name:         c.Name,
		RedirectURIs: c.RedirectURIs,
		GrantTypes:   c.GrantTypes,
		Scopes:       c.Scopes,
		CreatedAt:    c.CreatedAt,
		RevokedAt:    c.RevokedAt,
	}
}

func (o options) writeOIDCClientError(w http.ResponseWriter, r *http.Request, err error) {
	var fieldErr *oidc.FieldError

	switch {
	case errors.Is(err, oidc.ErrNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound, "no such OIDC client is visible to you")

	case errors.Is(err, oidc.ErrAlreadyRevoked):
		problemFor(w, r, http.StatusConflict, CodeConflict, "this OIDC client is already revoked")

	case errors.As(err, &fieldErr):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}
