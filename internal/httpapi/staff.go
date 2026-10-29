package httpapi


import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/users"
)

func (o options) registerStaffRoutes(r chiRouter) {
	r.Get("/v1/operator/me", o.requireStaffSession(o.handleOperatorMe))
	r.Get("/v1/operator/users", o.requireStaffSession(o.handleSearchOperatorUsers))
	r.Get("/v1/operator/summary", o.requireStaffSession(o.handleOperatorSummary))
	r.Get("/v1/operator/accounts", o.requireStaffSession(o.handleOperatorAccounts))
	r.Post("/v1/operator/users/{userID}/disable", o.requireStaffSession(o.handleStaffDisableUser))
	r.Post("/v1/operator/users/{userID}/enable", o.requireStaffSession(o.handleStaffEnableUser))
}

func (o options) requireStaffSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o.isAPIKeyRequest(r) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"the staff surface is reachable by a signed-in staff member's session only; "+
					"a scoped api key may not use it. The machine operator surface is "+
					"POST /v1/users/{userID}/disable, and the two credentials do not cross")
			return
		}
		user, ok := o.currentUser(w, r)
		if !ok {
			return
		}
		if !user.IsStaff {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this route is for platform staff; your account is not marked as staff. "+
					"No account role grants this — staff is a property of the user, not of a membership")
			return
		}
		next(w, r.WithContext(withStaffCaller(r.Context(), user)))
	}
}

type staffCallerKey struct{}

func withStaffCaller(ctx context.Context, user users.User) context.Context {
	return context.WithValue(ctx, staffCallerKey{}, user)
}

func staffFrom(ctx context.Context) (users.User, bool) {
	user, ok := ctx.Value(staffCallerKey{}).(users.User)
	if !ok || !user.IsStaff {
		return users.User{}, false
	}
	return user, true
}


type operatorMeResponse struct {
	User operatorMeUser `json:"user"`
}

type operatorMeUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Staff bool   `json:"staff"`
}

type staffUserEntry struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	DisplayName     *string    `json:"display_name,omitempty"`
	DisabledAt      *time.Time `json:"disabled_at"`
	EmailVerifiedAt *time.Time `json:"email_verified_at"`
	CreatedAt       time.Time  `json:"created_at"`
}

type staffUserListResponse struct {
	Users []staffUserEntry `json:"users"`
}

type operatorSummaryResponse struct {
	Users users.UserCounts `json:"users"`
}

type operatorAccountEntry struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Personal  bool      `json:"personal"`
	CreatedAt time.Time `json:"created_at"`
}

type operatorAccountsResponse struct {
	Accounts []operatorAccountEntry `json:"accounts"`
}


func (o options) handleOperatorMe(w http.ResponseWriter, r *http.Request) {
	staff, ok := staffFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoStaffCaller)
		return
	}
	writeJSON(w, http.StatusOK, operatorMeResponse{
		User: operatorMeUser{
			ID:    staff.ID.String(),
			Email: staff.Email,
			Staff: true,
		},
	})
}

func (o options) handleSearchOperatorUsers(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	if query == "" {
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the directory search needs a query to search for").
			withFieldErrors([]FieldError{{Field: "query", Code: apikeys.CodeRequired}}))
		return
	}
	if len([]rune(query)) < users.MinSearchLength {
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the directory search needs a longer query to search for").
			withFieldErrors([]FieldError{{Field: "query", Code: users.CodeTooShort}}))
		return
	}

	limit := users.DefaultSearchLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
				withDetail("the directory search limit is not one this endpoint accepts").
				withFieldErrors([]FieldError{{Field: "limit", Code: apikeys.CodeInvalidFormat}}))
			return
		}
		if parsed > users.MaxSearchLimit {
			writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
				withDetail("the directory search limit is not one this endpoint accepts").
				withFieldErrors([]FieldError{{Field: "limit", Code: apikeys.CodeOutOfRange}}))
			return
		}
		limit = parsed
	}

	entries, err := o.auth.SearchUsers(r.Context(), query, limit)
	if err != nil {
		unexpected(w, r, o.logger, err)
		return
	}

	out := make([]staffUserEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, staffUserEntry{
			ID:              e.ID.String(),
			Email:           e.Email,
			DisplayName:     e.DisplayName,
			DisabledAt:      e.DisabledAt,
			EmailVerifiedAt: e.EmailVerifiedAt,
			CreatedAt:       e.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, staffUserListResponse{Users: out})
}

var errNoStaffCaller = errors.New("a staff route reached its handler with no staff user in context")

func (o options) handleOperatorSummary(w http.ResponseWriter, r *http.Request) {
	counts, err := o.auth.UserCounts(r.Context())
	if err != nil {
		unexpected(w, r, o.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, operatorSummaryResponse{Users: counts})
}

func (o options) handleOperatorAccounts(w http.ResponseWriter, r *http.Request) {
	if o.tenancy == nil {
		unexpected(w, r, o.logger, errors.New("tenancy service is not configured"))
		return
	}

	query := strings.TrimSpace(r.URL.Query().Get("query"))

	limit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
				withDetail("the account search limit is not one this endpoint accepts").
				withFieldErrors([]FieldError{{Field: "limit", Code: apikeys.CodeInvalidFormat}}))
			return
		}
		if parsed > 50 {
			writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
				withDetail("the account search limit is not one this endpoint accepts").
				withFieldErrors([]FieldError{{Field: "limit", Code: apikeys.CodeOutOfRange}}))
			return
		}
		limit = parsed
	}

	entries, err := o.tenancy.SearchAccounts(r.Context(), query, limit)
	if err != nil {
		unexpected(w, r, o.logger, err)
		return
	}

	out := make([]operatorAccountEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, operatorAccountEntry{
			ID:        e.ID.String(),
			Name:      e.Name,
			Slug:      e.Slug,
			Personal:  e.Personal,
			CreatedAt: e.CreatedAt,
		})
	}
	if out == nil {
		out = []operatorAccountEntry{}
	}
	writeJSON(w, http.StatusOK, operatorAccountsResponse{Accounts: out})
}

func (o options) handleStaffDisableUser(w http.ResponseWriter, r *http.Request) {
	staff, ok := staffFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoStaffCaller)
		return
	}
	userID, ok := operatorSubject(r)
	if !ok {
		notFound(w, r)
		return
	}

	if err := o.auth.Disable(r.Context(), auth.DisableInput{
		UserID:      userID,
		ActorUserID: staff.ID,
		ActorKeyID:  id.UUID{},
		TraceID:     traceIDFrom(r.Context()),
		At:          o.clk.Now(),
	}); err != nil {
		o.writeOperatorError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (o options) handleStaffEnableUser(w http.ResponseWriter, r *http.Request) {
	staff, ok := staffFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoStaffCaller)
		return
	}
	userID, ok := operatorSubject(r)
	if !ok {
		notFound(w, r)
		return
	}

	if err := o.auth.Enable(r.Context(), auth.EnableInput{
		UserID:      userID,
		ActorUserID: staff.ID,
		ActorKeyID:  id.UUID{},
		TraceID:     traceIDFrom(r.Context()),
		At:          o.clk.Now(),
	}); err != nil {
		o.writeOperatorError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
