package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/platform/id"
)


// APIKeys is the part of apikeys.Service the v1 routes need.
//
// An interface declared here, at the consumer, for the reason Auth and Tenancy are:
// the handlers can be tested against a programmable double, and the HTTP layer has
// no dependency on the use case's internals. Every method takes ids and a
// clock-free input, so there is no way for a handler to reach past the
// authorization decision into a query it wrote itself.
type APIKeys interface {
	Mint(ctx context.Context, in apikeys.MintInput) (apikeys.IssuedKey, error)
	List(ctx context.Context, accountID id.UUID) ([]apikeys.Key, error)
	Revoke(ctx context.Context, in apikeys.RevokeInput) (apikeys.Key, error)
}

// WithAPIKeys mounts the api key routes.
//
// It is an Option for the reason every other service here is one: with no
// DATABASE_URL there is no api_keys table, and that process must still answer
// /healthz. The routes are absent rather than present-and-500.
func WithAPIKeys(k APIKeys) Option {
	return func(o *options) {
		if k != nil {
			o.apiKeys = k
		}
	}
}

func (o options) registerAPIKeyRoutes(r chiRouter) {
	if o.apiKeys == nil {
		return
	}
	r.Post("/v1/accounts/{accountID}/api-keys", o.requireAccountRole(accounts.RoleOwner, o.handleMintAPIKey))
	r.Get("/v1/accounts/{accountID}/api-keys", o.requireAccountRole(accounts.RoleOwner, o.handleListAPIKeys))
	r.Delete("/v1/accounts/{accountID}/api-keys/{keyID}", o.requireAccountRole(accounts.RoleOwner, o.handleRevokeAPIKey))
}


type apiKeyResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AccountID string    `json:"account_id"`
	UserID    string    `json:"user_id"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokeReason *string    `json:"revoke_reason,omitempty"`
}

type issuedAPIKeyResponse struct {
	apiKeyResponse
	Token string `json:"token"`
}

type mintAPIKeyRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresIn *int64   `json:"expires_in"`
}

type revokeAPIKeyRequest struct {
	Reason string `json:"reason"`
}


func (o options) handleMintAPIKey(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}
	account, _ := accountFrom(r.Context())

	var body *mintAPIKeyRequest
	if !decodeBody(w, r, &body) {
		return
	}

	in := apikeys.MintInput{
		AccountID: account.ID,
		Name:      body.Name,
		Scopes:    body.Scopes,
		MintedBy:  user.ID,
	}
	if body.ExpiresIn != nil {
		lifetime := time.Duration(*body.ExpiresIn) * time.Second
		in.ExpiresIn = &lifetime
	}

	issued, err := o.apiKeys.Mint(r.Context(), in)
	if err != nil {
		o.writeAPIKeyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, issuedAPIKeyResponse{
		apiKeyResponse: apiKeyFrom(issued.Key),
		Token:          issued.Token,
	})
}

func (o options) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())

	listed, err := o.apiKeys.List(r.Context(), account.ID)
	if err != nil {
		o.writeAPIKeyError(w, r, err)
		return
	}

	items := make([]apiKeyResponse, 0, len(listed))
	for _, k := range listed {
		items = append(items, apiKeyFrom(k))
	}

	writeJSON(w, http.StatusOK, items)
}

func (o options) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	keyID, ok := apiKeyIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	reason := ""
	if r.ContentLength != 0 {
		var body *revokeAPIKeyRequest
		if !decodeBody(w, r, &body) {
			return
		}
		reason = body.Reason
	}

	if _, err := o.apiKeys.Revoke(r.Context(), apikeys.RevokeInput{
		AccountID: account.ID,
		KeyID:     keyID,
		RevokedBy: user.ID,
		Reason:    reason,
	}); err != nil {
		o.writeAPIKeyError(w, r, err)
		return
	}

	noContent(w)
}

func apiKeyFrom(k apikeys.Key) apiKeyResponse {
	return apiKeyResponse{
		ID:        k.ID.String(),
		Name:      k.Name,
		AccountID: k.AccountID.String(),
		UserID:    k.UserID.String(),
		Scopes:       append([]string{}, k.Scopes...),
		ExpiresAt:    k.ExpiresAt,
		CreatedAt:    k.CreatedAt,
		LastUsedAt:   k.LastUsedAt,
		RevokedAt:    k.RevokedAt,
		RevokeReason: k.RevokeReason,
	}
}

func apiKeyIDFrom(r *http.Request) (id.UUID, bool) {
	raw := chi.URLParam(r, keyIDParam)
	parsed, err := id.Parse(raw)
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}

const keyIDParam = "keyID"


func (o options) writeAPIKeyError(w http.ResponseWriter, r *http.Request, err error) {
	var fieldErr *apikeys.FieldError

	switch {
	case errors.Is(err, apikeys.ErrNotAuthorized):
		problemFor(w, r, http.StatusForbidden, CodeForbidden,
			"only an owner may manage api keys for this account")

	case errors.Is(err, apikeys.ErrScopeNotMintableHere):
		problemFor(w, r, http.StatusForbidden, CodeForbidden,
			"an account's api keys cannot carry the "+apikeys.ScopeUsersDisable+" scope: it names no "+
				"account, so a credential minted for one account would be able to act on any user on the "+
				"deployment. That credential is a deployment fact, provisioned for the deployment rather "+
				"than minted from a tenant's settings")

	case errors.Is(err, apikeys.ErrNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no api key matches that id in this account")

	case errors.Is(err, apikeys.ErrAlreadyRevoked):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"this api key has already been revoked")

	case errors.Is(err, apikeys.ErrNameTaken):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an active api key with that name already exists in this account; revoke it first")

	case errors.As(err, &fieldErr):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}


// Introspector resolves a presented token to a claim document.
//
// It is separate from APIKeys because it is a READ of a credential rather than a
// management of one, and from APIKeyCaller because that one answers "who is
// calling" while this one answers "what may this token do" — and a token asking
// the second question about itself is the case that has no analog in the first.
type Introspector interface {
	Introspect(ctx context.Context, token string, now time.Time) (apikeys.Claims, error)
}

// WithIntrospection mounts the introspection route.
//
// Absent means the route is not mounted at all, and the OIDC provider's own
// SetIntrospectionFromToken keeps refusing — two different surfaces, two different
// credentials, and neither falling back to the other.
func WithIntrospection(i Introspector) Option {
	return func(o *options) {
		if i != nil {
			o.introspector = i
		}
	}
}

func (o options) registerIntrospectionRoute(r chiRouter) {
	if o.introspector == nil {
		return
	}
	r.Post("/v1/introspections", o.handleIntrospect)
}

type introspectRequest struct {
	Token string `json:"token"`
}

func (o options) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if o.presentedToken(r) == "" {
		unauthorized(w, r)
		return
	}

	var body *introspectRequest
	if !decodeBody(w, r, &body) {
		return
	}

	caller, ok := o.currentCaller(w, r)
	if !ok {
		return
	}

	claims, err := o.introspector.Introspect(r.Context(), body.Token, o.clk.Now())
	if err != nil {
		if errors.Is(err, apikeys.ErrNotFound) || errors.Is(err, apikeys.ErrNoAccountID) {
			writeJSON(w, http.StatusOK, apikeys.InactiveClaims())
			return
		}
		unexpected(w, r, o.logger, err)
		return
	}

	if !o.mayIntrospect(w, r, caller, claims) {
		return
	}

	writeJSON(w, http.StatusOK, claims)
}

func (o options) mayIntrospect(w http.ResponseWriter, r *http.Request, caller apikeys.Caller, claims apikeys.Claims) bool {
	if caller.Key.ID.IsZero() {
		accountID, err := apikeys.ResolveAccountID(claims)
		if err != nil {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this token cannot be attributed to an account")
			return false
		}
		_, role, err := o.tenancy.Get(r.Context(), accountID, caller.User.ID)
		if err != nil {
			problemFor(w, r, http.StatusNotFound, CodeNotFound,
				"no api key matches that token in an account you can see")
			return false
		}
		if !role.AtLeast(accounts.RoleOwner) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"only an owner may read an api key's grant in this account")
			return false
		}
		return true
	}

	if claims.TokenID != caller.Key.ID.String() {
		if !slices.Contains(caller.Key.Scopes, apikeys.ScopeTokensIntrospect) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"an api key may only introspect itself")
			return false
		}
	}
	return true
}


func (o options) presentedAPIKey(r *http.Request) string {
	token := bearerToken(r)
	if !strings.HasPrefix(token, apikeys.Prefix) {
		return ""
	}
	return token
}

func (o options) isAPIKeyRequest(r *http.Request) bool {
	return o.presentedAPIKey(r) != ""
}

func (o options) sessionCredentialOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o.isAPIKeyRequest(r) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"an api key may not use this endpoint; it is a session surface. "+
					"An api key acts on the account it was issued for, and only there")
			return
		}
		next(w, r)
	}
}
