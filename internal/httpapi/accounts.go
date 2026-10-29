package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/tenancy"
	"github.com/anywaye/identity/internal/users"
)


const accountIDParam = "accountID"

const userIDParam = "userID"

// Tenancy is the part of accounts.Service the v1 routes need.
//
// It is an interface declared here, at the consumer, for the same reason Auth is:
// the handlers can then be tested against a programmable double, and the HTTP
// layer has no dependency on the use cases' internals. Every method takes only
// ids and a clock-free input, so there is no way for a handler to reach past the
// authorization decision into a query it wrote itself.
type Tenancy interface {
	Create(ctx context.Context, in accounts.CreateInput) (accounts.Created, error)
	ListMine(ctx context.Context, userID id.UUID) ([]accounts.MemberSummary, error)
	SearchAccounts(ctx context.Context, query string, limit int) ([]accounts.Account, error)
	Get(ctx context.Context, accountID, userID id.UUID) (accounts.Account, accounts.Role, error)
	Members(ctx context.Context, accountID id.UUID) ([]accounts.MemberSummary, error)
	Rename(ctx context.Context, accountID id.UUID, name string) (accounts.Account, error)
	Delete(ctx context.Context, accountID id.UUID) error
	InviteRole(ctx context.Context, accountID id.UUID, email, role string, invitedBy id.UUID) (accounts.Invited, error)
	Accept(ctx context.Context, in accounts.AcceptInput) (accounts.Membership, error)
	ChangeRole(ctx context.Context, in accounts.ChangeRoleInput) (accounts.Membership, error)
	RemoveMember(ctx context.Context, in accounts.RemoveMemberInput) error
	TransferOwnership(ctx context.Context, in accounts.TransferInput) (accounts.Transferred, error)
}

// WithTenancy mounts the account routes.
//
// It is an Option rather than a constructor argument for the same reason
// WithAuth is: with no DATABASE_URL there is no accounts service, and that
// process must still answer /healthz. The account routes are simply absent when
// it is not given, so a misconfiguration is a 404 rather than a pile of 500s.
//
// It is ignored without Auth, because every account route starts by resolving a
// session and a service with no way to resolve one has nothing to mount.
func WithTenancy(t Tenancy) Option {
	return func(o *options) {
		if t != nil {
			o.tenancy = t
		}
	}
}

type accountScope struct {
	Account accounts.Account
	Role    accounts.Role
	User    users.User
	KeyID id.UUID
}

type accountContextKey struct{}

func accountFrom(ctx context.Context) (accounts.Account, bool) {
	scope, ok := ctx.Value(accountContextKey{}).(accountScope)
	return scope.Account, ok
}

func roleFrom(ctx context.Context) accounts.Role {
	scope, _ := ctx.Value(accountContextKey{}).(accountScope)
	return scope.Role
}

var accountRouteScopes = map[string]string{
	"GET /v1/accounts/{accountID}":         apikeys.ScopeAccountsRead,
	"GET /v1/accounts/{accountID}/members": apikeys.ScopeAccountsRead,

	"PATCH /v1/accounts/{accountID}":                   apikeys.ScopeAccountsWrite,
	"POST /v1/accounts/{accountID}/invitations":        apikeys.ScopeAccountsWrite,
	"PATCH /v1/accounts/{accountID}/members/{userID}":  apikeys.ScopeAccountsWrite,
	"DELETE /v1/accounts/{accountID}/members/{userID}": apikeys.ScopeAccountsWrite,

	"POST /v1/accounts/{accountID}/ownership-transfers": apikeys.ScopeAccountsWrite,

	"DELETE /v1/accounts/{accountID}": apikeys.ScopeAccountsDelete,

	"POST /v1/accounts/{accountID}/oidc-clients":              apikeys.ScopeOIDCClientsWrite,
	"GET /v1/accounts/{accountID}/oidc-clients":               apikeys.ScopeOIDCClientsWrite,
	"GET /v1/accounts/{accountID}/oidc-clients/{clientID}":    apikeys.ScopeOIDCClientsWrite,
	"DELETE /v1/accounts/{accountID}/oidc-clients/{clientID}": apikeys.ScopeOIDCClientsWrite,

	"GET /v1/accounts/{accountID}/admin/audit-log":                     apikeys.ScopeAuditLogRead,
	"DELETE /v1/accounts/{accountID}/admin/invitations/{invitationID}": apikeys.ScopeAccountInvitationsWrite,
	"POST /v1/accounts/{accountID}/admin/invitation-revocations":       apikeys.ScopeAccountInvitationsWrite,

	"POST /v1/session-links": apikeys.ScopeSessionsWrite,

	"POST /v1/users/{userID}/disable": apikeys.ScopeUsersDisable,
	"POST /v1/users/{userID}/enable":  apikeys.ScopeUsersDisable,

	"POST /v1/introspections": apikeys.ScopeTokensIntrospect,
}

func scopeRequiredBy(r *http.Request) string {
	route := chi.RouteContext(r.Context()).RoutePattern()
	if route == "" {
		return ""
	}
	return accountRouteScopes[strings.ToUpper(r.Method)+" "+route]
}

// APIKeyCaller resolves a scoped api key to its caller, or reports that the
// request is not presenting one.
//
// It is on the HTTP layer's own options rather than on Auth because it is a
// DIFFERENT CREDENTIAL with a different table, a different lifetime and a
// different revocation story, and routing it through Auth would put a lookup for a
// `anywaye_…` value in the sessions table on the path of every authenticated
// request.
type APIKeyCaller interface {
	Authenticate(ctx context.Context, token string, now time.Time) (apikeys.Caller, error)
}

// WithAPIKeyCaller teaches the router how to resolve a scoped token.
//
// Without it the account-scoped routes are SESSION-ONLY: a token presented to one
// is refused with the same 401 an unknown credential gets, because there is nothing
// here that could authenticate it. That is the fail-closed direction and it is a
// supported configuration — the routes still work for browsers.
func WithAPIKeyCaller(c APIKeyCaller) Option {
	return func(o *options) {
		if c != nil {
			o.apiKeyCaller = c
		}
	}
}

func (o options) requireAccountRole(min accounts.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := o.currentCaller(w, r)
		if !ok {
			return
		}
		user := caller.User

		accountID, ok := accountIDFrom(r)
		if !ok {
			notFound(w, r)
			return
		}

		account, role, err := o.tenancy.Get(r.Context(), accountID, user.ID)
		if err != nil {
			o.writeTenancyError(w, r, err)
			return
		}

		if !role.AtLeast(min) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"your role in this account does not permit this action")
			return
		}

		if !caller.Key.ID.IsZero() && caller.Key.AccountID != accountID {
			notFound(w, r)
			return
		}

		if !caller.Key.ID.IsZero() && !caller.Key.Allows(scopeRequiredBy(r)) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this api key does not carry the "+scopeRequiredBy(r)+" scope")
			return
		}

		ctx := tenancy.WithAccount(context.WithValue(r.Context(), accountContextKey{}, accountScope{
			Account: account, Role: role, User: user,
			KeyID: caller.Key.ID,
		}), account.ID)
		next(w, r.WithContext(ctx))
	}
}

func (o options) currentCaller(w http.ResponseWriter, r *http.Request) (apikeys.Caller, bool) {
	if token := o.presentedAPIKey(r); token != "" {
		if o.apiKeyCaller == nil {
			unauthorized(w, r)
			return apikeys.Caller{}, false
		}
		caller, err := o.apiKeyCaller.Authenticate(r.Context(), token, o.clk.Now())
		if err != nil {
			unauthorized(w, r)
			return apikeys.Caller{}, false
		}
		return caller, true
	}

	user, ok := o.currentUser(w, r)
	if !ok {
		return apikeys.Caller{}, false
	}
	return apikeys.Caller{User: user}, true
}

func (o options) currentUser(w http.ResponseWriter, r *http.Request) (users.User, bool) {
	token := o.presentedToken(r)
	if token == "" {
		unauthorized(w, r)
		return users.User{}, false
	}

	user, err := o.auth.Authenticate(r.Context(), token)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			unauthorized(w, r)
			return users.User{}, false
		}
		unexpected(w, r, o.logger, err)
		return users.User{}, false
	}
	return user, true
}

func accountIDFrom(r *http.Request) (id.UUID, bool) {
	raw := chi.URLParam(r, accountIDParam)
	parsed, err := id.Parse(raw)
	if err != nil {
		return id.UUID{}, false
	}
	if parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}

func userIDFrom(r *http.Request) (id.UUID, bool) {
	parsed, err := id.Parse(chi.URLParam(r, userIDParam))
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}


type accountResponse struct {
	ID        string               `json:"id"`
	Name      string               `json:"name"`
	Slug      string               `json:"slug"`
	Personal  bool                 `json:"personal"`
	Role      accounts.Role        `json:"role"`
	Members   []membershipResponse `json:"members,omitempty"`
	CreatedAt time.Time            `json:"created_at"`
	UpdatedAt time.Time            `json:"updated_at"`
}

type accountListItem struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Slug      string        `json:"slug"`
	Personal  bool          `json:"personal"`
	Role      accounts.Role `json:"role"`
	CreatedAt time.Time     `json:"created_at"`
}

type membershipResponse struct {
	AccountID string        `json:"account_id"`
	UserID    string        `json:"user_id"`
	Role      accounts.Role `json:"role"`
	CreatedAt time.Time     `json:"created_at"`
}

type invitationResponse struct {
	ID        string        `json:"id"`
	AccountID string        `json:"account_id"`
	Email     string        `json:"email"`
	Role      accounts.Role `json:"role"`
	Token     string        `json:"token"`
	ExpiresAt time.Time     `json:"expires_at"`
	CreatedAt time.Time     `json:"created_at"`
}

type createAccountRequest struct {
	Name string `json:"name"`
}

type renameAccountRequest struct {
	Name string `json:"name"`
}

type inviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type acceptInvitationRequest struct {
	Token string `json:"token"`
}

type changeRoleRequest struct {
	Role string `json:"role"`
}

type transferOwnershipRequest struct {
	NewOwnerUserID string `json:"new_owner_user_id"`
}

type ownershipTransferResponse struct {
	Account       accountResponse    `json:"account"`
	NewOwner      membershipResponse `json:"new_owner"`
	PreviousOwner membershipResponse `json:"previous_owner"`
}


func (o options) registerTenancyRoutes(r chiRouter) {
	r.Post("/v1/accounts", o.sessionCredentialOnly(o.handleCreateAccount))
	r.Get("/v1/accounts", o.sessionCredentialOnly(o.handleListAccounts))
	r.Post("/v1/invitations/accept", o.sessionCredentialOnly(o.handleAcceptInvitation))

	r.Get("/v1/accounts/{accountID}", o.requireAccountRole(accounts.RoleMember, o.handleGetAccount))
	r.Patch("/v1/accounts/{accountID}", o.requireAccountRole(accounts.RoleAdmin, o.handleRenameAccount))
	r.Delete("/v1/accounts/{accountID}", o.requireAccountRole(accounts.RoleOwner, o.handleDeleteAccount))

	r.Get("/v1/accounts/{accountID}/members", o.requireAccountRole(accounts.RoleMember, o.handleListMembers))
	r.Post("/v1/accounts/{accountID}/invitations", o.requireAccountRole(accounts.RoleAdmin, o.handleInvite))
	r.Patch("/v1/accounts/{accountID}/members/{userID}", o.requireAccountRole(accounts.RoleOwner, o.handleChangeRole))
	r.Delete("/v1/accounts/{accountID}/members/{userID}", o.requireAccountRole(accounts.RoleAdmin, o.handleRemoveMember))

	r.Post("/v1/accounts/{accountID}/ownership-transfers", o.requireAccountRole(accounts.RoleOwner, o.handleTransferOwnership))

	o.registerOIDCClientRoutes(r)

	o.registerAPIKeyRoutes(r)

	o.registerAdminRoutes(r)

	o.registerAgentRoutes(r)
}

func (o options) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *createAccountRequest
	if !decodeBody(w, r, &body) {
		return
	}

	created, err := o.tenancy.Create(r.Context(), accounts.CreateInput{Name: body.Name, Owner: user.ID})
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, accountResponse{
		ID:        created.Account.ID.String(),
		Name:      created.Account.Name,
		Slug:      created.Account.Slug,
		Personal:  created.Account.Personal,
		Role:      created.Membership.Role,
		CreatedAt: created.Account.CreatedAt,
		UpdatedAt: created.Account.UpdatedAt,
	})
}

func (o options) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	list, err := o.tenancy.ListMine(r.Context(), user.ID)
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	items := make([]accountListItem, 0, len(list))
	for _, m := range list {
		items = append(items, accountListItem{
			ID:        m.Account.ID.String(),
			Name:      m.Account.Name,
			Slug:      m.Account.Slug,
			Personal:  m.Account.Personal,
			Role:      m.Role,
			CreatedAt: m.Account.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, items)
}

func (o options) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())
	role := roleFrom(r.Context())

	members, err := o.tenancy.Members(r.Context(), account.ID)
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, accountResponse{
		ID:        account.ID.String(),
		Name:      account.Name,
		Slug:      account.Slug,
		Personal:  account.Personal,
		Role:      role,
		Members:   membershipResponses(members),
		CreatedAt: account.CreatedAt,
		UpdatedAt: account.UpdatedAt,
	})
}

func (o options) handleListMembers(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())

	members, err := o.tenancy.Members(r.Context(), account.ID)
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, struct {
		Memberships []membershipResponse `json:"memberships"`
		Role        accounts.Role        `json:"role"`
	}{
		Memberships: membershipResponses(members),
		Role:        roleFrom(r.Context()),
	})
}

func (o options) handleRenameAccount(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())

	var body *renameAccountRequest
	if !decodeBody(w, r, &body) {
		return
	}

	renamed, err := o.tenancy.Rename(r.Context(), account.ID, body.Name)
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, accountResponse{
		ID:        renamed.ID.String(),
		Name:      renamed.Name,
		Slug:      renamed.Slug,
		Personal:  renamed.Personal,
		Role:      roleFrom(r.Context()),
		CreatedAt: renamed.CreatedAt,
		UpdatedAt: renamed.UpdatedAt,
	})
}

func (o options) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())

	if err := o.tenancy.Delete(r.Context(), account.ID); err != nil {
		o.writeTenancyError(w, r, err)
		return
	}
	noContent(w)
}

func (o options) handleInvite(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *inviteRequest
	if !decodeBody(w, r, &body) {
		return
	}

	invited, err := o.tenancy.InviteRole(r.Context(), account.ID, body.Email, body.Role, user.ID)
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, invitationResponse{
		ID:        invited.Invitation.ID.String(),
		AccountID: invited.Invitation.AccountID.String(),
		Email:     invited.Invitation.Email,
		Role:      invited.Invitation.Role,
		Token:     invited.Token,
		ExpiresAt: invited.Invitation.ExpiresAt,
		CreatedAt: invited.Invitation.CreatedAt,
	})
}

func (o options) handleAcceptInvitation(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *acceptInvitationRequest
	if !decodeBody(w, r, &body) {
		return
	}

	membership, err := o.tenancy.Accept(r.Context(), accounts.AcceptInput{Token: body.Token, User: user.ID})
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, membershipResponse{
		AccountID: membership.AccountID.String(),
		UserID:    membership.UserID.String(),
		Role:      membership.Role,
		CreatedAt: membership.CreatedAt,
	})
}

func (o options) handleChangeRole(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())
	actor, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	target, ok := userIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	var body *changeRoleRequest
	if !decodeBody(w, r, &body) {
		return
	}

	role, err := accounts.ParseRole(body.Role)
	if err != nil {
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: "role", Code: accounts.CodeUnknownRole}}))
		return
	}

	membership, err := o.tenancy.ChangeRole(r.Context(), accounts.ChangeRoleInput{
		AccountID: account.ID,
		UserID:    target,
		Role:      role,
		Actor:     actor.ID,
	})
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, membershipResponse{
		AccountID: membership.AccountID.String(),
		UserID:    membership.UserID.String(),
		Role:      membership.Role,
		CreatedAt: membership.CreatedAt,
	})
}

func (o options) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())
	actor, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	target, ok := userIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	if err := o.tenancy.RemoveMember(r.Context(), accounts.RemoveMemberInput{
		AccountID: account.ID,
		UserID:    target,
		Actor:     actor.ID,
	}); err != nil {
		o.writeTenancyError(w, r, err)
		return
	}
	noContent(w)
}

func (o options) handleTransferOwnership(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())
	actor, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *transferOwnershipRequest
	if !decodeBody(w, r, &body) {
		return
	}

	heir, err := id.Parse(body.NewOwnerUserID)
	if err != nil || heir.IsZero() {
		notFound(w, r)
		return
	}

	done, err := o.tenancy.TransferOwnership(r.Context(), accounts.TransferInput{
		AccountID: account.ID,
		ToUserID:  heir,
		Actor:     actor.ID,
	})
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, ownershipTransferResponse{
		Account: accountResponse{
			ID:        done.Account.ID.String(),
			Name:      done.Account.Name,
			Slug:      done.Account.Slug,
			Personal:  done.Account.Personal,
			Role:      roleFrom(r.Context()),
			CreatedAt: done.Account.CreatedAt,
			UpdatedAt: done.Account.UpdatedAt,
		},
		NewOwner: membershipResponse{
			AccountID: done.NewOwner.AccountID.String(),
			UserID:    done.NewOwner.UserID.String(),
			Role:      done.NewOwner.Role,
			CreatedAt: done.NewOwner.CreatedAt,
		},
		PreviousOwner: membershipResponse{
			AccountID: done.PreviousOwner.AccountID.String(),
			UserID:    done.PreviousOwner.UserID.String(),
			Role:      done.PreviousOwner.Role,
			CreatedAt: done.PreviousOwner.CreatedAt,
		},
	})
}

func membershipResponses(members []accounts.MemberSummary) []membershipResponse {
	out := make([]membershipResponse, 0, len(members))
	for _, m := range members {
		out = append(out, membershipResponse{
			AccountID: m.Account.ID.String(),
			UserID:    m.UserID.String(),
			Role:      m.Role,
			CreatedAt: m.JoinedAt,
		})
	}
	return out
}


func (o options) writeTenancyError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		accountsField *accounts.FieldError
		usersField    *users.FieldError
	)

	switch {
	case errors.Is(err, accounts.ErrNotFound), errors.Is(err, accounts.ErrNotAMember):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no such account is visible to you")

	case errors.Is(err, accounts.ErrOwnerProtected):
		problemFor(w, r, http.StatusForbidden, CodeForbidden,
			"only an owner may act on an owner's membership")

	case errors.Is(err, accounts.ErrNotOwner):
		problemFor(w, r, http.StatusForbidden, CodeForbidden,
			"only an account's owner may do this")

	case errors.Is(err, accounts.ErrNotTransferable):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("this account cannot be transferred to another member").
			withFieldErrors([]FieldError{{Field: "new_owner_user_id", Code: "not_transferable"}}))

	case errors.Is(err, accounts.ErrTransferToSelf):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("an owner cannot transfer an account to themselves").
			withFieldErrors([]FieldError{{Field: "new_owner_user_id", Code: "transfer_to_self"}}))

	case errors.Is(err, accounts.ErrLastOwner):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("this account must keep at least one owner").
			withFieldErrors([]FieldError{{Field: "role", Code: "last_owner"}}))

	case errors.Is(err, accounts.ErrSelfRoleChange):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("you are the only owner of this account and cannot change your own role").
			withFieldErrors([]FieldError{{Field: "role", Code: "last_owner"}}))

	case errors.Is(err, accounts.ErrRoleNotInvitable):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("an invitation may only carry the admin or member role").
			withFieldErrors([]FieldError{{Field: "role", Code: "not_invitable"}}))

	case errors.Is(err, accounts.ErrSlugTaken):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an account with that name already exists; its handle is the name in lower case with dashes")

	case errors.Is(err, accounts.ErrAlreadyAMember):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"you are already a member of this account")

	case errors.Is(err, accounts.ErrInvitationEmailTaken):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"there is already a pending invitation for that address on this account")

	case errors.Is(err, accounts.ErrInvitationUsed):
		problemFor(w, r, http.StatusGone, CodeGone,
			"this invitation has already been accepted")

	case errors.Is(err, accounts.ErrInvitationExpired):
		problemFor(w, r, http.StatusGone, CodeGone,
			"this invitation has expired; ask for a new one")

	case errors.Is(err, accounts.ErrInvitationNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no invitation matches that token")

	case errors.As(err, &accountsField):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: accountsField.Field, Code: accountsField.Code}}))

	case errors.As(err, &usersField):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: usersField.Field, Code: usersField.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}
