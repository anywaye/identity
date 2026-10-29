package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/admin"
	"github.com/anywaye/identity/internal/agents"
	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	acctboundary "github.com/anywaye/identity/internal/tenancy"
	"github.com/anywaye/identity/internal/users"
)


const matrixPassword = "correct horse battery staple"

type actor struct {
	name string
	token string
	user  id.UUID
	role accounts.Role
}

type matrixCase struct {
	endpoint   matrixEndpoint
	actor      actor
	wantStatus int
	wantProblemCode string
}

type matrixEndpoint struct {
	name   string
	method string
	pattern string
	unscoped bool
	success int
	expect func(column actor) (status int, problemCode string)
	body func(f *matrixFixture) string
	min accounts.Role
}

func (e matrixEndpoint) path(accountID, memberID, clientID, keyID, invitationID id.UUID) string {
	out := e.pattern
	out = strings.ReplaceAll(out, "{accountID}", accountID.String())
	out = strings.ReplaceAll(out, "{userID}", memberID.String())
	out = strings.ReplaceAll(out, "{clientID}", clientID.String())
	out = strings.ReplaceAll(out, "{keyID}", keyID.String())
	out = strings.ReplaceAll(out, "{invitationID}", invitationID.String())
	return out
}

func matrixEndpoints() []matrixEndpoint {
	return []matrixEndpoint{
		{
			name: "list my accounts", method: http.MethodGet,
			pattern: "/v1/accounts", unscoped: true, success: http.StatusOK,
		},
		{
			name: "create an account", method: http.MethodPost,
			pattern: "/v1/accounts", unscoped: true, success: http.StatusCreated, body: func(f *matrixFixture) string {
				return `{"name":"` + f.caseName + `"}`
			},
		},
		{
			name: "accept an invitation", method: http.MethodPost,
			pattern: "/v1/invitations/accept", unscoped: true, success: http.StatusOK,
			body: func(f *matrixFixture) string { return `{"token":"` + f.pendingToken + `"}` },
			expect: func(column actor) (int, string) {
				if column.token == "" {
					return http.StatusUnauthorized, CodeUnauthorized
				}
				if column.role != "" {
					return http.StatusConflict, CodeConflict
				}
				return http.StatusOK, ""
			},
		},

		{
			name: "read the account", method: http.MethodGet,
			pattern: "/v1/accounts/{accountID}", min: accounts.RoleMember, success: http.StatusOK,
		},
		{
			name: "list the members", method: http.MethodGet,
			pattern: "/v1/accounts/{accountID}/members", min: accounts.RoleMember, success: http.StatusOK,
		},
		{
			name: "rename the account", method: http.MethodPatch,
			pattern: "/v1/accounts/{accountID}", min: accounts.RoleAdmin, success: http.StatusOK,
			body: func(*matrixFixture) string { return `{"name":"Renamed"}` },
		},
		{
			name: "invite a member", method: http.MethodPost,
			pattern: "/v1/accounts/{accountID}/invitations", min: accounts.RoleAdmin, success: http.StatusCreated,
			body: func(f *matrixFixture) string {
				return `{"email":"` + f.inviteeEmail + `","role":"member"}`
			},
		},
		{
			name: "remove a member", method: http.MethodDelete,
			pattern: "/v1/accounts/{accountID}/members/{userID}", min: accounts.RoleAdmin, success: http.StatusNoContent,
		},
		{
			name: "change a role", method: http.MethodPatch,
			pattern: "/v1/accounts/{accountID}/members/{userID}", min: accounts.RoleOwner, success: http.StatusOK,
			body: func(*matrixFixture) string { return `{"role":"admin"}` },
		},
		{
			name: "delete the account", method: http.MethodDelete,
			pattern: "/v1/accounts/{accountID}", min: accounts.RoleOwner, success: http.StatusNoContent,
		},

		{
			name: "claim an agent", method: http.MethodPost,
			pattern: "/v1/accounts/{accountID}/agents/claim", min: accounts.RoleMember, success: http.StatusOK,
			body: func(f *matrixFixture) string {
				token := f.registerAgent()
				return `{"token":"` + token + `"}`
			},
		},

		{
			name: "transfer ownership", method: http.MethodPost,
			pattern: "/v1/accounts/{accountID}/ownership-transfers",
			min:     accounts.RoleOwner, success: http.StatusOK,
			body: func(f *matrixFixture) string {
				return `{"new_owner_user_id":"` + f.memberID.String() + `"}`
			},
		},

		{
			name: "register an OIDC client", method: http.MethodPost,
			pattern: "/v1/accounts/{accountID}/oidc-clients", min: accounts.RoleOwner, success: http.StatusCreated,
			body: func(f *matrixFixture) string {
				return `{"name":"` + f.caseName + `","redirect_uris":["https://matrix.example.com/cb"],` +
					`"grant_types":["authorization_code"],"scopes":["openid","email"]}`
			},
		},
		{
			name: "list the OIDC clients", method: http.MethodGet,
			pattern: "/v1/accounts/{accountID}/oidc-clients", min: accounts.RoleOwner, success: http.StatusOK,
		},
		{
			name: "read an OIDC client", method: http.MethodGet,
			pattern: "/v1/accounts/{accountID}/oidc-clients/{clientID}", min: accounts.RoleOwner, success: http.StatusOK,
		},
		{
			name: "revoke an OIDC client", method: http.MethodDelete,
			pattern: "/v1/accounts/{accountID}/oidc-clients/{clientID}", min: accounts.RoleOwner, success: http.StatusNoContent,
		},

		{
			name: "mint an api key", method: http.MethodPost,
			pattern: "/v1/accounts/{accountID}/api-keys", min: accounts.RoleOwner, success: http.StatusCreated,
			body: func(f *matrixFixture) string {
				return `{"name":"` + f.caseName + `","scopes":["accounts:read"]}`
			},
		},
		{
			name: "list the api keys", method: http.MethodGet,
			pattern: "/v1/accounts/{accountID}/api-keys", min: accounts.RoleOwner, success: http.StatusOK,
		},
		{
			name: "revoke an api key", method: http.MethodDelete,
			pattern: "/v1/accounts/{accountID}/api-keys/{keyID}", min: accounts.RoleOwner, success: http.StatusNoContent,
		},

		{
			name: "read the admin audit log", method: http.MethodGet,
			pattern: "/v1/accounts/{accountID}/admin/audit-log", min: accounts.RoleAdmin, success: http.StatusOK,
			expect: adminRouteRefused,
		},
		{
			name: "revoke one pending invitation", method: http.MethodDelete,
			pattern: "/v1/accounts/{accountID}/admin/invitations/{invitationID}",
			min:     accounts.RoleOwner, success: http.StatusNoContent,
			expect: adminRouteRefused,
		},
		{
			name: "bulk revoke pending invitations", method: http.MethodPost,
			pattern: "/v1/accounts/{accountID}/admin/invitation-revocations",
			min:     accounts.RoleOwner, success: http.StatusOK,
			body: func(f *matrixFixture) string {
				return `{"invitation_ids":["` + f.pendingInvitationID.String() + `"],"confirm":true}`
			},
			expect: adminRouteRefused,
		},
	}
}

func adminRouteRefused(_ actor) (int, string) {
	return http.StatusForbidden, CodeForbidden
}

type matrixFixture struct {
	handler     http.Handler
	pool        *pgxpool.Pool
	clock       *clock.Fake
	oidcClients *oidc.Service
	apiKeys *apikeys.Service

	t *testing.T

	accountID id.UUID
	memberID  id.UUID
	pendingToken string
	caseName string
	seq int
	clientID id.UUID
	inviteeEmail string
	keyID id.UUID
	pendingInvitationID id.UUID

	owner    actor
	admin    actor
	member   actor
	stranger actor
	elsewhere actor
}

func newMatrixFixture(t *testing.T) *matrixFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	tenancy := realTenancy(pool, clk)
	authSvc := authServiceFor(pool, clk)
	clients := matrixOIDCClients(t, pool, clk)
	keys := matrixAPIKeys(pool, clk, tenancy)
	adminSvc := admin.NewService(
		db.TxRunner{Pool: pool},
		admin.NewStore(pool),
		accounts.NewStore(pool),
		db.Direct{Pool: pool},
		clk,
	)

	handler := New(nil,
		WithAuth(authSvc),
		WithTenancy(tenancy),
		WithOIDCClients(clients),
		WithOIDC(newFakeOIDC()),
		WithAPIKeys(keys),
		WithAPIKeyCaller(keys),
		WithAdmin(adminSvc),
		WithAgents(agents.NewService(pool)),
		WithLogger(slogLogger(&recordingHandler{})),
	)

	return &matrixFixture{
		t:           t,
		handler:     handler,
		pool:        pool,
		clock:       clk,
		oidcClients: clients,
		apiKeys:     keys,
		owner:       actor{name: "owner", role: accounts.RoleOwner},
		admin:       actor{name: "admin", role: accounts.RoleAdmin},
		member:      actor{name: "member", role: accounts.RoleMember},
		stranger:    actor{name: "non-member"},
		elsewhere:   actor{name: "owner of another account"},
	}
}

func matrixAPIKeys(pool *pgxpool.Pool, clk clock.Clock, tenancy *accounts.Service) *apikeys.Service {
	return apikeys.NewService(
		db.TxRunner{Pool: pool},
		acctboundary.CredentialResolver{TxRunner: db.TxRunner{Pool: pool}},
		db.Direct{Pool: pool},
		apikeys.NewStore(pool),
		outbox.NewStore(pool),
		tenancy,
		users.NewStore(pool),
		clk,
	)
}

func (f *matrixFixture) register(t *testing.T, a *actor) {
	t.Helper()

	email := dbtest.UniqueEmail(t)
	rec := post(t, f.handler, "/v1/users", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering the %s actor: %d; body: %s", a.name, rec.Code, rec.Body)
	}
	var created userResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("the registration body is not JSON: %v", err)
	}
	parsed, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("the service returned an id that does not parse: %v", err)
	}
	a.user = parsed

	login := post(t, f.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("signing the %s actor in: %d; body: %s", a.name, login.Code, login.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}
	a.token = session.Token
}

var anonymous = actor{name: "anonymous"}

func (f *matrixFixture) buildTarget(t *testing.T) {
	t.Helper()

	f.caseName = strings.ReplaceAll(t.Name(), "/", " ")
	f.inviteeEmail = dbtest.UniqueEmail(t)
	f.seq++

	created, err := realTenancy(f.pool, f.clock).Create(t.Context(), accounts.CreateInput{
		Name:  f.label("Matrix"),
		Owner: f.owner.user,
	})
	if err != nil {
		t.Fatalf("creating the target account: %v", err)
	}
	f.accountID = created.Account.ID

	store := accounts.NewStore(f.pool)
	add := func(userID id.UUID, role accounts.Role) {
		t.Helper()
		if _, err := store.AddMember(t.Context(), f.pool, accounts.Membership{
			AccountID: f.accountID, UserID: userID, Role: role,
		}); err != nil {
			t.Fatalf("adding the %s actor at %s: %v", userID, role, err)
		}
	}
	add(f.admin.user, accounts.RoleAdmin)
	add(f.member.user, accounts.RoleMember)
	f.memberID = f.member.user

	if _, err := realTenancy(f.pool, f.clock).Create(t.Context(), accounts.CreateInput{
		Name:  f.label("Elsewhere"),
		Owner: f.elsewhere.user,
	}); err != nil {
		t.Fatalf("creating the elsewhere account: %v", err)
	}

	registered, err := f.oidcClients.Register(t.Context(), oidc.RegisterInput{
		AccountID:    f.accountID,
		Name:         f.label("Matrix"),
		RedirectURIs: []string{"https://matrix.example.com/cb"},
		GrantTypes:   []string{oidc.GrantAuthorizationCode},
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeEmail},
		RegisteredBy: f.owner.user,
	})
	if err != nil {
		t.Fatalf("registering the matrix's OIDC client: %v", err)
	}
	f.clientID = registered.Client.ID

	invited, err := realTenancy(f.pool, f.clock).Invite(t.Context(), accounts.InviteInput{
		AccountID: f.accountID,
		Email:     dbtest.UniqueEmail(t),
		Role:      accounts.RoleMember,
		InvitedBy: f.owner.user,
	})
	if err != nil {
		t.Fatalf("creating the pending invitation: %v", err)
	}
	f.pendingToken = invited.Token

	adminInvite, err := realTenancy(f.pool, f.clock).Invite(t.Context(), accounts.InviteInput{
		AccountID: f.accountID,
		Email:     dbtest.UniqueEmail(t),
		Role:      accounts.RoleMember,
		InvitedBy: f.owner.user,
	})
	if err != nil {
		t.Fatalf("creating the admin surface's pending invitation: %v", err)
	}
	f.pendingInvitationID = adminInvite.Invitation.ID

	key, err := f.apiKeys.Mint(t.Context(), apikeys.MintInput{
		AccountID: f.accountID,
		Name:      f.label("Matrix"),
		Scopes:    []string{apikeys.ScopeAccountsRead},
		MintedBy:  f.owner.user,
	})
	if err != nil {
		t.Fatalf("minting the matrix's api key: %v", err)
	}
	f.keyID = key.Key.ID
}

func (f *matrixFixture) label(prefix string) string {
	return fmt.Sprintf("%s %d", prefix, f.seq)
}

func (f *matrixFixture) columns() []actor {
	return []actor{
		anonymous,
		f.stranger,
		f.elsewhere,
		f.member,
		f.admin,
		f.owner,
	}
}

func TestAuthorizationMatrix(t *testing.T) {
	f := newMatrixFixture(t)

	f.register(t, &f.owner)
	f.register(t, &f.admin)
	f.register(t, &f.member)
	f.register(t, &f.stranger)
	f.register(t, &f.elsewhere)

	for _, endpoint := range matrixEndpoints() {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, column := range f.columns() {
				t.Run(column.name, func(t *testing.T) {
					f.buildTarget(t)

					tt := matrixCase{endpoint: endpoint, actor: column}
					tt.wantStatus, tt.wantProblemCode = expectedStatus(t, endpoint, column)

					rec := f.send(t, endpoint, column)
					if rec.Code != tt.wantStatus {
						t.Fatalf("%s %s as %s = %d, want %d\nbody: %s",
							endpoint.method, endpoint.path(f.accountID, f.memberID, f.clientID, f.keyID, f.pendingInvitationID),
							column.name, rec.Code, tt.wantStatus, rec.Body)
					}
					if tt.wantProblemCode == "" {
						return
					}
					p := decodeProblem(t, rec)
					if p.Code != tt.wantProblemCode {
						t.Errorf("code = %q, want %q; body: %s", p.Code, tt.wantProblemCode, rec.Body)
					}
				})
			}
		})
	}
}

func expectedStatus(_ *testing.T, endpoint matrixEndpoint, column actor) (status int, problemCode string) {
	if endpoint.expect != nil {
		return endpoint.expect(column)
	}
	if column.token == "" {
		return http.StatusUnauthorized, CodeUnauthorized
	}

	switch {
	case column.token == "":
		return http.StatusUnauthorized, CodeUnauthorized

	case endpoint.unscoped:
		return endpoint.success, ""

	case column.role == "":
		return http.StatusNotFound, CodeNotFound

	case !column.role.AtLeast(endpoint.min):
		return http.StatusForbidden, CodeForbidden

	default:
		if endpoint.success == 0 {
			panic("matrix: " + endpoint.name + " declares no success status")
		}
		return endpoint.success, ""
	}
}

func (f *matrixFixture) send(t *testing.T, endpoint matrixEndpoint, column actor) *httptest.ResponseRecorder {
	t.Helper()

	body := ""
	if endpoint.body != nil {
		body = endpoint.body(f)
	}

	req := httptest.NewRequestWithContext(context.Background(), endpoint.method, endpoint.path(f.accountID, f.memberID, f.clientID, f.keyID, f.pendingInvitationID), strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if column.token != "" {
		req.Header.Set("Authorization", "Bearer "+column.token)
	}

	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func TestEveryRouteIsInTheMatrix(t *testing.T) {
	mounted := mountedAccountRoutes()

	covered := make(map[string]bool, len(matrixEndpoints()))
	for _, e := range matrixEndpoints() {
		covered[normalizeRoute(e.method, e.pattern)] = true
	}

	for _, route := range mounted {
		if !covered[route] {
			t.Errorf("route %s is mounted but has no row in the authorization matrix", route)
		}
	}
	if len(covered) > len(mounted) {
		t.Errorf("the matrix has %d rows for %d mounted routes; it is asserting on routes that do not exist",
			len(covered), len(mounted))
	}
}

func mountedAccountRoutes() []string {
	var found []string

	r := chi.NewRouter()
	opts := options{
		tenancy:     newFakeTenancy(),
		auth:        newFakeAuth(),
		oidcClients: newFakeOIDCClients(),
		apiKeys:     newFakeAPIKeys(),
		admin:        newFakeAdmin(),
		apiKeyCaller: newFakeAPIKeyCaller(users.User{ID: id.MustNew()}, apikeys.Key{ID: id.MustNew(), AccountID: id.MustNew()}),
		agents: newFakeAgents(),
	}
	opts.registerTenancyRoutes(r)

	_ = chi.Walk(r, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		found = append(found, normalizeRoute(method, route))
		return nil
	})

	sort.Strings(found)
	return found
}

func (f *matrixFixture) registerAgent() string {
	t := f.t
	t.Helper()

	link, digest, err := agents.NewToken()
	if err != nil {
		t.Fatalf("minting a claim link: %v", err)
	}

	store := agents.NewStore(f.pool)
	now := time.Now()
	if _, err := store.Create(context.Background(), f.pool, agents.NewAgent{
		Name:               "Matrix agent " + id.MustNew().String()[:8],
		ClaimDigest:        digest,
		ClaimLinkExpiresAt: now.Add(agents.ClaimLinkTTL),
		CreatedAt:          now,
	}); err != nil {
		t.Fatalf("registering the matrix's agent: %v", err)
	}
	return link
}

func normalizeRoute(method, route string) string {
	return method + " " + strings.TrimRight(route, "/")
}

func TestEveryMountedRouteIsAnAccountRoute(t *testing.T) {
	for _, route := range mountedAccountRoutes() {
		path := strings.TrimPrefix(route, strings.SplitN(route, " ", 2)[0]+" ")
		if !strings.HasPrefix(path, "/v1/accounts") && path != "/v1/invitations/accept" {
			t.Errorf("registerTenancyRoutes mounted %s, which is not a tenancy route — it belongs on the auth routes", route)
		}
	}
}
