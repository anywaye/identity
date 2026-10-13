package httpapi

// THE BOUNDARY, BY NAME.
//
// `operator_test.go` proves the gate works; this file exists because a boundary that
// is only tested inside the gate's own tests is a boundary whose regression message
// is a table row somebody has to read sideways to understand. These three tests are
// the ones D14 names, and each is a claim about the *deployment* rather than about
// one route:
//
//  1. no account route can be reached with `users:disable`;
//  2. every credential kind that is not the operator's is refused, over real rows;
//  3. the operator scope cannot be reached through an account-scoped credential at
//     any role, including owner.
//
// The first and the third are related but not the same, and the difference is the
// one a future packet would get wrong: widening `users:disable` onto an account path
// is caught by the first, and granting a role permission to call the operator routes
// is caught by the second and third.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/platform/id"
)

// TestNoAccountRouteDeclaresTheOperatorScope walks the scope table rather than the
// router, because the property is about DECLARATION: no row under `/v1/accounts/…`
// names `users:disable`.
//
// IT IS A TABLE WALK AND NOT A REQUEST WALK, and the reason is that a request walk
// cannot express this. Every account route also requires a role and a membership, so
// driving one with an operator token would be refused by the role check first and the
// test would pass whether or not the scope row existed — it would be measuring the
// membership lookup. The declaration is the thing that must be absent, so the
// declaration is what is read.
func TestNoAccountRouteDeclaresTheOperatorScope(t *testing.T) {
	t.Parallel()

	accountRows := 0
	for route, declared := range accountRouteScopes {
		if !strings.Contains(route, "/v1/accounts/") {
			continue
		}
		accountRows++
		if declared == apikeys.ScopeUsersDisable {
			t.Errorf("account route %s declares scope %q. The operator scope names no account, so "+
				"a row putting it on an account path is a tenancy somebody invented — and the "+
				"obvious invention, the caller's own account, would let one tenant reach a user who "+
				"works for another. See DECISIONS.md D14", route, declared)
		}
	}
	if accountRows == 0 {
		t.Fatal("the scope table holds no account row, so this test proves nothing about " +
			"account routes")
	}

	// AND THE ROWS THAT DO NAME IT ARE THE OPERATOR'S, which is the positive half:
	// a scope with no row is a comment with a type, and this says the two rows are
	// there rather than trusting the walk above to notice their absence.
	for _, want := range []string{
		"POST /v1/users/{userID}/disable",
		"POST /v1/users/{userID}/enable",
	} {
		if got := accountRouteScopes[want]; got != apikeys.ScopeUsersDisable {
			t.Errorf("the operator surface's row for %s declares %q, want %q. Deleting or "+
				"renaming it CLOSES the route to tokens — `Allows(\"\")` is false for every granted "+
				"set — which is the fail-closed direction, but it means the row is the capability "+
				"and not a description of it", want, got, apikeys.ScopeUsersDisable)
		}
	}
}

// everyAccountScope is the vocabulary MINUS the operator scope, and it is a
// function rather than a literal because the literal would rot the day a ninth scope
// lands — and it would rot silently, in a test whose whole claim is that this is
// everything an account-scoped credential can hold.
//
// THE OPERATOR SCOPE IS EXCLUDED DELIBERATELY, and saying why is the point of this
// file. A token holding `users:disable` IS the operator credential, whatever account
// it happens to carry an `account_id` in — the route reads the scope and nothing else,
// because a user is not an account. So "an account-scoped credential cannot disable a
// user" is NOT a claim about the account id on the row; it is two claims, and they
// are:
//
//	a credential an account owner can MINT cannot hold the operator scope — held by
//	    `TestTheMintRefusesToGrantTheOperatorScope` against the real use case;
//	a credential minted for one account that does NOT hold it is refused here —
//	    which is what this test walks.
//
// The first is the load-bearing one. A route-level refusal is only a boundary if
// there is no way to obtain a credential the route would accept, and the mint is the
// only way this service hands one out.
func everyAccountScope() []string {
	var out []string
	for _, scope := range apikeys.AllScopes() {
		if scope != apikeys.ScopeUsersDisable {
			out = append(out, scope)
		}
	}
	return out
}

// TestAnAccountScopedCredentialCannotDisableAUser is the boundary D2–D5 drew, named.
//
// It is stated over a token holding **every scope this service will let an account
// mint** — all seven non-operator names, for THIS account, presented by a user who
// is its OWNER — because that is the strongest account-scoped credential there is.
// If that one is refused, every weaker one is: an owner holding everything an account
// can be given, for their own account, cannot turn a person off, and the reason they
// cannot is the scope and not their role.
//
// THE ROLE IS NOT THE AXIS AND THAT IS THE POINT. Three roles are walked, and all
// three give the same answer, because there is no role on this surface at all: there
// is no account in the path to hold a minimum. A test asserting "member is refused
// and owner is allowed" would describe a service with an admin operator, which is
// the thing this packet exists not to build.
func TestAnAccountScopedCredentialCannotDisableAUser(t *testing.T) {
	t.Parallel()

	scopes := everyAccountScope()
	if len(scopes) == 0 {
		t.Fatal("the vocabulary holds no non-operator scope, so this test would walk an empty " +
			"grant and prove nothing")
	}

	for _, role := range []accounts.Role{
		accounts.RoleMember, accounts.RoleAdmin, accounts.RoleOwner,
	} {
		t.Run("as "+string(role), func(t *testing.T) {
			t.Parallel()

			accountID := id.MustNew()
			memberID := id.MustNew()
			subject := id.MustNew()

			auth := newFakeAuth()
			handler := New(nil,
				WithAuth(auth),
				WithTenancy(adminTenancy(accountID, role)),
				WithAPIKeyCaller(newFakeAPIKeyCaller(auth.user, apikeys.Key{
					ID:        id.MustNew(),
					UserID:    memberID,
					AccountID: accountID,
					Scopes:    scopes,
				})),
				WithAdmin(&fakeAdmin{}),
			)

			for _, action := range []string{"disable", "enable"} {
				req := httptest.NewRequest(http.MethodPost,
					"/v1/users/"+subject.String()+"/"+action, nil)
				req.Header.Set("Authorization", "Bearer "+apiKeySecret)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != http.StatusForbidden {
					t.Fatalf("%s with every scope at %s = %d, want 403; body: %s",
						action, role, rec.Code, rec.Body)
				}
				if got := decodeProblem(t, rec).Code; got != CodeForbidden {
					t.Errorf("code = %q, want %q", got, CodeForbidden)
				}
				if len(auth.disabled)+len(auth.enabled) != 0 {
					t.Fatalf("%s reached the use case as %s. An account admin — owner included — "+
						"must not be able to turn a person off: the person belongs to as many "+
						"accounts as they like, and this account has no authority over the rest",
						action, role)
				}
			}
		})
	}
}

// TestTheAdminSurfaceStillCannotReachAPerson is the mirror, and it is here because
// the two surfaces are the only places in this service where a credential's KIND is
// the authorization decision, and a rule restated in one place is a rule that quietly
// changes in the other.
//
// `requireAdminToken` refuses a session and `requireAccountRole` consults a scope
// table with no `users:disable` row — so an admin token reaches invitations and the
// audit trail and reaches nothing about a person. Stating it here means a packet that
// adds an operator route to the admin surface fails in a file whose name says what
// the property is.
func TestTheAdminSurfaceStillCannotReachAPerson(t *testing.T) {
	t.Parallel()

	auth := newFakeAuth()
	handler := New(nil,
		WithAuth(auth),
		WithTenancy(adminTenancy(id.MustNew(), accounts.RoleOwner)),
		WithAPIKeyCaller(newFakeAPIKeyCaller(auth.user, apikeys.Key{
			ID:        id.MustNew(),
			UserID:    auth.user.ID,
			AccountID: id.MustNew(),
			Scopes:    apikeys.AllScopes(),
		})),
		WithAdmin(&fakeAdmin{}),
	)

	// A path the admin surface could plausibly grow, sent with everything. It is a
	// 404 rather than a 403 because the route does not exist — and that IS the
	// assertion: there is no admin route about a person, and a deployment operator's
	// credential is the only one that reaches one.
	req := httptest.NewRequest(http.MethodPost, "/v1/accounts/"+id.MustNew().String()+"/admin/users/"+id.MustNew().String()+"/disable", nil)
	req.Header.Set("Authorization", "Bearer "+apiKeySecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("POST /v1/accounts/{id}/admin/users/{userId}/disable with every scope = %d, "+
			"want 404. There is no admin route about a person; the operator surface is at "+
			"/v1/users/{userId}/disable and carries no account", rec.Code)
	}
}

// TestTheOperatorSurfaceNeedsNoAdminService is the absence, stated rather than left
// implicit.
//
// The admin service is the operator surface's nearest neighbor by vocabulary and
// shares none of its wiring: mounting these two routes needs `auth` and nothing else,
// so a deployment with no `internal/admin` at all still serves them. That is worth a
// test because the intuitive implementation — hanging them off the `admin` option —
// would be a wiring that silently turns the operator surface off in every deployment
// that has not configured an audit log, and the resulting 404 reads like a
// misconfiguration rather than like a missing option.
func TestTheOperatorSurfaceNeedsNoAdminService(t *testing.T) {
	t.Parallel()

	auth := newFakeAuth()
	handler := New(nil,
		WithAuth(auth),
		WithAPIKeyCaller(newFakeAPIKeyCaller(auth.user, apikeys.Key{
			ID:     id.MustNew(),
			UserID: auth.user.ID,
			Scopes: []string{apikeys.ScopeUsersDisable},
		})),
		// No WithAdmin, no WithTenancy, no WithRecovery.
	)

	req := httptest.NewRequest(http.MethodPost,
		"/v1/users/"+id.MustNew().String()+"/disable", nil)
	req.Header.Set("Authorization", "Bearer "+apiKeySecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("disabling with only `auth` and a token = %d, want 204; body: %s", rec.Code, rec.Body)
	}
	if len(auth.disabled) != 1 {
		t.Fatalf("the use case was called %d times, want once", len(auth.disabled))
	}
	// And the admin service is genuinely absent from that router, so the assertion
	// above is about this wiring rather than about a router that happened to have it.
	var served bool
	for route := range routesIn(t, options{auth: newFakeAuth()}) {
		if strings.Contains(route.Path, "/admin/") {
			served = true
		}
	}
	if served {
		t.Error("a router built with only `auth` serves an admin route, so the assertion above " +
			"was not about the wiring it claims to be about")
	}
}

// compile-time proof that the doubles above satisfy the interfaces they are handed
// to, so a signature change in the admin double's or the tenancy double's fails here
// rather than as a confusing runtime refusal in a test about authorization.
var (
	_ Admin   = (*fakeAdmin)(nil)
	_ Tenancy = adminTenancy(id.MustNew(), accounts.RoleAdmin)
)
