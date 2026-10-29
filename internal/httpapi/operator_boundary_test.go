package httpapi


import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/platform/id"
)

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

func everyAccountScope() []string {
	var out []string
	for _, scope := range apikeys.AllScopes() {
		if scope != apikeys.ScopeUsersDisable && scope != apikeys.ScopeTokensIntrospect {
			out = append(out, scope)
		}
	}
	return out
}

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
				req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
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

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/accounts/"+id.MustNew().String()+"/admin/users/"+id.MustNew().String()+"/disable", nil)
	req.Header.Set("Authorization", "Bearer "+apiKeySecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("POST /v1/accounts/{id}/admin/users/{userId}/disable with every scope = %d, "+
			"want 404. There is no admin route about a person; the operator surface is at "+
			"/v1/users/{userId}/disable and carries no account", rec.Code)
	}
}

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
	)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
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

var (
	_ Admin   = (*fakeAdmin)(nil)
	_ Tenancy = adminTenancy(id.MustNew(), accounts.RoleAdmin)
)
