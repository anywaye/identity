package httpapi


import (
	"reflect"
	"sort"
	"testing"
)

var conditionalSurfaces = []string{
	"auth", "tenancy", "apiKeyCaller", "introspector", "apiKeys", "oidc",
	"oidcClients", "mfa", "admin", "recovery", "signup", "social",

	"deletion",

	"agents",
}

func TestEveryConditionalSurfaceIsVisibleToTheWalk(t *testing.T) {
	t.Parallel()

	fields := make(map[string]bool)
	for i := range reflect.TypeFor[options]().NumField() {
		fields[reflect.TypeFor[options]().Field(i).Name] = true
	}

	var missing []string
	for _, name := range conditionalSurfaces {
		if !fields[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("conditionalSurfaces names %v, which are not fields of options any more. Either the "+
			"field was renamed — in which case the walks in servedRoutes and mountedAccountRoutes "+
			"are also reading a struct literal that no longer sets it, and every route it gates is "+
			"invisible to two checks — or a surface was removed, in which case delete it from this "+
			"list and say so in the CHANGELOG", missing)
	}
}

func TestTheDriftWalkSeesTheAdminSurface(t *testing.T) {
	t.Parallel()

	served := servedRoutes(t)

	for _, want := range []operationKey{
		{Method: "GET", Path: "/v1/accounts/{}/admin/audit-log"},
		{Method: "DELETE", Path: "/v1/accounts/{}/admin/invitations/{}"},
		{Method: "POST", Path: "/v1/accounts/{}/admin/invitation-revocations"},
	} {
		if _, seen := served[want]; !seen {
			t.Errorf("servedRoutes did not report %s as served. The router serves it — "+
				"TestEveryServedRouteIsDocumentedOrNamed depends on this walk seeing every mounted "+
				"route, and a route missing from the walk is a route whose documentation is never "+
				"checked in either direction", want)
		}
	}
}

func TestTheDriftWalkSeesTheRecoverySurface(t *testing.T) {
	t.Parallel()

	served := servedRoutes(t)

	for _, want := range []operationKey{
		{Method: "POST", Path: "/v1/password-resets"},
		{Method: "POST", Path: "/v1/password-resets/confirm"},
		{Method: "POST", Path: "/v1/email-verifications"},
		{Method: "POST", Path: "/v1/email-verifications/confirm"},
		{Method: "GET", Path: "/v1/email-verification"},
		{Method: "POST", Path: "/v1/email-changes"},
		{Method: "POST", Path: "/v1/email-changes/current-address"},
		{Method: "POST", Path: "/v1/email-changes/new-address"},
	} {
		if _, seen := served[want]; !seen {
			t.Errorf("servedRoutes did not report %s as served. TestEveryServedRouteIsDocumentedOrNamed "+
				"depends on this walk seeing every mounted route, so a route missing from it has its "+
				"documentation checked in neither direction", want)
		}
	}
}

func TestTheDriftWalkSeesTheSessionLinkSurface(t *testing.T) {
	t.Parallel()

	for _, want := range []operationKey{
		{Method: "POST", Path: "/v1/session-links"},
		{Method: "POST", Path: "/v1/session-links/redeem"},
	} {
		if _, seen := servedRoutes(t)[want]; !seen {
			t.Errorf("servedRoutes did not report %s as served. The router mounts it once "+
				"`options.recovery` is set, and this walk is what decides whether its "+
				"documentation is checked — a route invisible here is a route whose document "+
				"entry nothing verifies", want)
		}
		if _, seen := routesIn(t, walkOptions())[want]; !seen {
			t.Errorf("walkOptions did not report %s. The two options literals describe the "+
				"same deployed router, and a suite that walks two different routers reports "+
				"agreement about a service neither one is", want)
		}
	}
}

func TestTheDriftWalkSeesTheSignupSurface(t *testing.T) {
	t.Parallel()

	for _, want := range []operationKey{
		{Method: "POST", Path: "/v1/signup-timestamp"},
	} {
		if _, seen := servedRoutes(t)[want]; !seen {
			t.Errorf("servedRoutes did not report %s as served. The router mounts it once "+
				"`options.signup` is set, and this walk is what decides whether its "+
				"documentation is checked — a route invisible here is a route whose document "+
				"entry nothing verifies", want)
		}
	}
}

func TestTheDriftWalkSeesTheSocialLoginSurface(t *testing.T) {
	t.Parallel()

	want := []operationKey{
		{Method: "GET", Path: "/v1/auth/oauth/{}"},
		{Method: "GET", Path: "/v1/auth/oauth/{}/callback"},
	}

	for _, key := range want {
		if _, seen := servedRoutes(t)[key]; !seen {
			t.Errorf("servedRoutes did not report %s. The router mounts it once `options.social` "+
				"is set, so this walk is reading a smaller service than the one that runs — and "+
				"every documentation check built on it is currently reporting agreement about a "+
				"surface it cannot see. That is exactly what happened to the social-login "+
				"tripwire: it stayed green on the day the routes appeared.", key)
		}
		if _, seen := routesIn(t, walkOptions())[key]; !seen {
			t.Errorf("walkOptions did not report %s. The two options literals describe the same "+
				"deployed router, and a test suite that walks two different routers reports "+
				"agreement about a service neither one is. Add the double to servedRoutes AND "+
				"walkOptions.", key)
		}
	}
}

func TestTheMatrixWalkSeesTheAdminSurface(t *testing.T) {
	t.Parallel()

	mounted := mountedAccountRoutes()
	seen := make(map[string]bool, len(mounted))
	for _, route := range mounted {
		seen[route] = true
	}

	for _, want := range []string{
		"GET /v1/accounts/{accountID}/admin/audit-log",
		"DELETE /v1/accounts/{accountID}/admin/invitations/{invitationID}",
		"POST /v1/accounts/{accountID}/admin/invitation-revocations",
	} {
		if !seen[want] {
			t.Errorf("mountedAccountRoutes did not report %s. TestEveryRouteIsInTheMatrix walks this "+
				"list, so a route missing from it needs no matrix row and the completeness check "+
				"passes on a service with an unchecked surface", want)
		}
	}
}
