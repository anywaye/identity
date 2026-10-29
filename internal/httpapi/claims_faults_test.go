package httpapi


import (
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/identity/internal/oauth"
)

func walkOptions() options {
	return options{
		auth:         newFakeAuth(),
		deletion:     newFakeDeletion(),
		tenancy:      newFakeTenancy(),
		oidcClients:  newFakeOIDCClients(),
		oidc:         newFakeOIDC(),
		apiKeys:      newFakeAPIKeys(),
		mfa:          newFakeMFAManage(),
		introspector: newFakeIntrospector(),
		admin:        newFakeAdmin(),
		recovery:     newFakeRecovery(),
		social: newFakeSocial(),
		signup: newFakeSignup(),
		agents: newFakeAgents(),
	}
}

func routesIn(t *testing.T, o options) map[operationKey]string {
	t.Helper()

	found := map[operationKey]string{}
	err := chi.Walk(newMux(nil, o), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		found[operationKey{Method: method, Path: normalisePath(route)}] = route
		return nil
	})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}
	return found
}

func TestTheClaimWalkSeesEveryConditionalSurface(t *testing.T) {
	found := routesIn(t, walkOptions())

	for _, want := range []struct {
		surface string
		key     operationKey
	}{
		{"auth", operationKey{Method: "POST", Path: "/v1/session"}},
		{"tenancy", operationKey{Method: "GET", Path: "/v1/accounts"}},
		{"oidcClients", operationKey{Method: "GET", Path: "/v1/accounts/{}/oidc-clients"}},
		{"oidc", operationKey{Method: "GET", Path: "/oidc/authorize"}},
		{"apiKeys", operationKey{Method: "GET", Path: "/v1/accounts/{}/api-keys"}},
		{"mfa", operationKey{Method: "GET", Path: "/v1/mfa"}},
		{"introspector", operationKey{Method: "POST", Path: "/v1/introspections"}},
		{"admin", operationKey{Method: "GET", Path: "/v1/accounts/{}/admin/audit-log"}},
		{"recovery", operationKey{Method: "POST", Path: "/v1/password-resets"}},
		{"social", operationKey{Method: "GET", Path: "/v1/auth/oauth/{}"}},
		{"signup", operationKey{Method: "POST", Path: "/v1/signup-timestamp"}},
	} {
		if _, ok := found[want.key]; !ok {
			t.Errorf("the claim walk does not see %s, so it does not see %s. The `options` "+
				"literal that configures the walk has no `%s` double, and `registerXRoutes` "+
				"returns early when the service is absent — so every claim check in this package "+
				"is currently reporting agreement about a service smaller than the one that runs.\n\n"+
				"Add the double to walkOptions AND to servedRoutes. They are the same tree and "+
				"they must not be configured separately.", want.key, want.surface, want.surface)
		}
	}
}

func TestTheClaimWalkSeesNothingWhenTheServicesAreAbsent(t *testing.T) {
	found := routesIn(t, options{})

	var conditional []string
	for key := range found {
		if key.Path == "/healthz" || key.Path == "/readyz" {
			continue
		}
		if strings.HasPrefix(key.Path, "/.well-known") {
			continue
		}
		conditional = append(conditional, key.String())
	}
	sort.Strings(conditional)

	if len(conditional) > 0 {
		t.Errorf("a router built with no services at all still serves %d conditional "+
			"route(s):\n\n  %s\n\n"+
			"Every one of these is behind a surface that should have been absent. A registrar "+
			"that ignores its options and mounts anyway is a service whose \"absent without "+
			"configuration\" guarantee — the property the whole options struct exists for — is "+
			"not real, and the claim checks above would be holding claims against a router that "+
			"does not match any deployment.", len(conditional), strings.Join(conditional, "\n  "))
	}
}

func TestServedRoutesAndTheClaimWalkAgree(t *testing.T) {
	declared := servedRoutes(t)
	actual := routesIn(t, walkOptions())

	for key := range declared {
		if _, ok := actual[key]; !ok {
			t.Errorf("servedRoutes reports %s but the walk this file configures does not. The "+
				"two options literals have diverged: openapi_drift_test.go's and this file's. "+
				"They describe the same deployed router, and a test suite that walks two "+
				"different routers reports agreement about a service neither one is.", key)
		}
	}
	for key := range actual {
		if _, ok := declared[key]; !ok {
			t.Errorf("the walk this file configures serves %s but servedRoutes does not report "+
				"it. Same divergence, other direction.", key)
		}
	}
}

func TestTheSocialLoginPrefixIsTheOneTheProviderBuilds(t *testing.T) {
	const base = "https://identity.anywaye.com"

	full := oauth.Google().RedirectURI(base)

	parsed, err := url.Parse(full)
	if err != nil {
		t.Fatalf("parsing %q: %v", full, err)
	}
	if parsed.Host != strings.TrimPrefix(base, "https://") {
		t.Errorf("RedirectURI built %q, whose host is %q rather than the configured base's. "+
			"The function's whole argument is that the callback is derived from configuration "+
			"and never from a request, so a host that is not the configured one is a defect "+
			"wherever it came from.", full, parsed.Host)
	}

	path := parsed.Path
	if !strings.HasPrefix(path, socialLoginPrefix+"/") {
		t.Errorf("oauth.Provider.RedirectURI builds the path %q, which does not begin with "+
			"socialLoginPrefix %q. The absence check in oauth_absent_test.go watches a path the "+
			"surface would never be mounted on, so it would pass while the feature shipped "+
			"somewhere else.", path, socialLoginPrefix)
	}
	if !strings.HasSuffix(path, "/callback") {
		t.Errorf("oauth.Provider.RedirectURI builds the path %q, which does not end in "+
			"/callback. The README records that path, and so does the state's own test.", path)
	}

	readme, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("reading %s: %v", readmePath, err)
	}
	quoted := socialLoginPrefix + "/{provider}/callback"
	if !strings.Contains(string(readme), quoted) {
		t.Errorf("README.md does not quote the callback path %q, and RedirectURI really builds "+
			"%q. The section tells a reader to check for themselves that nothing serves the "+
			"social callback, and a path that is not the real one does not let them.",
			quoted, path)
	}
}
