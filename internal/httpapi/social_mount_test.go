package httpapi


import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

var socialRoutes = []struct {
	name    string
	url     string
	pattern string
}{
	{"start", socialLoginPrefix + "/google", socialLoginPrefix + "/{provider}"},
	{"callback", socialLoginPrefix + "/google/callback", socialLoginPrefix + "/{provider}/callback"},
}

func TestTheSocialRoutesAreAbsentWithoutAProvider(t *testing.T) {
	t.Parallel()

	mux := newMux(nil, options{auth: newFakeAuth()})

	for _, route := range socialRoutes {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, route.url+"?code=real&state=real", nil)
		req.AddCookie(&http.Cookie{Name: OAuthStateCookieName, Value: "real"})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s answered %d with no provider configured. WithSocial's rule is that "+
				"the routes are ABSENT in that configuration, so a deployment with no OAuth client "+
				"credentials serves a clean 404 rather than a redirect to a provider it cannot "+
				"authenticate with. A %d here means a registrar mounted the surface with a nil "+
				"Social, which is the half-mounted flow WithSocial exists to prevent.",
				route.url, rec.Code, rec.Code)
		}
	}
}

func TestBothSocialRoutesMountTogether(t *testing.T) {
	t.Parallel()

	mux := newMux(nil, options{auth: newFakeAuth(), social: newFakeSocial()})

	for _, route := range socialRoutes {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, route.url, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s answered 404 with a Social configured. Both social routes mount "+
				"together or not at all — registerSocialRoutes is deliberately one function "+
				"because start and callback are one flow, and a router with only the start "+
				"route redirects a person to their provider and then 404s them on the way back.",
				route.url)
		}
	}
}

func TestTheSocialWalkSeesBothRoutesOrNeither(t *testing.T) {
	t.Parallel()

	for name, o := range map[string]options{
		"configured": {auth: newFakeAuth(), social: newFakeSocial()},
		"absent":     {auth: newFakeAuth()},
	} {
		mounted := socialRoutesIn(t, o)

		for _, route := range socialRoutes {
			got := mounted[route.pattern]
			want := o.social != nil

			if got != want {
				t.Errorf("with %q, the router mounts GET %s = %v, want %v. The two social routes "+
					"mount together or not at all; a router where the start and the callback can "+
					"be mounted independently is a router where half of one exists.",
					name, route.pattern, got, want)
			}
		}
	}
}

func socialRoutesIn(t *testing.T, o options) map[string]bool {
	t.Helper()

	mounted := map[string]bool{}
	total := 0
	err := chi.Walk(newMux(nil, o), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		total++
		if method == http.MethodGet {
			mounted[route] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}
	if total == 0 {
		t.Fatal("the router was read as mounting no routes at all, so this walk cannot see whether " +
			"the social routes are there. A check that reads an empty service agrees with " +
			"everything, which is the failure mode these files exist to prevent.")
	}
	return mounted
}
