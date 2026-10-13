package httpapi

// THE TRIPWIRE FOR THE SOCIAL-LOGIN MOUNT, and the tripwire that was deleted.
//
// # WHAT HAPPENED TO THE LAST ONE
//
// `oauth_absent_test.go` was removed in c1fc199 with the message "The surface is
// mounted, so the file's rule is satisfied by its deletion." It was not mounted.
// `WithSocial` had no call site outside its own definition and `cmd/identity`
// never appended it, so `options.social` was nil in every process and
// `registerSocialRoutes` returned before registering anything. The absence the
// file existed to watch for was exactly the absence that existed.
//
// That is the failure mode this repository names more than any other — a gate
// that is green about the wrong thing — and a replacement has to be able to fail
// for the reason the original could not. So this file asserts against a router
// BUILT BY `newMux` with an options value the test chose, not against a walk of a
// router somebody else configured, and it asks a question whose answer differs
// between the two worlds: is the ROUTE THERE when a provider is configured, and
// is it NOT there when none is.
//
// # WHAT IS ASSERTED, AND WHY EACH LINE IS HERE
//
// Three properties, all behavioral, all on real requests:
//
//  1. With no Social configured, BOTH social routes answer 404 — through the
//     router, as HTTP, not as an inspection of a route table. This is the rule
//     WithSocial's comment states, and it is the property that makes a
//     credential-less deployment safe: a 404 rather than a redirect to a
//     provider it cannot authenticate with.
//  2. With one configured, BOTH are mounted. "Both" and not "the one the test
//     happened to probe": start and callback are one flow, and a router where
//     half of one exists is a router where a person is redirected to a provider
//     and answered 404 on the way back.
//  3. Mounting one without the other fails. This is the check the original
//     could not have made, because it never built a router in either state.
//
// # WHY THE ABSENCE IS ASSERTED PER ROUTE RATHER THAN AS A COUNT
//
// A count is the shape that lets a check go green by not checking: a registrar
// that mounted the start route twice and the callback zero times would satisfy
// `len(served) == 2`. Two named routes, each asked for by its own URL and each
// required to 404, cannot be satisfied by any arrangement other than the
// intended one.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// socialRoutes is one of the two URLs, spelled through the constant the registrar
// uses rather than as a literal, so a rename of socialLoginPrefix cannot leave
// this file probing a path the router does not serve and reporting the router as
// correct.
//
// Two spellings each, and both are needed: `url` is what a BROWSER requests and
// `pattern` is what the router RECORDS, and chi.Walk reports patterns. A walk
// compared against concrete URLs would report both routes absent on a correctly
// mounted router — a green about nothing, which is the failure this whole file
// exists to be a different instance of.
//
// The pattern carries `{provider}` because that is the parameter name
// registerSocialRoutes hands chi; a test that spelled it differently would match
// nothing and then pass on the strength of its own absence.
var socialRoutes = []struct {
	name    string
	url     string
	pattern string
}{
	{"start", socialLoginPrefix + "/google", socialLoginPrefix + "/{provider}"},
	{"callback", socialLoginPrefix + "/google/callback", socialLoginPrefix + "/{provider}/callback"},
}

// TestTheSocialRoutesAreAbsentWithoutAProvider is property 1: the credential-less
// deployment's 404.
//
// The requests carry a state cookie and a code that would be perfectly good on a
// mounted router, so a red here cannot be explained by a refusal the handler
// would have made anyway. What is under test is the ROUTE, not the refusal.
//
// `auth` IS SET, and that is the whole of why this reproduces the defect rather
// than a smaller version of it. `registerRoutes` returns at its first line when
// `options.auth` is nil — BEFORE it reaches `registerSocialRoutes` at auth.go:195
// — so a router built with an empty options mounts no /v1 routes at all and this
// test would pass for a reason that has nothing to do with social login. An auth
// service is present and a Social is not, which is the configuration every
// deployment with a database and no OAUTH_* variables is actually running.
func TestTheSocialRoutesAreAbsentWithoutAProvider(t *testing.T) {
	t.Parallel()

	mux := newMux(nil, options{auth: newFakeAuth()})

	for _, route := range socialRoutes {
		req := httptest.NewRequest(http.MethodGet, route.url+"?code=real&state=real", nil)
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

// TestBothSocialRoutesMountTogether is property 2, and it is the assertion the
// deleted file's commit message claimed had been satisfied.
//
// It probes both routes and requires both to be REACHABLE — a 404 from either is
// a failure, because the surface is mounted and a mounted route that answers 404
// is indistinguishable from an absent one at the browser.
func TestBothSocialRoutesMountTogether(t *testing.T) {
	t.Parallel()

	mux := newMux(nil, options{auth: newFakeAuth(), social: newFakeSocial()})

	for _, route := range socialRoutes {
		req := httptest.NewRequest(http.MethodGet, route.url, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		// The double refuses the callback and has no state cookie, so a 400 is the
		// deepest point this file can assert without re-testing oauth.go's own
		// refusals: it is a 400 from the HANDLER, which proves the route resolved and
		// its body ran. A 404 would mean the route is not there.
		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s answered 404 with a Social configured. Both social routes mount "+
				"together or not at all — registerSocialRoutes is deliberately one function "+
				"because start and callback are one flow, and a router with only the start "+
				"route redirects a person to their provider and then 404s them on the way back.",
				route.url)
		}
	}
}

// TestTheSocialWalkSeesBothRoutesOrNeither is property 3, and it is what makes
// properties 1 and 2 mean what they say.
//
// It takes the union of what the two configurations mount and requires each
// configuration to account for all of it or none of it. A registrar that mounted
// only the start route fails here on BOTH tests at once — with no provider (one
// route where it wants none) and with one (one where it wants both) — so the
// "never one" half of the rule is enforced rather than described.
//
// It reads the router with chi.Walk rather than by making requests, because the
// requests above cannot tell "route absent" from "route present and refusing" in
// every direction, and this one is about the mount, not the handler.
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

// socialRoutesIn returns the social-login PATTERNS the given options mount.
//
// IT WALKS THE ROUTER ITSELF rather than calling `routesIn` from
// claims_faults_test.go, and the reason is that this file is a tripwire: a
// tripwire that shares its reader with the checks it is meant to be independent
// of is one edit away from agreeing with whatever that reader reports. chi.Walk
// over the mux this package builds is six lines and has no interpretation in it.
//
// The emptiness guard is the other half of that. A walk that finds no routes at
// all returns an empty map, and every assertion above is then false — so a
// silently-broken walk would report "both routes absent" and the absent case
// would pass while saying nothing about the configured one. Requiring the walk to
// have seen the router at all turns that into a named failure.
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
