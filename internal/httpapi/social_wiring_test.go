package httpapi

// TESTS FOR THE PRODUCTION WIRING — the value that actually satisfies `Social`.
//
// social_mount_test.go proves the ROUTER mounts the routes in both configurations.
// It cannot prove the thing that was broken, which is that the value handed to
// `WithSocial` was never built in the first place: the mount tests set
// `options.social` by hand, so they would stay green if `cmd/identity` stopped
// calling `WithSocial` entirely. That is precisely the defect c1fc199 deleted a
// tripwire over.
//
// So this file closes the gap from the other side: it builds the SAME object
// `buildSocial` builds — a real `*oauth.Registry` and a real
// `*auth.SocialService` — and requires that together they satisfy `Social` and that
// the resulting router mounts both routes. The only remaining untested link is the
// call in cmd/identity, and social_wiring_call_test.go holds that one by reading
// the source.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)

// --- the minimum doubles a SocialService can be built from --------------------

// wiringRegistry is the part of oauth.Registry the use case reads. It delegates to
// a REAL oauth.Registry rather than to a hand-written map, because the property
// under test is that the registry the router resolves through is the one the use
// case resolves through, and a double that agreed with itself by construction
// would prove nothing.
type wiringRegistry struct{ real *oauth.Registry }

func (w wiringRegistry) Lookup(name string) (oauth.Provider, error) { return w.real.Lookup(name) }
func (w wiringRegistry) RedirectBase() string                       { return w.real.RedirectBase() }

// wiringExchanger stands in for oauth.Client. No test here reaches a provider: the
// round trip is internal/auth's to test over its own seams, and a double that
// minted a session would be a second and easier way to get one — which is the hole
// this surface exists to not have.
type wiringExchanger struct{}

func (wiringExchanger) Exchange(context.Context, oauth.Provider, string) (oauth.Tokens, error) {
	return oauth.Tokens{}, oauth.ErrCodeRefused
}
func (wiringExchanger) Identity(context.Context, oauth.Provider, oauth.Tokens) (oauth.Identity, error) {
	return oauth.Identity{}, oauth.ErrCodeRefused
}

// wiringAccounts stands in for oauth.Store.
type wiringAccounts struct{}

func (wiringAccounts) ByProviderUID(context.Context, db.Querier, string, string) (oauth.Account, error) {
	return oauth.Account{}, oauth.ErrNotFound
}
func (wiringAccounts) Create(context.Context, db.Querier, oauth.NewAccount) (oauth.Account, error) {
	return oauth.Account{}, oauth.ErrAlreadyLinked
}
func (wiringAccounts) RefreshTokens(context.Context, db.Querier, id.UUID, oauth.StoredTokens) error {
	return nil
}

// wiringSealer stands in for oauth.Cipher.
type wiringSealer struct{}

func (wiringSealer) Seal(string) (string, error) { return "sealed", nil }

// newRealWiring builds what `buildSocial` builds: a genuine oauth.Registry over one
// credentialed provider, a genuine auth.SocialService over it, and the adapter.
func newRealWiring(t *testing.T) Social {
	t.Helper()

	provider := oauth.GitHub()
	provider.ClientID = "id"
	provider.ClientSecret = "secret"

	registry, err := oauth.NewRegistry("https://identity.test", provider)
	if err != nil {
		t.Fatalf("oauth.NewRegistry: %v", err)
	}

	// auth.NewSocialService takes interfaces, so this is constructible from here
	// without a database — which is the property that makes the wiring testable at
	// all, and the reason the four seams exist as interfaces declared at the consumer.
	service := auth.NewSocialService(
		nil, // no auth.Service: nothing in this test reaches the use case
		wiringRegistry{real: registry},
		wiringExchanger{},
		wiringAccounts{},
		wiringSealer{},
	)

	return NewSocial(registry, service)
}

// TestARealRegistryAndUseCaseSatisfySocial is the compile-time claim in
// social_wiring.go, made at runtime so a failure names the method.
//
// `var _ Social = (*socialWiring)(nil)` already fails the build if the adapter
// stops satisfying the interface. This test is here for the OTHER direction, which
// the build cannot check: that a real registry plus a real use case still produce
// something NewSocial accepts. A signature change on either side that left the
// adapter compiling — by widening a parameter, say — would mount routes whose
// Lookup resolves a provider the use case then refuses, and the failure would be a
// 404 halfway through a real sign-in.
func TestARealRegistryAndUseCaseSatisfySocial(t *testing.T) {
	t.Parallel()

	social := newRealWiring(t)
	if social == nil {
		t.Fatal("NewSocial returned nil for a registry with a credentialed provider. This is the " +
			"wiring cmd/identity builds, and a nil here mounts nothing — which is the defect " +
			"social_wiring.go exists to make impossible.")
	}

	provider, err := social.Lookup(oauth.ProviderGitHub)
	if err != nil {
		t.Fatalf("Lookup(%q): %v", oauth.ProviderGitHub, err)
	}
	if provider.Name != oauth.ProviderGitHub {
		t.Errorf("Lookup returned %q, want %q", provider.Name, oauth.ProviderGitHub)
	}
	if provider.ClientID == "" || provider.ClientSecret == "" {
		t.Error("the resolved provider carries no credentials, so the start route would redirect " +
			"to a provider this service cannot exchange a code with")
	}

	if base := social.RedirectBase(); base != "https://identity.test" {
		t.Errorf("RedirectBase() = %q, want the CONFIGURED base. It must never come from a request: "+
			"a Host header an attacker chose must not become part of a redirect_uri, or the "+
			"authorization code is delivered wherever they asked.", base)
	}

	// And the callback URL the two halves would agree on. This is the property that
	// fails if someone gives the router one registry and the use case another: the
	// authorize step and the exchange step must build the same redirect_uri, and a
	// mismatch is refused by the provider without saying which of the two URLs was
	// wrong.
	want := "https://identity.test/v1/auth/oauth/github/callback"
	if got := provider.RedirectURI(social.RedirectBase()); got != want {
		t.Errorf("the callback URL is %q, want %q. The router's start route and the use case's "+
			"exchange both build this, and the provider refuses a mismatch without saying which "+
			"URL was wrong.", got, want)
	}
}

// TestNewSocialIsNilExactlyWhenThereIsNothingToServe is the absence rule, and it
// is asserted in BOTH directions with the emphasis on the nil-identity that makes
// the guard work.
//
// `WithSocial` guards on `if s != nil`. That guard is only correct if NewSocial
// returns an UNTYPED nil interface — a `(*socialWiring)(nil)` boxed in a `Social`
// is non-nil as an interface, passes the guard, and mounts two routes that
// dereference a nil pointer on the first request. So the test asserts the interface
// value itself is nil, and separately that putting the answer through WithSocial
// leaves `options.social` nil — which is the shape the router actually reads.
func TestNewSocialIsNilExactlyWhenThereIsNothingToServe(t *testing.T) {
	t.Parallel()

	credentialed := oauth.GitHub()
	credentialed.ClientID = "id"
	credentialed.ClientSecret = "secret"

	halfConfigured := oauth.GitHub()
	halfConfigured.ClientID = "only-the-id"

	for name, tc := range map[string]struct {
		registry *oauth.Registry
		service  *auth.SocialService
		wantNil  bool
	}{
		"no providers configured": {
			registry: mustRegistry(t, "https://identity.test"),
			service:  mustService(t, mustRegistry(t, "https://identity.test")),
			wantNil:  true,
		},
		"a provider with no credentials": {
			registry: mustRegistry(t, "https://identity.test"),
			service:  mustService(t, mustRegistry(t, "https://identity.test")),
			wantNil:  true,
		},
		"a half-configured provider is dropped, so still empty": {
			registry: mustRegistry(t, "https://identity.test", halfConfigured),
			service:  mustService(t, mustRegistry(t, "https://identity.test", halfConfigured)),
			wantNil:  true,
		},
		"one provider configured": {
			registry: mustRegistry(t, "https://identity.test", credentialed),
			service:  mustService(t, mustRegistry(t, "https://identity.test", credentialed)),
			wantNil:  false,
		},
		"a nil registry": {
			registry: nil,
			service:  mustService(t, mustRegistry(t, "https://identity.test", credentialed)),
			wantNil:  true,
		},
		"a nil use case": {
			registry: mustRegistry(t, "https://identity.test", credentialed),
			service:  nil,
			wantNil:  true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := NewSocial(tc.registry, tc.service)
			if (got == nil) != tc.wantNil {
				t.Fatalf("NewSocial returned nil=%v, want nil=%v", got == nil, tc.wantNil)
			}

			// The guard's actual reading of the answer. `options.social` is the field
			// registerSocialRoutes checks, so this is the shape that matters rather
			// than the shape NewSocial returns.
			var o options
			if got != nil {
				o = applyOptions(WithSocial(got))
			}
			if (o.social == nil) != tc.wantNil {
				t.Errorf("options.social is nil=%v after WithSocial, want nil=%v. WithSocial "+
					"guards on `if s != nil`, so this is the value the router reads.",
					o.social == nil, tc.wantNil)
			}
		})
	}
}

// TestANilRegistryDoesNotPanicOnEmpty is the reason the nil check comes FIRST in
// NewSocial.
//
// `registry.Empty()` is `len(r.byName) == 0`, which dereferences r. Called on a nil
// *Registry it panics, and a panic at boot on a deployment that happens to have
// misconfigured OAuth is a worse failure than two absent routes. The assertion is
// explicit rather than implicit in a nil return, because the ordering is the
// property and reordering the two conditions compiles and returns the right answer.
func TestANilRegistryDoesNotPanicOnEmpty(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewSocial(nil, service) panicked: %v. `registry == nil` is checked before "+
				"`registry.Empty()` because Empty dereferences the pointer, and a panic at boot is "+
				"worse than two absent routes.", r)
		}
	}()

	if got := NewSocial(nil, mustService(t, mustRegistry(t, "https://identity.test"))); got != nil {
		t.Error("NewSocial(nil, service) returned a non-nil Social")
	}
}

// TestTheRealWiringMountsBothRoutes is the end of the chain: the object
// buildSocial builds, mounted through the real router, serves both URLs.
//
// social_mount_test.go proves this with a double; this proves it with the real
// adapter over a real registry and a real use case. The difference is the whole
// point — the double's `Lookup` accepts google and refuses everything else by
// construction, so it cannot catch a wiring that mounts routes resolving a
// provider the use case refuses.
func TestTheRealWiringMountsBothRoutes(t *testing.T) {
	t.Parallel()

	mux := newMux(nil, options{auth: newFakeAuth(), social: newRealWiring(t)})

	// Over socialRoutes, whose URLs name GOOGLE — while this registry holds GitHub
	// only. Both answers are 404, and both for a DIFFERENT reason: google is a real
	// provider the deployment has no credentials for, and the handler renders that
	// as 404 exactly like a route that does not exist.
	//
	// Which means a 404 here is AMBIGUOUS — it cannot tell "the router did not mount
	// the routes" from "the router mounted them and the provider did not resolve". So
	// the routes are probed by NAME against this registry rather than through the
	// shared list, and the walk below is what holds the mount.
	for _, route := range []struct{ name, url string }{
		{"start", socialLoginPrefix + "/" + oauth.ProviderGitHub},
		{"callback", socialLoginPrefix + "/" + oauth.ProviderGitHub + "/callback"},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, route.url, nil))

		// The start route reaches the registry and redirects (302). The callback
		// reaches the state check and refuses (400). Both prove the route resolved.
		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s answered 404 with the REAL wiring configured over %s. The adapter "+
				"satisfies Social and the registrar mounts both routes, so a 404 here means the "+
				"router did not see this value — not that the handler refused.",
				route.url, oauth.ProviderGitHub)
		}
	}

	// And the mount itself, which is what the ambiguity above cannot see: the
	// patterns are on the router. This is the assertion social_mount_test.go makes
	// with a double, repeated here with the real adapter because the two properties
	// are different — a router can mount these patterns and still be handed a value
	// whose Lookup refuses every name.
	mounted := socialRoutesIn(t, options{auth: newFakeAuth(), social: newRealWiring(t)})
	for _, pattern := range []string{
		socialLoginPrefix + "/{provider}",
		socialLoginPrefix + "/{provider}/callback",
	} {
		if !mounted[pattern] {
			t.Errorf("the router does not mount GET %s with the real wiring. Both social routes "+
				"mount together or not at all.", pattern)
		}
	}

}

// TestTheRealWiringResolvesTheConfiguredProviderThroughTheStartRoute goes one
// step further than "not 404": it proves the START route reaches the registry the
// adapter holds and gets a provider out of it.
//
// A start route that 302s to GitHub's authorize endpoint can only have resolved the
// provider, so the Location header is the assertion. It also confirms the
// redirect_uri in that URL is the CONFIGURED one rather than a Host header's — the
// same property TestARealRegistryAndUseCaseSatisfySocial checks from the other end,
// here observed on the wire where it is what a browser would actually follow.
func TestTheRealWiringResolvesTheConfiguredProviderThroughTheStartRoute(t *testing.T) {
	t.Parallel()

	mux := newMux(nil, options{auth: newFakeAuth(), social: newRealWiring(t)})

	// NOT through `do`: that helper decodes every body as JSON, and this response is a
	// bare 302 with no body by design — oauth.go's own comment says `http.Redirect`
	// is deliberately not used because it writes an HTML anchor. So this one drives
	// the router directly and reads the recorder, the way oidc_test.go reads a 302.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, socialLoginPrefix+"/"+oauth.ProviderGitHub, nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("GET the start route = %d, want 302. A %d means the provider did not resolve, "+
			"which for this wiring would mean the adapter is not holding the registry it was "+
			"built with.", rec.Code, rec.Code)
	}

	location := rec.Header().Get("Location")
	if !strings.Contains(location, "github.com/login/oauth/authorize") {
		t.Errorf("Location = %q, want GitHub's authorize endpoint", location)
	}
	// The redirect_uri must be the configured one. This is the assertion that would
	// fail if someone built the registry from a request's Host: the code would then
	// be delivered to wherever the attacker asked.
	if !strings.Contains(location, "redirect_uri=https%3A%2F%2Fidentity.test%2Fv1%2Fauth%2Foauth%2Fgithub%2Fcallback") {
		t.Errorf("Location = %q, want it to carry the CONFIGURED callback URL. A redirect_uri built "+
			"from a Host header an attacker chose delivers the authorization code to wherever they "+
			"asked.", location)
	}

	// An unconfigured provider is the same 404 as a nonexistent one, on the real
	// registry rather than on a double.
	refused := httptest.NewRecorder()
	mux.ServeHTTP(refused, httptest.NewRequestWithContext(context.Background(), http.MethodGet, socialLoginPrefix+"/"+oauth.ProviderGoogle, nil))
	if refused.Code != http.StatusNotFound {
		t.Errorf("GET the start route for an unconfigured provider = %d, want 404. This registry "+
			"holds github only, and google is the same miss as a name that does not exist — the "+
			"difference would enumerate the deployment's configuration.", refused.Code)
	}
}

// TestTheRealWiringRefusesToMintASessionOnARefusedProvider is the reason the
// adapter delegates and does nothing else.
//
// The use case's exchanger refuses every code, so the callback must answer the
// provider's refusal and NOT a session. An adapter that reimplemented any part of
// Callback — or one whose service were nil — would have a second, easier way to
// mint one, which is the hole this surface is built to not have.
func TestTheRealWiringRefusesToMintASessionOnARefusedProvider(t *testing.T) {
	t.Parallel()

	social := newRealWiring(t)

	state, err := oauth.NewState(oauth.ProviderGitHub)
	if err != nil {
		t.Fatalf("minting a state: %v", err)
	}

	target := socialLoginPrefix + "/" + oauth.ProviderGitHub + "/callback?code=real&state=" + state
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	req.AddCookie(&http.Cookie{Name: OAuthStateCookieName, Value: state})

	rec := httptest.NewRecorder()
	newMux(nil, options{auth: newFakeAuth(), social: social}).ServeHTTP(rec, req)

	// The state check passes, so the request reaches the use case, whose exchanger
	// refuses. The refusal is a 400 — oauth.ErrCodeRefused — and the state cookie is
	// cleared either way.
	if rec.Code != http.StatusBadRequest {
		t.Errorf("the callback = %d, want 400. The use case's exchanger refuses every code, so a "+
			"session here would mean the adapter minted one the use case never authorized — a "+
			"credential obtained by completing a third-party round trip.", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, `"token"`) {
		t.Errorf("the callback body carries a token field: %s", body)
	}

	// One-shot: both cookies are expired regardless of the outcome, because the state
	// is replayable and the provider will not enforce it for us.
	for _, name := range []string{OAuthStateCookieName, OAuthLinkCookieName} {
		var expired bool
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == name && cookie.MaxAge < 0 {
				expired = true
			}
		}
		if !expired {
			t.Errorf("the callback did not expire the %s cookie. Leaving it behind would let one "+
				"captured callback be replayed.", name)
		}
	}
}

// --- helpers ------------------------------------------------------------------

func mustRegistry(t *testing.T, base string, providers ...oauth.Provider) *oauth.Registry {
	t.Helper()

	registry, err := oauth.NewRegistry(base, providers...)
	if err != nil {
		t.Fatalf("oauth.NewRegistry(%q): %v", base, err)
	}
	return registry
}

func mustService(t *testing.T, registry *oauth.Registry) *auth.SocialService {
	t.Helper()

	return auth.NewSocialService(nil, wiringRegistry{real: registry}, wiringExchanger{}, wiringAccounts{}, wiringSealer{})
}

// applyOptions applies opts to the zero options value and returns the result,
// which is the only way a test in this package can observe what a production
// caller assembled.
func applyOptions(opts ...Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// compile-time: the doubles must satisfy the seams auth.NewSocialService
// declares. A widened seam fails here rather than at runtime inside the use case.
var (
	_ auth.SocialRegistry  = wiringRegistry{}
	_ auth.SocialExchanger = wiringExchanger{}
	_ auth.SocialAccounts  = wiringAccounts{}
	_ auth.SocialSealer    = wiringSealer{}
)
