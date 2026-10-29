package httpapi


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


type wiringRegistry struct{ real *oauth.Registry }

func (w wiringRegistry) Lookup(name string) (oauth.Provider, error) { return w.real.Lookup(name) }
func (w wiringRegistry) RedirectBase() string                       { return w.real.RedirectBase() }

type wiringExchanger struct{}

func (wiringExchanger) Exchange(context.Context, oauth.Provider, string) (oauth.Tokens, error) {
	return oauth.Tokens{}, oauth.ErrCodeRefused
}
func (wiringExchanger) Identity(context.Context, oauth.Provider, oauth.Tokens) (oauth.Identity, error) {
	return oauth.Identity{}, oauth.ErrCodeRefused
}

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

type wiringSealer struct{}

func (wiringSealer) Seal(string) (string, error) { return "sealed", nil }

func newRealWiring(t *testing.T) Social {
	t.Helper()

	provider := oauth.GitHub()
	provider.ClientID = "id"
	provider.ClientSecret = "secret"

	registry, err := oauth.NewRegistry("https://identity.test", provider)
	if err != nil {
		t.Fatalf("oauth.NewRegistry: %v", err)
	}

	service := auth.NewSocialService(
		nil,
		wiringRegistry{real: registry},
		wiringExchanger{},
		wiringAccounts{},
		wiringSealer{},
	)

	return NewSocial(registry, service)
}

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

	want := "https://identity.test/v1/auth/oauth/github/callback"
	if got := provider.RedirectURI(social.RedirectBase()); got != want {
		t.Errorf("the callback URL is %q, want %q. The router's start route and the use case's "+
			"exchange both build this, and the provider refuses a mismatch without saying which "+
			"URL was wrong.", got, want)
	}
}

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

func TestTheRealWiringMountsBothRoutes(t *testing.T) {
	t.Parallel()

	mux := newMux(nil, options{auth: newFakeAuth(), social: newRealWiring(t)})

	for _, route := range []struct{ name, url string }{
		{"start", socialLoginPrefix + "/" + oauth.ProviderGitHub},
		{"callback", socialLoginPrefix + "/" + oauth.ProviderGitHub + "/callback"},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, route.url, nil))

		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s answered 404 with the REAL wiring configured over %s. The adapter "+
				"satisfies Social and the registrar mounts both routes, so a 404 here means the "+
				"router did not see this value — not that the handler refused.",
				route.url, oauth.ProviderGitHub)
		}
	}

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

func TestTheRealWiringResolvesTheConfiguredProviderThroughTheStartRoute(t *testing.T) {
	t.Parallel()

	mux := newMux(nil, options{auth: newFakeAuth(), social: newRealWiring(t)})

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
	if !strings.Contains(location, "redirect_uri=https%3A%2F%2Fidentity.test%2Fv1%2Fauth%2Foauth%2Fgithub%2Fcallback") {
		t.Errorf("Location = %q, want it to carry the CONFIGURED callback URL. A redirect_uri built "+
			"from a Host header an attacker chose delivers the authorization code to wherever they "+
			"asked.", location)
	}

	refused := httptest.NewRecorder()
	mux.ServeHTTP(refused, httptest.NewRequestWithContext(context.Background(), http.MethodGet, socialLoginPrefix+"/"+oauth.ProviderGoogle, nil))
	if refused.Code != http.StatusNotFound {
		t.Errorf("GET the start route for an unconfigured provider = %d, want 404. This registry "+
			"holds github only, and google is the same miss as a name that does not exist — the "+
			"difference would enumerate the deployment's configuration.", refused.Code)
	}
}

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

	if rec.Code != http.StatusBadRequest {
		t.Errorf("the callback = %d, want 400. The use case's exchanger refuses every code, so a "+
			"session here would mean the adapter minted one the use case never authorized — a "+
			"credential obtained by completing a third-party round trip.", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, `"token"`) {
		t.Errorf("the callback body carries a token field: %s", body)
	}

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

func applyOptions(opts ...Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

var (
	_ auth.SocialRegistry  = wiringRegistry{}
	_ auth.SocialExchanger = wiringExchanger{}
	_ auth.SocialAccounts  = wiringAccounts{}
	_ auth.SocialSealer    = wiringSealer{}
)
