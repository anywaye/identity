package oauth


import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func credentials(p Provider) Provider {
	p.ClientID = "client-id-" + p.Name
	p.ClientSecret = "client-secret-" + p.Name
	return p
}

func newTestRegistry(t *testing.T, base string, names ...string) *Registry {
	t.Helper()

	all := map[string]Provider{ProviderGoogle: Google(), ProviderGitHub: GitHub(), ProviderApple: Apple()}
	providers := make([]Provider, 0, len(names))
	for _, name := range names {
		def, ok := all[name]
		if !ok {
			t.Fatalf("test asked for a provider that does not exist: %q", name)
		}
		providers = append(providers, credentials(def))
	}

	registry, err := NewRegistry(base, providers...)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return registry
}


func TestTheProviderDefinitionsAreFixed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		provider      Provider
		wantName      string
		wantOpts      int
		wantEndpoints map[string]bool
	}{
		{name: "google", provider: Google(), wantName: ProviderGoogle, wantOpts: 1,
			wantEndpoints: map[string]bool{"AuthorizeURL": true, "TokenURL": true, "UserInfoURL": true, "EmailsURL": false, "JWKSURL": false}},
		{name: "github", provider: GitHub(), wantName: ProviderGitHub,
			wantEndpoints: map[string]bool{"AuthorizeURL": true, "TokenURL": true, "UserInfoURL": true, "EmailsURL": true, "JWKSURL": false}},
		{name: "microsoft", provider: Microsoft(), wantName: ProviderMicrosoft,
			wantEndpoints: map[string]bool{"AuthorizeURL": true, "TokenURL": true, "UserInfoURL": true, "EmailsURL": false, "JWKSURL": false}},
		{name: "apple", provider: Apple(), wantName: ProviderApple,
			wantEndpoints: map[string]bool{"AuthorizeURL": true, "TokenURL": true, "UserInfoURL": false, "EmailsURL": false, "JWKSURL": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.provider.Name != tc.wantName {
				t.Errorf("Name = %q, want %q. The name is the `oauth_provider` enum value and the "+
					"path segment in the URL, so a mismatch here is a route nobody can reach.",
					tc.provider.Name, tc.wantName)
			}
			if len(tc.provider.ExtraAuthorizeOptions) != tc.wantOpts {
				t.Errorf("ExtraAuthorizeOptions has %d entries, want %d for %s. Google needs "+
					"access_type=offline or its accounts get no refresh token; GitHub must not carry "+
					"it, because the parameter is Google's and sending it elsewhere is noise at best.",
					len(tc.provider.ExtraAuthorizeOptions), tc.wantOpts, tc.name)
			}
			for field, wantNonEmpty := range tc.wantEndpoints {
				value := reflect.ValueOf(tc.provider).FieldByName(field)
				if !value.IsValid() {
					t.Errorf("Provider has no field %q, so this test's expectation for %s cannot be checked", field, tc.name)
					continue
				}
				got := value.String() != ""
				if got != wantNonEmpty {
					t.Errorf("%s set = %v, want %v for %s. The endpoints are fields rather than constants so a "+
						"test can point a flow at an httptest server, which means a production endpoint "+
						"is a value nothing else in the type guarantees is right — and an endpoint that "+
						"should be absent (Apple's UserInfoURL, Google's EmailsURL) is a call this service "+
						"would make to a provider that does not answer it.",
						field, got, wantNonEmpty, tc.name)
				}
			}
		})
	}
}


func TestNewRegistryDropsAProviderWithNoCredentials(t *testing.T) {
	t.Parallel()

	idOnly := GitHub()
	idOnly.ClientID = "only-the-id"

	secretOnly := GitHub()
	secretOnly.ClientSecret = "only-the-secret"

	for name, p := range map[string]Provider{
		"no credentials at all":  GitHub(),
		"only the client id":     idOnly,
		"only the client secret": secretOnly,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			registry, err := NewRegistry("https://identity.test", p)
			if err != nil {
				t.Fatalf("NewRegistry: %v", err)
			}
			if !registry.Empty() {
				t.Errorf("registry holds %v after being given a %q provider. A provider with no "+
					"credentials must be dropped: keeping it would mount a start route that redirects "+
					"to a provider this service cannot exchange a code with, which is a half-mounted "+
					"flow rather than an absent one.", registry.Names(), name)
			}
			if _, err := registry.Lookup(ProviderGitHub); !errors.Is(err, ErrUnknownProvider) {
				t.Errorf("Lookup(%q) after the drop = %v, want ErrUnknownProvider. An unconfigured "+
					"provider and a nonexistent one have to be the same miss, or this endpoint "+
					"enumerates the deployment's configuration.", ProviderGitHub, err)
			}
		})
	}
}

func TestNewRegistryRejectsAnUnusableBase(t *testing.T) {
	t.Parallel()

	for name, base := range map[string]string{
		"empty":                               "",
		"no scheme":                           "identity.test",
		"a scheme a browser cannot return to": "ftp://identity.test",
		"no host":                             "https://",
		"carries a query":                     "https://identity.test?tenant=acme",
		"carries a fragment":                  "https://identity.test#top",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			registry, err := NewRegistry(base, credentials(GitHub()))
			if !errors.Is(err, ErrInvalidRedirectBaseURL) {
				t.Errorf("NewRegistry(%q) error = %v, want ErrInvalidRedirectBaseURL. This base "+
					"cannot produce a callback URL a browser comes back to, and every callback this "+
					"service builds is appended to it.", base, err)
			}
			if registry != nil {
				t.Errorf("NewRegistry(%q) returned a registry alongside its error. A caller that "+
					"checks the error and proceeds anyway would build callbacks from a base the "+
					"constructor just refused.", base)
			}
		})
	}
}

func TestNewRegistryAcceptsABaseWithATrailingSlash(t *testing.T) {
	t.Parallel()

	withSlash, err := NewRegistry("https://identity.test/", credentials(GitHub()))
	if err != nil {
		t.Fatalf("NewRegistry with a trailing slash: %v", err)
	}

	got := GitHub().RedirectURI(withSlash.RedirectBase())
	if strings.Contains(got, "//v1") {
		t.Errorf("RedirectURI(%q) = %q, which contains an empty path segment. The provider compares "+
			"redirect_uri against the value registered for this client and refuses a mismatch "+
			"without saying which of the two URLs was wrong.",
			withSlash.RedirectBase(), got)
	}
	if want := "https://identity.test/v1/auth/oauth/github/callback"; got != want {
		t.Errorf("RedirectURI(%q) = %q, want %q", withSlash.RedirectBase(), got, want)
	}
}


func TestLookupRefusesAnUnconfiguredProviderAndAnAbsentOneAlike(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, "https://identity.test", ProviderGitHub)

	unknown, unknownErr := registry.Lookup("netflix")
	unconfigured, unconfiguredErr := registry.Lookup(ProviderGoogle)

	for name, err := range map[string]error{
		"a provider this service does not offer":            unknownErr,
		"a provider this deployment has no credentials for": unconfiguredErr,
	} {
		if !errors.Is(err, ErrUnknownProvider) {
			t.Errorf("Lookup for %s = %v, want ErrUnknownProvider. The router renders both as 404, "+
				"and it can only do that if both are the same error.", name, err)
		}
	}

	const substituted = "PROVIDER"
	strippedUnconfigured := strings.Replace(unconfiguredErr.Error(), ProviderGoogle, substituted, 1)
	strippedUnknown := strings.Replace(unknownErr.Error(), "netflix", substituted, 1)

	if strippedUnconfigured != strippedUnknown {
		t.Errorf("the two misses differ in something other than the requested name:\n"+
			"  unconfigured (asked %q): %q\n  unknown      (asked %q): %q\n"+
			"The requested name is the caller's own URL segment and discloses nothing. Anything else "+
			"that differs between a provider this deployment lacks and one that does not exist is a "+
			"configuration oracle reachable with no credential.",
			ProviderGoogle, strippedUnconfigured, "netflix", strippedUnknown)
	}

	for name, err := range map[string]error{
		"netflix": unknownErr,
		"google":  unconfiguredErr,
	} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal for %q does not quote the name asked for: %q", name, err.Error())
		}
	}

	held := newTestRegistry(t, "https://identity.test", ProviderGoogle)
	if _, err := held.Lookup(ProviderGoogle); err != nil {
		t.Errorf("Lookup(%q) on a registry that holds it = %v", ProviderGoogle, err)
	}

	if unknown.Name != "" || unconfigured.Name != "" {
		t.Errorf("a refused Lookup returned a provider: %+v and %+v. A caller that ignored the "+
			"error would be building a redirect_uri out of a zero value.", unknown, unconfigured)
	}
}

func TestLookupReturnsTheConfiguredProvider(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, "https://identity.test", ProviderGitHub)

	got, err := registry.Lookup(ProviderGitHub)
	if err != nil {
		t.Fatalf("Lookup(%q): %v", ProviderGitHub, err)
	}

	if got.Name != ProviderGitHub {
		t.Errorf("Name = %q, want %q", got.Name, ProviderGitHub)
	}
	if got.ClientID == "" || got.ClientSecret == "" {
		t.Errorf("the returned provider carries no credentials (id %q, secret %q). Lookup feeds "+
			"AuthCodeURL and Client.Exchange, and a definition without the operator's credentials "+
			"redirects to a provider that then refuses the exchange.",
			got.ClientID, got.ClientSecret)
	}
	if got.AuthorizeURL == "" || got.TokenURL == "" || got.UserInfoURL == "" {
		t.Errorf("the returned provider is missing an endpoint: %+v", got)
	}
}

func TestLookupIsCaseSensitive(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, "https://identity.test", ProviderGitHub)

	for _, name := range []string{"GitHub", "GITHUB", " github", "github "} {
		if _, err := registry.Lookup(name); !errors.Is(err, ErrUnknownProvider) {
			t.Errorf("Lookup(%q) = %v, want ErrUnknownProvider. The registry is keyed on the enum "+
				"value, which the migration's CHECK constraint is lowercase; a lookup that accepted "+
				"another spelling would resolve a name the database would then refuse to store.",
				name, err)
		}
	}
}

func TestLookupOnAnEmptyRegistryRefusesEverything(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry("https://identity.test")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	for _, name := range []string{ProviderGoogle, ProviderGitHub, ProviderMicrosoft, ProviderApple, "netflix", ""} {
		if _, err := registry.Lookup(name); !errors.Is(err, ErrUnknownProvider) {
			t.Errorf("Lookup(%q) on an empty registry = %v, want ErrUnknownProvider", name, err)
		}
	}
}


func TestNamesIsSortedAndIndependentOfConfigurationOrder(t *testing.T) {
	t.Parallel()

	googleThenGitHub := newTestRegistry(t, "https://identity.test", ProviderGoogle, ProviderGitHub)
	gitHubThenGoogle := newTestRegistry(t, "https://identity.test", ProviderGitHub, ProviderGoogle)

	first := googleThenGitHub.Names()
	second := gitHubThenGoogle.Names()

	want := []string{ProviderGitHub, ProviderGoogle}
	if len(first) != len(want) {
		t.Fatalf("Names() = %v, want %v", first, want)
	}
	for i := range want {
		if first[i] != want[i] {
			t.Errorf("Names() = %v, want %v (sorted)", first, want)
			break
		}
	}
	for i := range want {
		if second[i] != want[i] {
			t.Errorf("the registry built in the opposite order reported %v, want %v. A startup log "+
				"naming the configured providers has to be stable between restarts of the same "+
				"configuration, or an operator diffing two of them reads a phantom change.",
				second, want)
			break
		}
	}

	first[0] = "mutated"
	if again := googleThenGitHub.Names(); again[0] == "mutated" {
		t.Error("Names() returned a slice aliasing the registry's state: writing to it changed what " +
			"the next call reports. It has to be a fresh slice each time.")
	}
}

func TestNamesIsEmptyAndEmptyIsTrueOnABareRegistry(t *testing.T) {
	t.Parallel()

	bare, err := NewRegistry("https://identity.test")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if !bare.Empty() {
		t.Errorf("Empty() = false on a registry over no providers. WithSocial's rule is that the " +
			"routes are absent in that state, so a deployment with no OAuth credentials serves a " +
			"clean 404 rather than a redirect to a provider it cannot authenticate with.")
	}
	if got := bare.Names(); len(got) != 0 {
		t.Errorf("Names() = %v on a bare registry, want empty", got)
	}

	one := newTestRegistry(t, "https://identity.test", ProviderGitHub)
	if one.Empty() {
		t.Errorf("Empty() = true on a registry holding %v. A configured deployment whose routes "+
			"stay unmounted serves 404s for a feature it has, which is the other half of the same "+
			"mistake.", one.Names())
	}
	if got := one.Names(); len(got) != 1 || got[0] != ProviderGitHub {
		t.Errorf("Names() = %v, want [%s]", got, ProviderGitHub)
	}
}

func TestKnownProvidersMatchesTheNamesTheEnumAccepts(t *testing.T) {
	t.Parallel()

	enum, ok := connectedAccountProviderEnum()
	if !ok {
		t.Fatal("could not read the oauth_provider enum out of migrations/00008_connected_accounts.sql. " +
			"If that migration moved, point this check at the file that holds the enum rather than " +
			"deleting it: the closed set in provider.go and the column's CHECK constraint have to " +
			"agree, and nothing in Go holds them together.")
	}

	if len(knownProviders) != len(enum) {
		t.Errorf("knownProviders = %v but the migration's enum accepts %v. A name in one and not "+
			"the other is a provider the code offers and the database refuses, or one a connected "+
			"account can name and no registry can resolve.",
			knownProviders, enum)
	}
	for _, name := range knownProviders {
		if !contains(enum, name) {
			t.Errorf("knownProviders holds %q, which the migration's oauth_provider enum does not "+
				"accept (%v). Store.Create would have its insert refused by a CHECK constraint.", name, enum)
		}
	}
}
