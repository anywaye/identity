package oauth

// TESTS FOR THE PROVIDER REGISTRY — the file that decides WHICH providers a
// deployment will accept, and the second of the two files in this package that
// carried a security decision with no test at all.
//
// # WHAT IS WORTH A TEST HERE, AND WHAT IS NOT
//
// `Registry` is a map with four accessors. What makes it worth a file is not the
// accessors; it is that three of them encode a REFUSAL, and a refusal is a
// security decision that a future edit can quietly undo:
//
//   - `NewRegistry` DROPS a provider with no credentials rather than storing a
//     broken entry, so a half-configured deployment serves a 404 instead of a
//     redirect that cannot complete.
//   - `Lookup` answers ErrUnknownProvider for a real provider this deployment has
//     no credentials for AND for a name that does not exist. Those two must stay
//     indistinguishable, because telling them apart enumerates a deployment's
//     configuration through an unauthenticated endpoint.
//   - `Empty` is what the mount consults to decide whether to serve social login
//     at all, so its answer is a routing decision and not a convenience.
//
// The tests below assert those three refusals and the shape of the two provider
// definitions. They do NOT test `AuthCodeURL` or `oauth2Config` beyond what
// internal/httpapi and client_test.go already cover, and they do not test
// `validateRedirectBase` exhaustively — settings_test.go holds the matrix of
// valid and invalid bases through `Settings.Validate`, which reaches the same
// function. Duplicating that table here would be a second list to keep in step
// with the first.

import (
	"errors"
	"strings"
	"testing"
)

// credentials returns a provider definition with both halves of its credentials
// present, which is the only form NewRegistry keeps.
func credentials(p Provider) Provider {
	p.ClientID = "client-id-" + p.Name
	p.ClientSecret = "client-secret-" + p.Name
	return p
}

// newTestRegistry returns a registry over base with the named providers
// credentialed.
func newTestRegistry(t *testing.T, base string, names ...string) *Registry {
	t.Helper()

	all := map[string]Provider{ProviderGoogle: Google(), ProviderGitHub: GitHub()}
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

// ---------------------------------------------------------------------------
// The definitions
// ---------------------------------------------------------------------------

// TestTheProviderDefinitionsAreFixed pins the two definitions.
//
// It is here because both endpoint sets are FIELDS rather than constants, and
// that is deliberate (client_test.go needs to point a flow at an httptest
// server). The cost of fields is that a typo in a production endpoint is a valid
// Go value that a test has to catch — and an endpoint is a URL this service sends
// a person's authorization code to, so "wrong host" is not a cosmetic error.
//
// Google carries `access_type=offline` and GitHub does not, because the two
// providers differ there and the asymmetry is real: Google issues a refresh token
// only on first consent unless the request asks for offline access, so a Google
// account without this parameter has a stored credential that dies in an hour.
// Asserting the asymmetry is the point; asserting the parameter's spelling for
// Google alone would not catch GitHub acquiring one.
func TestTheProviderDefinitionsAreFixed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		provider Provider
		wantName string
		wantOpts int
		emails   bool
	}{
		{name: "google", provider: Google(), wantName: ProviderGoogle, wantOpts: 1},
		{name: "github", provider: GitHub(), wantName: ProviderGitHub, emails: true},
		// Microsoft carries no extra authorize option — its offline access is a
		// SCOPE, not a parameter, and sending Google's access_type to it would be
		// the same noise in the other direction — and no emails endpoint, because
		// its userinfo carries the address itself.
		{name: "microsoft", provider: Microsoft(), wantName: ProviderMicrosoft},
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
			if got := tc.provider.EmailsURL != ""; got != tc.emails {
				t.Errorf("EmailsURL set = %v, want %v for %s. It is GitHub-only: /user returns a "+
					"null email for a private address and /user/emails is the documented way to get "+
					"it. Google's userinfo carries the address itself.",
					got, tc.emails, tc.name)
			}
			for field, value := range map[string]string{
				"AuthorizeURL": tc.provider.AuthorizeURL,
				"TokenURL":     tc.provider.TokenURL,
				"UserInfoURL":  tc.provider.UserInfoURL,
			} {
				if value == "" {
					t.Errorf("%s is empty on %s. The endpoints are fields rather than constants so a "+
						"test can point a flow at an httptest server, which means a production endpoint "+
						"is a value nothing else in the type guarantees is right.", field, tc.name)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NewRegistry
// ---------------------------------------------------------------------------

// TestNewRegistryDropsAProviderWithNoCredentials is the half-configured refusal.
//
// `NewRegistry`'s own comment says providers with no credentials are "dropped
// rather than stored as broken entries", and the reason is in ErrIncompleteProvider:
// a sign-in button that 404s because a secret went missing should have been a
// failed deploy, and a deploy that failed loudly leaves nothing to drop.
//
// So the property under test is that a provider with only ONE half of its
// credentials does not become a route. Three ways to be incomplete are checked —
// neither half, and each half alone — because the code tests
// `p.ClientID == "" || p.ClientSecret == ""` and a test that only supplied the
// empty-empty case would pass against an implementation that had inverted the
// condition to `&&`.
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

// TestNewRegistryRejectsAnUnusableBase covers the one error NewRegistry has.
//
// The returned error is only ever about baseURL — providers with no credentials
// are dropped, not rejected — so this is the single failure mode of the
// constructor, and a test that only checked the happy path would leave the
// constructor's error return unexercised.
//
// The three cases are the three things validateRedirectBase refuses for three
// different reasons, and the reason they are named rather than table-driven over
// a list of strings is that a list of invalid bases is a second copy of the rule
// in validateRedirectBase's comment that goes stale silently. Each case here
// corresponds to a distinct branch in that function.
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

// TestNewRegistryAcceptsABaseWithATrailingSlash covers the one normalisation the
// constructor performs.
//
// `Provider.RedirectURI` does `strings.TrimSuffix(baseURL, "/")`, and the reason
// it has to is that the callback is appended as a path: a base ending in "/" plus
// an untrimmed append produces `https://identity.test//v1/auth/oauth/github/callback`,
// which the provider refuses to match against the registered redirect_uri without
// saying which of the two URLs was wrong. The trimming is verified here against
// the real function rather than by asserting on the base.
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

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

// TestLookupRefusesAnUnconfiguredProviderAndAnAbsentOneAlike is the property
// `Lookup`'s own comment claims and the security reason the method exists.
//
// Two names are asked for: "apple", which this service has never heard of, and
// "google" on a registry configured with only GitHub. Both must be
// ErrUnknownProvider, and — the half that is easy to get wrong and the half an
// attacker wants — both must be the same ERROR apart from the name the caller
// themselves supplied.
//
// # WHAT "THE SAME ERROR" HAS TO MEAN HERE, PRECISELY
//
// `Lookup` wraps the sentinel with the requested name: `fmt.Errorf("%w: %q",
// ErrUnknownProvider, name)`. So the two strings are NOT byte-identical, and the
// first version of this test asserted they were — which was wrong, and worth
// recording why. It was asserting that the error carry no diagnostic at all,
// which is a different and worse requirement than this repository holds anywhere
// else, and following it would have meant deleting the one useful thing about the
// message.
//
// The requested name is not deployment state. It is the caller's own URL segment,
// which the caller already knows. What must not vary is whether the REGISTRY knew
// the name. So the check below substitutes the requested name out of both messages
// and requires what remains to be identical, which is precisely the part an
// attacker cannot already supply.
//
// # WHY errors.Is ALONE IS NOT ENOUGH
//
// A `Lookup` that returned a bare ErrUnknownProvider for a name it has never heard
// of and a wrapped "provider google is not configured on this deployment" for one
// it holds would satisfy every `errors.Is(err, ErrUnknownProvider)` assertion in
// this repository — and would still enumerate the deployment's configuration,
// because an unauthenticated caller can ask for every name in the closed set and
// read which ones come back with the extra sentence. The router renders both as a
// constant 404, so the difference is invisible in a response and fully visible in
// a log the caller does not have.
func TestLookupRefusesAnUnconfiguredProviderAndAnAbsentOneAlike(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, "https://identity.test", ProviderGitHub)

	unknown, unknownErr := registry.Lookup("apple")
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

	// The comparison errors.Is does NOT cover. `google` is a real provider this
	// deployment lacks; `apple` is not a provider at all. With the caller's own
	// name substituted out, nothing else may differ.
	const substituted = "PROVIDER"
	strippedUnconfigured := strings.Replace(unconfiguredErr.Error(), ProviderGoogle, substituted, 1)
	strippedUnknown := strings.Replace(unknownErr.Error(), "apple", substituted, 1)

	if strippedUnconfigured != strippedUnknown {
		t.Errorf("the two misses differ in something other than the requested name:\n"+
			"  unconfigured (asked %q): %q\n  unknown      (asked %q): %q\n"+
			"The requested name is the caller's own URL segment and discloses nothing. Anything else "+
			"that differs between a provider this deployment lacks and one that does not exist is a "+
			"configuration oracle reachable with no credential.",
			ProviderGoogle, strippedUnconfigured, "apple", strippedUnknown)
	}

	// Both misses still quote what was asked for, because that string never reaches a
	// caller — the router renders a constant 404 — and it is the difference between a
	// 404 an operator can debug and one they cannot.
	for name, err := range map[string]error{
		"apple":  unknownErr,
		"google": unconfiguredErr,
	} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal for %q does not quote the name asked for: %q", name, err.Error())
		}
	}

	// And the precondition the miss comparison above depends on: a provider this
	// deployment DOES hold must resolve. If configured and unconfigured were the same
	// answer, the distinction from the unknown-name case would be gone too, and no
	// caller — including a legitimate user — could tell a configured deployment from
	// an unconfigured one. This is the direction that would break sign-in rather than
	// leak, which is why it is asserted alongside the leak.
	held := newTestRegistry(t, "https://identity.test", ProviderGoogle)
	if _, err := held.Lookup(ProviderGoogle); err != nil {
		t.Errorf("Lookup(%q) on a registry that holds it = %v", ProviderGoogle, err)
	}

	if unknown.Name != "" || unconfigured.Name != "" {
		t.Errorf("a refused Lookup returned a provider: %+v and %+v. A caller that ignored the "+
			"error would be building a redirect_uri out of a zero value.", unknown, unconfigured)
	}
}

// TestLookupReturnsTheConfiguredProvider is the positive case, and it asserts the
// CREDENTIALS come back rather than just the name.
//
// The name alone would pass against a registry that stored definitions without
// operator credentials, which is the shape a "build the redirect from the
// definition and the secret from elsewhere" implementation takes — and that shape
// cannot exchange a code, so it fails at the provider with an error a person sees
// as a broken login.
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

// TestLookupIsCaseSensitive guards a decision the map makes implicitly.
//
// `byName` is keyed on the exact enum value, so "GitHub" and "GITHUB" are both
// misses. That is the right direction — the enum is lowercase, the migration's
// CHECK constraint is lowercase, and a case-insensitive lookup would resolve a
// name the database would then refuse to store — but it is a decision, and a
// future switch to `strings.ToLower` here would change it silently.
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

// TestLookupOnAnEmptyRegistryRefusesEverything closes the shape a nil-guard
// would take.
//
// A registry over no providers answers ErrUnknownProvider for every name, which is
// what makes `Empty()` a sufficient flag for the mount rather than one case of a
// decision the mount still has to make. If this ever answered something else, the
// absence rule in WithSocial would have a hole in it that only a configured
// deployment would notice.
func TestLookupOnAnEmptyRegistryRefusesEverything(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry("https://identity.test")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	for _, name := range []string{ProviderGoogle, ProviderGitHub, ProviderMicrosoft, "apple", ""} {
		if _, err := registry.Lookup(name); !errors.Is(err, ErrUnknownProvider) {
			t.Errorf("Lookup(%q) on an empty registry = %v, want ErrUnknownProvider", name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Names and Empty
// ---------------------------------------------------------------------------

// TestNamesIsSortedAndIndependentOfConfigurationOrder covers the two properties
// `Names`'s comment states: sorted, and stable between restarts.
//
// The stability claim is about a startup log line, so the assertion is that two
// registries built from the SAME configuration in OPPOSITE orders produce the same
// slice. Without it, `Names` could depend on map iteration order and an operator
// diffing two restarts' logs would see a provider added and removed.
//
// The returned slice is also required not to alias the registry's own state: a
// caller that sorts or truncates it must not be able to change what a later call
// reports. That is the kind of property a test is the only cheap way to hold,
// because the map is unexported and nothing else would notice.
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

	// Mutating the caller's copy must not reach the registry.
	first[0] = "mutated"
	if again := googleThenGitHub.Names(); again[0] == "mutated" {
		t.Error("Names() returned a slice aliasing the registry's state: writing to it changed what " +
			"the next call reports. It has to be a fresh slice each time.")
	}
}

// TestNamesIsEmptyAndEmptyIsTrueOnABareRegistry is the flag the mount consults.
//
// `Empty` is described as the thing "the process mounts the OAuth routes only when
// this is false", which makes it a ROUTING decision: get it wrong in one
// direction and a credential-less deployment mounts a flow that cannot complete,
// in the other and a configured deployment serves 404s for a feature it has.
//
// The negative direction matters equally. `len(r.byName) == 0` is the whole of
// `Empty`, so a registry holding exactly one provider must answer false, and a
// test that only checked the bare case would pass against an implementation that
// ignored the map entirely and always returned true.
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

// TestKnownProvidersMatchesTheNamesTheEnumAccepts holds the closed set against
// what the rest of the service can actually store.
//
// `knownProviders` is declared at the top of this file as "the closed set, in the
// order they are logged", and its own comment says the two names are the values of
// the `oauth_provider` enum in migrations/00008_connected_accounts.sql. Nothing in
// Go ties the two together: a provider added to the enum and not to this slice is
// a provider `Settings.Providers` will never offer, and one added here and not to
// the enum is an insert the database refuses.
//
// The migration is read rather than restated, so this cannot go stale the way a
// duplicated list of two strings would — which is the whole reason to read a file
// in a test at all.
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
