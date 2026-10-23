package oauth

// The endpoint overrides are the one thing in this package that lets a DEPLOYMENT
// — rather than a test — point the whole sign-in flow at a server it controls. The
// property that makes that safe is narrow and is asserted here rather than argued:
// with nothing set, this service dials exactly the URLs it dialed before these
// variables existed, and with them set the URLs it dials are the ones the deployer
// chose.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// THE DEFAULTS, SPELLED OUT AGAIN ON PURPOSE. A test that compared them to
// `GoogleAuthorizeURL` would pass if the constant were wrong, which is the one
// thing this packet must not be able to do: the value that used to be a literal in
// a struct literal is the value every deployment that sets nothing gets, and it has
// to be the one Google and GitHub actually serve.
const (
	shippedGoogleAuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
	shippedGoogleTokenURL     = "https://oauth2.googleapis.com/token"
	shippedGoogleUserInfoURL  = "https://openidconnect.googleapis.com/v1/userinfo"
	shippedGoogleScopes       = "openid email profile"

	shippedGitHubAuthorizeURL = "https://github.com/login/oauth/authorize"
	shippedGitHubTokenURL     = "https://github.com/login/oauth/access_token"
	shippedGitHubUserInfoURL  = "https://api.github.com/user"
	shippedGitHubEmailsURL    = "https://api.github.com/user/emails?per_page=100"
	shippedGitHubScopes       = "read:user user:email"
)

// configuredProviders is a Settings with both providers fully configured and NO
// endpoint overrides: the deployment that has credentials and says nothing about
// where to send people.
func configuredProviders() Settings {
	return Settings{
		RedirectBaseURL: "https://identity.anywaye.com",
		EncryptionKey:   testKeyBase64(9),
		Google:          ProviderSettings{ClientID: "google-id", ClientSecret: "google-secret"},
		GitHub:          ProviderSettings{ClientID: "github-id", ClientSecret: "github-secret"},
	}
}

// THE REGRESSION GUARD FOR THIS PACKET. Every field of both providers, byte for
// byte, plus the scopes and the one extra authorize option — because "behavior
// must be identical with nothing set" includes the parameters on the wire, and an
// override that dropped `access_type=offline` would leave every Google account
// without a refresh token and every assertion in this file green.
func TestUnsetOverridesLeaveTheShippedEndpointsAndParameters(t *testing.T) {
	t.Parallel()

	providers := configuredProviders().Providers()
	if len(providers) != 2 {
		t.Fatalf("Providers() returned %d, want 2", len(providers))
	}

	want := []struct {
		name                                       string
		authorize, token, userInfo, emails, scopes string
	}{
		{
			name:      ProviderGoogle,
			authorize: shippedGoogleAuthorizeURL,
			token:     shippedGoogleTokenURL,
			userInfo:  shippedGoogleUserInfoURL,
			scopes:    shippedGoogleScopes,
		},
		{
			name:      ProviderGitHub,
			authorize: shippedGitHubAuthorizeURL,
			token:     shippedGitHubTokenURL,
			userInfo:  shippedGitHubUserInfoURL,
			emails:    shippedGitHubEmailsURL,
			scopes:    shippedGitHubScopes,
		},
	}

	for i, w := range want {
		got := providers[i]
		if got.Name != w.name {
			t.Fatalf("Providers()[%d].Name = %q, want %q", i, got.Name, w.name)
		}
		if got.AuthorizeURL != w.authorize {
			t.Errorf("%s AuthorizeURL = %q, want %q", w.name, got.AuthorizeURL, w.authorize)
		}
		if got.TokenURL != w.token {
			t.Errorf("%s TokenURL = %q, want %q", w.name, got.TokenURL, w.token)
		}
		if got.UserInfoURL != w.userInfo {
			t.Errorf("%s UserInfoURL = %q, want %q", w.name, got.UserInfoURL, w.userInfo)
		}
		if got.EmailsURL != w.emails {
			t.Errorf("%s EmailsURL = %q, want %q", w.name, got.EmailsURL, w.emails)
		}
		if gotScopes := strings.Join(got.Scopes, " "); gotScopes != w.scopes {
			t.Errorf("%s Scopes = %q, want %q", w.name, gotScopes, w.scopes)
		}
		if got.ClientID == "" || got.ClientSecret == "" {
			t.Errorf("%s lost its credentials: %+v", w.name, got)
		}
	}
}

// Google's offline access option is the one provider-specific authorize parameter
// this service sets, and it is invisible in every URL comparison above, so it is
// asserted on its own. Losing it is a slow failure: every connected account would
// store a refresh token of NULL and die an hour later with nothing to renew it.
func TestGoogleKeepsAskingForOfflineAccessWithNoOverridesSet(t *testing.T) {
	t.Parallel()

	authorizeURL, err := url.Parse(configuredProviders().Providers()[0].AuthCodeURL("state-123", "https://identity.anywaye.com/v1/auth/oauth/google/callback"))
	if err != nil {
		t.Fatalf("parsing the authorize url: %v", err)
	}
	if got := authorizeURL.Query().Get("access_type"); got != "offline" {
		t.Errorf("access_type = %q, want offline", got)
	}
	if got := authorizeURL.Query().Get("state"); got != "state-123" {
		t.Errorf("state = %q, want state-123", got)
	}
}

// An override has to reach the URL the BROWSER is sent to, not a field that was
// set. This asserts on the URL x/oauth2 built, which is the thing a person is about
// to be redirected to.
func TestAnAuthorizeOverrideReachesTheURLTheBrowserIsSentTo(t *testing.T) {
	t.Parallel()

	s := configuredProviders()
	s.Google.Endpoints.AuthorizeURL = "https://idp.test/fake/google/authorize"
	s.GitHub.Endpoints.AuthorizeURL = "https://idp.test/fake/github/authorize"

	redirectURI := "https://identity.anywaye.com/v1/auth/oauth/google/callback"
	for _, p := range s.Providers() {
		authorizeURL, err := url.Parse(p.AuthCodeURL("state-123", redirectURI))
		if err != nil {
			t.Fatalf("%s: parsing the authorize url: %v", p.Name, err)
		}
		wantHost, wantPath := "idp.test", "/fake/"+p.Name+"/authorize"
		if authorizeURL.Host != wantHost || authorizeURL.Path != wantPath {
			t.Errorf("%s authorize url = %s://%s%s, want host %s and path %s",
				p.Name, authorizeURL.Scheme, authorizeURL.Host, authorizeURL.Path, wantHost, wantPath)
		}
	}
}

// The other three endpoints are calls this service makes with the access token, so
// the proof that they were overridden is the server receiving them. The fake answers
// each path with the shape the real provider returns, because an override that
// reached the right path and then failed to decode would be a different bug and
// this test would rather not report it.
func TestTokenUserInfoAndEmailsOverridesReachTheCallsThisServiceMakes(t *testing.T) {
	t.Parallel()

	server := newFakeProvider(t)
	defer server.Close()

	s := configuredProviders()
	s.Google.Endpoints.TokenURL = server.URL + "/google/token"
	s.Google.Endpoints.UserInfoURL = server.URL + "/google/userinfo"
	s.GitHub.Endpoints.TokenURL = server.URL + "/github/token"
	s.GitHub.Endpoints.UserInfoURL = server.URL + "/github/user"
	s.GitHub.Endpoints.EmailsURL = server.URL + "/github/emails?per_page=100"

	providers := make(map[string]Provider, 2)
	for _, p := range s.Providers() {
		providers[p.Name] = p
	}

	client := NewClient(ClientOptions{RedirectBaseURL: "https://identity.anywaye.com"})

	tests := []struct {
		name     string
		provider string
		wantHits []string
		wantUID  string
	}{
		{
			name:     ProviderGoogle,
			provider: ProviderGoogle,
			// Google returns the address on the identity call, so there is no second
			// call for an emails override to reach.
			wantHits: []string{"/google/token", "/google/userinfo"},
			wantUID:  "google-sub",
		},
		{
			name:     ProviderGitHub,
			provider: ProviderGitHub,
			// The query on the emails override has to survive: this service's own
			// default carries one, so an override that dropped it would be a
			// regression against the URL it is replacing.
			wantHits: []string{"/github/token", "/github/user", "/github/emails"},
			wantUID:  "4242",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := len(server.Hits())

			p := providers[tt.provider]
			exchanged, err := client.Exchange(context.Background(), p, "fake-code")
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if exchanged.AccessToken == "" {
				t.Fatal("Exchange returned no access token")
			}

			identity, err := client.Identity(context.Background(), p, Tokens{AccessToken: exchanged.AccessToken})
			if err != nil {
				t.Fatalf("Identity: %v", err)
			}
			if identity.ProviderUID != tt.wantUID {
				t.Errorf("ProviderUID = %q, want %q", identity.ProviderUID, tt.wantUID)
			}

			if got := server.Hits()[before:]; !equalPaths(got, tt.wantHits) {
				t.Errorf("the fake provider received %v, want %v", got, tt.wantHits)
			}
		})
	}
}

// The point of the packet in one test: with nothing set, the ONLY addresses this
// service dials are the five it dialed before these variables existed. Every
// request is refused and its URL recorded, so the assertion is about which endpoints
// were chosen rather than about a field that was set — and an override applied when
// none was configured moves one of these and fails.
//
// X/OAUTH2 ASKS FOR A TOKEN TWICE on a client-secret provider, once per
// authentication style, so the URLs are compared as a set.
func TestWithNoOverridesSetTheOnlyOutboundCallsAreTheShippedEndpoints(t *testing.T) {
	t.Parallel()

	recorder := &recordingTransport{}
	client := NewClient(ClientOptions{
		RedirectBaseURL: "https://identity.anywaye.com",
		HTTPClient:      &http.Client{Transport: recorder},
	})
	ctx := context.Background()

	for _, p := range configuredProviders().Providers() {
		if _, err := client.Exchange(ctx, p, "fake-code"); !errors.Is(err, ErrProviderUnavailable) {
			t.Errorf("%s Exchange = %v, want ErrProviderUnavailable", p.Name, err)
		}
		if _, err := client.Identity(ctx, p, Tokens{AccessToken: "t"}); !errors.Is(err, ErrProviderUnavailable) {
			t.Errorf("%s Identity = %v, want ErrProviderUnavailable", p.Name, err)
		}
	}

	want := []string{
		shippedGoogleTokenURL,
		shippedGoogleUserInfoURL,
		shippedGitHubTokenURL,
		shippedGitHubUserInfoURL,
		// GitHub's emails endpoint is NOT here, and its absence is not a gap: this
		// service only dials /user/emails after /user comes back with no address,
		// and every call in this test is refused before any answer arrives. The fake
		// provider test above is where that last URL is exercised.
	}
	if got := recorder.Dialed(); !equalPaths(got, want) {
		t.Errorf("this service dialed %v, want exactly %v", got, want)
	}
}

// recordingTransport refuses every request and remembers its URL. It is how the test
// above turns "the endpoints are the shipped ones" from a claim into a list.
type recordingTransport struct {
	mu   sync.Mutex
	urls []string
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.urls = append(rt.urls, r.URL.String())
	rt.mu.Unlock()

	return nil, errors.New("refusing to dial in a test that only records endpoints")
}

// Dialed returns the distinct URLs requested, in the order they were first asked
// for.
func (rt *recordingTransport) Dialed() []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	seen := make(map[string]bool, len(rt.urls))
	out := make([]string, 0, len(rt.urls))
	for _, u := range rt.urls {
		if seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// A present-but-wrong value is a startup failure and never a silent fall back to
// the default: a deployer who set the variable and got Google's real endpoint has a
// working sign-in flow pointing somewhere they did not choose, with no way to find
// out.
func TestAMalformedEndpointOverrideIsRefusedAndNamesTheEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "no scheme", value: "idp.test/token"},
		{name: "not http", value: "gopher://idp.test/token"},
		{name: "no host", value: "https://"},
		{name: "a fragment, which is never sent to a server", value: "https://idp.test/token#frag"},
		{name: "unparseable", value: "https://idp.test/%zztoken"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := configuredProviders()
			s.Google.Endpoints.TokenURL = tt.value

			err := s.Validate()
			if !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("Validate = %v, want ErrInvalidEndpoint", err)
			}

			var endpointErr *EndpointError
			if !errors.As(err, &endpointErr) {
				t.Fatalf("Validate = %v, want an *EndpointError", err)
			}
			if endpointErr.Provider != ProviderGoogle || endpointErr.Field != "TokenURL" {
				t.Errorf("EndpointError = %+v, want google/TokenURL", endpointErr)
			}
			// The message is what an operator reads, so it has to say which endpoint
			// and not merely that one of them is bad.
			for _, want := range []string{ProviderGoogle, "TokenURL", "OAUTH_GOOGLE_TOKEN_URL"} {
				if strings.Contains(err.Error(), want) {
					continue
				}
				if want == "OAUTH_GOOGLE_TOKEN_URL" {
					// internal/oauth does not know the variable names; internal/config
					// turns this error into one. Its own test asserts that.
					continue
				}
				t.Errorf("Validate = %q, want it to name %q", err, want)
			}
		})
	}
}

// A deployer who has set an endpoint and not the credentials should hear about the
// endpoint at boot, not on the day somebody adds the credentials. This is the
// encryption key's rule — checked whenever present, provider configured or not —
// applied to the setting whose wrong value is otherwise a working service.
func TestAnEndpointOverrideIsCheckedWithoutAnyCredentials(t *testing.T) {
	t.Parallel()

	var s Settings
	s.Google.Endpoints.TokenURL = "not a url at all"
	s.RedirectBaseURL = "https://identity.anywaye.com"
	s.EncryptionKey = testKeyBase64(4)

	if err := s.Validate(); !errors.Is(err, ErrInvalidEndpoint) {
		t.Errorf("Validate = %v, want ErrInvalidEndpoint", err)
	}
	if s.Enabled() {
		t.Error("Enabled = true, want false: an endpoint override is not a credential")
	}
}

// An override for an endpoint a provider does not have is a setting that does
// nothing while reading as if it did. Google's identity call returns the address,
// so there is no /user/emails to point anywhere — and a variable that existed for it
// would be a lie in the table rather than a feature.
func TestAnOverrideForAnEndpointAProviderDoesNotHaveIsRefused(t *testing.T) {
	t.Parallel()

	s := configuredProviders()
	s.Google.Endpoints.EmailsURL = "https://idp.test/google/emails"

	err := s.Validate()
	if !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("Validate = %v, want ErrInvalidEndpoint", err)
	}
	var endpointErr *EndpointError
	if !errors.As(err, &endpointErr) || endpointErr.Field != "EmailsURL" {
		t.Fatalf("Validate = %v, want an *EndpointError naming EmailsURL", err)
	}
}

// A query is allowed and a fragment is not, because this service's own GitHub
// emails endpoint carries one: a rule that refused queries would refuse the default
// it ships with, and a rule that allowed fragments would silently accept a URL
// different from the one the deployer wrote.
func TestAQueryIsAllowedAndAFragmentIsNot(t *testing.T) {
	t.Parallel()

	withQuery := ProviderEndpoints{EmailsURL: "https://idp.test/emails?per_page=100"}
	if err := withQuery.validate(ProviderGitHub); err != nil {
		t.Errorf("a query is part of GitHub's own default and must be allowed: %v", err)
	}

	withFragment := ProviderEndpoints{UserInfoURL: "https://idp.test/userinfo#anchor"}
	if err := withFragment.validate(ProviderGoogle); !errors.Is(err, ErrInvalidEndpoint) {
		t.Errorf("a fragment is never sent to a server, so it must be refused: %v", err)
	}
}

// An unset override keeps the default rather than emptying the endpoint. A field
// that could be blanked would be a way to configure a provider this service cannot
// complete a sign-in with, which is not a supported state — it is a broken one.
func TestAnUnsetOverrideKeepsTheDefaultRatherThanEmptyingIt(t *testing.T) {
	t.Parallel()

	s := configuredProviders()
	s.Google.Endpoints.AuthorizeURL = "https://idp.test/authorize"
	// TokenURL, UserInfoURL and EmailsURL are all left empty.

	var google Provider
	for _, p := range s.Providers() {
		if p.Name == ProviderGoogle {
			google = p
		}
	}

	if google.AuthorizeURL != "https://idp.test/authorize" {
		t.Errorf("AuthorizeURL = %q, want the override", google.AuthorizeURL)
	}
	if google.TokenURL != GoogleTokenURL {
		t.Errorf("TokenURL = %q, want the default %q", google.TokenURL, GoogleTokenURL)
	}
	if google.UserInfoURL != GoogleUserInfoURL {
		t.Errorf("UserInfoURL = %q, want the default %q", google.UserInfoURL, GoogleUserInfoURL)
	}
	if google.EmailsURL != "" {
		t.Errorf("EmailsURL = %q, want it still empty for a provider that has none", google.EmailsURL)
	}
}

// Every endpoint a deployment can configure is listed in exactly one place — the
// list `applyTo` and `validate` both walk — so a field added to ProviderEndpoints
// and forgotten there would be a setting no variable could set and no test would
// catch. Both directions are checked because either one alone is satisfiable by an
// empty list.
func TestEveryEndpointFieldIsInTheOneList(t *testing.T) {
	t.Parallel()

	inList := make(map[string]bool)
	for _, o := range (ProviderEndpoints{}).overrides() {
		inList[o.field] = true
	}

	inStruct := make(map[string]bool)
	reflected := reflect.TypeOf(ProviderEndpoints{})
	for i := 0; i < reflected.NumField(); i++ {
		inStruct[reflected.Field(i).Name] = true
	}

	for field := range inStruct {
		if !inList[field] {
			t.Errorf("ProviderEndpoints has field %q and the override list does not, so no variable can set it", field)
		}
	}
	for field := range inList {
		if !inStruct[field] {
			t.Errorf("the override list names %q and ProviderEndpoints has no such field", field)
		}
	}
	if len(inList) == 0 {
		t.Fatal("the override list is empty, so every comparison above agreed with nothing")
	}
}

// Every provider this service offers is in the settings table and vice versa. Both
// directions, because a table that is missing one produces a provider with no
// settings — and the missing one is silent, because the provider still builds and
// still signs in.
func TestEveryProviderThisServiceOffersIsInTheTable(t *testing.T) {
	t.Parallel()

	fromSettings := map[string]bool{}
	for _, np := range (Settings{}).providers() {
		fromSettings[np.name] = true
	}

	if len(knownProviders) == 0 {
		t.Fatal("knownProviders is empty, so every comparison above agreed with nothing")
	}
	for _, name := range knownProviders {
		if !fromSettings[name] {
			t.Errorf("knownProviders offers %q and the settings table has no entry for it", name)
		}
	}
	for name := range fromSettings {
		offered := false
		for _, known := range knownProviders {
			if known == name {
				offered = true
			}
		}
		if !offered {
			t.Errorf("the settings table has %q, which knownProviders does not offer", name)
		}
	}
}

// An override changes where this service dials and NOTHING else. The name, the
// scopes and the extra authorize options are not configuration, so a deployment
// that set an endpoint must not be able to change what it asks for.
func TestAnOverrideChangesNoOtherPartOfAProvider(t *testing.T) {
	t.Parallel()

	shipped := Google()
	s := Settings{
		RedirectBaseURL: "https://identity.anywaye.com",
		EncryptionKey:   testKeyBase64(5),
		Google: ProviderSettings{
			ClientID:     "google-id",
			ClientSecret: "google-secret",
			Endpoints: ProviderEndpoints{
				AuthorizeURL: "https://idp.test/authorize",
				TokenURL:     "https://idp.test/token",
				UserInfoURL:  "https://idp.test/userinfo",
			},
		},
	}

	overridden := s.Providers()[0]

	shipped.ClientID = overridden.ClientID
	shipped.ClientSecret = overridden.ClientSecret
	shipped.AuthorizeURL = overridden.AuthorizeURL
	shipped.TokenURL = overridden.TokenURL
	shipped.UserInfoURL = overridden.UserInfoURL

	if !reflect.DeepEqual(shipped, overridden) {
		t.Errorf("an override changed more than the endpoints:\n got %+v\nwant %+v", overridden, shipped)
	}
}

// fakeProvider is a stand-in for Google or GitHub: it answers /token,
// /userinfo, /user and /emails with the shapes the real providers return, and
// records the paths it was asked for.
//
// It exists here rather than through internal/platform/oauthtest because that
// package imports this one, and an in-package test file importing it back is an
// import cycle.
type fakeProvider struct {
	*httptest.Server
	t    *testing.T
	mu   sync.Mutex
	hits []string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()

	f := &fakeProvider{t: t}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeProvider) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits = append(f.hits, r.URL.Path)
	f.mu.Unlock()

	// The token endpoint takes a form post and answers form-encoded, which is what
	// x/oauth2 expects to decode; answering JSON here would fail the exchange for a
	// reason that has nothing to do with the endpoint under test.
	switch {
	case strings.HasSuffix(r.URL.Path, "/token"):
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte("access_token=fake-access-token&token_type=bearer&refresh_token=fake-refresh&expires_in=3600"))
	case strings.HasSuffix(r.URL.Path, "/userinfo"):
		writeFakeJSON(f.t, w, map[string]any{
			"sub":            "google-sub",
			"email":          "kaka@example.com",
			"email_verified": true,
			"name":           "Kaka",
		})
	case strings.HasSuffix(r.URL.Path, "/user"):
		// A null email is GitHub's normal case for a private address, which is what
		// makes the emails call happen.
		writeFakeJSON(f.t, w, map[string]any{
			"id":    4242,
			"email": nil,
			"login": "kaka",
			"name":  "Kaka",
		})
	case strings.HasSuffix(r.URL.Path, "/emails"):
		writeFakeJSON(f.t, w, []map[string]any{
			{"email": "kaka@example.com", "primary": true, "verified": true},
		})
	default:
		http.NotFound(w, r)
	}
}

// Hits returns the paths the fake was asked for, in order.
func (f *fakeProvider) Hits() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.hits...)
}

func writeFakeJSON(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encoding the fake provider's answer: %v", err)
	}
}

func equalPaths(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
