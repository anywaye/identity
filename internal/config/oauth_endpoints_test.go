package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/oauth"
)

// This file holds the two halves of the endpoint-override wiring that
// internal/oauth cannot see: the read (which variable sets which field) and the
// naming (which variable an operator is told about when one is refused).
//
// internal/oauth refuses an endpoint by provider and struct field, because the
// variable names live here. That split is the reason these tests exist — a boot log
// that says "TokenURL" instead of OAUTH_GOOGLE_TOKEN_URL sends a deployer looking
// through thirteen variables, and nothing in the oauth package's tests would notice.

// oauthTestKey is a valid token encryption key: standard base64 of 32 bytes.
func oauthTestKey() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
}

// oauthTestEnv is a deployment with every provider configured and nothing else
// overridden. Every endpoint test starts from it, because an endpoint override in a
// deployment with no credentials is a deployment that does not mount the routes at
// all.
func oauthTestEnv() map[string]string {
	return map[string]string{
		OAuthRedirectBaseURLVar:       "https://identity.cafaye.com",
		OAuthEncryptionKeyVar:         oauthTestKey(),
		OAuthGoogleClientIDVar:        "google-id",
		OAuthGoogleClientSecretVar:    "google-secret",
		OAuthGitHubClientIDVar:        "github-id",
		OAuthGitHubClientSecretVar:    "github-secret",
		OAuthMicrosoftClientIDVar:     "microsoft-id",
		OAuthMicrosoftClientSecretVar: "microsoft-secret",
	}
}

// oauthTestEndpointNames is every endpoint field on a provider, in the order they
// appear in the struct. It is here rather than derived so that a row in the table
// naming a field this list does not have is visible as a failure, and it is compared
// against the struct by reflection in the test below.
var oauthTestEndpointNames = []string{"AuthorizeURL", "TokenURL", "UserInfoURL", "EmailsURL"}

// endpointValue reads one endpoint off a provider by field name.
//
// It reflects because the point of the comparisons that use it is that they walk the
// struct rather than spell out four assignments per provider: an expectation written
// out a second time would agree with the second copy.
func endpointValue(p oauth.Provider, field string) string {
	value := reflect.ValueOf(p).FieldByName(field)
	if !value.IsValid() || value.Kind() != reflect.String {
		return ""
	}
	return value.String()
}

// providerEndpoints reads the endpoints off a provider definition by field name.
func providerEndpoints(name string) map[string]string {
	var definition oauth.Provider
	switch name {
	case oauth.ProviderGoogle:
		definition = oauth.Google()
	case oauth.ProviderGitHub:
		definition = oauth.GitHub()
	case oauth.ProviderMicrosoft:
		definition = oauth.Microsoft()
	case oauth.ProviderApple:
		definition = oauth.Apple()
	default:
		return nil
	}

	out := make(map[string]string, len(oauthTestEndpointNames))
	for _, field := range oauthTestEndpointNames {
		out[field] = endpointValue(definition, field)
	}
	return out
}

// Every endpoint a provider HAS has a variable that sets it, and every variable in
// the table sets an endpoint a provider has. Both directions, because either alone
// is satisfiable by a table with nothing in it: a provider whose token URL cannot be
// pointed anywhere is a deployment stuck with the real one, and a variable that sets
// no field is one that reads as if it configures something.
//
// The shape of the table is therefore decided by internal/oauth — three endpoints
// for Google, four for GitHub, two for Apple — and not by this file, which is the
// point of the directions: GitHub has an emails endpoint and Google does not, so
// OAUTH_GITHUB_EMAILS_URL exists and OAUTH_GOOGLE_EMAILS_URL is not a variable
// anybody is missing. Apple has no userinfo endpoint (its identity comes from a
// verified id_token) and its JWKS document is deliberately NOT overridable — a
// deployment that could point it at a key document of its own could forge
// identities — so OAUTH_APPLE_AUTHORIZE_URL and OAUTH_APPLE_TOKEN_URL exist and
// there is no OAUTH_APPLE_JWKS_URL.
func TestEveryOAuthEndpointHasAVariableAndEveryVariableHasAnEndpoint(t *testing.T) {
	t.Parallel()

	fromDefinitions := map[string]bool{}
	for _, provider := range []string{oauth.ProviderGoogle, oauth.ProviderGitHub, oauth.ProviderMicrosoft, oauth.ProviderApple} {
		for field, endpoint := range providerEndpoints(provider) {
			if endpoint == "" {
				continue
			}
			fromDefinitions[provider+"."+field] = true
		}
	}

	fromTable := map[string]bool{}
	variablesSeen := map[string]bool{}
	for _, v := range oauthEndpointVars {
		key := v.provider + "." + v.field
		if fromTable[key] {
			t.Errorf("%s appears twice in the endpoint table, so one variable is unreachable", key)
		}
		fromTable[key] = true

		if variablesSeen[v.variable] {
			t.Errorf("%s is listed twice in the endpoint table", v.variable)
		}
		variablesSeen[v.variable] = true

		if !strings.HasPrefix(v.variable, "OAUTH_") {
			t.Errorf("%s is not an OAUTH_ variable", v.variable)
		}
	}

	// The field names a row may name are the ones the struct has. A row pointing at
	// a field that does not exist compiles fine — it is a string in a table — and
	// would set nothing while reading as if it set something.
	fields := map[string]bool{}
	reflected := reflect.TypeOf(oauth.ProviderEndpoints{})
	for i := 0; i < reflected.NumField(); i++ {
		fields[reflected.Field(i).Name] = true
	}
	if len(fields) != len(oauthTestEndpointNames) {
		t.Errorf("oauth.ProviderEndpoints has %d fields and this test knows %d of them: %v",
			len(fields), len(oauthTestEndpointNames), fields)
	}

	for key := range fromDefinitions {
		if !fromTable[key] {
			t.Errorf("%s is an endpoint this service dials and no variable sets it", key)
		}
	}
	for _, v := range oauthEndpointVars {
		if !fromDefinitions[v.provider+"."+v.field] {
			t.Errorf("%s sets %s.%s, which is not an endpoint that provider has", v.variable, v.provider, v.field)
		}
		if !fields[v.field] {
			t.Errorf("%s names field %q and oauth.ProviderEndpoints has no such field", v.variable, v.field)
		}
	}
	if len(fromDefinitions) == 0 || len(fromTable) == 0 {
		t.Fatal("one side of the comparison is empty, so it agreed with nothing")
	}
}

// The whole point of the variables: a deployment can point this service's provider
// calls at a server it controls. The assertion is on what this process would DIAL
// and where it would SEND A BROWSER, not on the settings struct having a field set.
func TestTheEndpointOverridesReachTheBuiltAuthorizeURLAndTheTokenURL(t *testing.T) {
	t.Parallel()

	env := oauthTestEnv()
	env[OAuthGoogleAuthorizeURLVar] = "https://idp.test/fake/google/authorize"
	env[OAuthGoogleTokenURLVar] = "https://idp.test/fake/google/token"
	env[OAuthGoogleUserInfoURLVar] = "https://idp.test/fake/google/userinfo"
	env[OAuthGitHubAuthorizeURLVar] = "https://idp.test/fake/github/authorize"
	env[OAuthGitHubTokenURLVar] = "https://idp.test/fake/github/token"
	env[OAuthGitHubUserInfoURLVar] = "https://idp.test/fake/github/user"
	env[OAuthGitHubEmailsURLVar] = "https://idp.test/fake/github/emails?per_page=100"
	env[OAuthMicrosoftAuthorizeURLVar] = "https://idp.test/fake/microsoft/authorize"
	env[OAuthMicrosoftTokenURLVar] = "https://idp.test/fake/microsoft/token"
	env[OAuthMicrosoftUserInfoURLVar] = "https://idp.test/fake/microsoft/userinfo"

	cfg, err := Load(lookupFrom(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := map[string]struct{ authorize, token, userInfo, emails string }{
		oauth.ProviderGoogle: {
			authorize: "https://idp.test/fake/google/authorize",
			token:     "https://idp.test/fake/google/token",
			userInfo:  "https://idp.test/fake/google/userinfo",
		},
		oauth.ProviderGitHub: {
			authorize: "https://idp.test/fake/github/authorize",
			token:     "https://idp.test/fake/github/token",
			userInfo:  "https://idp.test/fake/github/user",
			emails:    "https://idp.test/fake/github/emails?per_page=100",
		},
		oauth.ProviderMicrosoft: {
			authorize: "https://idp.test/fake/microsoft/authorize",
			token:     "https://idp.test/fake/microsoft/token",
			userInfo:  "https://idp.test/fake/microsoft/userinfo",
		},
	}

	providers := cfg.OAuth.Providers()
	if len(providers) != 3 {
		t.Fatalf("Providers() returned %d, want 3", len(providers))
	}

	for _, p := range providers {
		w, ok := want[p.Name]
		if !ok {
			t.Fatalf("unexpected provider %q", p.Name)
		}
		if p.AuthorizeURL != w.authorize || p.TokenURL != w.token || p.UserInfoURL != w.userInfo || p.EmailsURL != w.emails {
			t.Errorf("%s = %+v, want authorize %q, token %q, userinfo %q, emails %q",
				p.Name, p, w.authorize, w.token, w.userInfo, w.emails)
		}

		// The browser goes to the override, and the redirect_uri it carries is still
		// the configured one rather than anything the deployment's endpoints suggest.
		authorizeURL, err := url.Parse(p.AuthCodeURL("state-123", cfg.OAuth.RedirectBaseURL+"/v1/auth/oauth/"+p.Name+"/callback"))
		if err != nil {
			t.Fatalf("%s: parsing the authorize url: %v", p.Name, err)
		}
		if authorizeURL.Host != "idp.test" {
			t.Errorf("%s sends the browser to %s, want host idp.test", p.Name, authorizeURL)
		}
		if got := authorizeURL.Query().Get("redirect_uri"); got != cfg.OAuth.RedirectBaseURL+"/v1/auth/oauth/"+p.Name+"/callback" {
			t.Errorf("%s redirect_uri = %q, want the configured base", p.Name, got)
		}
	}
}

// With nothing set, this service dials the endpoints its definitions carry. The
// comparison is against the definitions rather than against literals because that is
// the concern at this layer: the READ must not blank a field, reorder a provider or
// substitute anything. That the definitions are Google's and GitHub's real endpoints
// is internal/oauth's regression guard, which spells them out.
func TestWithNothingSetTheEndpointsAreTheDefinitions(t *testing.T) {
	t.Parallel()

	cfg, err := Load(lookupFrom(oauthTestEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	providers := cfg.OAuth.Providers()
	if len(providers) != 3 {
		t.Fatalf("Providers() returned %d, want 3", len(providers))
	}

	byName := map[string]oauth.Provider{}
	for _, p := range providers {
		byName[p.Name] = p
	}
	for name, definition := range map[string]oauth.Provider{
		oauth.ProviderGoogle:    oauth.Google(),
		oauth.ProviderGitHub:    oauth.GitHub(),
		oauth.ProviderMicrosoft: oauth.Microsoft(),
	} {
		got, ok := byName[name]
		if !ok {
			t.Fatalf("%s is missing from the providers this deployment would serve", name)
		}
		for _, endpoint := range oauthTestEndpointNames {
			if endpointValue(got, endpoint) == "" {
				continue
			}
			if endpointValue(got, endpoint) != endpointValue(definition, endpoint) {
				t.Errorf("%s %s = %q, want the definition's %q",
					name, endpoint, endpointValue(got, endpoint), endpointValue(definition, endpoint))
			}
		}
	}
}

// A present-but-wrong value fails startup, and the message names the VARIABLE. That
// is the difference between a boot log that sends a deployer to one line of a config
// file and one that says "TokenURL", which is not in any config file at all.
func TestAMalformedEndpointOverrideFailsStartupNamingTheVariable(t *testing.T) {
	t.Parallel()

	variables := []string{
		OAuthGoogleAuthorizeURLVar,
		OAuthGoogleTokenURLVar,
		OAuthGoogleUserInfoURLVar,
		OAuthGitHubAuthorizeURLVar,
		OAuthGitHubTokenURLVar,
		OAuthGitHubUserInfoURLVar,
		OAuthGitHubEmailsURLVar,
		OAuthMicrosoftAuthorizeURLVar,
		OAuthMicrosoftTokenURLVar,
		OAuthMicrosoftUserInfoURLVar,
	}

	for _, variable := range variables {
		t.Run(variable, func(t *testing.T) {
			t.Parallel()

			for _, value := range []string{"idp.test/no-scheme", "gopher://idp.test/token", "https://", "https://idp.test/token#frag"} {
				env := oauthTestEnv()
				env[variable] = value

				_, err := Load(lookupFrom(env))
				if !errors.Is(err, ErrInvalidOAuth) {
					t.Fatalf("%s=%q: Load = %v, want ErrInvalidOAuth", variable, value, err)
				}
				if !errors.Is(err, oauth.ErrInvalidEndpoint) {
					t.Errorf("%s=%q: Load = %v, want it to wrap oauth.ErrInvalidEndpoint", variable, value, err)
				}
				if !strings.Contains(err.Error(), variable) {
					t.Errorf("%s=%q: Load = %q, want it to name the variable", variable, value, err)
				}
			}
		})
	}
}

// One override is enough to make the deployment's endpoints inconsistent — a code
// exchanged at the fake IdP's authorize URL and presented to Google's token URL —
// so the variable being set alone, with no credentials, still has to be loud.
func TestAnEndpointOverrideIsCheckedEvenWithNoProviderConfigured(t *testing.T) {
	t.Parallel()

	env := map[string]string{OAuthGoogleTokenURLVar: "not a url"}
	_, err := Load(lookupFrom(env))
	if !errors.Is(err, oauth.ErrInvalidEndpoint) {
		t.Fatalf("Load = %v, want it to wrap oauth.ErrInvalidEndpoint", err)
	}
	if !strings.Contains(err.Error(), OAuthGoogleTokenURLVar) {
		t.Errorf("Load = %q, want it to name %s", err, OAuthGoogleTokenURLVar)
	}
}

// A variable that is PRESENT AND WRONG is a startup failure; a variable that is
// absent is a deployment that said nothing, which is the shipped state. Both halves,
// because a rule that treated every value as fatal would stop this service booting
// anywhere without thirteen new variables set.
func TestAnAbsentEndpointOverrideKeepsTheDefaultsAndBoots(t *testing.T) {
	t.Parallel()

	env := oauthTestEnv()
	// Present-but-empty is how compose passes an unset variable through, and
	// lookupValue trims it, so it must read as absent rather than as a broken URL.
	env[OAuthGoogleTokenURLVar] = "   "

	cfg, err := Load(lookupFrom(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.OAuth.Google.Endpoints.TokenURL; got != "" {
		t.Errorf("Google token url override = %q, want empty so the default applies", got)
	}
	if got := cfg.OAuth.Providers()[0].TokenURL; got != oauth.GoogleTokenURL {
		t.Errorf("Google TokenURL = %q, want the default %q", got, oauth.GoogleTokenURL)
	}
}
