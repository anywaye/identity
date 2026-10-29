package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/oauth"
)


func oauthTestKey() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
}

func oauthTestEnv() map[string]string {
	return map[string]string{
		OAuthRedirectBaseURLVar:       "https://identity.anywaye.com",
		OAuthEncryptionKeyVar:         oauthTestKey(),
		OAuthGoogleClientIDVar:        "google-id",
		OAuthGoogleClientSecretVar:    "google-secret",
		OAuthGitHubClientIDVar:        "github-id",
		OAuthGitHubClientSecretVar:    "github-secret",
		OAuthMicrosoftClientIDVar:     "microsoft-id",
		OAuthMicrosoftClientSecretVar: "microsoft-secret",
		"SIGNUP_SIGNING_KEY":          base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
	}
}

var oauthTestEndpointNames = []string{"AuthorizeURL", "TokenURL", "UserInfoURL", "EmailsURL"}

func endpointValue(p oauth.Provider, field string) string {
	value := reflect.ValueOf(p).FieldByName(field)
	if !value.IsValid() || value.Kind() != reflect.String {
		return ""
	}
	return value.String()
}

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

func TestAnAbsentEndpointOverrideKeepsTheDefaultsAndBoots(t *testing.T) {
	t.Parallel()

	env := oauthTestEnv()
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
