package config

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"
)


const localEnvPath = "../../config/local.env"

const (
	localIssuer       = "https://auth.anywaye.test"
	localCallbackBase = "https://auth.anywaye.test"
	localStubHost     = "localhost"
)

func parseLocalEnv(t *testing.T, path string) map[string]string {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("the local profile is not where this test expects it (%s): %v", path, err)
	}
	defer file.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			t.Fatalf("%s:%d is not KEY=VALUE and the profile would be read as nothing: %q", path, line, text)
		}
		key = strings.TrimSpace(key)
		if _, seen := values[key]; seen {
			t.Fatalf("%s sets %s twice; the last one would win in a shell and in a shell only", path, key)
		}
		values[key] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if len(values) == 0 {
		t.Fatalf("%s parsed to nothing; a profile no test can read is a profile nothing checks", path)
	}
	return values
}

func TestTheCommittedLocalProfileIsInvalidWithoutKeyMaterial(t *testing.T) {
	t.Parallel()

	values := parseLocalEnv(t, localEnvPath)
	if _, err := Load(lookupFrom(values)); !errors.Is(err, ErrInvalidOIDC) {
		t.Fatalf("Load(config/local.env) error = %v, want ErrInvalidOIDC naming the missing key; "+
			"the profile ships no key material and must be a refusal rather than a provider that cannot sign", err)
	}
}

func TestTheLocalProfileIsProdShaped(t *testing.T) {
	t.Parallel()

	values := parseLocalEnv(t, localEnvPath)

	values["SIGNUP_SIGNING_KEY"] = signupTestKey
	values["OAUTH_ENCRYPTION_KEY"] = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	values["OIDC_SIGNING_KEY"] = "-----BEGIN PRIVATE KEY-----\nlocal\n-----END PRIVATE KEY-----\n"

	cfg, err := Load(lookupFrom(values))
	if err != nil {
		t.Fatalf("Load(config/local.env with generated key material) = %v, want a valid configuration", err)
	}

	if !cfg.OIDCEnabled() {
		t.Fatal("OIDCEnabled is false; the local profile exists to be an OpenID Connect provider")
	}
	if cfg.OIDCIssuer != localIssuer {
		t.Errorf("OIDCIssuer = %q, want %q — the issuer is baked into every token and is the one value "+
			"PLAN §1 says is never moved after first issuance, so a local run that minted anything else "+
			"would be practicing a shape no verifier accepts", cfg.OIDCIssuer, localIssuer)
	}
	if cfg.OIDCAllowInsecure {
		t.Error("OIDCAllowInsecure is true; the local issuer is https and must not need the escape hatch")
	}
	if cfg.OIDCLoginUIURL == "" {
		t.Error("OIDCLoginUIURL is empty; a provider with no login UI refuses to start (internal/oidc)")
	}

	if cfg.OAuth.RedirectBaseURL != localCallbackBase {
		t.Errorf("OAuthRedirectBaseURL = %q, want %q (the identity face, where the browser returns to)",
			cfg.OAuth.RedirectBaseURL, localCallbackBase)
	}

	for _, tc := range []struct{ name, got, want string }{
		{"google authorize", cfg.OAuth.Google.Endpoints.AuthorizeURL, "http://" + localStubHost + ":19081/google/authorize"},
		{"google token", cfg.OAuth.Google.Endpoints.TokenURL, "http://" + localStubHost + ":19081/google/token"},
		{"google userinfo", cfg.OAuth.Google.Endpoints.UserInfoURL, "http://" + localStubHost + ":19081/google/userinfo"},
		{"github authorize", cfg.OAuth.GitHub.Endpoints.AuthorizeURL, "http://" + localStubHost + ":19082/github/authorize"},
		{"github token", cfg.OAuth.GitHub.Endpoints.TokenURL, "http://" + localStubHost + ":19082/github/access_token"},
		{"github userinfo", cfg.OAuth.GitHub.Endpoints.UserInfoURL, "http://" + localStubHost + ":19082/github/user"},
		{"github emails", cfg.OAuth.GitHub.Endpoints.EmailsURL, "http://" + localStubHost + ":19082/github/user/emails"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q — a URL left on the real provider's default is a local run that "+
				"reaches Google, which is the one thing the stub exists to prevent", tc.name, tc.got, tc.want)
		}
	}

	if cfg.OAuth.Google.ClientID == cfg.OAuth.GitHub.ClientID {
		t.Errorf("the Google and GitHub client ids are both %q; oauth-stub holds one pair per instance",
			cfg.OAuth.Google.ClientID)
	}
}

func TestTheLocalProfileCoversEveryProviderItCredentialises(t *testing.T) {
	t.Parallel()

	values := parseLocalEnv(t, localEnvPath)

	for _, pair := range [][2]string{
		{"OAUTH_GOOGLE_CLIENT_ID", "OAUTH_GOOGLE_AUTHORIZE_URL"},
		{"OAUTH_GITHUB_CLIENT_ID", "OAUTH_GITHUB_AUTHORIZE_URL"},
	} {
		id, credentalled := values[pair[0]]
		_, pointed := values[pair[1]]
		if credentalled && !pointed {
			t.Errorf("%s is set but %s is not; this provider would be reached at its REAL endpoint "+
				"from a local run, which is the one outcome the local profile exists to prevent",
				pair[0], pair[1])
		}
		if pointed && !credentalled {
			t.Errorf("%s is set but %s is not; a stub with no client credentials refuses the exchange "+
				"with invalid_client", pair[1], pair[0])
		}
		_ = id
	}
}
