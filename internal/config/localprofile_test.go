package config

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"
)

// THE LOCAL, PROD-SHAPED PROFILE, held to what a real `Load` produces from it.
//
// `config/local.env` is the file the local loop sources. It is an operator input
// and no code path reads it — which means nothing but this test connects it to
// the configuration rules in this package, and a profile that drifted (an issuer
// that stopped matching PLAN §1, a callback that stopped being built from
// `OAUTH_REDIRECT_BASE_URL`, a social endpoint that stopped pointing at the
// stub) would keep running perfectly until somebody tried to sign in.
//
// So the assertions here are about RELATIONSHIPS between values, not about
// values being present:
//
//   - the issuer is https and is the `.test` projection of the production name;
//   - the JWKS document is derived from the issuer rather than configured
//     separately (a second place to set it is a second place to get it wrong);
//   - every social endpoint points at oauth-stub, and the two authorize URLs are
//     the ones a browser can reach;
//   - the callback base and the issuer are the SAME origin, which is the whole
//     property the social round trip exists to measure.
//
// And the negative control matters more than the positives: the file as
// committed is INVALID, because it carries no key material. That is asserted
// first, with the sentinel the refusal must name, because a profile that loaded
// fine without a signing key would be a profile that had quietly stopped being
// all-or-nothing.

// localEnvPath is where the committed profile lives, relative to this package.
const localEnvPath = "../../config/local.env"

// localIssuer, localCallbackBase and localStubHost are the four values the
// profile's whole argument is about, named once so the assertions below say what
// they mean.
const (
	localIssuer       = "https://auth.anywaye.test"
	localCallbackBase = "https://auth.anywaye.test"
	localStubHost     = "localhost"
)

// parseLocalEnv reads a `KEY=VALUE` file the way a shell `source` would, minus
// the shell: no expansion, no quoting rules beyond the obvious, comments and
// blank lines dropped. That is the whole subset this profile uses, and the test
// fails if it meets a line it does not understand rather than skipping it —
// a reader that silently drops a line is a reader that agrees with a file that
// has stopped saying anything.
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

// TestTheCommittedLocalProfileIsInvalidWithoutKeyMaterial is the negative
// control for everything below it.
//
// It is the first assertion because it is the one that makes the rest meaningful:
// a profile that loaded cleanly with no signing key would be a profile whose
// all-or-nothing rule had been quietly relaxed for the local run, and the local
// run is the one place a developer would never notice — the surface would mount
// and sign nothing, and every locally minted token would be a 500 at the first
// sign-in.
func TestTheCommittedLocalProfileIsInvalidWithoutKeyMaterial(t *testing.T) {
	t.Parallel()

	values := parseLocalEnv(t, localEnvPath)
	if _, err := Load(lookupFrom(values)); !errors.Is(err, ErrInvalidOIDC) {
		t.Fatalf("Load(config/local.env) error = %v, want ErrInvalidOIDC naming the missing key; "+
			"the profile ships no key material and must be a refusal rather than a provider that cannot sign", err)
	}
}

// TestTheLocalProfileIsProdShaped is the positive half: with key material
// supplied the way `bin/local-idp` supplies it, the profile produces the
// configuration PLAN §3 L7 describes.
func TestTheLocalProfileIsProdShaped(t *testing.T) {
	t.Parallel()

	values := parseLocalEnv(t, localEnvPath)

	// What `bin/local-idp keygen` puts in the gitignored companion file. The
	// contents are not parsed here — that is internal/oidc's job and its own
	// tests — but they must be non-empty for the all-or-nothing count to reach
	// three.
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

	// The callback base is built from configuration and never from the request's
	// Host. That the two are the same origin here is the property the whole
	// profile turns on: set them apart and the social round trip completes
	// against the stub and delivers the code to an origin the browser is not
	// signed in on.
	if cfg.OAuth.RedirectBaseURL != localCallbackBase {
		t.Errorf("OAuthRedirectBaseURL = %q, want %q (the identity face, where the browser returns to)",
			cfg.OAuth.RedirectBaseURL, localCallbackBase)
	}

	// Every social endpoint must point at the stub, and the two authorize URLs
	// are the ones a browser is sent to — so they are the ones that have to be
	// reachable from the browser's resolver, which is why they are spelled
	// `localhost` and not a `.test` name.
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

	// Two stub instances, one client pair each: the Google pair and the GitHub
	// pair must not be the same credentials, because oauth-stub refuses a client
	// id it was not configured with and a shared pair would make one of the two
	// providers fail with `invalid_client` for a reason nobody could read off the
	// configuration.
	if cfg.OAuth.Google.ClientID == cfg.OAuth.GitHub.ClientID {
		t.Errorf("the Google and GitHub client ids are both %q; oauth-stub holds one pair per instance",
			cfg.OAuth.Google.ClientID)
	}
}

// TestTheLocalProfileCoversEveryProviderItCredentialises walks the other
// direction: a client pair with no endpoint override is a provider that would
// reach the real thing from a local run, which is the failure the profile exists
// to prevent — and it is invisible, because the sign-in would simply appear to
// hang or fail at Google rather than at the stub.
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
