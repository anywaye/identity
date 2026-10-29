package oauth

import (
	"net/url"
	"strings"
	"testing"
)


func TestNewStateBindsTheProvider(t *testing.T) {
	t.Parallel()

	raw, err := NewState("github")
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}

	name, token, ok := strings.Cut(raw, ".")
	if !ok {
		t.Fatalf("NewState = %q, want it to carry a provider prefix", raw)
	}
	if name != "github" {
		t.Errorf("the state names %q, want the provider it was minted for", name)
	}
	if len(token) != 43 {
		t.Errorf("the state token is %d characters, want 43 (32 bytes of base64url)", len(token))
	}
	for _, r := range token {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			t.Errorf("the state token %q is not base64url", token)
			break
		}
	}
}

func TestNewStateIsNotRepeated(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 64)
	for range 64 {
		raw, err := NewState("google")
		if err != nil {
			t.Fatalf("NewState: %v", err)
		}
		if seen[raw] {
			t.Fatalf("NewState produced %q twice; the token is not random per call", raw)
		}
		seen[raw] = true
	}
}

func TestVerifyStateAcceptsOnlyTheExactPair(t *testing.T) {
	t.Parallel()

	sealed, err := NewState("google")
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}

	if !VerifyState("google", sealed, sealed) {
		t.Error("VerifyState rejected the pair it should accept")
	}

	other, err := NewState("google")
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}

	tests := []struct {
		name      string
		provider  string
		sealed    string
		presented string
	}{
		{name: "a different token from the same provider", provider: "google", sealed: sealed, presented: other},
		{name: "nothing presented", provider: "google", sealed: sealed, presented: ""},
		{name: "nothing in the cookie", provider: "google", sealed: "", presented: sealed},
		{name: "the token without its provider", provider: "google", sealed: sealed, presented: strings.TrimPrefix(sealed, "google.")},
		{name: "a truncated token", provider: "google", sealed: sealed, presented: sealed[:len(sealed)-1]},
		{name: "no separator at all", provider: "google", sealed: "no-separator-here", presented: "no-separator-here"},
		{name: "the provider prefix only", provider: "google", sealed: "google.", presented: "google."},
		{name: "an empty token on both sides", provider: "google", sealed: "google.", presented: "google."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if VerifyState(tt.provider, tt.sealed, tt.presented) {
				t.Errorf("VerifyState(%q, %q, %q) = true, want false", tt.provider, tt.sealed, tt.presented)
			}
		})
	}
}

func TestVerifyStateRejectsAStateMintedForAnotherProvider(t *testing.T) {
	t.Parallel()

	sealed, err := NewState("github")
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}

	if VerifyState("google", sealed, sealed) {
		t.Error("a github state verified at the google callback")
	}
}

func TestVerifyStateMatchesTheProviderExactly(t *testing.T) {
	t.Parallel()

	sealed, err := NewState("google")
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}

	for _, provider := range []string{"Google", "GOOGLE", "goo gle", "", "google "} {
		if VerifyState(provider, sealed, sealed) {
			t.Errorf("VerifyState accepted the provider %q", provider)
		}
	}
}

func TestVerifyStateSplitsOnTheFirstSeparatorOnly(t *testing.T) {
	t.Parallel()

	if VerifyState("google", "google.x.y", "google.x.y") {
		t.Error("a state with two separators verified")
	}
}

func TestNewStateTakesNoArgumentsBeyondTheProvider(t *testing.T) {
	t.Parallel()

	newState := NewState
	if _, err := newState("google"); err != nil {
		t.Fatalf("NewState: %v", err)
	}
}

func TestProviderAuthCodeURLCarriesTheRequiredParameters(t *testing.T) {
	t.Parallel()

	p := Google()
	p.ClientID = "client-id"
	redirect := "https://identity.anywaye.com/v1/auth/oauth/google/callback"

	parsed, err := url.Parse(p.AuthCodeURL("the-state", redirect))
	if err != nil {
		t.Fatalf("parsing the authorize URL: %v", err)
	}

	if parsed.Scheme != "https" || parsed.Host != "accounts.google.com" {
		t.Errorf("the authorize URL points at %s://%s, want Google's", parsed.Scheme, parsed.Host)
	}

	query := parsed.Query()
	for name, want := range map[string]string{
		"client_id":     "client-id",
		"redirect_uri":  redirect,
		"response_type": "code",
		"scope":         strings.Join(p.Scopes, " "),
		"state":         "the-state",
	} {
		if got := query.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestGoogleAsksForOfflineAccess(t *testing.T) {
	t.Parallel()

	query, err := url.Parse(Google().AuthCodeURL("s", "https://example.test/cb"))
	if err != nil {
		t.Fatalf("parsing the authorize URL: %v", err)
	}
	if got := query.Query().Get("access_type"); got != "offline" {
		t.Errorf("access_type = %q, want offline", got)
	}
}

func TestProviderScopesAreTheOnesTheIdentityEndpointsNeed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		provider Provider
		want     []string
	}{
		{provider: Google(), want: []string{"openid", "email", "profile"}},
		{provider: GitHub(), want: []string{"read:user", "user:email"}},
	}

	for _, tt := range tests {
		t.Run(tt.provider.Name, func(t *testing.T) {
			t.Parallel()

			if strings.Join(tt.provider.Scopes, " ") != strings.Join(tt.want, " ") {
				t.Errorf("scopes = %v, want %v", tt.provider.Scopes, tt.want)
			}
		})
	}
}
