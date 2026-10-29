package oidc

import (
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)


func TestNewClientCredentialsAreRandomAndUnguessable(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 32)
	for i := 0; i < 32; i++ {
		clientID, secret, err := NewClientCredentials()
		if err != nil {
			t.Fatalf("NewClientCredentials: %v", err)
		}
		if seen[clientID] {
			t.Fatalf("client id %q came up twice in 32 draws", clientID)
		}
		seen[clientID] = true

		if clientID != base64.RawURLEncoding.EncodeToString(mustDecode(t, clientID)) {
			t.Errorf("client id %q is not base64url", clientID)
		}
		if len(mustDecode(t, clientID)) != clientIDBytes {
			t.Errorf("client id carries %d bytes, want %d", len(mustDecode(t, clientID)), clientIDBytes)
		}
		if secret == clientID {
			t.Error("the client secret equals the client id; one leaked value would then be both")
		}
	}
}

func TestSecretDigestIsNotTheSecret(t *testing.T) {
	t.Parallel()

	_, secret, err := NewClientCredentials()
	if err != nil {
		t.Fatalf("NewClientCredentials: %v", err)
	}

	digest := SecretDigest(secret)
	if digest == secret {
		t.Fatal("SecretDigest returned the secret itself")
	}
	if len(digest) != 64 {
		t.Errorf("the digest is %d characters, want 64 (lower-case hex SHA-256)", len(digest))
	}
	if strings.ToLower(digest) != digest {
		t.Errorf("the digest %q is not lower case; the column is compared with equality", digest)
	}
	if SecretDigest(secret) != digest {
		t.Error("SecretDigest is not stable for one secret")
	}
	if SecretDigest(secret+"x") == digest {
		t.Error("two different secrets produced one digest")
	}
}

func TestValidateRedirectURIs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give []string
		want []string
		wantCode string
	}{
		{
			name: "one https origin",
			give: []string{"https://app.example.com/cb"},
			want: []string{"https://app.example.com/cb"},
		},
		{
			name: "several, deduplicated and sorted",
			give: []string{"https://b.example.com/cb", "https://a.example.com/cb", "https://b.example.com/cb"},
			want: []string{"https://a.example.com/cb", "https://b.example.com/cb"},
		},
		{
			name: "loopback http is allowed",
			give: []string{"http://localhost:3000/cb", "http://127.0.0.1:8080/cb"},
			want: []string{"http://127.0.0.1:8080/cb", "http://localhost:3000/cb"},
		},
		{name: "none at all", give: nil, wantCode: CodeRequired},
		{name: "plain http is not", give: []string{"http://app.example.com/cb"}, wantCode: CodeInvalidFormat},
		{name: "a bare host is not a redirect target", give: []string{"app.example.com/cb"}, wantCode: CodeInvalidFormat},
		{name: "a custom scheme is not", give: []string{"myapp://cb"}, wantCode: CodeInvalidFormat},
		{
			name: "a fragment is not", give: []string{"https://app.example.com/cb#done"}, wantCode: CodeInvalidFormat,
		},
		{
			name: "a wildcard is not", give: []string{"https://*.example.com/cb"}, wantCode: CodeInvalidFormat,
		},
		{name: "empty", give: []string{""}, wantCode: CodeInvalidFormat},
		{name: "more than the maximum", give: manyRedirectURIs(MaxRedirectURIs + 1), wantCode: CodeTooMany},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ValidateRedirectURIs(tt.give)
			if tt.wantCode != "" {
				assertFieldError(t, err, "redirect_uris", tt.wantCode)
				return
			}
			if err != nil {
				t.Fatalf("ValidateRedirectURIs(%v) = %v, want it accepted", tt.give, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("ValidateRedirectURIs(%v) = %v, want %v", tt.give, got, tt.want)
			}
		})
	}
}

func TestValidateGrantTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		give     []string
		want     []string
		wantCode string
	}{
		{name: "authorization_code alone", give: []string{GrantAuthorizationCode}, want: []string{GrantAuthorizationCode}},
		{name: "deduplicated", give: []string{GrantAuthorizationCode, GrantAuthorizationCode}, want: []string{GrantAuthorizationCode}},
		{name: "a refresh token grant", give: []string{GrantAuthorizationCode, GrantRefreshToken}, want: []string{GrantAuthorizationCode, GrantRefreshToken}},
		{name: "client credentials", give: []string{GrantClientCredentials}, wantCode: CodeUnsupported},
		{name: "nothing at all", give: nil, wantCode: CodeRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ValidateGrantTypes(tt.give)
			if tt.wantCode != "" {
				assertFieldError(t, err, "grant_types", tt.wantCode)
				return
			}
			if err != nil {
				t.Fatalf("ValidateGrantTypes(%v) = %v, want it accepted", tt.give, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("ValidateGrantTypes(%v) = %v, want %v", tt.give, got, tt.want)
			}
		})
	}
}

func TestValidateRegistrationScopesRequiresOpenID(t *testing.T) {
	t.Parallel()

	_, err := ValidateRegistrationScopes([]string{"email"})
	assertFieldError(t, err, "scopes", CodeOpenIDRequired)

	got, err := ValidateRegistrationScopes([]string{"accounts", "openid", "phone"})
	if err != nil {
		t.Fatalf("ValidateRegistrationScopes = %v, want the supported two accepted", err)
	}
	if !slices.Equal(got, []string{"accounts", "openid"}) {
		t.Errorf("scopes = %v, want the supported two, sorted", got)
	}
}

func TestRevokedClientIsNotActive(t *testing.T) {
	t.Parallel()

	live := Client{}
	if !live.IsActive() {
		t.Error("a client with no revoked_at is not active; that is backwards")
	}

	at := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	revoked := Client{RevokedAt: &at}
	if revoked.IsActive() {
		t.Error("a revoked client reports itself active")
	}
}

func manyRedirectURIs(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, "https://app"+string(rune('a'+i%26))+itoa(i)+".example.com/cb")
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding %q: %v", s, err)
	}
	return raw
}

func assertFieldError(t *testing.T, err error, field, code string) {
	t.Helper()

	if err == nil {
		t.Fatalf("got a nil error, want a field error on %q with code %q", field, code)
	}
	var fieldErr *FieldError
	if !errors.As(err, &fieldErr) {
		t.Fatalf("error %v is not a *FieldError", err)
	}
	if fieldErr.Field != field || fieldErr.Code != code {
		t.Errorf("field error = %q/%q, want %q/%q", fieldErr.Field, fieldErr.Code, field, code)
	}
}
