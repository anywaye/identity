package sessions

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewTokenProducesAURLSafeHighEntropySecret(t *testing.T) {
	t.Parallel()

	token, _, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	for _, bad := range []string{"+", "/", "="} {
		if strings.Contains(token, bad) {
			t.Errorf("token %q contains %q; it must be base64url without padding", token, bad)
		}
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token %q is not base64url: %v", token, err)
	}
	if want := 32; len(decoded) != want {
		t.Errorf("token decodes to %d bytes, want %d (256 bits of entropy)", len(decoded), want)
	}
}

func TestNewTokenNeverStoresTheTokenItself(t *testing.T) {
	t.Parallel()

	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if digest == token {
		t.Fatal("the digest equals the token; the raw credential would be in the database")
	}
	if want := Digest(token); digest != want {
		t.Errorf("digest = %q, want Digest(token) = %q", digest, want)
	}
	if strings.Contains(digest, token) {
		t.Error("the digest contains the token")
	}
}

func TestNewTokenIsUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 1000)
	for range 1000 {
		token, _, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if _, dup := seen[token]; dup {
			t.Fatalf("NewToken repeated %s", token)
		}
		seen[token] = struct{}{}
	}
}

func TestDigestIsDeterministic(t *testing.T) {
	t.Parallel()

	token, first, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if second := Digest(token); second != first {
		t.Errorf("Digest is not deterministic: %q then %q", first, second)
	}
}

func TestDigestDistinguishesTokens(t *testing.T) {
	t.Parallel()

	first, _, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	second, _, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if Digest(first) == Digest(second) {
		t.Error("two different tokens produced the same digest")
	}
}

func TestDigestIsLowercaseHexOfSHA256(t *testing.T) {
	t.Parallel()

	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

	if got := Digest("hello"); got != want {
		t.Errorf("Digest(\"hello\") = %q, want %q", got, want)
	}
}

func TestDigestOfGarbageIsStillAWellFormedDigest(t *testing.T) {
	t.Parallel()

	tests := []string{"", "not a token", "!!!!", strings.Repeat("a", 10000)}

	for _, give := range tests {
		got := Digest(give)

		if len(got) != 64 {
			t.Errorf("Digest(%q) = %q, want 64 hex characters", truncate(give), got)
		}
		for _, c := range got {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Errorf("Digest(%q) = %q contains a non-hex character %q", truncate(give), got, c)
			}
		}
	}
}

func truncate(s string) string {
	if len(s) > 20 {
		return s[:20] + "…"
	}
	return s
}
