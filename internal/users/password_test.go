package users

import (
	"strings"
	"testing"

	"github.com/alexedwards/argon2id"
)

func fastHasher() *Hasher {
	return NewHasherWithParams(&argon2id.Params{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
}

func TestHashPasswordProducesAVerifiableArgon2idDigest(t *testing.T) {
	t.Parallel()

	h := fastHasher()

	digest, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if !strings.HasPrefix(digest, "$argon2id$") {
		t.Errorf("digest %q does not start with $argon2id$", digest)
	}
	if strings.Contains(digest, "correct horse") {
		t.Errorf("digest %q contains the plaintext password", digest)
	}
}

func TestVerifyPassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		password  string
		presented string
		want      bool
	}{
		{name: "the right password", password: "correct horse battery staple", presented: "correct horse battery staple", want: true},
		{name: "a wrong password", password: "correct horse battery staple", presented: "correct horse battery stapl", want: false},
		{name: "an empty password cannot match", password: "correct horse battery staple", presented: "", want: false},
		{name: "a unicode password round-trips", password: "pässwörd🔐", presented: "pässwörd🔐", want: true},
		{name: "the wrong unicode password is rejected", password: "pässwörd🔐", presented: "pässwörd🔒", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := fastHasher()
			digest, err := h.Hash(tt.password)
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}

			if got := h.Verify(digest, tt.presented); got != tt.want {
				t.Errorf("Verify(%q) = %v, want %v", tt.presented, got, tt.want)
			}
		})
	}
}

func TestHashPasswordSaltsEachDigest(t *testing.T) {
	t.Parallel()

	h := fastHasher()

	first, err := h.Hash("same password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	second, err := h.Hash("same password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if first == second {
		t.Error("two hashes of the same password are identical; the salt is not random")
	}
	if !h.Verify(first, "same password") || !h.Verify(second, "same password") {
		t.Error("a salted digest failed to verify against its own password")
	}
}

func TestVerifyPasswordRejectsMalformedDigests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		digest string
	}{
		{name: "empty", digest: ""},
		{name: "plaintext", digest: "correct horse battery staple"},
		{name: "truncated argon2id", digest: "$argon2id$v=19$m=65536"},
		{name: "wrong algorithm", digest: "$2a$10$abcdefghijklmnopqrstuv"},
		{name: "valid prefix, garbage body", digest: "$argon2id$v=19$m=65536,t=1,p=2$AAAA$!!!!not base64!!!!"},
		{name: "not base64 at all", digest: "not-a-digest"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if fastHasher().Verify(tt.digest, "anything") {
				t.Errorf("Verify(%q) returned true for a malformed digest", tt.digest)
			}
		})
	}
}

func TestVerifyDummyDoesTheWorkWithoutAccepting(t *testing.T) {
	t.Parallel()

	h := fastHasher()

	for _, presented := range []string{"", "password", "anything at all"} {
		h.VerifyDummy(presented)
	}

	if h.Verify(h.dummyDigest(), "anything at all") {
		t.Error("the dummy digest verified a presented password; it must never match")
	}
}

func TestDummyDigestIsWellFormed(t *testing.T) {
	t.Parallel()

	h := fastHasher()

	digest := h.dummyDigest()
	if !strings.HasPrefix(digest, "$argon2id$") {
		t.Fatalf("dummy digest %q is not an argon2id digest", digest)
	}
	if _, _, _, err := argon2id.DecodeHash(digest); err != nil {
		t.Errorf("dummy digest does not parse: %v", err)
	}
}

func TestDefaultParamsAreNotWeakerThanTheLibraryDefaults(t *testing.T) {
	t.Parallel()

	p := DefaultParams()

	if p.Memory < argon2id.DefaultParams.Memory {
		t.Errorf("Memory = %d KiB, want at least the library default %d KiB", p.Memory, argon2id.DefaultParams.Memory)
	}
	if p.Iterations < argon2id.DefaultParams.Iterations {
		t.Errorf("Iterations = %d, want at least the library default %d", p.Iterations, argon2id.DefaultParams.Iterations)
	}
	if p.SaltLength < argon2id.DefaultParams.SaltLength {
		t.Errorf("SaltLength = %d, want at least %d", p.SaltLength, argon2id.DefaultParams.SaltLength)
	}
	if p.KeyLength < argon2id.DefaultParams.KeyLength {
		t.Errorf("KeyLength = %d, want at least %d", p.KeyLength, argon2id.DefaultParams.KeyLength)
	}
	if p.Parallelism < 1 {
		t.Errorf("Parallelism = %d, want at least 1", p.Parallelism)
	}
}

func TestHashPasswordRejectsEmptyInput(t *testing.T) {
	t.Parallel()

	if _, err := NewHasher().Hash(""); err == nil {
		t.Error("Hash(\"\") returned no error, want a rejection")
	}
}
