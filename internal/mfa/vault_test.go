package mfa

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
)

var (
	six  = otp.DigitsSix
	sha1 = otp.AlgorithmSHA1
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestVaultRoundTripsASecret(t *testing.T) {
	vault, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	user := mustUUID(t, "6f1a3f2e-0000-4000-8000-000000000001")

	sealed, err := vault.Seal(user, rawKey)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(sealed, rawKey) {
		t.Fatal("the sealed value contains the secret in the clear")
	}
	if !strings.HasPrefix(sealed, SealPrefix) {
		t.Errorf("the sealed value has no version prefix: %q", sealed)
	}

	opened, err := vault.Open(user, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened != rawKey {
		t.Errorf("Open = %q, want %q", opened, rawKey)
	}
}

func TestTheSameSecretSealsDifferentlyEveryTime(t *testing.T) {
	vault, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	user := mustUUID(t, "6f1a3f2e-0000-4000-8000-000000000001")

	first, err := vault.Seal(user, rawKey)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := vault.Seal(user, rawKey)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if first == second {
		t.Error("two seals of the same secret produced identical ciphertext")
	}
}

func TestASealedSecretCannotBeMovedBetweenUsers(t *testing.T) {
	vault, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	attacker := mustUUID(t, "6f1a3f2e-0000-4000-8000-0000000000aa")
	victim := mustUUID(t, "6f1a3f2e-0000-4000-8000-0000000000bb")

	sealed, err := vault.Seal(attacker, rawKey)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := vault.Open(victim, sealed); !errors.Is(err, ErrMalformedSeal) {
		t.Errorf("Open for the wrong user = %v, want ErrMalformedSeal", err)
	}
}

func TestASecretSealedUnderAnotherKeyDoesNotOpen(t *testing.T) {
	first, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	other, err := NewAESCipher([]byte("fedcba9876543210fedcba9876543210"))
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	user := mustUUID(t, "6f1a3f2e-0000-4000-8000-000000000001")

	sealed, err := first.Seal(user, rawKey)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := other.Open(user, sealed); !errors.Is(err, ErrMalformedSeal) {
		t.Errorf("Open under the wrong key = %v, want ErrMalformedSeal", err)
	}
}

func TestAVaultRefusesAnEditedCiphertext(t *testing.T) {
	vault, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	user := mustUUID(t, "6f1a3f2e-0000-4000-8000-000000000001")

	sealed, err := vault.Seal(user, rawKey)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	edited := []byte(sealed)
	edited[len(edited)-2] ^= 'A' ^ 'B'

	if _, err := vault.Open(user, string(edited)); !errors.Is(err, ErrMalformedSeal) {
		t.Errorf("Open of an edited value = %v, want ErrMalformedSeal", err)
	}
}

func TestTheKeyLengthIsExact(t *testing.T) {
	for _, size := range []int{0, 1, 16, 24, 31, 33, 64} {
		if _, err := NewAESCipher(make([]byte, size)); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("NewAESCipher(%d bytes) = %v, want ErrInvalidKey", size, err)
		}
	}
}

func TestUnavailableVaultFailsClosed(t *testing.T) {
	var vault Vault = Unavailable{}
	user := mustUUID(t, "6f1a3f2e-0000-4000-8000-000000000001")

	if _, err := vault.Seal(user, rawKey); !errors.Is(err, ErrNoVault) {
		t.Errorf("Seal = %v, want ErrNoVault", err)
	}
	if _, err := vault.Open(user, "whatever"); !errors.Is(err, ErrNoVault) {
		t.Errorf("Open = %v, want ErrNoVault", err)
	}
}

func TestTheVaultIsNotTheOAuthOne(t *testing.T) {
	if strings.HasPrefix(SealPrefix, "v1.") {
		t.Error("the mfa seal prefix collides with internal/oauth's")
	}
}

func TestHotpOptionsRejectsWhatTheSchemaForbids(t *testing.T) {
	if _, err := hotpOptions(DigitEight, AlgorithmSHA1); err != nil {
		t.Errorf("eight digits should be verifiable: %v", err)
	}
	for _, c := range []struct{ digits, algorithm string }{
		{"7", AlgorithmSHA1},
		{"0", AlgorithmSHA1},
		{"", AlgorithmSHA1},
		{DigitSix, "SHA256"},
		{DigitSix, ""},
	} {
		if _, err := hotpOptions(c.digits, c.algorithm); err == nil {
			t.Errorf("hotpOptions(%q, %q) accepted a value the schema forbids", c.digits, c.algorithm)
		}
	}
}

func TestTotpCodeGeneratesTheCodeForAnInstant(t *testing.T) {
	got, err := Code(rawKey, at)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if !isTOTPCode(got) {
		t.Errorf("Code produced %q, which is not a six-digit code", got)
	}
	if got != codeFor(t, rawKey, stepBase) {
		t.Errorf("Code = %q, want %q", got, codeFor(t, rawKey, stepBase))
	}
	if _, err := Code(rawKey, time.Unix(-60, 0)); err == nil {
		t.Error("Code accepted a pre-epoch instant")
	}
	if _, err := totpCode(rawKey, at, "7", AlgorithmSHA1, Period); err == nil {
		t.Error("totpCode accepted a digit count the schema forbids")
	}
}
