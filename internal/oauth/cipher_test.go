package oauth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
)


func TestCipherSealAndOpenRoundTrip(t *testing.T) {
	t.Parallel()

	c := mustCipher(t, testKey(1))

	for _, plaintext := range []string{
		"ya29.a0AfB_byC-very-long-google-access-token-value",
		"gho_16C7e42F292c6912E7710c838347Ae178B4a",
		"x",
	} {
		sealed, err := c.Seal(plaintext)
		if err != nil {
			t.Fatalf("Seal(%q): %v", plaintext, err)
		}
		if len(plaintext) >= 8 && strings.Contains(sealed, plaintext) {
			t.Errorf("Seal(%q) = %q, which contains the plaintext", plaintext, sealed)
		}

		opened, err := c.Open(sealed)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if opened != plaintext {
			t.Errorf("Open = %q, want %q", opened, plaintext)
		}
	}
}

func TestCipherNonceIsNotRepeated(t *testing.T) {
	t.Parallel()

	c := mustCipher(t, testKey(2))

	seen := make(map[string]bool, 64)
	for range 64 {
		sealed, err := c.Seal("the same token over and over")
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if seen[sealed] {
			t.Fatalf("Seal produced %q twice; the nonce is not random per call", sealed)
		}
		seen[sealed] = true
	}
}

func TestCipherOpenRejectsAValueSealedUnderAnotherKey(t *testing.T) {
	t.Parallel()

	sealed, err := mustCipher(t, testKey(3)).Seal("a token")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := mustCipher(t, testKey(4)).Open(sealed); !errors.Is(err, ErrMalformedCiphertext) {
		t.Errorf("Open under a different key = %v, want ErrMalformedCiphertext", err)
	}
}

func TestCipherOpenRejectsTamperedOrTruncatedValues(t *testing.T) {
	t.Parallel()

	c := mustCipher(t, testKey(5))
	sealed, err := c.Seal("a token that matters")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tampered := []byte(sealed)
	tampered[len(tampered)-1] ^= 0x01

	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "no prefix", value: "aGVsbG8"},
		{name: "unknown version", value: "v9.aGVsbG8"},
		{name: "prefix only", value: SealPrefix},
		{name: "not base64", value: SealPrefix + "!!!!"},
		{name: "truncated", value: sealed[:len(sealed)-4]},
		{name: "one flipped ciphertext bit", value: string(tampered)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := c.Open(tt.value); !errors.Is(err, ErrMalformedCiphertext) {
				t.Errorf("Open(%q) = %v, want ErrMalformedCiphertext", tt.value, err)
			}
		})
	}
}

func TestCipherSealProducesTheDocumentedFormat(t *testing.T) {
	t.Parallel()

	c := mustCipher(t, testKey(6))

	sealed, err := c.Seal("x")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if want := len(SealPrefix) + base64.RawURLEncoding.EncodedLen(12+1+16); len(sealed) != want {
		t.Errorf("len(Seal(%q)) = %d, want %d (prefix plus base64url of nonce, ciphertext and tag)", "x", len(sealed), want)
	}
	for _, r := range strings.TrimPrefix(sealed, SealPrefix) {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			t.Errorf("Seal produced %q, which is not base64url", sealed)
			break
		}
	}
}

func TestNewCipherRejectsAKeyOfTheWrongLength(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		t.Run("a key of "+strconv.Itoa(n)+" bytes", func(t *testing.T) {
			t.Parallel()

			if _, err := NewCipher(bytes.Repeat([]byte{7}, n)); !errors.Is(err, ErrInvalidEncKey) {
				t.Errorf("NewCipher with a %d-byte key = %v, want ErrInvalidEncKey", n, err)
			}
		})
	}
}

func TestNewCipherAcceptsExactlyThirtyTwoBytes(t *testing.T) {
	t.Parallel()

	if _, err := NewCipher(bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Errorf("NewCipher with a 32-byte key = %v, want success", err)
	}
}

func mustCipher(t *testing.T, key []byte) *Cipher {
	t.Helper()

	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func testKey(n byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = n
	}
	return key
}
