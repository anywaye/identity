package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	ErrInvalidEncKey = errors.New("oauth encryption key must be 32 bytes")

	ErrMalformedCiphertext = errors.New("oauth token ciphertext is malformed")
)

// SealPrefix marks the format version of a stored token.
//
// It is in the stored value rather than in the schema because the schema is a
// migration and a migration is not free to run again: a key rotation has to be
// able to read what the previous key wrote, and the version is what tells it
// which format it is looking at. A column named only after the current version
// cannot be rolled back to.
const SealPrefix = "v1."

// Cipher seals and opens the provider tokens this service holds for a connected
// account.
//
// AES-256-GCM: authenticated, so a value edited in the database fails to open
// rather than decrypting to something an attacker chose. The key never leaves
// this struct and is never written anywhere.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher returns a Cipher for a 32-byte AES-256 key.
//
// The key length is exact rather than "at least 16": a shorter key would be
// accepted by AES and silently weaken the guarantee that a database dump plus
// this column does not yield usable credentials.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidEncKey, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("building the AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("building the GCM cipher: %w", err)
	}

	return &Cipher{aead: aead}, nil
}

// Seal encrypts plaintext and returns the value to store.
//
// The nonce is 12 bytes from crypto/rand on every call, which is what makes GCM's
// catastrophic failure — two messages under one nonce — a probabilistic event
// rather than a structural one. The cost is 12 bytes per row and a reseed-free
// key: a deterministic nonce would need a counter in the database, and a
// database counter that can be rolled back is exactly the state a nonce must not
// depend on.
func (c *Cipher) Seal(plaintext string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("reading random bytes for the GCM nonce: %w", err)
	}

	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return SealPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open decrypts a value produced by Seal.
//
// A failure here is always ErrMalformedCiphertext, including a value that
// decrypted under the wrong key. The caller cannot do anything useful with the
// distinction, and a caller that could — an operator rotating keys — wants to see
// the failure, not to have it silently succeed.
func (c *Cipher) Open(value string) (string, error) {
	if !strings.HasPrefix(value, SealPrefix) {
		return "", fmt.Errorf("%w: missing the %q prefix", ErrMalformedCiphertext, SealPrefix)
	}

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, SealPrefix))
	if err != nil {
		return "", fmt.Errorf("%w: not base64url: %w", ErrMalformedCiphertext, err)
	}

	nonceSize := c.aead.NonceSize()
	if len(raw) < nonceSize+c.aead.Overhead() {
		return "", fmt.Errorf("%w: %d bytes is shorter than a nonce and a tag", ErrMalformedCiphertext, len(raw))
	}

	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	opened, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("%w: authentication failed", ErrMalformedCiphertext)
	}

	return string(opened), nil
}
