package mfa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anywaye/identity/internal/platform/id"
)


// SealPrefix marks the format version of a sealed secret.
//
// It is in the stored value rather than in the schema because a rotation has to
// be able to read what the previous key wrote, and the version is what tells it
// which reader it is looking at. A column named only after the current format
// cannot be rolled back to.
const SealPrefix = "mfa1."

const aadPrefix = "anywaye/identity/mfa/totp-secret/v1\x00"

// ErrInvalidKey means the configured key is not 32 bytes. It is never padded or
// truncated: an operator who pasted a 16-byte key has configured half the
// entropy they think they have, and quietly stretching it would hide that until
// the day it matters.
var ErrInvalidKey = errors.New("the MFA encryption key must be 32 bytes")

// ErrMalformedSeal means a stored value is not something this Vault wrote: no
// prefix, an unknown version, not base64, truncated, or sealed under a different
// key. All of those are one failure at the call site, because there is no
// recovery that distinguishes them.
var ErrMalformedSeal = errors.New("mfa: the stored TOTP secret is malformed")

// Vault seals and opens a TOTP secret.
//
// An interface rather than a concrete type for the reason the session token is
// not one: the use cases have to be testable without a key, and because a process
// with no MFA_ENCRYPTION_KEY has to have a real object here rather than a nil
// pointer that a caller might dereference. Unavailable is that object.
type Vault interface {
	Seal(userID id.UUID, secret string) (string, error)
	Open(userID id.UUID, sealed string) (string, error)
}

// AESVault is AES-256-GCM under a key from the environment.
//
// Authenticated, so a secret edited in the database fails to open rather than
// decrypting to something an attacker chose. The key never leaves this struct
// and is never written anywhere.
type AESVault struct {
	aead cipher.AEAD
}

// NewAESCipher returns a Vault for a 32-byte key.
//
// The key length is exact rather than "at least 16": a shorter key would be
// accepted by AES and silently weaken the guarantee that a database dump plus
// this column does not yield a usable second factor.
func NewAESCipher(key []byte) (*AESVault, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKey, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("mfa: building the AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mfa: building the GCM cipher: %w", err)
	}
	return &AESVault{aead: aead}, nil
}

// Seal encrypts a TOTP secret for a user.
func (v *AESVault) Seal(userID id.UUID, secret string) (string, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("mfa: reading random bytes for the GCM nonce: %w", err)
	}

	sealed := v.aead.Seal(nonce, nonce, []byte(secret), aad(userID))
	return SealPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open decrypts a value produced by Seal.
//
// Every failure is ErrMalformedSeal, including a value that decrypted under the
// wrong key or for the wrong user. The caller cannot act on the distinction, and
// a caller that could — an operator mid-rotation — needs to see the failure, not
// have it silently succeed.
func (v *AESVault) Open(userID id.UUID, sealed string) (string, error) {
	if !strings.HasPrefix(sealed, SealPrefix) {
		return "", fmt.Errorf("%w: missing the %q prefix", ErrMalformedSeal, SealPrefix)
	}

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, SealPrefix))
	if err != nil {
		return "", fmt.Errorf("%w: not base64url", ErrMalformedSeal)
	}

	nonceSize := v.aead.NonceSize()
	if len(raw) < nonceSize+v.aead.Overhead() {
		return "", fmt.Errorf("%w: %d bytes is shorter than a nonce and a tag", ErrMalformedSeal, len(raw))
	}

	opened, err := v.aead.Open(nil, raw[:nonceSize], raw[nonceSize:], aad(userID))
	if err != nil {
		return "", fmt.Errorf("%w: authentication failed", ErrMalformedSeal)
	}
	return string(opened), nil
}

// Unavailable is the Vault a process with no MFA_ENCRYPTION_KEY gets.
//
// It is a real value rather than a nil interface, so the use cases need no nil
// check and cannot forget one, and every method fails with a named error that
// says what is wrong with the deployment.
//
// THE FAILURE IS CLOSED, AND THAT IS THE ENTIRE POINT OF IT HAVING A TYPE. A
// user who has enrolled a second factor cannot be verified by a process that
// cannot decrypt it, and the two available answers are both wrong: refuse them,
// or let them in on their password. So the login path still creates a challenge —
// the service knows they have MFA, and pretending otherwise would be a bypass —
// and the factor submission fails. `MFA_ENCRYPTION_KEY is not configured` in a
// startup log is the fix.
type Unavailable struct{}

// Seal always fails.
func (Unavailable) Seal(id.UUID, string) (string, error) { return "", ErrNoVault }

// Open always fails.
func (Unavailable) Open(id.UUID, string) (string, error) { return "", ErrNoVault }

func aad(userID id.UUID) []byte {
	return append([]byte(aadPrefix), userID.String()...)
}
