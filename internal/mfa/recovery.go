package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)


var recoveryAlphabet = base32.StdEncoding.WithPadding(base32.NoPadding)

const recoveryGroup = 4

// NewRecoveryCodes mints a full set.
//
// The set is returned once and never again: there is no endpoint that re-reads
// it, and the table holds a digest per code. The reasoning is the one
// internal/oidc/service.go states for a client secret and it applies verbatim —
// a secret this service can produce again is a secret this service is storing,
// and the only safe way to show ten of them is to show them exactly once.
//
// A failure of crypto/rand is returned, not worked around. A recovery set with a
// predictable code in it is a way into an account, and it is discovered by the
// user rather than by the service.
func NewRecoveryCodes() ([]string, error) {
	codes := make([]string, 0, RecoveryCodeCount)
	for i := 0; i < RecoveryCodeCount; i++ {
		code, err := NewRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// NewRecoveryCode mints one recovery code in its display form.
func NewRecoveryCode() (string, error) {
	raw := make([]byte, RecoveryCodeBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("mfa: reading random bytes for a recovery code: %w", err)
	}
	return formatRecoveryCode(recoveryAlphabet.EncodeToString(raw)), nil
}

func formatRecoveryCode(joined string) string {
	var b strings.Builder
	for i, r := range joined {
		if i > 0 && i%recoveryGroup == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// NormalizeRecoveryCode is the form that gets hashed, and the form two spellings
// of the same code have to agree on.
//
// Upper case, no dashes, no spaces. A user reading a code off a piece of paper
// writes a space where the dash is, or types the whole thing in lower case
// because their keyboard was set that way, or transcribes "O" for "0" — and
// none of those is a different code. Everything a human types goes through here
// before it is compared, and the comparison is against a value that has been
// stored in this same normalised form, so the two sides cannot disagree about
// spelling.
func NormalizeRecoveryCode(code string) string {
	stripped := strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ', '\t', '\n':
			return -1
		}
		return r
	}, strings.ToUpper(strings.TrimSpace(code)))
	return stripped
}

// IsRecoveryCode reports whether a presented value could be a recovery code.
//
// The length is the whole test, and it is enough: 16 base32 characters is 80
// bits, and no other value in this service is that shape. A code is checked for
// shape BEFORE any query runs, so a value that is neither six digits nor sixteen
// base32 characters costs one comparison and no database round trip.
func IsRecoveryCode(value string) bool {
	normalized := NormalizeRecoveryCode(value)
	if len(normalized) != recoveryEncodingLen {
		return false
	}
	for _, r := range normalized {
		if !strings.ContainsRune(recoveryAlphabetChars, r) {
			return false
		}
	}
	return true
}

var recoveryEncodingLen = (RecoveryCodeBytes*8 + 4) / 5

const recoveryAlphabetChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// RecoveryDigest is the value stored in mfa_recovery_codes.code_digest.
//
// SHA-256 and not argon2id, for the reason sessions.Digest gives and the reason
// is the same: a recovery code is 80 bits of crypto/rand output with no structure
// to guess, so a memory-hard hash would buy nothing that the entropy has not
// already bought, and would cost tens of milliseconds on every sign-in that
// reaches for it. Argon2id exists to make GUESSING expensive, and there is
// nothing here to guess.
//
// The invariant both columns share is the one that matters: the presented value
// is never stored, so a dump of this table is not a set of credentials.
func RecoveryDigest(code string) string {
	sum := sha256.Sum256([]byte(NormalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}
