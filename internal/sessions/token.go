package sessions

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

const tokenBytes = 32

// NewToken mints a session token and its stored digest.
//
// It returns both because the caller needs them at different moments and in
// opposite directions: the token goes to the client exactly once, in a cookie and
// in a response body, and the digest goes into the row and is never rendered.
// Returning a pair rather than a struct with an exported Token field is a nudge
// against a handler that reaches for the wrong one.
func NewToken() (token, digest string, err error) {
	raw := make([]byte, tokenBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", "", fmt.Errorf("reading random bytes for a session token: %w", err)
	}

	token = base64.RawURLEncoding.EncodeToString(raw)

	return token, Digest(token), nil
}

// Digest returns the value stored in sessions.token_digest: the lower-case hex
// SHA-256 of the presented token.
//
// SHA-256 rather than argon2id, unlike the password column, and the reason is
// that argon2id exists to make *guessing* expensive. A 256-bit random token has
// no guessable structure, so a slow hash would buy no security and would cost
// every authenticated request tens of milliseconds of memory-hard work. The rule
// that matters on both columns is the same: the presented value is never stored,
// so a database dump does not yield a usable credential.
//
// A malformed or empty token still produces a well-formed digest. The lookup is
// then an ordinary indexed equality test that matches nothing, which keeps "no
// token", "wrong token" and "expired token" on one code path and one response
// time instead of three.
func Digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
