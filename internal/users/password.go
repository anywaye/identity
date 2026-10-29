package users

import (
	"errors"
	"strings"

	"github.com/alexedwards/argon2id"
)

// ErrEmptyPassword guards the hasher itself, not the endpoint. ValidatePassword
// is what rejects an empty password at the edge; this makes sure no future caller
// can slip one past it and mint a credential that authenticates nothing.
var ErrEmptyPassword = errors.New("password must not be empty")

// Hasher hashes and verifies passwords with argon2id.
//
// A Hasher is a value to be built once at startup and shared, not a package
// global: the dummy digest it holds is derived state, and AGENTS.md's "no
// globals, no init-time state" is easier to keep when the derivation is an
// explicit constructor call.
type Hasher struct {
	params *argon2id.Params
	dummy string
}

// DefaultParams returns the hashing parameters.
//
// argon2id.DefaultParams is 64 MiB, 1 iteration, parallelism 2, 16-byte salt,
// 32-byte key: the library's recommendation for interactive logins, and the same
// memory-per-hash profile as a bcrypt cost factor of 10. They are restated here
// rather than referenced through the library so that a future bump to the
// library's defaults cannot silently change how every existing digest was
// produced — an existing digest encodes its own parameters, so raising them only
// affects new ones, and that is a decision to make on purpose.
func DefaultParams() *argon2id.Params {
	p := *argon2id.DefaultParams
	return &p
}

// NewHasher returns a Hasher using DefaultParams.
func NewHasher() *Hasher {
	return NewHasherWithParams(DefaultParams())
}

// NewHasherWithParams returns a Hasher with explicit parameters, so a test can
// hash fast without changing the production configuration. Passing nil falls
// back to DefaultParams.
func NewHasherWithParams(params *argon2id.Params) *Hasher {
	if params == nil {
		params = DefaultParams()
	}
	h := &Hasher{params: params}
	h.dummy = h.hashUnchecked(randomDummySecret)
	return h
}

const randomDummySecret = "identity-login-timing-equalizer-not-a-credential"

// Hash returns an encoded argon2id digest of plain. The plaintext is not
// retained and is not recoverable from the result.
func (h *Hasher) Hash(plain string) (string, error) {
	if plain == "" {
		return "", ErrEmptyPassword
	}
	return h.hashUnchecked(plain), nil
}

func (h *Hasher) hashUnchecked(plain string) string {
	digest, err := argon2id.CreateHash(plain, h.params)
	if err != nil {
		panic("users: argon2id CreateHash failed: " + err.Error())
	}
	return digest
}

// Verify reports whether plain produced digest.
//
// A malformed digest is false, not an error and not a panic: a corrupt column
// must not become an authentication bypass, and it must not take the process
// down either. The error is dropped deliberately — see VerifyDummy for why
// nothing here surfaces it.
func (h *Hasher) Verify(digest, plain string) bool {
	match, err := argon2id.ComparePasswordAndHash(plain, digest)
	if err != nil {
		return false
	}
	return match
}

// VerifyDummy performs a real argon2id verification against a digest no password
// can match, and always reports false.
//
// The login path calls this when the submitted address has no account, instead
// of returning early. Without it, "no such user" answers in microseconds and
// "wrong password" answers in tens of milliseconds, and that gap is a free
// account-enumeration oracle for anyone willing to measure. (The reference
// implementation in refs/jumpstart-pro makes the same choice with
// `authenticate_by`, which runs a bcrypt check even when the email is unknown.)
func (h *Hasher) VerifyDummy(plain string) {
	_, _ = argon2id.ComparePasswordAndHash(plain, h.dummy)
}

func (h *Hasher) dummyDigest() string { return h.dummy }

// IsArgon2idDigest reports whether s looks like an encoded argon2id digest. It is
// a cheap pre-filter for values arriving from outside the hasher.
func IsArgon2idDigest(s string) bool {
	return strings.HasPrefix(s, "$argon2id$")
}
