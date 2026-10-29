package signup

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"time"
)

const (
	MinAge = 2 * time.Second

	MaxAge = time.Hour
)

// Pair is a minted timestamp and its signature.
//
// It IS the wire shape on both ends: the mint endpoint renders it as the
// response body, and the registration request carries the same two fields. It
// is a type of its own rather than two loose arguments so that a minted pair
// and a presented pair cannot be told apart by anything but their values —
// there is no "minted" flag for a forger to set.
type Pair struct {
	Timestamp int64 `json:"timestamp"`
	Signature string `json:"signature"`
}

// Service mints and verifies pairs under one key.
//
// It is a struct of one field so the key has exactly one home in the process:
// it is read from the environment once at boot (internal/config), handed here
// once at wiring, and never copied into a request, a log line or a response.
type Service struct {
	key []byte
}

// New returns a Service that mints and verifies under key.
//
// It does not copy the key, deliberately: the Config it comes from is already
// immutable, and a copy would be a second place for the secret to live. The
// caller owns the slice's lifetime.
func New(key []byte) *Service {
	return &Service{key: key}
}

// Mint returns a fresh pair for now.
//
// now is a parameter rather than a field because the instant a credential is
// minted at has to be the instant the rest of the process believes it is —
// the HTTP layer's clock (internal/platform/clock) is the seam that lets a
// test move time exactly, and a service that read time on its own would be
// minting against a different second than the one its caller holds.
func (s *Service) Mint(now time.Time) Pair {
	timestamp := now.Unix()
	return Pair{Timestamp: timestamp, Signature: sign(s.key, timestamp)}
}

// Verify reports whether pair is a pair this key minted, and whether it is
// inside the age window, at now.
//
// EVERY rejection is a plain false and there is no branch that reveals which
// part failed: a caller that presents a forged signature, an instant
// submission, an expired one and a future one gets the same answer, and the
// handler answers all four with the same generic 422. The signature is
// compared in constant time with hmac.Equal — the same property
// internal/oauth/state.go's VerifyState gets from subtle.ConstantTimeCompare,
// and the reason both exist: a byte-by-byte comparison that returns early
// leaks how much of the signature was right, and a signature is the one value
// a caller can guess at byte by byte.
func (s *Service) Verify(pair Pair, now time.Time) bool {
	presented, err := base64.RawURLEncoding.DecodeString(pair.Signature)
	if err != nil {
		return false
	}
	if !hmac.Equal(mac(s.key, pair.Timestamp), presented) {
		return false
	}

	age := now.Sub(time.Unix(pair.Timestamp, 0))
	return age >= MinAge && age <= MaxAge
}

func mac(key []byte, timestamp int64) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(strconv.FormatInt(timestamp, 10)))
	return h.Sum(nil)
}

func sign(key []byte, timestamp int64) string {
	return base64.RawURLEncoding.EncodeToString(mac(key, timestamp))
}
