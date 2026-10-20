// Package signup mints and verifies the signed timestamp that proves a signup
// submission came from the form rather than from a bot.
//
// # WHY THIS EXISTS
//
// The honeypot field (the hidden `website` input on the sign-in form, refused
// by internal/httpapi's registerRequest) stops a bot that fills every field the
// form presents. A bot that leaves the trap empty sails through. The signed
// timestamp is the second half: the form carries `timestamp` + `signature`, and
// the server verifies the pair before accepting the submission.
//
// The signature is an HMAC-SHA256 over the timestamp, keyed with a server
// secret (SIGNUP_SIGNING_KEY) that only identity holds. The client cannot sign
// anything — identity mints the pair and hands it out, and the same secret
// verifies it on submission. Without the secret there is nothing to verify
// against, and a forged timestamp is indistinguishable from a real one; that is
// why the variable is required at boot rather than optional like the feature
// keys. See REPORT-identity-spamprotection-01 for the per-secret argument
// against reusing one of the four existing secrets.
//
// # WHAT IS SIGNED, AND IN WHICH FORM
//
// The message is the timestamp as a DECIMAL STRING — the canonical form of an
// integer, so the signed bytes do not depend on how a client spelled the
// number. The signature itself is base64url without padding, the same alphabet
// as every other opaque value this service issues (session tokens, oauth
// states, api keys), so a value of the wrong kind is never mistaken for one.
//
// # THE TWO WINDOWS
//
// A signed timestamp is a bearer credential for submitting the form, so it
// expires: a timestamp older than MaxAge is refused, because a captured pair
// must not stay usable for the life of the deployment. And it must be at least
// MinAge old: a person needs seconds to fill a form, a bot submits instantly,
// and the floor is what separates the two. Both bounds are checked AFTER the
// signature, so a caller that cannot produce a valid pair learns nothing
// about which bound it would have failed.
package signup

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"time"
)

const (
	// MinAge is the youngest a timestamp may be and still verify.
	//
	// A submission arrives at least this long after the form was rendered: a
	// person reads fields and types, a bot fills and submits in the same
	// instant. The floor is what separates them, and it is deliberately small —
	// it exists to catch the submission that carries no human delay, not to
	// measure one.
	MinAge = 2 * time.Second

	// MaxAge is the oldest a timestamp may be and still verify.
	//
	// A signed timestamp is a bearer credential, and a bearer credential that
	// never expires is a credential that can be captured and replayed for as
	// long as the deployment lives. One hour is long enough for a person to
	// fill a form and short enough that a captured pair dies before it is
	// useful.
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
	// Timestamp is the Unix time the pair was minted at, in seconds.
	Timestamp int64 `json:"timestamp"`
	// Signature is the base64url (no padding) HMAC-SHA256 over the decimal
	// string of Timestamp.
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
		// A signature that is not base64url is not a signature this service
		// minted, whatever it decodes to. Refusing here rather than comparing
		// the string keeps the constant-time comparison between two values of
		// the same kind, which is the only kind it makes a promise about.
		return false
	}
	if !hmac.Equal(mac(s.key, pair.Timestamp), presented) {
		return false
	}

	// The age window, checked after the signature so that a caller without a
	// valid pair never learns which bound it would have failed. A timestamp
	// in the future has a negative age and fails the floor with the instant
	// submission — one comparison covers both, and there is no second source
	// of truth to consult: mint and verify run on the same server's clock.
	age := now.Sub(time.Unix(pair.Timestamp, 0))
	return age >= MinAge && age <= MaxAge
}

// mac is the HMAC-SHA256 over the decimal string of a timestamp.
func mac(key []byte, timestamp int64) []byte {
	h := hmac.New(sha256.New, key)
	// The message is the canonical decimal form, so the signed bytes do not
	// depend on how the number was spelled on the wire.
	h.Write([]byte(strconv.FormatInt(timestamp, 10)))
	return h.Sum(nil)
}

// sign is the wire form of mac: base64url without padding.
func sign(key []byte, timestamp int64) string {
	return base64.RawURLEncoding.EncodeToString(mac(key, timestamp))
}
