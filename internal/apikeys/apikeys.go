package apikeys

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// Prefix is what every credential this platform issues begins with.
//
// IT IS A FEATURE AND THE FEATURE IS RECOGNITION. A secret that leaks — into a
// CI log, a shell history, a support ticket, a screenshot, a paste buffer — is
// recognized as a anywaye credential by its first seven characters, which turns
// "somebody has to guess which of these strings is a working key" into a grep.
// It is the same reason the OIDC client id is 32 random bytes rather than a
// counter, and the same reason gateway's api key carries a prefix: a credential
// you cannot recognize is a credential you cannot revoke in time.
//
// It is the PREFIX of the value rather than a separator somewhere in the middle
// because a scanner that looks at the first bytes is looking at the bytes a
// truncated log line is most likely to have kept.
const Prefix = "anywaye_"

// SecretBytes is the entropy behind the prefix.
//
// 256 bits, which is the same budget as a session token, an invitation token and
// an OIDC client secret, and for the same reason: none of them are the weak link,
// and a credential this service issues is never guessable by anything that can
// do arithmetic in the time the universe has left.
//
// It is deliberately not larger. The prefix is public and the secret's job is to
// be unguessable; 256 bits is already past every physical attack that could ever
// be mounted against a running process, and a 512-bit token is a longer thing to
// paste, log and truncate.
const SecretBytes = 32

// DefaultTTL is how long a token lives when the caller does not say.
//
// NINETY DAYS, and the number is a judgement about two failure modes rather than
// a round number chosen for looks:
//
//   - long enough that a CI job somebody set up in a hurry does not fail on a
//     Tuesday three months later and get "just make a new one" as the answer to
//     a question they cannot ask;
//   - short enough that "we rotated our tokens" is a thing that happens without
//     anybody having to decide to make it happen.
//
// A permanent credential has no such moment. That is the whole of the expiry
// decision, and this constant is where it lives.
const DefaultTTL = 90 * 24 * time.Hour

// MaxTTL is the ceiling.
//
// A year, enforced here AND by the table's `api_keys_maximum_lifetime` CHECK, so
// a caller that reaches the database without the service cannot write a longer
// one. Two statements of one policy is the arrangement the OIDC access-token
// migration already uses, and the reason is that the drift between a constant in
// Go and a policy in SQL is always in the direction of the credential outliving
// its own rules.
const MaxTTL = 365 * 24 * time.Hour

// MinTTL is the floor: an hour.
//
// It exists for one case — a caller who meant "as long as possible" and typed
// something small — and the answer is a 422 rather than a credential that stops
// working between the 201 and the first request. An hour is long enough that a
// token minted at this floor has been used at least once.
const MinTTL = 24 * time.Hour

// LastUsedResolution is how stale `last_used_at` is allowed to get.
//
// FIVE MINUTES, and the number is a statement about writes rather than about
// time. A CI token at a thousand requests a second must not put a thousand
// UPDATE round trips a second on one row: a single row's lock is a queue, and a
// queue on the hot path of every authenticated machine request is a
// self-inflicted denial of service against the credential's own owner. The
// column is therefore advanced at most once every five minutes, and the cost is
// that it is accurate to within five minutes — which is written on the column
// in the migration rather than discovered by somebody who needed the second.
const LastUsedResolution = 5 * time.Minute

const (
	ScopeAccountsRead = "accounts:read"
	ScopeAccountsWrite = "accounts:write"
	ScopeAccountsDelete = "accounts:delete"
	ScopeOIDCClientsWrite = "oidc_clients:write"

	ScopeAuditLogRead = "audit_log:read"

	ScopeAccountInvitationsWrite = "account_invitations:write"

	ScopeSessionsWrite = "sessions:write"

	ScopeUsersDisable = "users:disable"
	ScopeTokensIntrospect = "tokens:introspect"
)

// AllScopes is the vocabulary, in a fixed order.
//
// A slice rather than a set for the reason internal/oidc's SupportedScopes is
// one: the order reaches an error message and a response, and a map's iteration
// order would make two identical requests answer differently.
func AllScopes() []string {
	return []string{
		ScopeAccountsRead, ScopeAccountsWrite, ScopeAccountsDelete,
		ScopeOIDCClientsWrite, ScopeAuditLogRead, ScopeAccountInvitationsWrite,
		ScopeSessionsWrite, ScopeUsersDisable, ScopeTokensIntrospect,
	}
}

// IsSupportedScope reports whether this build implements a scope. Exact match,
// never a prefix: `accounts` is not `accounts:read`, and a comparison that
// accepted the first because it starts with the second would hand out a
// capability set nobody wrote down.
func IsSupportedScope(scope string) bool {
	return slices.Contains(AllScopes(), scope)
}

const (
	CodeRequired      = "required"
	CodeInvalidFormat = "invalid_format"
	CodeTooLong       = "too_long"
	CodeTooMany       = "too_many"
	CodeUnsupported   = "unsupported"
	CodeOutOfRange    = "out_of_range"
)

// MaxNameLength bounds api_keys.name. It is characters rather than bytes,
// matching the table's CHECK, because a name is typed by a person into a
// settings page and "my deploy key 🚀" is a name.
const MaxNameLength = 80

// MaxScopes bounds a single token's scope list.
//
// Eight, and the closed vocabulary has four names, so the ceiling exists only to
// stop a caller sending the list four thousand times. It is a DoS control on the
// request, not a policy.
const MaxScopes = 9

// FieldError is a per-field validation failure, rendered as one entry of a 422's
// errors[].
//
// Structurally the same type as users.FieldError and mfa.FieldError and
// deliberately a separate declaration in each package: the three do not depend
// on each other, and a shared one would be the first edge between them.
type FieldError struct {
	Field string
	Code  string
}

func (e *FieldError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Code) }

func fieldErr(field, code string) error { return &FieldError{Field: field, Code: code} }

// NewToken mints an api key and the digest stored in its place.
//
// The pair is returned rather than a struct with an exported Token field, and it
// is the shape sessions.NewToken and accounts.NewToken both use, for the same
// reason: the two values go in opposite directions. The token reaches the client
// exactly once, in a 201 body, and the digest goes into the row and is never
// rendered anywhere. A struct with a `Token` field is a nudge towards a handler
// reaching for the wrong one.
func NewToken() (token, digest string, err error) {
	raw := make([]byte, SecretBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", "", fmt.Errorf("reading random bytes for an api key: %w", err)
	}

	token = Prefix + base64.RawURLEncoding.EncodeToString(raw)

	return token, Digest(token), nil
}

// Digest is the value stored in api_keys.token_digest: the lower-case hex
// SHA-256 of the presented value, PREFIX INCLUDED.
//
// SHA-256 rather than argon2id, and the package comment says the whole of the
// argument; the load-bearing half is that argon2id makes GUESSING expensive and
// there is nothing here to guess. 256 bits of crypto/rand has no structure, so a
// memory-hard function over it buys nothing and would cost tens of milliseconds
// on every machine request across the platform.
//
// THE WHOLE VALUE IS HASHED, PREFIX AND ALL, and the reason is one of
// uniqueness rather than security: hashing the secret alone would mean the
// presented string and the stored digest were not the same shape, and two
// credential formats minting the same random bytes would produce the same
// digest. There is no attack there — the digests are not comparable across
// tables — and there is a real ambiguity, which is why this is a decision.
//
// A MALFORMED OR EMPTY VALUE STILL PRODUCES A WELL-FORMED DIGEST. That is the
// timing answer, and it is structural rather than a property of a comparison
// function: the store never sees the presented value at all, so a value of any
// length reaches the database as the same 64-character hex string, and the
// lookup it performs is an ordinary indexed equality in exactly one shape. There
// is no length comparison anywhere on this path for an early return to skip.
func Digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NormalizeName trims a caller-supplied name. It does not collapse internal
// whitespace: "CI  deploy" is a typo, and silently repairing it would store a
// name the caller did not choose.
func NormalizeName(name string) string { return strings.TrimSpace(name) }

// ValidateName checks a name and returns the normalized value.
//
// THREE RULES, and the third is the one that surprises people:
//
//	non-empty after trimming      an operator revokes by what they can read
//	within MaxNameLength          characters, because the column's CHECK counts
//	                              characters and a name that passes here and fails
//	                              there is a 500
//	no control characters         a name lands in a log line, a settings page and
//	                              an incident report, and a name carrying \n or \r
//	                              is three lines where somebody wrote one
func ValidateName(give string) (string, error) {
	normalized := NormalizeName(give)
	switch {
	case normalized == "":
		return "", fieldErr("name", CodeRequired)
	case len([]rune(normalized)) > MaxNameLength:
		return "", fieldErr("name", CodeTooLong)
	case hasControl(normalized):
		return "", fieldErr("name", CodeInvalidFormat)
	}
	return normalized, nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// ValidateScopes checks and normalizes a token's scope list.
//
// REFUSES rather than curates, which is the difference from internal/oidc's
// registration path and it is deliberate. A product registering itself asks for
// what it would like and an operator curates what it gets, so dropping an
// unsupported scope there is a convenience. Here the caller is asking for a
// credential RIGHT NOW: a CI job that asks for `accounts:admin` and silently
// receives `accounts:read` is a script that runs for a week and fails on the
// write it was written to do.
//
// Empty is refused rather than defaulted. A token with no scopes is a session
// that never expires, and it arrives as "the client did not send the field" —
// which is exactly how the dangerous case looks.
func ValidateScopes(give []string) ([]string, error) {
	if len(give) > MaxScopes {
		return nil, fieldErr("scopes", CodeTooMany)
	}

	out := make([]string, 0, len(give))
	for _, raw := range give {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			continue
		}
		if !IsSupportedScope(scope) {
			return nil, fieldErr("scopes", CodeUnsupported)
		}
		if !slices.Contains(out, scope) {
			out = append(out, scope)
		}
	}

	if len(out) == 0 {
		return nil, fieldErr("scopes", CodeRequired)
	}

	slices.Sort(out)
	return out, nil
}

// HasScope reports whether a granted set contains scope.
//
// EXACT MATCH, and it is the second place in this repository where a prefix
// comparison would be a vulnerability: `accounts` is not `accounts:read`, and a
// token created with a mangled scope name would otherwise receive the real one.
//
// An empty or nil set holds nothing, which is the direction that fails closed.
func HasScope(granted []string, scope string) bool {
	return slices.Contains(granted, scope)
}

// FirstUnsupported returns the first requested scope this build does not
// implement, or "" when they all are.
//
// The NAME comes back rather than a boolean because the caller of this is a 422
// naming the field, and "unknown scope" without the name leaves a developer
// editing a config file for an afternoon.
func FirstUnsupported(give []string) string {
	for _, raw := range give {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			continue
		}
		if !IsSupportedScope(scope) {
			return scope
		}
	}
	return ""
}

// ResolveExpiry decides when a new credential stops working.
//
// THREE ANSWERS, and the absence of a fourth is the packet's expiry decision:
//
//	nil      DefaultTTL from created. The common case, and the one a client that
//	         does not care should not have to spell.
//	0 or <0  REFUSED. This is where "never expires" would have gone, and it is
//	         not here. A token that cannot expire is a permanent credential: it
//	         outlives the employee who minted it, the laptop it was on, and every
//	         incident it was leaked in.
//	> MaxTTL refused rather than clamped, so a client asking for ten years learns
//	         that ten years is not a thing rather than getting a year and finding
//	         out at the first expiry.
//
// The cost, stated because it is real: a CI credential that has to be replaced
// every quarter is friction on precisely the use case that motivates the
// feature. What it buys is a moment at which a credential nobody is using gets
// noticed, and `last_used_at` is how that moment is acted on rather than
// guessed at.
func ResolveExpiry(created time.Time, requested *time.Duration) (time.Time, error) {
	lifetime := DefaultTTL
	if requested != nil {
		lifetime = *requested
		switch {
		case lifetime <= 0:
			return time.Time{}, fieldErr("expires_in", CodeOutOfRange)
		case lifetime < MinTTL:
			return time.Time{}, fieldErr("expires_in", CodeOutOfRange)
		case lifetime > MaxTTL:
			return time.Time{}, fieldErr("expires_in", CodeTooLong)
		}
	}

	expiry := created.Add(lifetime)

	if expiry.After(created.Add(MaxTTL)) {
		return time.Time{}, fieldErr("expires_in", CodeTooLong)
	}

	return expiry, nil
}

// ErrNotFound means no live api key matches a presented value.
//
// It covers four situations that MUST be indistinguishable to the caller: no such
// token, a revoked token, an expired token, and a token whose user has since been
// deleted or removed from the account. One error, one status code, one response
// time — the same rule sessions.ErrNotFound follows and the same reason.
var ErrNotFound = errors.New("api key not found")

