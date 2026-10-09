// Package agents holds the agent principal: the identity that exists before
// anybody owns it.
//
// WHY IT LIVES HERE AND NOT IN CONDUCTOR. Decision D3. Identity is the fleet's
// auth authority — conductor forwards a bearer here and verifies nothing itself,
// fail-closed — and this service already owns scoped opaque API keys
// (SHA-256 at rest), introspection, session-links (a minted link IS the
// credential) and invitations (a thing exists, a human confirms it, it binds to
// an account). An agent claim is that last flow with a stranger on the other end
// of the link, and the principal that flow binds is this.
//
// THE ONE DIFFERENCE FROM api_keys, AND IT IS THE WHOLE PACKET. An api key is
// minted by a signed-in user FOR an account they already hold, so it is born
// knowing its account and its owner. An agent registers itself: nobody is
// authenticated, there is no account, and the principal's first state carries no
// authority at all. So this is a NEW LIFECYCLE over the same hashing and
// introspection machinery — not a second token system, and not a second place
// anything verifies a credential.
//
// WHAT THIS PACKET OWNS AND WHAT IT DOES NOT. The substrate: the principal, its
// lifecycle, its credential digests and its audit rows. W1-P2 (public
// registration, the scoped-token create/show/rotate/revoke set) and W2-P2 (claim
// binds, mint the scoped token) build on it. Nothing here mounts a route; the
// claim route that exercises the bind lives in internal/httpapi.
package agents

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The lifecycle, in order, with the transitions written out.
//
// TWO TRANSITIONS IN AND A THIRD THAT IS NOT THE REVERSE OF ANYTHING:
//
//	unclaimed → claimed   a human, authenticated, on the claim screen. The link
//	                      is the credential and the click is explicit; nothing
//	                      auto-accepts, which is the invitation flow's whole
//	                      rule and deciding D4.
//	claimed   → disabled  the account's owner turns it off. The row, the id, the
//	                      name and the trail all survive — which is why a disable
//	                      is not a delete.
//	disabled  → claimed  re-enabling, by the same owner.
//
// AND THE ONE THAT DOES NOT EXIST AT ALL: unclaimed → disabled. An agent nobody
// has claimed is a stranger's registration, and "disabled" is an act of ownership
// over something with no owner yet. The table's CHECK refuses the state; this
// function refuses the move, so a caller cannot ask for either.
//
// The ordering is a total order rather than a set because the transitions are
// reachable in exactly one direction of history except for the re-enable, and a
// caller that has to reason about that in three places reasons about it wrongly
// in the third.
const (
	// StatusUnclaimed is what a registration produces: it exists, it holds no
	// authority, and nothing it can do depends on a row in `accounts`.
	StatusUnclaimed = "unclaimed"
	// StatusClaimed is bound to a human account.
	StatusClaimed = "claimed"
	// StatusDisabled was claimed and has been turned off. Its tokens do not
	// resolve; the row is kept.
	StatusDisabled = "disabled"
)

// AllStatuses is the closed set, in lifecycle order.
func AllStatuses() []string {
	return []string{StatusUnclaimed, StatusClaimed, StatusDisabled}
}

// IsKnownStatus reports whether this build implements a status. Exact match,
// never a prefix: `claim` is not `claimed`.
func IsKnownStatus(status string) bool {
	for _, known := range AllStatuses() {
		if status == known {
			return true
		}
	}
	return false
}

// ErrUnknownStatus means a caller asked for a state this build does not have.
var ErrUnknownStatus = errors.New("unknown agent status")

// ParseStatus validates a caller-supplied status against the closed set.
func ParseStatus(give string) (string, error) {
	status := strings.TrimSpace(give)
	if !IsKnownStatus(status) {
		return "", fmt.Errorf("%w: %q", ErrUnknownStatus, give)
	}
	return status, nil
}

// MayTransition reports whether from → to is a legal move for one agent.
//
// A TOTAL FUNCTION over the closed set, and the two illegal answers are not
// symmetric in what they cost:
//
//	unclaimed → claimed   refused unless the caller is the human who redeemed
//	                      the claim link. This function is only about the STATE
//	                      MACHINE; the credential check is the route's and the
//	                      two are separate because one is arithmetic and the
//	                      other is authority.
//	claimed → unclaimed   REFUSED AND THERE IS NO UN-CLAIM. Ownership is not
//	                      revocable by the agent or by a second claim link: the
//	                      account that claimed it disables it, which is a state
//	                      this build has.
//
// The same status is always allowed, because a store that writes the current
// status back — an idempotent retry, an event replayed — is not asking for a
// transition and must not be told no.
func MayTransition(from, to string) bool {
	if from == to {
		return true
	}
	switch from {
	case StatusUnclaimed:
		return to == StatusClaimed
	case StatusClaimed:
		return to == StatusDisabled
	case StatusDisabled:
		return to == StatusClaimed
	}
	return false
}

// --- the credential, and the one thing this package will not store --------

// Prefix is what every credential this package issues begins with.
//
// The SAME prefix apikeys uses and the reason is the same one: it is recognition.
// A secret that leaks into a transcript, a CI log or a support ticket is
// recognised as a cafaye credential by its first seven characters, which turns
// "somebody has to guess which of these strings is a working key" into a grep.
//
// IT IS DELIBERATELY NOT A DISTINCT PREFIX. A second prefix — `cafaye_agent_` —
// would buy a way to tell an agent credential from a user's api key by looking at
// it, and that is a property this platform refuses to build: identity's whole
// argument is that a credential's shape is NOT a public fact worth having, which
// is why apikeys.Prefix decides which table a presented value is looked up in
// before any query runs and nothing else does. One prefix, two tables, and the
// discriminator is the prefix ALONE — meaning an agent token must be looked up in
// agent_tokens and nowhere else, by the same rule.
const Prefix = "cafaye_"

// SecretBytes is the entropy behind the prefix: 256 bits, the same budget as a
// session token, an api key and an invitation token, for the same reason — none
// of them is the weak link.
const SecretBytes = 32

// Digest is the value stored in agent_tokens.token_digest and
// agents.claim_token_digest: the lower-case hex SHA-256 of the presented value,
// WHOLE STRING INCLUDING THE PREFIX.
//
// This is internal/apikeys' Digest restated rather than called, and that is a
// decision rather than laziness. Calling it would make this package's credential
// storage depend on a package whose comment is about a DIFFERENT lifetime
// (months, held by a CI job) and whose vocabulary (scopes, names per account) is
// not this one. The bytes are identical and a future divergence between the two
// would be a bug in whichever file changed — but a reviewer reading
// `apikeys.Digest` at the top of an agent-credential path has to know that the
// argument applies, and this package's own comment is where they learn it.
//
// SHA-256 rather than argon2id, and the argument is unchanged from
// internal/sessions/token.go: argon2id exists to make GUESSING expensive, and
// 256 bits of crypto/rand has no guessable structure for a memory-hard function
// to slow down. What makes a leaked agent credential survivable is that it is
// revocable, that it expires, and that the plaintext was never anywhere for a
// backup to pick up.
//
// THE WHOLE VALUE IS HASHED, PREFIX AND ALL. Not needed for security — nothing
// here compares a digest to a guess — and here because it removes a question: two
// credential types can never produce the same digest for the same random bytes.
func Digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewToken mints a credential and the digest stored in its place.
//
// The pair is returned rather than a struct with an exported Token field, for the
// reason internal/apikeys and internal/sessions both use: the two values go in
// opposite directions. The token reaches the caller exactly once — a 201 body, a
// CLI's stderr, an OS keyring — and the DIGEST goes into the row and is never
// rendered anywhere. There is no column and no field that could hold it later,
// and "no plaintext token at rest" is that sentence rather than a policy.
//
// The digest is also the only part that may be put in a log line, an audit row or
// an error. `%+v` of the returned value is safe; `%+v` of a struct holding both
// is not, which is why this returns two strings and not one struct.
func NewToken() (token, digest string, err error) {
	raw := make([]byte, SecretBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		// Same reasoning as every mint in this service: a failure of crypto/rand
		// means there is no trustworthy entropy, and minting a credential from a
		// degraded source is not something to discover when it turns out to be
		// guessable.
		return "", "", fmt.Errorf("reading random bytes for an agent token: %w", err)
	}
	token = Prefix + base64.RawURLEncoding.EncodeToString(raw)
	return token, Digest(token), nil
}

// Agent is a row in the agents table, and the struct a handler holds.
//
// THERE IS NO TOKEN FIELD ON IT. The claim link's plaintext exists exactly once,
// in the response to the registration that produced it, and the digest is the
// only part of it any later code can reach. `ClaimTokenDigest` is here because
// the row holds it; adding a `ClaimToken` beside it would be the bug this
// package exists to prevent, and it is the same rule `Token` on api_keys.Key
// refuses.
//
// ClaimedByAccountID is nil while unclaimed and non-nil from the claim onwards,
// including through a disable — the table's CHECK says so, so this struct does
// not have to.
type Agent struct {
	ID                 id.UUID
	Name               string
	Status             string
	ClaimTokenDigest   *string
	ClaimLinkExpiresAt *time.Time
	ClaimedByAccountID *id.UUID
	ClaimedAt          *time.Time
	Device             map[string]any
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// IsClaimed reports whether the agent is bound to an account, disabled or not.
//
// A DISABLED AGENT IS CLAIMED, and that is the whole reason this is one method
// and not `Status == StatusClaimed`: "has this ever been claimed" and "is it
// currently usable" are two different questions, and a caller writing
// `== StatusClaimed` when they meant "was it claimed" is a caller who has just
// answered a security question about ownership with a question about liveness.
func (a Agent) IsClaimed() bool { return a.ClaimedByAccountID != nil }

// Token is a row in agent_tokens, and the struct the resolution query returns.
//
// TokenDigest is here because the row holds it, and it is the ONLY part of a
// credential on this struct. There is no Token field, and adding one would be the
// bug this package exists to prevent: the plaintext lives once, in one response,
// and there is no column and no field that could hold it later. A careless
// `%+v` in an audit path has a digest to write down and nothing else.
type Token struct {
	ID          id.UUID
	AgentID     id.UUID
	Name        string
	TokenDigest string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	// LastUsedAt is nil until the credential has been used. A pointer because
	// "never used" and "used at the epoch" are different answers, and the first
	// is the one an operator wants to notice.
	LastUsedAt *time.Time
	// RevokedAt and RevokedReason are set together or not at all, and the
	// table's CHECK says so. RevokedReason is a pointer because "" is a real
	// answer and NULL is "none given".
	RevokedAt     *time.Time
	RevokedReason *string
}

// IsRevoked reports whether the credential has been withdrawn.
func (t Token) IsRevoked() bool { return t.RevokedAt != nil }

// IsExpired reports whether the credential is past its deadline at now.
//
// The boundary is `now >= expires_at`: a token whose expiry is exactly now is
// spent, and the resolution query agrees. Two implementations of one boundary is
// how a token stays usable for a second longer than the response that used it
// said it would.
func (t Token) IsExpired(now time.Time) bool { return !t.ExpiresAt.After(now) }

// UsableAt reports whether this credential may be presented at now, for a
// principal in status.
//
// IT JOINS THE TWO, and that is the whole point: an agent credential's authority
// is not the row's own state alone. A token held by a DISABLED agent does not
// resolve, and the statement that expresses that is here — one place — rather
// than in every caller that has both values in hand. The resolution query
// inner-joins the principal so the database says the same thing this method
// says, and this method is what a caller holding an already-loaded pair can ask
// without a second query.
func (t Token) UsableAt(now time.Time, agentStatus string) bool {
	if t.IsRevoked() || t.IsExpired(now) {
		return false
	}
	// An unknown status is refused rather than treated as live. The closed set is
	// a code fact, and a row carrying a status this build has never seen is a row
	// written by a future or broken deployment — the direction that fails there
	// is closed, never open.
	return agentStatus == StatusClaimed
}
