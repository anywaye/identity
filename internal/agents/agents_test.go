package agents

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The lifecycle, the credential shape, and the two properties a reviewer has to
// be able to trust before anything is built on top of this package.
//
// These are pure functions and not routes: the transitions are the CONTRACT every
// later packet builds on, and a state machine tested only through a route is a
// state machine tested by whatever the route happened to send.

// TestTheLifecycleAllowsExactlyTheseTransitions is the table a packet reads before
// it depends on this package. Three legal moves, one same-state retry, and the
// illegal ones with the direction they fail in.
func TestTheLifecycleAllowsExactlyTheseTransitions(t *testing.T) {
	cases := []struct {
		name string
		from string
		to   string
		want bool
	}{
		// THE THREE LEGAL TRANSITIONS.
		{"an agent registers unclaimed and is claimed", StatusUnclaimed, StatusClaimed, true},
		{"a claimed agent is disabled", StatusClaimed, StatusDisabled, true},
		{"a disabled agent is re-enabled", StatusDisabled, StatusClaimed, true},

		// A RETRY OR A REPLAYED EVENT asking for the status the row already has.
		// A store that writes the current status back is not asking for a
		// transition and must not be told no.
		{"unclaimed again while unclaimed", StatusUnclaimed, StatusUnclaimed, true},
		{"claimed again while claimed", StatusClaimed, StatusClaimed, true},
		{"disabled again while disabled", StatusDisabled, StatusDisabled, true},

		// THE ONE THAT DOES NOT EXIST, and it is the one an engineer reaches for.
		{"an unclaimed agent cannot be disabled", StatusUnclaimed, StatusDisabled, false},

		// AND THE ONE THAT WOULD UNDO OWNERSHIP.
		{"a claimed agent cannot go back to unclaimed", StatusClaimed, StatusUnclaimed, false},
		{"a disabled agent cannot go back to unclaimed", StatusDisabled, StatusUnclaimed, false},

		// An unknown status on either side, because a row written by a future
		// deployment must not be treated as a legal move.
		{"an unknown source status is refused", "pending", StatusClaimed, false},
		{"an unknown target status is refused", StatusClaimed, "pending", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MayTransition(tc.from, tc.to); got != tc.want {
				t.Errorf("MayTransition(%q, %q) = %v, want %v", tc.from, tc.to, got, tc.want)
			}
		})
	}
}

// TestEveryStatusIsKnownAndTheSetIsClosed is the check that keeps the enum and
// the state machine the same set. A status the state machine has no opinion about
// is a status a caller can write and nothing can act on.
func TestEveryStatusIsKnownAndTheSetIsClosed(t *testing.T) {
	statuses := AllStatuses()
	if len(statuses) != 3 {
		t.Fatalf("AllStatuses() has %d members, want 3: %v", len(statuses), statuses)
	}
	for _, status := range statuses {
		if !IsKnownStatus(status) {
			t.Errorf("IsKnownStatus(%q) is false for a member of AllStatuses()", status)
		}
		if !MayTransition(StatusUnclaimed, status) && status != StatusDisabled {
			// Unclaimed reaches claimed directly; it never reaches disabled,
			// which is the point of the transition table.
			t.Errorf("status %q is in the closed set but unreachable from unclaimed", status)
		}
	}

	for _, unknown := range []string{"", " ", "UNCLAIMED", "claim", "active", "revoked"} {
		if IsKnownStatus(unknown) {
			t.Errorf("IsKnownStatus(%q) is true; the set is closed", unknown)
		}
		if _, err := ParseStatus(unknown); err == nil {
			t.Errorf("ParseStatus(%q) returned no error; an unknown status must be refused", unknown)
		} else if !strings.Contains(err.Error(), "unknown agent status") {
			t.Errorf("ParseStatus(%q) error %v does not name the sentinel", unknown, err)
		}
	}

	for _, status := range statuses {
		got, err := ParseStatus(status)
		if err != nil {
			t.Errorf("ParseStatus(%q): %v", status, err)
			continue
		}
		if got != status {
			t.Errorf("ParseStatus(%q) = %q", status, got)
		}
	}
}

// TestATokenAndItsDigestAreOneFact is the "no plaintext at rest" property at the
// shape level: the digest is the ONLY thing a store can be handed, it is a
// fixed-width hex string, and it is not recoverable from the token by anything
// this package exposes.
func TestATokenAndItsDigestAreOneFact(t *testing.T) {
	for i := range 16 {
		token, digest, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}

		// The wire format, asserted as a literal rather than computed so that
		// raising the entropy is a FAILING test here and not a silently longer
		// token. 32 bytes in base64url without padding is 43 characters.
		secret, ok := strings.CutPrefix(token, Prefix)
		if !ok {
			t.Fatalf("token %d does not carry the prefix %q: %q", i, Prefix, token)
		}
		if len(secret) != 43 {
			t.Errorf("token %d's secret is %d characters, want 43", i, len(secret))
		}
		if strings.ContainsAny(secret, "+/=") {
			t.Errorf("token %d's secret is not base64url without padding: %q", i, secret)
		}

		// 64 lower-case hex characters: SHA-256 rendered by hex.EncodeToString,
		// which is what the column's CHECK asserts.
		if len(digest) != 64 {
			t.Fatalf("token %d's digest is %d characters, want 64", i, len(digest))
		}
		if digest != strings.ToLower(digest) {
			t.Errorf("token %d's digest is not lower case: %q", i, digest)
		}
		if strings.ContainsAny(digest, "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ+/=") {
			t.Errorf("token %d's digest is not hex: %q", i, digest)
		}

		// THE PROPERTY ITSELF: the digest does not CONTAIN the value, and two
		// presentations of the same value produce the same digest while the
		// plaintext appears nowhere in it. A dump yields this and nothing else.
		if strings.Contains(digest, secret) {
			t.Errorf("token %d's digest carries the secret: %q", i, digest)
		}
		if again := Digest(token); again != digest {
			t.Errorf("Digest(%q) is not stable: %q then %q", token, digest, again)
		}
		if other := Digest(token + "x"); other == digest {
			t.Errorf("Digest accepted a modified value as the same credential")
		}
	}
}

// TestTheDigestIsOfTheWholeValueIncludingThePrefix is the uniqueness decision
// stated in the code rather than in a comment: hashing the secret alone would
// make two credential formats produce the same digest for the same random bytes,
// and the digest is bound to the format it was minted in.
func TestTheDigestIsOfTheWholeValueIncludingThePrefix(t *testing.T) {
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	secret := strings.TrimPrefix(token, Prefix)
	if Digest(secret) == digest {
		t.Fatal("the digest is of the secret alone, so two credential formats share a digest for one random value")
	}
	if Digest(token) != digest {
		t.Fatal("the digest is not of the whole presented value")
	}
}

// TestNoStructCarriesAPlaintextCredential is the structural half of the property
// and the one that survives a future packet adding a field. A `Token string`
// field on any struct in this package is a leak no method can intercept: `fmt`
// prints an exported field by value under `%#v` and that verb does not consult
// String().
func TestNoStructCarriesAPlaintextCredential(t *testing.T) {
	for _, v := range []any{Agent{}, Token{}} {
		typ := reflect.TypeOf(v)
		for i := range typ.NumField() {
			field := typ.Field(i)
			if field.Type.Kind() == reflect.String &&
				!strings.HasSuffix(field.Name, "Digest") &&
				strings.Contains(strings.ToLower(field.Name), "token") {
				t.Errorf("%s.%s is a string field holding a token; a credential on a struct is a credential a value verb can print",
					typ.Name(), field.Name)
			}
		}
	}
}

// TestACredentialIsJudgedAgainstTheAgentsStatus is the join, asserted in Go
// because the database makes the same join and the two must not disagree.
func TestACredentialIsJudgedAgainstTheAgentsStatus(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	live := Token{CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}

	// A live credential held by a claimed agent works, and by nothing else.
	for _, status := range []string{StatusUnclaimed, StatusDisabled} {
		if live.UsableAt(now, status) {
			t.Errorf("a credential resolves for an agent in status %q", status)
		}
	}
	if !live.UsableAt(now, StatusClaimed) {
		t.Error("a live credential does not resolve for a claimed agent")
	}

	// The three ways it stops, each independent.
	revokedAt := now.Add(-time.Minute)
	if (Token{ExpiresAt: now.Add(time.Hour), RevokedAt: &revokedAt}).UsableAt(now, StatusClaimed) {
		t.Error("a revoked credential resolves")
	}
	if (Token{ExpiresAt: now.Add(-time.Minute)}).UsableAt(now, StatusClaimed) {
		t.Error("an expired credential resolves")
	}

	// THE BOUNDARY IS >=, on both sides of the package: a token whose expiry is
	// exactly now is spent, and the resolution query agrees.
	if (Token{ExpiresAt: now}).UsableAt(now, StatusClaimed) {
		t.Error("a credential whose expiry is exactly now is still usable")
	}
	if !(Token{ExpiresAt: now.Add(time.Nanosecond)}).UsableAt(now, StatusClaimed) {
		t.Error("a credential a nanosecond from expiry is already spent")
	}

	// An unknown status is refused rather than treated as live, which is the
	// direction that fails closed.
	if live.UsableAt(now, "pending") {
		t.Error("a credential resolves for an agent in a status this build has never seen")
	}
}

// TestAnAgentThatWasClaimedStaysClaimedWhenDisabled is the ownership question
// separated from the liveness one, which is the reason IsClaimed exists rather
// than a comparison against StatusClaimed at every call site.
func TestAnAgentThatWasClaimedStaysClaimedWhenDisabled(t *testing.T) {
	account := id.MustNew()
	claimedAt := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

	disabled := Agent{Status: StatusDisabled, ClaimedByAccountID: &account, ClaimedAt: &claimedAt}
	if !disabled.IsClaimed() {
		t.Error("a disabled agent is not claimed, so a caller asking about ownership is told no")
	}

	unclaimed := Agent{Status: StatusUnclaimed}
	if unclaimed.IsClaimed() {
		t.Error("an unclaimed agent is claimed")
	}
}
