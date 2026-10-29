package agents

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


func TestTheLifecycleAllowsExactlyTheseTransitions(t *testing.T) {
	cases := []struct {
		name string
		from string
		to   string
		want bool
	}{
		{"an agent registers unclaimed and is claimed", StatusUnclaimed, StatusClaimed, true},
		{"a claimed agent is disabled", StatusClaimed, StatusDisabled, true},
		{"a disabled agent is re-enabled", StatusDisabled, StatusClaimed, true},

		{"unclaimed again while unclaimed", StatusUnclaimed, StatusUnclaimed, true},
		{"claimed again while claimed", StatusClaimed, StatusClaimed, true},
		{"disabled again while disabled", StatusDisabled, StatusDisabled, true},

		{"an unclaimed agent cannot be disabled", StatusUnclaimed, StatusDisabled, false},

		{"a claimed agent cannot go back to unclaimed", StatusClaimed, StatusUnclaimed, false},
		{"a disabled agent cannot go back to unclaimed", StatusDisabled, StatusUnclaimed, false},

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

func TestATokenAndItsDigestAreOneFact(t *testing.T) {
	for i := range 16 {
		token, digest, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}

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

		if len(digest) != 64 {
			t.Fatalf("token %d's digest is %d characters, want 64", i, len(digest))
		}
		if digest != strings.ToLower(digest) {
			t.Errorf("token %d's digest is not lower case: %q", i, digest)
		}
		if strings.ContainsAny(digest, "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ+/=") {
			t.Errorf("token %d's digest is not hex: %q", i, digest)
		}

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

func TestACredentialIsJudgedAgainstTheAgentsStatus(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	live := Token{CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}

	for _, status := range []string{StatusUnclaimed, StatusDisabled} {
		if live.UsableAt(now, status) {
			t.Errorf("a credential resolves for an agent in status %q", status)
		}
	}
	if !live.UsableAt(now, StatusClaimed) {
		t.Error("a live credential does not resolve for a claimed agent")
	}

	revokedAt := now.Add(-time.Minute)
	if (Token{ExpiresAt: now.Add(time.Hour), RevokedAt: &revokedAt}).UsableAt(now, StatusClaimed) {
		t.Error("a revoked credential resolves")
	}
	if (Token{ExpiresAt: now.Add(-time.Minute)}).UsableAt(now, StatusClaimed) {
		t.Error("an expired credential resolves")
	}

	if (Token{ExpiresAt: now}).UsableAt(now, StatusClaimed) {
		t.Error("a credential whose expiry is exactly now is still usable")
	}
	if !(Token{ExpiresAt: now.Add(time.Nanosecond)}).UsableAt(now, StatusClaimed) {
		t.Error("a credential a nanosecond from expiry is already spent")
	}

	if live.UsableAt(now, "pending") {
		t.Error("a credential resolves for an agent in a status this build has never seen")
	}
}

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
