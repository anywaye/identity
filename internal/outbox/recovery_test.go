package outbox

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)

// The two recovery events, under the same envelope rules as the tenancy ones:
// every event is validated here against core's envelope rules before it can
// reach the table, because a malformed event is rejected by every consumer on
// the platform rather than at the one place that wrote it.

func TestSessionsRevokedEnvelope(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	userID := id.MustNew()

	e, err := NewSessionsRevoked(now, userID, "owner@example.com", ReasonPasswordReset)
	if err != nil {
		t.Fatalf("NewSessionsRevoked: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope does not satisfy core's schema: %v", err)
	}
	if e.Type != EventSessionsRevoked {
		t.Errorf("type = %q, want %q", e.Type, EventSessionsRevoked)
	}
	// The subject is the user, not an account: the credentials ended belong to
	// one person, and a consumer dropping its cache for them keys on this.
	if e.Subject != userID.String() {
		t.Errorf("subject = %q, want the user id %q", e.Subject, userID)
	}

	var data struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
		Reason string `json:"reason"`
	}
	decodeData(t, e, &data)

	if data.UserID != userID.String() {
		t.Errorf("user_id = %q, want %q", data.UserID, userID)
	}
	if data.Reason != "password reset" {
		t.Errorf("reason = %q, want %q", data.Reason, "password reset")
	}
	// The address travels because both notices this event can trigger are mailed
	// — "your password was changed" and "your email address was changed" — and the
	// consumer that mails them cannot read the user row. See NewSessionsRevoked.
	if data.Email != "owner@example.com" {
		t.Errorf("email = %q, want the user's address — the notice has no recipient without it", data.Email)
	}
}

// TestSessionsRevokedCarriesTheEmailChangeReason is the second half of the
// closed set: the address-moved notice goes to the address the user holds when
// the event is built, which for this reason is the NEW one. The choice is
// recorded in REPORT-identity-event-payloads-01; what is pinned here is that
// the reason and the address travel together.
func TestSessionsRevokedCarriesTheEmailChangeReason(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	userID := id.MustNew()

	e, err := NewSessionsRevoked(now, userID, "new-address@example.com", ReasonEmailChanged)
	if err != nil {
		t.Fatalf("NewSessionsRevoked: %v", err)
	}

	var data struct {
		Email  string `json:"email"`
		Reason string `json:"reason"`
	}
	decodeData(t, e, &data)

	if data.Reason != "email address changed" {
		t.Errorf("reason = %q, want %q", data.Reason, "email address changed")
	}
	if data.Email != "new-address@example.com" {
		t.Errorf("email = %q, want the address the user holds after the move", data.Email)
	}
}

// TestSessionsRevokedRefusesAnEmptyEmail is the fail-closed half of the payload
// above: a notice with no recipient is not a notice, and an event that omitted
// the address would leave the consumer holding a fact it cannot act on.
func TestSessionsRevokedRefusesAnEmptyEmail(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	userID := id.MustNew()

	_, err := NewSessionsRevoked(now, userID, "", ReasonPasswordReset)
	if err == nil {
		t.Fatal("NewSessionsRevoked accepted an empty user address — the notice would have no recipient")
	}
}

// TestSessionsRevokedRefusesAnUnknownReason pins the closed set itself. A
// reason this build does not implement is refused at the builder rather than
// published, because a consumer switching on `reason` cannot act on a value it
// has never seen — the same rule api_keys' scopes follow.
func TestSessionsRevokedRefusesAnUnknownReason(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	userID := id.MustNew()

	_, err := NewSessionsRevoked(now, userID, "owner@example.com", "admin revocation")
	if err == nil {
		t.Fatal("NewSessionsRevoked accepted a reason this build does not implement")
	}
}

// TestUserEmailVerifiedEnvelope pins the deliberate omission: this event
// carries a user id and nothing else, because no consumer mails on it — the
// verification flow mails the LINK, not a confirmation after. core's payload
// schema for the type says the same ("ONE field, and the emptiness is the
// contract"), so a field added here without a decision would be a contract
// change wearing a feature's clothes.
func TestUserEmailVerifiedEnvelope(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	userID := id.MustNew()

	e, err := NewUserEmailVerified(now, userID)
	if err != nil {
		t.Fatalf("NewUserEmailVerified: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope does not satisfy core's schema: %v", err)
	}
	if e.Type != EventUserEmailVerified {
		t.Errorf("type = %q, want %q", e.Type, EventUserEmailVerified)
	}
	if e.Subject != userID.String() {
		t.Errorf("subject = %q, want the user id %q", e.Subject, userID)
	}

	var data map[string]any
	if err := json.Unmarshal(e.Data, &data); err != nil {
		t.Fatalf("the payload is not the object the test expects: %v\n%s", err, e.Data)
	}
	if len(data) != 1 || data["user_id"] != userID.String() {
		t.Errorf("payload = %v, want exactly {user_id: %s} — the address and the token are deliberately absent", data, userID)
	}
}
