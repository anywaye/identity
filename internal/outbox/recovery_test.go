package outbox

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


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
	if data.Email != "owner@example.com" {
		t.Errorf("email = %q, want the user's address — the notice has no recipient without it", data.Email)
	}
}

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

func TestSessionsRevokedRefusesAnEmptyEmail(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	userID := id.MustNew()

	_, err := NewSessionsRevoked(now, userID, "", ReasonPasswordReset)
	if err == nil {
		t.Fatal("NewSessionsRevoked accepted an empty user address — the notice would have no recipient")
	}
}

func TestSessionsRevokedRefusesAnUnknownReason(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	userID := id.MustNew()

	_, err := NewSessionsRevoked(now, userID, "owner@example.com", "admin revocation")
	if err == nil {
		t.Fatal("NewSessionsRevoked accepted a reason this build does not implement")
	}
}

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
