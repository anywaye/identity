package outbox

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)

var eventAt = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

var (
	userA = fixtureID("6f1a3f2e-0000-4000-8000-00000000000a")
	credA = fixtureID("6f1a3f2e-0000-4000-8000-0000000000c1")
	credB = fixtureID("6f1a3f2e-0000-4000-8000-0000000000c2")
)

func fixtureID(raw string) id.UUID {
	parsed, err := id.Parse(raw)
	if err != nil {
		panic("outbox: parsing the fixture id " + raw + ": " + err.Error())
	}
	return parsed
}

func TestTheEventNamesAreCoreCatalogSpelling(t *testing.T) {
	cases := []struct{ got, want string }{
		{EventMFAEnabled, "identity.mfa.enabled"},
		{EventMFADisabled, "identity.mfa.disabled"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("event name = %q, want core's catalog spelling %q", c.got, c.want)
		}
	}
}

func TestMFAEventsAreThreeSegmentAndCarryTheUser(t *testing.T) {
	enabled, err := NewMFAEnabled(eventAt, userA, credA, "totp")
	if err != nil {
		t.Fatalf("NewMFAEnabled: %v", err)
	}
	disabled, err := NewMFADisabled(eventAt, userA, "totp")
	if err != nil {
		t.Fatalf("NewMFADisabled: %v", err)
	}

	for _, e := range []Envelope{enabled, disabled} {
		if got := strings.Count(e.Type, "."); got != 2 {
			t.Errorf("%s has %d segments, want 2", e.Type, got)
		}
		if e.Subject != userA.String() {
			t.Errorf("%s subject = %q, want the user %q", e.Type, e.Subject, userA)
		}
		if e.Source != SourceIdentity {
			t.Errorf("%s source = %q, want %q", e.Type, e.Source, SourceIdentity)
		}
		if !e.Time.Equal(eventAt) {
			t.Errorf("%s time = %s, want %s (the injected clock, so the row and the event agree)", e.Type, e.Time, eventAt)
		}
		if err := e.Validate(); err != nil {
			t.Errorf("%s is not a valid envelope: %v", e.Type, err)
		}
	}
}

func TestMFAEventPayloadsCarryNoCredential(t *testing.T) {
	canaries := []string{
		"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		"7KQF-4W2X-5DTR-M3HN",
		"a4b1c0f3e2d5a6b7c8d9e0f1a2b3c4d5",
		"otpauth://totp/anywaye%20identity?secret=JBSWY3DPEHPK3PXP",
	}

	enabled, err := NewMFAEnabled(eventAt, userA, credA, "totp")
	if err != nil {
		t.Fatalf("NewMFAEnabled: %v", err)
	}
	disabled, err := NewMFADisabled(eventAt, userA, "totp")
	if err != nil {
		t.Fatalf("NewMFADisabled: %v", err)
	}

	allowed := map[string]bool{"user_id": true, "credential_id": true, "method": true}
	for _, e := range []Envelope{enabled, disabled} {
		rendered := string(e.Data)
		for _, canary := range canaries {
			if strings.Contains(rendered, canary) {
				t.Errorf("%s payload carries %q: %s", e.Type, canary, rendered)
			}
		}
		var keys map[string]any
		if err := json.Unmarshal(e.Data, &keys); err != nil {
			t.Fatalf("%s payload is not an object: %v", e.Type, err)
		}
		for key := range keys {
			if !allowed[key] {
				t.Errorf("%s payload has an unexpected key %q: %s", e.Type, key, rendered)
			}
		}
	}

	var enabledPayload struct {
		UserID       string `json:"user_id"`
		CredentialID string `json:"credential_id"`
		Method       string `json:"method"`
	}
	if err := json.Unmarshal(enabled.Data, &enabledPayload); err != nil {
		t.Fatalf("the enabled payload: %v", err)
	}
	if enabledPayload.UserID != userA.String() || enabledPayload.CredentialID != credA.String() {
		t.Errorf("enabled payload = %+v", enabledPayload)
	}
	if enabledPayload.Method != "totp" {
		t.Errorf("method = %q, want the caller's own string", enabledPayload.Method)
	}
}

func TestTheDisabledPayloadNamesWhatStillExists(t *testing.T) {
	disabled, err := NewMFADisabled(eventAt, userA, "totp")
	if err != nil {
		t.Fatalf("NewMFADisabled: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(disabled.Data, &payload); err != nil {
		t.Fatalf("the disabled payload: %v", err)
	}
	if _, present := payload["credential_id"]; present {
		t.Error("the disabled payload carries a credential id, which is gone by the time the event is written")
	}
	if payload["user_id"] != userA.String() || payload["method"] != "totp" {
		t.Errorf("disabled payload = %v", payload)
	}
}

func TestMFAEventsHaveDistinctEnvelopeIDs(t *testing.T) {
	first, err := NewMFAEnabled(eventAt, userA, credA, "totp")
	if err != nil {
		t.Fatalf("NewMFAEnabled: %v", err)
	}
	second, err := NewMFAEnabled(eventAt, userA, credB, "totp")
	if err != nil {
		t.Fatalf("NewMFAEnabled: %v", err)
	}
	if first.ID == second.ID {
		t.Error("two events about the same user share an envelope id")
	}
	if len(first.Data) == 0 || len(second.Data) == 0 {
		t.Error("an event has no payload")
	}
}
