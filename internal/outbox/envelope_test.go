package outbox

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


func TestEnvelopeValidatesAgainstCoreSchema(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		give    Envelope
		wantErr string
	}{
		{
			name: "a well-formed envelope",
			give: Envelope{
				SpecVersion: SpecVersion,
				ID:          id.MustNew(),
				Type:        EventUserCreated,
				Source:      SourceIdentity,
				Subject:     "usr_01J9Z8QK5M4N7P2R3T6V8W9X0A",
				Time:        time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC),
				Data:        json.RawMessage(`{"user_id":"usr_01J9Z8QK5M4N7P2R3T6V8W9X0A"}`),
			},
		},
		{
			name: "a wrong specversion",
			give: Envelope{SpecVersion: "0.9", ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "specversion",
		},
		{
			name: "a missing id",
			give: Envelope{SpecVersion: SpecVersion, Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "id",
		},
		{
			name: "the nil id",
			give: Envelope{SpecVersion: SpecVersion, ID: id.UUID{}, Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "id",
		},
		{
			name: "an upper-case segment",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: "identity.User.created", Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "type",
		},
		{
			name: "camelCase is not snake_case",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: "identity.userCreated", Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "type",
		},
		{
			name: "a single segment",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: "created", Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "type",
		},
		{
			name: "four segments",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: "a.b.c.d", Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "type",
		},
		{
			name: "an upper-case source",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: "Identity",
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "source",
		},
		{
			name: "a source with an underscore",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: "my_service",
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "source",
		},
		{
			name: "an empty subject means no single entity",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
		},
		{
			name: "the platform subject",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "platform", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
		},
		{
			name: "an over-long subject",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: strings.Repeat("u", 201), Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "subject",
		},
		{
			name: "a subject containing a space",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr 1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "subject",
		},
		{
			name: "a zero time",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr_1", Time: time.Time{}, Data: json.RawMessage(`{}`)},
			wantErr: "time",
		},
		{
			name: "absent data",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC()},
			wantErr: "data",
		},
		{
			name: "data that is not JSON at all",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{broken`)},
			wantErr: "data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.give.Validate()

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want an error about %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestEnvelopeMarshalsToExactlyTheCoreAttributeSet(t *testing.T) {
	t.Parallel()

	e := Envelope{
		SpecVersion: SpecVersion,
		ID:          id.MustNew(),
		Type:        EventUserCreated,
		Source:      SourceIdentity,
		Subject:     "usr_01J9Z8QK5M4N7P2R3T6V8W9X0A",
		Time:        time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC),
		Data:        json.RawMessage(`{"user_id":"usr_1","email":"kaka@example.com"}`),
	}

	encoded, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	want := map[string]bool{
		"specversion": true, "id": true, "type": true,
		"source": true, "subject": true, "time": true, "data": true,
	}
	for name := range decoded {
		if !want[name] {
			t.Errorf("envelope carries %q, which core's schema does not define", name)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("envelope is missing %q", name)
	}

	if got := decoded["specversion"]; got != "1.0" {
		t.Errorf("specversion = %v, want \"1.0\"", got)
	}
	if got := decoded["time"]; got != "2026-09-30T04:19:00Z" {
		t.Errorf("time = %v, want 2026-09-30T04:19:00Z", got)
	}
	data, ok := decoded["data"].(map[string]any)
	if !ok {
		t.Fatalf("data = %#v, want a JSON object", decoded["data"])
	}
	if data["email"] != "kaka@example.com" {
		t.Errorf("data.email = %v, want kaka@example.com", data["email"])
	}
}

func TestEnvelopeOmitsAnEmptySubject(t *testing.T) {
	t.Parallel()

	e := Envelope{
		SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
		Time: time.Now().UTC(), Data: json.RawMessage(`{}`),
	}

	encoded, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(encoded), "subject") {
		t.Errorf("envelope %s carries an empty subject; core's pattern requires minLength 1", encoded)
	}
}

func TestUserCreatedEnvelope(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC)
	userID := id.MustNew()

	e, err := NewUserCreated(now, userID, "kaka@example.com")
	if err != nil {
		t.Fatalf("NewUserCreated: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Errorf("the envelope this service builds does not satisfy its own contract: %v", err)
	}
	if e.Type != EventUserCreated {
		t.Errorf("Type = %q, want %q", e.Type, EventUserCreated)
	}
	if e.Source != SourceIdentity {
		t.Errorf("Source = %q, want %q — it must equal `name` in anywaye.yml", e.Source, SourceIdentity)
	}
	if e.Subject != userID.String() {
		t.Errorf("Subject = %q, want the user id %q", e.Subject, userID)
	}
	if !e.Time.Equal(now) {
		t.Errorf("Time = %s, want %s — it is the state change, not the publish", e.Time, now)
	}
	if e.ID.IsZero() {
		t.Error("ID is zero; consumers deduplicate on it")
	}

	encoded, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded struct {
		Data struct {
			UserID string `json:"user_id"`
			Email  string `json:"email"`
		} `json:"data"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Data.UserID != userID.String() {
		t.Errorf("data.user_id = %q, want %q", decoded.Data.UserID, userID)
	}
	if decoded.Data.Email != "kaka@example.com" {
		t.Errorf("data.email = %q, want kaka@example.com", decoded.Data.Email)
	}
}

func TestNewUserCreatedIsUniquePerCall(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()

	first, err := NewUserCreated(now, id.MustNew(), "a@example.com")
	if err != nil {
		t.Fatalf("NewUserCreated: %v", err)
	}
	second, err := NewUserCreated(now, id.MustNew(), "b@example.com")
	if err != nil {
		t.Fatalf("NewUserCreated: %v", err)
	}

	if first.ID == second.ID {
		t.Error("two registrations produced the same envelope id")
	}
}

func TestUserCreatedDataIsStable(t *testing.T) {
	t.Parallel()

	userID := id.MustNew()

	e, err := NewUserCreated(time.Now().UTC(), userID, "kaka@example.com")
	if err != nil {
		t.Fatalf("NewUserCreated: %v", err)
	}

	want := `{"user_id":"` + userID.String() + `","email":"kaka@example.com"}`
	if got := string(e.Data); got != want {
		t.Errorf("Data = %s, want %s", got, want)
	}
}
