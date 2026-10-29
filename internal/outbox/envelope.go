package outbox

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)

const (
	SpecVersion = "1.0"

	SourceIdentity = "identity"

	EventUserCreated = "identity.user.created"
)

// Envelope is the anywaye event envelope, reproducing
// anywaye/core/schemas/event-envelope.schema.json.
//
// The JSON tags are the wire contract. core sets additionalProperties:false, so
// every attribute is declared here and nothing else is ever added: an undeclared
// attribute is rejected by every consumer on the platform.
//
// `subject` is omitempty because core requires minLength 1 on it — emitting
// `""` for an event with no entity would fail validation, whereas omitting it
// passes. Entity events in this service always have one.
type Envelope struct {
	SpecVersion string          `json:"specversion"`
	ID          id.UUID         `json:"id"`
	Type        string          `json:"type"`
	Source      string          `json:"source"`
	Subject     string          `json:"subject,omitempty"`
	Time        time.Time       `json:"time"`
	Data        json.RawMessage `json:"data"`
}

var (
	eventTypePattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*(\.[a-z][a-z0-9]*(_[a-z0-9]+)*){1,2}$`)
	serviceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	subjectPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]*$`)
)

const (
	maxSubjectLength = 200
	minSourceLength  = 2
	maxSourceLength  = 40
	minTypeLength    = 5
	maxTypeLength    = 120
)

// Validate reports whether the envelope satisfies core's schema.
//
// It is called before every append. The alternative is letting a bad envelope
// reach the table and fail at every consumer instead of at the one place that
// wrote it — and the table's CHECK constraints would catch the two patterns, but
// not a missing subject or an unparseable payload.
func (e Envelope) Validate() error {
	if e.SpecVersion != SpecVersion {
		return fmt.Errorf("outbox: specversion is %q, want %q", e.SpecVersion, SpecVersion)
	}
	if e.ID.IsZero() {
		return fmt.Errorf("outbox: id is required; consumers deduplicate on it")
	}
	if !validEventType(e.Type) {
		return fmt.Errorf("outbox: type %q does not match core's eventType pattern", e.Type)
	}
	if !validServiceName(e.Source) {
		return fmt.Errorf("outbox: source %q does not match core's serviceName pattern", e.Source)
	}
	if e.Subject != "" {
		if len(e.Subject) > maxSubjectLength {
			return fmt.Errorf("outbox: subject is %d characters, want at most %d", len(e.Subject), maxSubjectLength)
		}
		if !subjectPattern.MatchString(e.Subject) {
			return fmt.Errorf("outbox: subject %q does not match core's subject pattern", e.Subject)
		}
	}
	if e.Time.IsZero() {
		return fmt.Errorf("outbox: time is required")
	}
	if !json.Valid(e.Data) {
		return fmt.Errorf("outbox: data is not valid JSON")
	}
	return nil
}

// NewUserCreated builds the event emitted when a registration succeeds.
//
// now is the moment of the state change, not the moment of publishing, and it
// comes from the injected clock for the same reason every other timestamp in this
// service does: the two must agree, and only one of them is under test control.
//
// The payload carries the user id and email and nothing else. In particular no
// password digest and no lockout state: the envelope goes to every subscriber on
// the platform, and this is the only place where that boundary is enforced.
func NewUserCreated(now time.Time, userID id.UUID, email string) (Envelope, error) {
	eventID, err := id.New()
	if err != nil {
		return Envelope{}, fmt.Errorf("outbox: minting an envelope id: %w", err)
	}

	payload, err := json.Marshal(struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
	}{UserID: userID.String(), Email: email})
	if err != nil {
		return Envelope{}, fmt.Errorf("outbox: building the user.created payload: %w", err)
	}

	return Envelope{
		SpecVersion: SpecVersion,
		ID:          eventID,
		Type:        EventUserCreated,
		Source:      SourceIdentity,
		Subject:     userID.String(),
		Time:        now.UTC(),
		Data:        payload,
	}, nil
}

func validEventType(s string) bool {
	if len(s) < minTypeLength || len(s) > maxTypeLength {
		return false
	}
	return eventTypePattern.MatchString(s)
}

func validServiceName(s string) bool {
	if len(s) < minSourceLength || len(s) > maxSourceLength {
		return false
	}
	return serviceNamePattern.MatchString(s)
}
