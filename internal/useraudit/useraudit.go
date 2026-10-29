package useraudit

import (
	"errors"
	"fmt"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)

// Action is one of the things that can be done to a person by an operator.
//
// IT IS A CLOSED SET IN GO AND NOT A CHECK IN THE SCHEMA, and the reason is the one
// 00011 gives for `api_keys.scopes` and 00012 gives for its own action column: a
// closed vocabulary is a code fact, and putting it in the schema would make adding
// an action a migration. A row holding an action this build does not know about is
// refused at the point of use, which is the fail-closed direction — treating an
// unknown action as "and so anything goes" is the bug a future migration would
// otherwise introduce silently.
type Action string

const (
	ActionUserDisabled Action = "user.disabled"

	ActionUserEnabled Action = "user.enabled"
)

// AllActions is the vocabulary, in a fixed order, for the same reason
// admin.AllActions is: the order reaches a response, and a map's iteration order
// would make two identical requests answer differently.
func AllActions() []Action {
	return []Action{ActionUserDisabled, ActionUserEnabled}
}

// ErrUnknownAction is a row or a request naming an action this build does not
// implement.
var ErrUnknownAction = errors.New("not an action the operator surface performs")

func validateAction(action string) error {
	for _, known := range AllActions() {
		if string(known) == action {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrUnknownAction, action)
}

const maxTraceIDLength = 64

// Actor is who performed the operation.
//
// TWO IDS AND A TRACE ID, and the absence of a third field is the design — copied
// from admin.Actor, and for its reason: this reaches a table an operator reads
// during an incident, and an api key's VALUE must never reach it. The row id is what
// the operator needs anyway, because that is the id they revoke by.
//
// A ZERO KEY ID IS A HUMAN SESSION, and that sentence is new in D17. The machine
// surface (D14) is token-only, so every row it wrote named a key; the staff
// surface is session-only, so its rows name the signed-in staff user and no key.
// The column stays NOT NULL — the nil uuid is a value, not an absence — and
// `HumanSession` is how a reader tells the two apart. `validate` still requires
// the user and the trace id on every row: a record that names nobody, or that
// cannot be joined to its request's log line, is refused whichever surface
// wrote it. The per-surface gates keep the stronger promise: `operatorActorFrom`
// (machine) 500s on a zero key, because a token call without one is a wiring
// fault rather than a request.
type Actor struct {
	UserID id.UUID
	KeyID id.UUID
	TraceID string
}

// HumanSession reports whether this action was performed by a signed-in staff
// human rather than by a machine credential.
//
// It is a method rather than a comparison against the nil uuid at every call
// site because the two answers callers want are "was this a person" and "was
// this a token", and a caller that forgets the second has made a claim about a
// credential nobody presented.
func (a Actor) HumanSession() bool { return a.KeyID.IsZero() }

func (a Actor) validate() error {
	if a.UserID.IsZero() {
		return errors.New("an operator action must name the user that performed it")
	}
	if a.TraceID == "" {
		return errors.New("an operator action must carry the request's trace id")
	}
	if len(a.TraceID) > maxTraceIDLength {
		return fmt.Errorf("an audit record's trace id is %d characters, over the %d accepted", len(a.TraceID), maxTraceIDLength)
	}
	return nil
}

// Entry is a request to record one event. It is what an operation builds from its
// own inputs; Record is what comes back out of the table.
type Entry struct {
	UserID id.UUID
	Action Action
	Actor  Actor
	OccurredAt time.Time
}

// Record is one row of user_audit_log.
type Record struct {
	ID          id.UUID
	UserID      id.UUID
	Action      Action
	ActorUserID id.UUID
	ActorKeyID  id.UUID
	TraceID     string
	OccurredAt  time.Time
}

func (e Entry) validate() error {
	if e.UserID.IsZero() {
		return errors.New("an audit record must name the user it was taken on")
	}
	if err := validateAction(string(e.Action)); err != nil {
		return err
	}
	if err := e.Actor.validate(); err != nil {
		return err
	}
	if e.OccurredAt.IsZero() {
		return errors.New("an audit record must carry the instant it happened")
	}
	return nil
}
