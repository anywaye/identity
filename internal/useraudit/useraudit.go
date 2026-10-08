// Package useraudit is the record of what was done to a PERSON.
//
// # WHY THIS EXISTS ALONGER THAN account_audit_log
//
// `internal/admin` is the house's audit trail and it cannot hold a disable. That is
// not a missing column; it is `account_id NOT NULL` (migrations/00012) being load
// bearing. A disable names no account, which is DECISIONS.md D14 in one line:
// `users:disable` is its own scope with no account in its path because its subject is
// a person rather than one of their memberships. Inventing an account to hang a row
// on would reintroduce the tenancy fiction the scope exists to avoid — and a user
// belongs to as many accounts as they like, so "the caller's own account" would grant
// one tenant that power once per membership.
//
// So the log is scoped to a user, and it is scoped to a user for exactly the reason
// the scope is. What it copies from its twin is the discipline, not the schema: the
// append-only trigger, the two unconstrained actor ids, the closed set validated here
// rather than by the database, and the same-transaction write. Where it differs, the
// difference is that D14 removed something 00012 had — there is no account to be
// scoped by, so there is no per-tenant boundary to enforce, and
// `internal/tenancy`'s `identityTables` deliberately does not name this table.
package useraudit

import (
	"errors"
	"fmt"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
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
	// ActionUserDisabled is `POST /v1/users/{userID}/disable`.
	ActionUserDisabled Action = "user.disabled"

	// ActionUserEnabled is `POST /v1/users/{userID}/enable`.
	//
	// A SEPARATE ACTION AND NOT A REPEATED ONE, on the twin's reasoning: one person
	// turned off is a decision about a person, and an operator reading the trail
	// afterwards is asking "was this one, or was this all of them". The answer here
	// is not a count — `disabled_at` is a nullable column on one row, so there is
	// only ever one subject per event — but it is still a different event, and a
	// trail that recorded only the disable would answer "who turned this person
	// off, and when" while staying silent on the question that follows it: whether
	// the account is currently off at all.
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

// maxTraceIDLength matches the CHECK on the column, so a row this package refuses
// and a row the database refuses are the same set of rows rather than two sets that
// can drift.
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
	// UserID is the human on the other side: the token's holder on the machine
	// surface, the signed-in staff user on the staff surface.
	UserID id.UUID
	// KeyID is WHICH token. "Somebody" is not an answer an incident review can use.
	//
	// REQUIRED ON THE MACHINE SURFACE, and the gate enforces it there: that
	// surface is reachable only by a token, so every event in it was recorded by
	// one and an event with no key id is an event nobody can attribute to a
	// credential. ZERO ON THE STAFF SURFACE, where no token acted: a human
	// session has no row id to name, and inventing one would be a lie the table
	// then has to be trusted about. See `HumanSession`.
	KeyID id.UUID
	// TraceID joins the audit row to the request's log line. Never a token, and the
	// reason is the same one: a trace id is safe to print in both places.
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
		// A zero actor means the row would name nobody, and a record that names
		// nobody is a record of an action with no responsible party.
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
	// UserID is the subject: the person the operation was performed on. It is the
	// only subject this table has, and it is deliberately not accompanied by an
	// account (D14, and migrations/00022's header for the long form).
	UserID id.UUID
	Action Action
	Actor  Actor
	// OccurredAt is the service's clock, passed in so the row and the request that
	// made it agree and only one of the two is under test control.
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
		// NOT AN OPTIONAL FIELD. `occurred_at` is NOT NULL in the table, so a zero
		// time would be rejected by the database with a message about a timestamp
		// rather than about the caller that forgot the clock, and the refusal would
		// arrive from inside a transaction the caller is trying to roll back for
		// another reason. The epoch is not a time this service has ever acted at.
		return errors.New("an audit record must carry the instant it happened")
	}
	return nil
}
