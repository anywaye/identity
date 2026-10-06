package outbox

import (
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// # THE USER-SCOPED LIFECYCLE EVENTS.
//
// `identity.user.created` is declared in cafaye.yml because core ships a payload
// schema for it. This file's event does not have one — core 0.2's catalog has no
// row for a deletion at all — so it is emitted undeclared and pinned in
// `internal/platform/ci/event_grammar_test.go`'s `knownUndeclaredEvents`, which
// is the honest place for a gap that is blocked on core rather than here.
//
// # WHY THE PAYLOAD IS AN ID AND NOTHING ELSE
//
// The obvious temptation is to put the email in here, so a consumer can address
// the person without a call back. That is the same argument `NewUserEmailVerified`
// rejects and it is worth restating because here it is stronger: by the time this
// event is written the `users` row is GONE inside the same transaction, so the
// email is no longer readable by anybody — including the publisher. A payload
// carrying it would be the only surviving copy of the address, in the one table
// that every subscriber on the platform can read. There is no consumer for whom
// that is a trade worth making, and the id is enough: a consumer that needs the
// person asks a service that still has them, or reads its own copy of the
// relationship this event announces.

// EventUserDeleted is emitted when a person ends their own account.
//
// IT IS A DIFFERENT EVENT FROM `identity.session.revoked`, and the difference is
// what a consumer can conclude. That one means "this person's credentials are
// gone; drop whatever you cached against them" and the person is still here. This
// one means the row is gone, and a consumer holding a customer record, a
// subscription, an address book entry or a support thread is holding a reference
// to something that will not resolve again.
//
// # WHY IT IS NOT `identity.user.disabled`
//
// That event does not exist, and `user_audit_log`'s `user.disabled` is a
// different thing with a different reader: it is the record of an OPERATOR
// turning somebody off, which outlives the user by design. A self-service
// deletion has no operator, and conflating the two would put "they asked for it"
// and "we did it to them" on one wire type where a consumer cannot tell them
// apart. That distinction is the whole reason both names are worth having.
const EventUserDeleted = "identity.user.deleted"

// NewUserDeleted builds the event emitted when a user removes their own account.
//
// `at` is the service's clock rather than the database's, for the reason every
// other constructor here takes one: the transaction has one instant, and an event
// whose timestamp is `now()` inside a statement that also committed three other
// writes is an event whose time depends on how long the lock was held.
func NewUserDeleted(now time.Time, userID id.UUID) (Envelope, error) {
	return newSubjectEvent(now, EventUserDeleted, userID.String(), struct {
		UserID string `json:"user_id"`
	}{
		UserID: userID.String(),
	})
}
