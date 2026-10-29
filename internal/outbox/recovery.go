package outbox

import (
	"fmt"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


const (
	EventUserEmailVerified = "identity.user.email_verified"

	EventSessionsRevoked = "identity.session.revoked"
)

const (
	ReasonPasswordReset = "password reset"

	ReasonEmailChanged = "email address changed"
)

func validateReason(reason string) error {
	switch reason {
	case ReasonPasswordReset, ReasonEmailChanged:
		return nil
	default:
		return fmt.Errorf("outbox: %q is not a reason this service ends credentials for", reason)
	}
}

// NewUserEmailVerified builds the event emitted when an address is proved.
//
// THERE IS NO SECRET IN THIS PAYLOAD, and the omission is the interesting part: no
// token, no digest, and no address beyond the one already on the account row. Every
// event on the platform reaches every subscriber, which is exactly the wrong place
// for a credential.
//
// THE ADDRESS IS OMITTED ANYWAY, and not for the reason this comment used to give.
// "A fact every consumer can already read from the user it is about" was true only
// for a consumer holding an identity client; the fleet's actual consumer has none
// (REPORT-courier-consumer-invite-01 §2.6), which is why the three events that
// carry a mail each carry the address — or the token — themselves. This one
// carries neither because no consumer mails on it: the verification flow mails the
// link, not a confirmation after. When one does, the field is added here, at the
// builder, so that no call site can forget it.
func NewUserEmailVerified(now time.Time, userID id.UUID) (Envelope, error) {
	return newSubjectEvent(now, EventUserEmailVerified, userID.String(), struct {
		UserID string `json:"user_id"`
	}{
		UserID: userID.String(),
	})
}

// NewSessionsRevoked builds the event emitted when every credential a user holds
// is ended.
//
// `reason` is required and is one of the two constants above. It is validated here
// rather than at the call site because a caller that passed an arbitrary string
// would produce an envelope that satisfies the schema and says nothing a consumer
// can act on.
//
// `email` is required for the same fail-closed reason, and it travels because
// both notices this event can trigger are mailed: "your password was changed"
// (reason `password reset`) and "your email address was changed" (reason `email
// address changed`). The consumer is cross-service — courier has no identity
// client and no identity tables — so the address is not a fact it can read from
// the user row (REPORT-courier-consumer-invite-01 §2.6).
func NewSessionsRevoked(now time.Time, userID id.UUID, email, reason string) (Envelope, error) {
	if err := validateReason(reason); err != nil {
		return Envelope{}, err
	}
	if email == "" {
		return Envelope{}, fmt.Errorf("outbox: refusing to build an %s payload with no user address", EventSessionsRevoked)
	}
	return newSubjectEvent(now, EventSessionsRevoked, userID.String(), struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
		Reason string `json:"reason"`
	}{
		UserID: userID.String(),
		Email:  email,
		Reason: reason,
	})
}
