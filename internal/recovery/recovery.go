package recovery

import (
	"context"
	"errors"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/users"
)

// Purpose is what a row of `recovery_tokens` is for.
//
// IT IS A CLOSED SET IN GO AND A CHECK IN THE SCHEMA, for the reason 00011 gives
// for api_keys.scopes: a closed vocabulary is a code fact, and putting it in the
// schema would make adding a purpose a migration. The CHECK is a second opinion,
// and a row naming a purpose this build does not know about is refused on the way
// in — which is the fail-closed direction, since treating an unknown purpose as
// "and so anything goes" is the bug a later migration would otherwise introduce
// silently.
type Purpose string

const (
	PurposePasswordReset Purpose = "password_reset"

	PurposeVerifyEmail Purpose = "verify_email"

	PurposeEmailChange Purpose = "email_change"

	PurposeSessionLink Purpose = "session_link"
)

func allPurposes() []Purpose {
	return []Purpose{
		PurposePasswordReset,
		PurposeVerifyEmail,
		PurposeEmailChange,
		PurposeSessionLink,
	}
}

var callerDeliveredPurposes = map[Purpose]string{
	PurposeSessionLink: "the credential holder that minted it delivers it and relays the redeem",
}

const (
	PasswordResetTTL = 30 * time.Minute

	VerifyEmailTTL = 24 * time.Hour

	EmailChangeTTL = 24 * time.Hour

	// SessionLinkTTL is ten minutes.
	//
	// MUCH SHORTER THAN THE OTHER TWO, and the reasoning is not that a link is more
	// dangerous — it is not, since it can only mint the session its subject could
	// have had by signing in anyway. The reasoning is that the other three windows
	// are sized around DELIVERY, and this one is not delivered by this service at
	// all: the caller hands the token to a browser that is already in front of
	// somebody. Ten minutes is long enough for a person to read a message, open a
	// link, have it relayed and click through, and short enough that a link which
	// escapes into a chat log, a support ticket or a shared browser history is dead
	// by lunchtime.
	//
	// MaxSessionLinkTTL is one hour, and it is the answer to "a caller may choose a
	// shorter window" rather than a license to choose a longer one. The maximum is
	// what actually bounds how long a delivered link stays live, so it is a
	// published number rather than a field the caller fills in.
	SessionLinkTTL    = 10 * time.Minute
	MaxSessionLinkTTL = time.Hour

	RequestWindow = time.Minute
)

// TTLFor is a purpose's window. It is a function rather than three exported
// constants read at the call site because the call sites are the use cases, and a
// use case that picked its own window would be a use case that could pick a
// different one on a different day.
func TTLFor(p Purpose) time.Duration {
	switch p {
	case PurposeVerifyEmail, PurposeEmailChange:
		return VerifyEmailTTL
	case PurposeSessionLink:
		return SessionLinkTTL
	default:
		return PasswordResetTTL
	}
}

var (
	ErrTokenNotFound = errors.New("no live recovery token matches that")

	ErrNoMailer = errors.New("this deployment cannot send email")

	ErrEmailTaken = users.ErrEmailTaken

	ErrSameAddress = errors.New("that is already this account's address")
)

// Message is one email, and it is the whole of what leaves this process.
//
// IT IS A VALUE WITH NO TEMPLATE NAME, and that is the property worth reading: the
// subject and the body are already rendered by the time anything else sees this
// struct, so there is no code path where a delivery adapter chooses what the mail
// says and no code path where a body is built with a token in one branch and
// without it in another.
//
// A message carries no template identifier and no layout, deliberately. The moment
// this type grows a `Template` field, identity has taken courier's rendering
// decisions, and the two will disagree.
//
// # WHY THERE IS ONE FIELD THAT IS NOT PROSE, AND WHY IT IS NOT A `Template`
//
// `UserID`, and a reader will reasonably assume the rule above forbids it. The
// distinction is the difference between a RENDERING decision and a FACT about the
// recipient, and it is worth being exact about because both are fields on this
// struct.
//
// A `Template` field would be a rendering decision — "use layout 3", "use the HTML
// variant" — and identity would then be a second opinion about how a mail looks,
// disagreeing with the service that renders it. `UserID` is not that. It says WHICH
// ACCOUNT the message is about, and a platform mailer needs that for reasons with
// nothing to do with prose:
//
//   - courier reads that recipient's notification preferences by it, so a send
//     without one cannot be checked against a decline;
//   - it is what the `courier.email.delivered` event is attributed to, so a bounce
//     can be traced back to the account it concerned.
//
// Naming the account by ADDRESS would be worse than useless for both. An address
// changes — that is the entire point of the email-change flow two files over — and
// a preference table and a suppression list are keyed by an opaque id. Every body
// here names the address in prose because a PERSON reads it; none carries a uuid
// because a person has no use for one.
//
// So this is a fact every flow in this package already held. It was not on the
// struct because no implementation needed it, and adding it is the composition the
// delivery seam needed rather than a widening of the `Mailer` interface: `Send`
// still takes one argument and returns one error, and no implementation learns
// about courier.
type Message struct {
	To string
	Subject string
	Body    string

	UserID id.UUID
}

// Mailer hands one rendered message to the platform's mail service.
//
// ONE SEAM, TWO METHODS, and the second one is not padding. `Ready` exists because
// every request flow has to know whether a message CAN be delivered BEFORE it
// decides to mint a token, and the reason it has to know is the enumeration
// property: a deployment that cannot send mail has to refuse a reset request for a
// registered address and a reset request for an unregistered one at the same
// place, or "503" against "202" becomes an account-existence oracle. Asking the
// seam is honest about what it knows; a `mailer != Unavailable{}` type assertion
// in three flows is not.
//
// An implementation MUST NOT log a message, and the reason is the token in the
// body. Every message this package produces contains a live credential until it is
// spent, and an operator's log aggregator is searchable, retained, and usually
// readable by everybody who can read a deployment's metrics.
type Mailer interface {
	Send(ctx context.Context, m Message) error

	Ready(ctx context.Context) error
}

// Unavailable is the Mailer a deployment with no delivery path has.
//
// IT FAILS LOUDLY AND IT FAILS EVERY TIME, which is the whole of its design. The
// tempting alternative — a logger, or a nil check somewhere further up — produces
// a service that tells a user their password reset is on its way and drops the
// message on the floor, and a user who believes a reset was sent and was not is a
// user who does not ask a human for help.
//
// It is a struct rather than a nil Mailer so that no caller has to decide whether
// a nil is a supported configuration, and `main` cannot wire a process in which
// the flows are mounted and silent.
//
// # IT IS STILL REACHABLE, AND THAT IS THE REASON TO KEEP IT
//
// A courier-backed implementation exists, so the obvious question is why this one
// is not deleted. Because a deployment with no `COURIER_TOKEN` is a SUPPORTED
// state — a local stack, or one where mail has not been turned on — and the honest
// shape of "this deployment cannot send email" is a seam that refuses rather than a
// `nil` that panics, a logger that leaks the token, or a `courier.Client` built
// from an empty credential that would present nothing and get a 401 per send.
//
// `TestAMailerIsCouriersOrUnavailableAndNothingElse` in `cmd/identity` holds that
// these are the only two things `buildMailer` can return, so an "unavailable" a
// reader cannot reach is not hiding here.
type Unavailable struct{}

// Send returns ErrNoMailer.
func (Unavailable) Send(context.Context, Message) error { return ErrNoMailer }

// Ready returns ErrNoMailer.
func (Unavailable) Ready(context.Context) error { return ErrNoMailer }
