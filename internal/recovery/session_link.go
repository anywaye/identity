package recovery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// THE MINT, AND THE REFUSALS A MINT OWNS.
//
// Two routes, and this file is the half of them a machine credential reaches.
// The other half — spending the token and writing a session — is in
// session_link_redeem.go, and the two are here rather than in the three mailed
// flows above because neither of them mails anything.
//
// # WHAT A LINK IS: A DELIBERATE FAILURE OF DELIVERY, NOT A FOURTH MAIL
//
// The other three purposes exist because a person cannot finish the flow without
// an inbox, so this service sends the message. A session link has no inbox behind
// it: the caller that holds `sessions:write` already has a channel to the browser
// in front of the user, and minting a message here would put a second delivery
// path beside courier's for a message nobody asked this service to send. That is
// the whole of `callerDeliveredPurposes`, and it is why there is no `messageKind`
// on this path and no `Mailer.Ready` check in `MintSessionLink`.
//
// # THE REFUSALS, AND WHY EACH ONE IS WHAT IT IS
//
//	unknown subject          404  a named user id that is not there. Behind a
//	                            machine credential, not behind a stranger.
//	second factor enrolled   409  the subject has MFA, and a link cannot answer a
//	                            challenge. See the long argument below.
//	window over the ceiling  422  refused rather than clamped.
//
// A BOUND THAT IS REFUSED BEATS A BOUND THAT IS CLAMPED, and this is the same rule
// `apikeys.ResolveExpiry` states: a caller that asked for a day and received an
// hour has been told a lie about how long the credential it is about to hand
// somebody else stays live. The link is delivered to a browser, so the window is
// the window somebody else has to click through.

// Errors the mint returns. The HTTP layer matches them with errors.Is and nothing
// here is compared by string.
var (
	// ErrSubjectNotFound means the named subject is not a user this service has.
	//
	// IT IS ITS OWN SENTINEL AND NOT `users.ErrNotFound` RE-EXPORTED, and the
	// difference is deliberate: `users` is the table's rule and this route's answer
	// to it is 404 on a machine-credential surface, which is a different status from
	// anything the recovery flows produce. Aliasing it would put two statuses on one
	// `errors.Is` and the second mapping written would win the first.
	ErrSubjectNotFound = errors.New("no such user to mint a session link for")

	// ErrSubjectHasSecondFactor means the subject has a live second factor.
	//
	// IT IS A REFUSAL AND NOT A CHALLENGE, and the reason is a security property
	// rather than a missing feature. A session link redeems into a session, so
	// honouring one for an enrolled subject would let a token holder turn a first
	// factor into a complete login: the whole value of MFA is that the second factor
	// is required on every session, and a route that mints one without it is the
	// downgrade this service's own vocabulary says no machine credential may perform.
	//
	// WHY IT IS NOT "JUST SEND A CHALLENGE" — because the redemption is a public
	// route with no credential beyond the link itself, so a threaded challenge flow
	// would be a second authentication surface with its own state, its own expiry
	// and its own failure modes, mounted on an unauthenticated path. That is a
	// packet of its own and this one does not pretend to be it. The refusal is
	// therefore exact: 409, and a code that says what it is.
	ErrSubjectHasSecondFactor = errors.New("that account has a second factor, which a session link cannot answer")
)

// ErrMFAUnavailable means this deployment cannot answer whether anybody has a
// second factor, and the mint refuses rather than assume.
//
// IT IS A SENTINEL RATHER THAN A BOOLEAN `canAsk` FOR THE SAME REASON ErrNoMailer
// is: a seam that fails is honest about what it knows, and a `false` from a
// deployment that cannot look is indistinguishable from a real "this user has no
// second factor". Assuming "no" there would make the refusal above the one control
// this route has.
var ErrMFAUnavailable = errors.New("this deployment cannot say whether an account has a second factor")

// SecondFactorState is the one question the mint asks about a subject.
//
// IT IS `mfa.Service.Enabled` BY SIGNATURE AND DECLARED HERE RATHER THAN IMPORTED,
// for the reason SessionRevoker and AccessTokenRevoker are: `recovery_tokens` and
// `mfa_credentials` are two tables with nothing to say to each other, and the RULE
// this package states is that a link must not outlive the account's ability to sign
// in — not anything about how a TOTP secret is sealed. An import in both
// directions would be an edge between two tables for one boolean.
type SecondFactorState interface {
	Enabled(ctx context.Context, q db.Querier, userID id.UUID) (bool, error)
}

// MintSessionLinkInput is a named subject and an optional window.
//
// The subject is a USER and not an account: what a session belongs to is the user,
// and the accounts a user belongs to are a question the caller already has a route
// for. Naming an account here would be a second way to express tenancy, and this
// service has exactly one.
type MintSessionLinkInput struct {
	UserID id.UUID
	// Window is the requested lifetime. Zero means the default, and a value over
	// MaxSessionLinkTTL is REFUSED rather than clamped.
	Window time.Duration
}

// SessionLink is the minted pair: the plaintext the CALLER delivers, and when it
// stops working.
//
// Token is here, and it is here because the route's whole contract is to hand the
// value back exactly once. It is a return value rather than a field on a row for
// the reason Token carries no plaintext: the digest goes in and the plaintext goes
// out, and there is no object in between that could hold both.
type SessionLink struct {
	Token     string
	ExpiresAt time.Time
}

// MintSessionLink writes one row of the token machine for a named subject and hands
// back the plaintext.
//
// THE ORDER IS THE SECURITY PROPERTY, and each step is where a decision that would
// otherwise be made after a credential exists is made before one does:
//
//  1. resolve the window       a caller that asked for too long is told so before
//     anything is written
//  2. resolve the subject      404 for a user that is not there. Ahead of the MFA
//     question on purpose, and specifically rather than
//     generally: answering 409 ("that account has a second
//     factor") for an id that is not an account at all would
//     make the 409 a probe for which uuids are enrolled and the
//     404 a probe for which are real. One lookup, one answer per
//     outcome. DECISIONS.md D12 is why the 404 is safe HERE and
//     is a 202 on every self-service route in this service
//  3. ask about the second     409 for an enrolled subject. Ahead of the mint, so a
//     factor                   refused link leaves no row at all
//  4. mint and store           one insert, the digest only
//
// # WHAT IS NOT CHECKED HERE, AND WHY IT IS NOT AN OVERSIGHT
//
// There is no "may this account hold a session" step, because `users` has no
// column that says an account cannot: the table carries a lockout and a verified
// address and nothing else. A check written against a column that does not exist
// would be a check that passes for every subject, which is worse than no check —
// so the redemption carries no disabled-user branch either, and says so where a
// reader will look for one. The rule that a link must not outlive an account's
// ability to sign in is currently vacuous because every account can; the moment
// `users` grows a state that says otherwise, the redemption is where the refusal
// belongs, and it must be the SHAPE of an unknown token rather than its own
// status.
func (s *Service) MintSessionLink(ctx context.Context, in MintSessionLinkInput) (SessionLink, error) {
	// (1)
	window := in.Window
	switch {
	case window == 0:
		window = SessionLinkTTL
	case window < 0:
		// invalid_format and not out_of_range: `users`' vocabulary has no
		// out_of_range, and a negative duration is not a number this field accepts
		// rather than a number outside a range within it. Adding a code to
		// `users` for one call site would put a name in the contract that every
		// other field's codes have to be reconciled against.
		return SessionLink{}, &users.FieldError{Field: "window", Code: users.CodeInvalidFormat}
	case window > MaxSessionLinkTTL:
		// too_long, which is the same code `apikeys.ResolveExpiry` uses for a
		// requested lifetime over `MaxTTL`, for the same reason: the request asked
		// for more than this field holds.
		return SessionLink{}, &users.FieldError{Field: "window", Code: users.CodeTooLong}
	}

	now := s.clk.Now()
	q := s.read.Queryer()

	// (2)
	user, err := s.users.ByID(ctx, q, in.UserID)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			return SessionLink{}, ErrSubjectNotFound
		}
		return SessionLink{}, fmt.Errorf("recovery: looking up the subject for a session link: %w", err)
	}

	// (3) A subject that cannot be asked about gets no link, and the error says the
	// deployment is at fault rather than the subject — the alternative is a link
	// minted on an assumption, which is the control this step exists to be.
	if s.secondFactor == nil {
		return SessionLink{}, ErrMFAUnavailable
	}
	enrolled, err := s.secondFactor.Enabled(ctx, q, user.ID)
	if err != nil {
		if errors.Is(err, ErrMFAUnavailable) {
			return SessionLink{}, ErrMFAUnavailable
		}
		return SessionLink{}, fmt.Errorf("recovery: asking whether the subject has a second factor: %w", err)
	}
	if enrolled {
		return SessionLink{}, ErrSubjectHasSecondFactor
	}

	// (4)
	token, digest, err := sessions.NewToken()
	if err != nil {
		return SessionLink{}, fmt.Errorf("recovery: minting a session link: %w", err)
	}

	expiresAt := now.Add(window)
	if err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := s.tokens.Create(ctx, q, NewToken{
			UserID:    user.ID,
			Purpose:   PurposeSessionLink,
			Digest:    digest,
			CreatedAt: now,
			ExpiresAt: expiresAt,
		})
		return err
	}); err != nil {
		return SessionLink{}, err
	}

	return SessionLink{Token: token, ExpiresAt: expiresAt}, nil
}
