package recovery

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
)

// THE REDEMPTION, AND THE ORDER ITS WRITES HAPPEN IN.
//
// # WHAT A LINK IS AT THIS END: A PASSWORD THE CALLER DECIDED TO DELIVER
//
// The mint hands back a plaintext and no delivery. This method turns that plaintext
// into a browser session, which makes it the narrowest and the widest thing in the
// package at the same time: narrow because it changes nothing about the account, and
// wide because a session is the credential every other route in this service
// trusts.
//
// # THE ORDER, AND WHY EACH STEP IS WHERE IT IS
//
//	1. resolve the token          OUTSIDE the transaction. It writes nothing, and the
//	                              conditional write below is the authority rather
//	                              than this read — the same argument RedeemPasswordReset
//	                              gives for reading before the transaction.
//	2. refuse a deployment that   INSIDE, and BEFORE the spend.
//	   cannot ask about MFA
//	3. refuse a disabled subject  INSIDE, and BEFORE the spend. See redeemableFor,
//	                              which is one helper for four doors.
//	4. refuse an enrolled         INSIDE, and BEFORE the spend. The race the mint's
//	   subject                       refusal does not close; see the long argument below.
//	5. spend the token            The conditional write. This is the single-use
//	                              guarantee and the only thing that makes it one.
//	6. write the session          In the same transaction, so a failure to write it
//	                              rolls the spend back rather than handing over a
//	                              spent link and no session.
//
// # WHY STEPS 2 TO 4 ARE REPEATED HERE RATHER THAN LEFT TO THE MINT
//
// Because the mint's refusals were about a state at a moment, and this is a
// different moment.
//
// `MintSessionLink` refuses a subject with a second factor (409) and a disabled
// subject (403), so at MINT time no link exists for either. A ten-minute window is
// long enough for both to change inside it:
//
//   - a user enrolls a second factor AFTER the link was minted and BEFORE it is
//     redeemed. Redeeming would turn possession of a delegated link into a COMPLETE
//     login for an account whose owner chose two — which is precisely the downgrade
//     `ErrSubjectHasSecondFactor` exists to prevent, arriving through the other
//     door. The mint's refusal is necessary and not sufficient;
//   - a person disables the account in the same window. This is the reset flow's
//     argument (`redeemableFor`) and it is a stronger one here, because a session
//     link is not a mailbox: there is no second factor to answer and no inbox that
//     proves anything about who is clicking.
//
// The alternative for the MFA case would be a threaded challenge flow on an
// unauthenticated route: a second authentication surface, with its own state, its
// own expiry and its own failure modes, mounted where no credential has been
// presented. That is a packet of its own. This one refuses instead, and says so.
//
// # AND EVERY ACCOUNT-SHAPED REFUSAL HERE IS ErrTokenNotFound
//
// Not its own status, and not the mint's 409/403. The token IS the credential on
// this route: the caller is the subject or whoever took the link, and an answer that
// named the account's state would publish it to exactly the person the operator
// acted about. One status, one body, one round trip — the four filters
// `Store.Live` already applies in one statement, extended by two checks that are
// about accounts rather than about rows.
//
// The ONE exception is the deployment check, which is not about any account.
//
// # AND A REFUSAL SPENDS NOTHING
//
// Steps 2 to 4 run BEFORE the spend, so a refused redemption leaves the link live. A
// refusal that consumed it would be an irreversible decision made on somebody's
// behalf: un-disabling the account, or un-enrolling the second factor, would leave
// the user holding a link that no longer works and no session, which is
// indistinguishable from a service that lost their state.

// RedeemedSessionTTL is how long a session minted by a link lives.
//
// IT IS A SEPARATE CONSTANT FROM `SessionLinkTTL` rather than a reuse, and the
// distinction is the whole of the route's timing: the LINK lives ten minutes because
// it is a value in transit to a browser, and the SESSION lives weeks because it is a
// credential somebody signs in with. Reusing one number for both would mint a
// session that dies when the link would have, and a caller that had successfully
// redeemed would hold a dead credential with no error anywhere.
//
// The value is `auth.DefaultSessionTTL`, restated rather than imported:
// `internal/auth` depends on this package's tables' rules and not the other way
// round, so importing it would put an edge between two packages for one duration.
// `TestTheSessionWindowIsTheSameWindowThePasswordRouteMints` in `internal/auth`
// pins the two to each other, because a constant that can drift from its twin is
// two constants.
const RedeemedSessionTTL = 30 * 24 * time.Hour

// RedeemSessionLinkInput is the token from a link the CALLER delivered.
//
// NO REDIRECT, NO LANDING PAGE, AND NOTHING ELSE, and the absence is the design
// rather than an omission. The caller already owns the channel the link arrived over
// and therefore already knows where the browser is; a parameter here would be a
// value this service stores about somebody else's front end and hands back on a
// public route, which is an open redirector with a session attached. There is
// nothing to allow-list because there is nothing here to allow-list.
type RedeemSessionLinkInput struct {
	// Token is the plaintext the mint handed the caller. It is digested here and
	// never written.
	Token string
	// UserAgent and IP are recorded on the session row, exactly as `POST /v1/session`
	// records them, because they are evidence for an incident and nothing trusts
	// either. A delegation is not a reason to record less than a password login.
	UserAgent string
	IP        *netip.Addr
}

// RedeemedSession is what a completed redemption returns: the value the browser
// carries, and when it stops working.
//
// It is a dedicated type rather than `SessionLink`, because the two are opposites —
// one is a credential that MINTS a session, the other IS a session — and a single
// type that could be either would be a type a caller could hand back into the mint.
type RedeemedSession struct {
	Token     string
	ExpiresAt time.Time
}

// SessionIssuer is the slice of the sessions table the redemption needs: the write
// that mints a browser session.
//
// IT IS AN INTERFACE AND NOT THE STORE for the reason SessionRevoker and
// AccessTokenRevoker are: the RULE this package states is that a link must not
// outlive the account's ability to sign in, and not anything about how a session row
// is written. An import in both directions would be an edge between two tables for
// one INSERT.
//
// SessionStore is the union of the two, and it is a union rather than two
// constructor arguments because a caller passing two objects that are the same
// `*sessions.Store` has been asked to prove nothing: the two halves are one table,
// and the split exists to say what each flow asks of it.
type SessionIssuer interface {
	Create(ctx context.Context, q db.Querier, n sessions.NewSession) (sessions.Session, error)
}

// RedeemSessionLink turns a live, unspent link into a browser session, in one
// transaction, and spends the link in it.
//
// THE ONLY THING THAT MAKES THIS SINGLE-USE IS `Store.Consume`. Everything else here
// is a check, and a check is not a lock: two requests carrying the same token both
// resolve it above, both find the subject live, and both reach the spend, and the
// conditional UPDATE is what makes one of them win. A read-then-write redemption
// would mint two sessions from one link and pass every other test in this package —
// which is why the concurrency assertion is a SUM and not "at least one".
func (s *Service) RedeemSessionLink(ctx context.Context, in RedeemSessionLinkInput) (RedeemedSession, error) {
	now := s.clk.Now()

	// (1) Outside the transaction: four filters in one statement, so a spent link, an
	// expired one and one minted for another flow are the same answer as one that
	// never existed.
	live, err := s.tokens.Live(ctx, s.read.Queryer(), sessions.Digest(in.Token), PurposeSessionLink, now)
	if err != nil {
		return RedeemedSession{}, err
	}

	// The session token is minted OUTSIDE the transaction, for the reason
	// RedeemPasswordReset hashes its password outside: a mint that fails must not
	// hold a connection open, and must not have written anything.
	token, digest, err := sessions.NewToken()
	if err != nil {
		return RedeemedSession{}, fmt.Errorf("recovery: minting a session for a session link: %w", err)
	}
	expiresAt := now.Add(RedeemedSessionTTL)

	var out RedeemedSession
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		// (2) and (4), as ONE question asked twice for two different reasons — the
		// deployment and then the subject. Both before the spend, so a refusal leaves
		// the link live.
		if err := s.redeemableWithoutSecondFactor(ctx, q, live.UserID); err != nil {
			return err
		}

		// (3) A disabled subject. Before the spend, so the link survives — see this
		// file's header, and `redeemableFor`'s argument for one helper over four
		// doors.
		if err := s.redeemableFor(ctx, q, live.UserID); err != nil {
			return err
		}

		// (5) The spend. Conditional, and the only authority this method has over
		// single use.
		spent, err := s.tokens.Consume(ctx, q, live.ID, now)
		if err != nil {
			return err
		}
		if !spent {
			// Somebody redeemed it between the read above and here. ErrTokenNotFound
			// rather than a new error, and the transaction rolls back rather than
			// writing a session nobody may hold.
			return ErrTokenNotFound
		}

		// (6) The session, in the same transaction. If this fails the spend rolls back
		// with it, so a failure here leaves the link live and the user able to press
		// "try again" rather than being told a link that still works has expired.
		if _, err := s.sessions.Create(ctx, q, sessions.NewSession{
			UserID:      live.UserID,
			TokenDigest: digest,
			ExpiresAt:   expiresAt,
			UserAgent:   in.UserAgent,
			IP:          in.IP,
		}); err != nil {
			return err
		}

		out = RedeemedSession{Token: token, ExpiresAt: expiresAt}
		return nil
	})
	if err != nil {
		return RedeemedSession{}, err
	}
	return out, nil
}

// redeemableWithoutSecondFactor refuses a redemption whose subject HAS a second
// factor, and refuses the whole ROUTE when this deployment cannot ask.
//
// # TWO REFUSALS IN ONE FUNCTION, AND THEY ARE NOT THE SAME SHAPE ON PURPOSE
//
//	ErrTokenNotFound   the subject has a live second factor. The shape of a token
//	                   that never existed, because the token IS the credential here
//	                   and the caller may be whoever took the link — so 409, which is
//	                   the mint's answer, would publish the account's MFA state to
//	                   exactly the person a subject would not want to know it.
//	ErrMFAUnavailable  THIS DEPLOYMENT cannot say. Not ErrTokenNotFound, because
//	                   that sentence is about a credential and this fact is about the
//	                   server: it is true of every caller and every subject alike,
//	                   which makes it a 503 a product can act on by not depending on
//	                   this instance. Folding it into the 404 would also make a
//	                   misconfigured deployment look like a very quiet successful
//	                   attack, which is the one reading of it nobody wants at 3am.
//
// # WHY IT IS ASKED AGAIN AT ALL
//
// Because the mint's answer was about a different moment. `MintSessionLink` refuses
// an enrolled subject at mint time, so no link for one exists then; a user can
// enroll in the ten-minute window before redeeming, and honoring the link would
// hand a first factor's worth of credential to whoever holds it. That is the
// downgrade `ErrSubjectHasSecondFactor` exists to prevent, arriving through the
// other door, so the mint's refusal is necessary and not sufficient.
//
// The threaded alternative — issue a challenge here and let the browser finish the
// login — is a second authentication surface on an unauthenticated route, with its
// own state, expiry and failure modes. It is a packet of its own.
func (s *Service) redeemableWithoutSecondFactor(ctx context.Context, q db.Querier, userID id.UUID) error {
	if s.secondFactor == nil {
		return ErrMFAUnavailable
	}
	enrolled, err := s.secondFactor.Enabled(ctx, q, userID)
	if err != nil {
		if errors.Is(err, ErrMFAUnavailable) {
			return ErrMFAUnavailable
		}
		return fmt.Errorf("recovery: asking whether the subject has a second factor: %w", err)
	}
	if enrolled {
		return ErrTokenNotFound
	}
	return nil
}
