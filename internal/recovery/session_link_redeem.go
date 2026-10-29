package recovery

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
)


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
	Token string
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

	live, err := s.tokens.Live(ctx, s.read.Queryer(), sessions.Digest(in.Token), PurposeSessionLink, now)
	if err != nil {
		return RedeemedSession{}, err
	}

	token, digest, err := sessions.NewToken()
	if err != nil {
		return RedeemedSession{}, fmt.Errorf("recovery: minting a session for a session link: %w", err)
	}
	expiresAt := now.Add(RedeemedSessionTTL)

	var out RedeemedSession
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := s.redeemableWithoutSecondFactor(ctx, q, live.UserID); err != nil {
			return err
		}

		if err := s.redeemableFor(ctx, q, live.UserID); err != nil {
			return err
		}

		spent, err := s.tokens.Consume(ctx, q, live.ID, now)
		if err != nil {
			return err
		}
		if !spent {
			return ErrTokenNotFound
		}

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
