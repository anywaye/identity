package agents

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/tenancy"
)

// The service: the use cases that sit between a route and the store.
//
// ONE USE CASE IS MOUNTED IN THIS PACKET — Claim — and the others the store's
// methods would serve are deliberately absent. W1-P2 owns registration (a public
// route with a response shape this packet does not get to choose), W1-P3 owns
// conductor's capabilities, W2-P2 owns the scoped-token mint at claim time. A use
// case with no route is the shape AGENTS.md refuses: a tested method nobody calls
// is an invitation to wire it without reading why it was not wired, and the honest
// state for "we decided not to do this" is a paragraph and no code.
//
// SO WHAT IS HERE IS THE CLAIM, and the claim is what every later packet is
// written against.

// Service is the agent principal's use cases.
type Service struct {
	store *Store
	pool  db.Pool
	// claimUI is the absolute base the claim screen lives at, configured per
	// deployment (AGENT_CLAIM_UI_URL) and never a default. Registration and the
	// refresh both need it to render a claim URL; empty means both refuse rather
	// than mint an unclaimable agent. See WithClaimUI.
	claimUI string
}

// NewService returns a Service backed by pool, configured by opts.
func NewService(pool db.Pool, opts ...ServiceOpt) *Service {
	s := &Service{store: NewStore(pool), pool: pool}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ClaimInput is what a claim needs, and every field is a decision about who
// supplied it.
type ClaimInput struct {
	// Token is the claim link as presented. NEVER a row id: a route that accepted
	// an agent id would be a route where a stranger names the principal they are
	// binding to themselves, which is the whole thing the link exists to prevent.
	Token string
	// Account is the claiming account, resolved from the session by the route.
	Account id.UUID
	// User is the human whose session did it, for the event row. It is the actor
	// and not the owner: an account may have several humans in it, and "who
	// claimed this" is a question about a person.
	User id.UUID
	// TraceID joins the event row to the request's log line.
	TraceID string
	// Now is the service's clock, passed in rather than read, so the row, the
	// event announcing it and the response agreeing about the instant are one
	// fact under test control.
	Now time.Time
}

// Claimed is the result of a successful claim.
type Claimed struct {
	Agent Agent
}

// Claim binds an unclaimed agent to the caller's account.
//
// FOUR STEPS IN ONE TRANSACTION, and the transaction is the argument rather than
// a convenience: the claim and the event recording who did it are one fact or
// neither. A claim visible without its record is an agent bound by nobody.
//
//  1. digest the presented link. The plaintext exists in exactly one place —
//     this function's local — and is never written anywhere.
//  2. resolve it. The store's lookup filters on the digest, the status AND the
//     expiry in one statement, so a wrong token, an expired link, an
//     already-claimed agent and an agent that never existed are one value.
//  3. the conditional UPDATE, which is the thing that actually decides. The
//     WHERE carries the digest and the status, so the database is the arbiter
//     and two concurrent clicks produce one claim.
//  4. append the event with the human as its actor.
//
// STEP 3 IS THE ONLY ONE THAT CAN CHANGE STATE, and steps 2 and 4 are around it
// rather than instead of it. A use case that read the row and then wrote it
// without the condition would have a window in which the second claimant wins,
// and the window is exactly as wide as the network between the two.
//
// THE ACCOUNT IS NEVER TAKEN FROM THE LINK. The link names the agent; the account
// comes from the session. A link that carried an account would be a link that
// binds whoever holds it to an account they did not choose, which is not a
// weaker version of this flow — it is a different and dangerous one.
func (s *Service) Claim(ctx context.Context, in ClaimInput) (Claimed, error) {
	if in.Account.IsZero() || in.User.IsZero() {
		// A caller with no resolved session has no business here, and the route
		// resolves both before it calls this. Refusing rather than writing a row
		// that names nobody is the fail-closed direction.
		return Claimed{}, fmt.Errorf("agents: a claim must name the account and the human claiming it")
	}

	// The link is digested here and the plaintext goes no further. There is no
	// field it could be stored in and no log line it reaches.
	digest := Digest(in.Token)
	if digest == "" {
		return Claimed{}, ErrNotFound
	}

	// One transaction for the claim and its record. Pool rather than Querier,
	// because the boundary belongs HERE: the three statements below are one fact.
	//
	// IT IS TxRunner AND NOT A BARE Begin, and that is not a style choice — see the
	// BeginAccount call inside for what the difference buys. A use case that opened
	// its own transaction would read zero rows from every table whose policy
	// predicate reads the account GUC, and the claim would fail as a 404 for an
	// agent that exists.
	var bound Agent
	err := db.TxRunner{Pool: s.pool}.Do(ctx, func(ctx context.Context, tx db.Querier) error {
		// THE ACCOUNT BOUNDARY, SET ON THIS TRANSACTION.
		//
		// `requireAccountRole` put the account on the request context, and
		// `cafaye.begin_account/1` is `set_config(..., is_local => true)` — which
		// outside an explicit transaction expires at the end of the STATEMENT that
		// set it, so a caller reaching the database in autocommit reads zero rows.
		//
		// It is here and not in the route because the transaction is opened here:
		// one function opens the transaction and sets its identity, and a caller
		// that had to remember to do it from outside would be a caller who forgets.
		if err := tenancy.BeginAccount(ctx, tx, in.Account); err != nil {
			return fmt.Errorf("agents: setting the claim's account boundary: %w", err)
		}

		agent, err := s.store.ByClaimDigest(ctx, tx, digest, in.Now)
		if err != nil {
			return err
		}

		claimed, err := s.store.Claim(ctx, tx, agent.ID, digest, in.Account, in.Now)
		if err != nil {
			return err
		}

		if _, err := s.store.AppendEvent(ctx, tx, Event{
			AgentID:    claimed.ID,
			Action:     ActionClaimed,
			UserID:     in.User,
			TraceID:    in.TraceID,
			OccurredAt: in.Now,
		}); err != nil {
			return err
		}

		bound = claimed
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrAlreadyClaimed) {
			// ONE ANSWER, and it is the same one a stranger guessing gets. The four
			// ways this fails — wrong token, expired link, already claimed, never
			// existed — are not told apart anywhere, and a use case that logged
			// which one it was would be a log line an attacker can read.
			//
			// AlreadyClaimed is mapped onto the same value: it is distinct in the
			// store for the benefit of a caller holding the row, and the route is
			// not that caller.
			return Claimed{}, ErrNotFound
		}
		return Claimed{}, err
	}
	return Claimed{Agent: bound}, nil
}
