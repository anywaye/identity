package agents

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/tenancy"
)

// The service: the use cases that sit between a route and the store.
//
// WHAT IS HERE AND WHAT IS NOT. The registration and the claim-link refresh
// (register.go), the bearer-token lifecycle (tokens.go) and the claim, which
// since W2-P2 also mints the credential the claim hands back. The use cases the
// store's methods would serve but no route mounts are deliberately absent: a
// tested method nobody calls is an invitation to wire it without reading why it
// was not wired, and the honest state for "we decided not to do this" is a
// paragraph and no code.

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
//
// TWO THINGS COME BACK AND THE SECOND IS THE POINT OF THIS PACKET. The agent, at
// the status the claim wrote, and the bearer credential the claim minted for it.
// The mint is here rather than being a second call the claim screen would have
// to make because the claim is the instant the principal becomes anything: an
// agent that is bound and holds no credential is a claim a human completed and
// an agent cannot use.
//
// TokenPlaintext is on this type rather than on Token for the reason
// `Registered` states: the digest is the only part of a credential any struct
// holds, and the plaintext travels into one response and is dropped.
type Claimed struct {
	Agent Agent
	// Token is the credential the claim minted, as the row holds it.
	Token Token
	// TokenPlaintext is that credential's bearer value, rendered exactly once.
	TokenPlaintext string
}

// claimTokenName is what the credential a claim mints is called.
//
// NOT `defaultTokenName`, and not a second "bootstrap": the registration's
// credential is named after the state it was minted in, and a partial unique
// index (one live token per name per agent) would refuse the claim outright if
// the two shared a name. The names read as a history in a management list —
// `bootstrap` minted while the agent was nobody's, `claimed` minted by the human
// who made it somebody's.
const claimTokenName = "claimed"

// Claim binds an unclaimed agent to the caller's account, and mints the
// credential it presents from then on.
//
// FIVE STEPS IN ONE TRANSACTION, and the transaction is the argument rather than
// a convenience: the claim, the credential and the events recording who did it
// are one fact or none of them is. A claim visible without its record is an agent
// bound by nobody.
//
//  1. digest the presented link. The plaintext exists in exactly one place —
//     this function's local — and is never written anywhere.
//  2. resolve it. The store's lookup filters on the digest, the status AND the
//     expiry in one statement, so a wrong token, an expired link, an
//     already-claimed agent and an agent that never existed are one value.
//  3. the conditional UPDATE, which is the thing that actually decides. The
//     WHERE carries the digest and the status, so the database is the arbiter
//     and two concurrent clicks produce one claim.
//  4. the credential, minted and stored in the same transaction as the binding.
//  5. two events with the human as their actor: the claim, and the mint it caused.
//
// STEP 3 IS THE ONLY ONE THAT CAN CHANGE THE BINDING, and steps 2, 4 and 5 are
// around it rather than instead of it. A use case that read the row and then
// wrote it without the condition would have a window in which the second
// claimant wins, and the window is exactly as wide as the network between the
// two.
//
// THE ACCOUNT IS NEVER TAKEN FROM THE LINK. The link names the agent; the account
// comes from the session. A link that carried an account would be a link that
// binds whoever holds it to an account they did not choose, which is not a
// weaker version of this flow — it is a different and dangerous one.
//
// STEP 4 CANNOT COLLIDE WITH A NAME THE AGENT ALREADY HOLD. `claimTokenName` is
// distinct from the registration's `bootstrap`, and the token surface an agent
// reaches with its own credential is closed to an unclaimed principal
// (ErrUnclaimed, D4) — so nothing can have minted "claimed" on this row before
// the claim got there. That is what makes the mint's refusal a 500 rather than a
// 409, which is the honest grade of "this cannot happen": if it ever does, the
// deployment has a bug and should say so loudly.
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

	// The credential, minted BEFORE the transaction so a failure of crypto/rand
	// aborts before a row exists rather than rolling a claim back. The digest goes
	// into `agent_tokens`; the plaintext goes into this function's return value
	// and from there into one HTTP response, and nowhere else — there is no column
	// and no field on the store's types that could hold it again.
	tokenValue, tokenDigest, err := NewToken()
	if err != nil {
		return Claimed{}, err
	}
	tokenExpiry := in.Now.Add(DefaultTokenTTL)

	var (
		bound  Agent
		minted Token
	)
	err = db.TxRunner{Pool: s.pool}.Do(ctx, func(ctx context.Context, tx db.Querier) error {
		// THE ACCOUNT BOUNDARY, SET ON THIS TRANSACTION.
		//
		// `requireAccountRole` put the account on the request context, and
		// `anywaye.begin_account/1` is `set_config(..., is_local => true)` — which
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

		// STEP 4. The credential the agent presents from here on, in the same
		// transaction as the binding that gives it any meaning. Rolling them
		// apart would leave the two failure modes the transaction exists to
		// refuse: a bound agent with no credential, or a credential for a
		// principal nobody owns.
		minted, err = s.store.CreateToken(ctx, tx, NewAgentToken{
			AgentID:   claimed.ID,
			Name:      claimTokenName,
			Digest:    tokenDigest,
			CreatedAt: in.Now,
			ExpiresAt: tokenExpiry,
		})
		if err != nil {
			return err
		}

		// STEP 5, second event. Its actor is USERID and not the credential that
		// was just minted, and that is not a default: `agent.token_minted` on the
		// rotation path names the token that asked, but this mint was caused by a
		// human clicking Approve. Recording the credential as its own actor would
		// say the agent issued itself a token by being claimed, which is the
		// story D4 exists to refuse.
		if _, err := s.store.AppendEvent(ctx, tx, Event{
			AgentID:    claimed.ID,
			Action:     ActionTokenMinted,
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
	return Claimed{Agent: bound, Token: minted, TokenPlaintext: tokenValue}, nil
}
