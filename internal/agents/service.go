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


// Service is the agent principal's use cases.
type Service struct {
	store *Store
	pool  db.Pool
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

// ListAgents returns all agents claimed by an account.
func (s *Service) ListAgents(ctx context.Context, accountID id.UUID) ([]Agent, error) {
	return s.store.ListForAccount(ctx, s.pool, accountID)
}

type ClaimInput struct {
	Token string
	Account id.UUID
	User id.UUID
	TraceID string
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
	Token Token
	TokenPlaintext string
}

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
		return Claimed{}, fmt.Errorf("agents: a claim must name the account and the human claiming it")
	}

	digest := Digest(in.Token)
	if digest == "" {
		return Claimed{}, ErrNotFound
	}

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
			return Claimed{}, ErrNotFound
		}
		return Claimed{}, err
	}
	return Claimed{Agent: bound, Token: minted, TokenPlaintext: tokenValue}, nil
}
