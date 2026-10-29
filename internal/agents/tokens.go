package agents

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)


// TokenInput is what issuing a token needs.
type TokenInput struct {
	Agent id.UUID
	Name string
	ExpiresIn *time.Duration
	TraceID string
	Now time.Time
}

// IssuedToken is a minted credential and its plaintext, together exactly once.
type IssuedToken struct {
	Token     Token
	Plaintext string
}

// Owner is a presented credential resolved to the principal that holds it.
type Owner struct {
	Agent Agent
	Token Token
	ActorID id.UUID
}

// RequireClaimed is the D4 gate on a resolved credential, and it is a method on
// Owner rather than a branch in a handler because "who may act" belongs beside
// the lifecycle that decides it.
//
// IT IS ONE STATEMENT, DELIBERATELY, AND THE PATH THAT DOES NOT CALL IT IS NAMED.
// An unclaimed principal may reach exactly one route — the claim-link refresh,
// which is the only thing it can do that a human has not already done for it.
// Everything else on the agent surface (the token lifecycle) goes through this,
// because an agent acting alone gets nothing (D4), and a credential minted
// before a human claimed anything is a token whose authority would outrun the
// claim that was supposed to create it.
//
// CLAIMED AND DISABLED BOTH PASS HERE, and that is not an oversight: a disabled
// principal's credential does not resolve at all (Authenticate refuses it), so
// the only status this method can see is unclaimed. What it answers is "was this
// ever bound", which is the ownership question, not "is it live".
func (o Owner) RequireClaimed() error {
	if !o.Agent.IsClaimed() {
		return ErrUnclaimed
	}
	return nil
}

// Authenticate resolves an agent's presented bearer credential to its principal,
// via OwnerByTokenDigest. It is the agent-surface analog of currentCaller, and
// it is on the service rather than in the HTTP layer so the transaction boundary
// and the status rule live in one place.
//
// A caller who is DEACTIVATED (a disabled principal) gets ErrNotFound, same as a
// caller whose token never resolved: the management surface a disabled agent would
// reach is closed, and a disabled agent and a bad token must not be tellable apart
// by a stranger guessing. A live-but-unclaimed agent resolves — that is the whole
// point of OwnerByTokenDigest — and the use case that follows decides what an
// unclaimed agent may do with what it reached.
func (s *Service) Authenticate(ctx context.Context, presented string, now time.Time) (Owner, error) {
	digest := Digest(presented)
	if digest == "" {
		return Owner{}, ErrNotFound
	}

	var owner Owner
	err := db.TxRunner{Pool: s.pool}.Do(ctx, func(ctx context.Context, tx db.Querier) error {
		resolved, err := s.store.OwnerByTokenDigest(ctx, tx, digest, now)
		if err != nil {
			return ErrNotFound
		}
		if resolved.AgentStatus == StatusDisabled || !IsKnownStatus(resolved.AgentStatus) {
			return ErrNotFound
		}
		agent, err := s.store.ByID(ctx, tx, resolved.AgentID)
		if err != nil {
			return err
		}
		owner = Owner{Agent: agent, Token: resolved.Token, ActorID: resolved.ID}
		return nil
	})
	if err != nil {
		return Owner{}, err
	}
	return owner, nil
}

// IssueToken mints a named bearer credential for an agent.
//
// It is NOT wrapped in the owner-authenticating transaction a caller might expect
// it to open; the caller (a route) has already resolved the owner and passes the
// agent id down, so this only opens the transaction its own writes belong in. The
// token and the mint event are one fact in that transaction.
//
// ErrNameTaken propagates from the partial unique index — the same 409 apikeys
// answers — so creating a second live "deploy" token is refused distinctly from
// revoking the first.
func (s *Service) IssueToken(ctx context.Context, in TokenInput) (IssuedToken, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 80 {
		return IssuedToken{}, ErrInvalidTokenName
	}
	if in.Agent.IsZero() {
		return IssuedToken{}, ErrNotFound
	}

	expiresAt := in.Now.Add(DefaultTokenTTL)
	if in.ExpiresIn != nil {
		if *in.ExpiresIn <= 0 || *in.ExpiresIn > maxTokenLifetime {
			return IssuedToken{}, ErrInvalidLifetime
		}
		expiresAt = in.Now.Add(*in.ExpiresIn)
	}

	value, digest, err := NewToken()
	if err != nil {
		return IssuedToken{}, err
	}

	var token Token
	err = db.TxRunner{Pool: s.pool}.Do(ctx, func(ctx context.Context, tx db.Querier) error {
		minted, mintErr := s.store.CreateToken(ctx, tx, NewAgentToken{
			AgentID:   in.Agent,
			Name:      name,
			Digest:    digest,
			CreatedAt: in.Now,
			ExpiresAt: expiresAt,
		})
		if mintErr != nil {
			return mintErr
		}
		if _, evErr := s.store.AppendEvent(ctx, tx, Event{
			AgentID:    in.Agent,
			Action:     ActionTokenMinted,
			TokenID:    minted.ID,
			TraceID:    in.TraceID,
			OccurredAt: in.Now,
		}); evErr != nil {
			return evErr
		}
		token = minted
		return nil
	})
	if err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{Token: token, Plaintext: value}, nil
}

// ListTokens returns the credentials an agent holds, newest first, revoked ones
// included — the same "withdrawn, or always broken?" support question apikeys'
// List answers by keeping the row. A read, not a mutation, and scoped by the agent
// id the caller resolved rather than any path parameter.
func (s *Service) ListTokens(ctx context.Context, agentID id.UUID) ([]Token, error) {
	if agentID.IsZero() {
		return []Token{}, nil
	}
	var out []Token
	err := db.TxRunner{Pool: s.pool}.Do(ctx, func(ctx context.Context, tx db.Querier) error {
		listed, err := s.store.ListTokensForAgent(ctx, tx, agentID)
		if err != nil {
			return err
		}
		out = listed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeToken withdraws a named credential of an agent.
//
// SCOPED BY agent AS WELL AS id, on apikeys' argument: the caller has established
// the agent, and a query that says so again refuses a cross-principal revocation
// outright. ErrAlreadyRevoked is distinct so a caller who clicked twice is told
// so rather than sold a second success.
func (s *Service) RevokeToken(ctx context.Context, agent, tokenID id.UUID, reason, traceID string, now time.Time) (Token, error) {
	if agent.IsZero() || tokenID.IsZero() {
		return Token{}, ErrNotFound
	}
	var token Token
	err := db.TxRunner{Pool: s.pool}.Do(ctx, func(ctx context.Context, tx db.Querier) error {
		revoked, revErr := s.store.RevokeToken(ctx, tx, tokenID, agent, now, reason)
		if revErr != nil {
			return revErr
		}
		if _, evErr := s.store.AppendEvent(ctx, tx, Event{
			AgentID:    agent,
			Action:     ActionTokenRevoked,
			TokenID:    tokenID,
			TraceID:    traceID,
			OccurredAt: now,
		}); evErr != nil {
			return evErr
		}
		token = revoked
		return nil
	})
	if err != nil {
		return Token{}, err
	}
	return token, nil
}

// RotateToken withdraws a live credential and mints a new one of the SAME NAME in
// its place, returning the new plaintext.
//
// # TWO WRITES, ONE NAMED CREDENTIAL
//
// The partial unique index (one live token per name per agent) is what makes this
// two statements rather than a find-a-free-name dance: revoking the old one first
// frees the name, then the mint takes it. Both are in one transaction, so a crash
// between them cannot leave the agent with neither a revoked old token NOR a new
// one — it rolls back to the live old one. The new token's LIFETIME is fresh
// (DefaultTokenTTL or the caller's expires_in), which is what "rotate" means: the
// clock restarts.
//
// # WHY IT IS A SINGLE ENDPOINT AND NOT TWO REQUESTS
//
// A client that revokes then mints has, for an instant, NO credential for that
// name and a two-round-trip window in which it can be left with none at all. The
// rotation is one call that either gives you the new token or tells you the old
// one still works.
func (s *Service) RotateToken(ctx context.Context, agent, tokenID id.UUID, expiresIn *time.Duration, traceID string, now time.Time) (IssuedToken, error) {
	if agent.IsZero() || tokenID.IsZero() {
		return IssuedToken{}, ErrNotFound
	}

	value, digest, err := NewToken()
	if err != nil {
		return IssuedToken{}, err
	}

	expiresAt := now.Add(DefaultTokenTTL)
	if expiresIn != nil {
		if *expiresIn <= 0 || *expiresIn > maxTokenLifetime {
			return IssuedToken{}, ErrInvalidLifetime
		}
		expiresAt = now.Add(*expiresIn)
	}

	var out Token
	err = db.TxRunner{Pool: s.pool}.Do(ctx, func(ctx context.Context, tx db.Querier) error {
		current, loadErr := s.store.ByTokenID(ctx, tx, tokenID)
		if loadErr != nil {
			return ErrNotFound
		}
		if current.AgentID != agent {
			return ErrNotFound
		}
		if current.IsRevoked() {
			return fmt.Errorf("agents: credential %s: %w", tokenID, ErrAlreadyRevoked)
		}

		if _, revErr := s.store.RevokeToken(ctx, tx, tokenID, agent, now, rotationReason); revErr != nil {
			return revErr
		}

		minted, mintErr := s.store.CreateToken(ctx, tx, NewAgentToken{
			AgentID:   agent,
			Name:      current.Name,
			Digest:    digest,
			CreatedAt: now,
			ExpiresAt: expiresAt,
		})
		if mintErr != nil {
			return mintErr
		}

		if _, evErr := s.store.AppendEvent(ctx, tx, Event{
			AgentID:    agent,
			Action:     ActionTokenMinted,
			TokenID:    minted.ID,
			TraceID:    traceID,
			OccurredAt: now,
		}); evErr != nil {
			return evErr
		}
		if _, evErr := s.store.AppendEvent(ctx, tx, Event{
			AgentID:    agent,
			Action:     ActionTokenRevoked,
			TokenID:    tokenID,
			TraceID:    traceID,
			OccurredAt: now,
		}); evErr != nil {
			return evErr
		}
		out = minted
		return nil
	})
	if err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{Token: out, Plaintext: value}, nil
}

const rotationReason = "rotated"

var (
	ErrInvalidTokenName = errors.New("a token name is required and must be between 1 and 80 characters")
	ErrInvalidLifetime  = errors.New("the requested lifetime must be positive and no more than a year")
)
