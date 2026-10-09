package agents

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// THE AGENT TOKEN LIFECYCLE: create, list, revoke, rotate — the routes `caf agent
// token …` calls to manage the credentials its principal holds.
//
// # WHY THIS IS A PARALLEL OF api_keys AND NOT A CALL INTO IT
//
// Same hashing, same introspection argument, a DIFFERENT lifetime and a different
// owner: an agent token is held by a principal that may be unclaimed, minted by
// the agent for itself rather than by a signed-in owner for an account. So it is
// a parallel lifecycle over the same digest machinery, exactly as Register is a
// parallel of a signup. Nothing here reaches into internal/apikeys, and nothing
// there is asked about a value that begins with the shared `cafaye_` prefix: each
// surface resolves its own table, which is the one thing that prefix is FOR (see
// the agents package header).
//
// # WHAT THE SCOPES ARE, AND ARE NOT
//
// NOTHING in this file grants a scope. Migration 00031 left `scopes` out of
// agent_tokens by name and said W1-P2 would declare the vocabulary "one name at a
// time against a route that exists". The routes an agent token would gate — box
// enrollment, conductor capabilities — do not exist yet (they are W1-P3/W2), so
// there is no vocabulary to fill a column with, and inventing one now would be a
// promise about the future rather than a control over the present. Until then
// these credentials authenticate the agent to its OWN management surface and
// resolve via the plain introspected principal once claimed (W2-P2 mints the
// first scoped token against that vocabulary). "Scoped" here means "held by one
// principal and revocable on it", which is the property the table already has.

// TokenInput is what issuing a token needs.
type TokenInput struct {
	// Agent is the principal the credential belongs to, resolved from the
	// presented token by Authenticate and passed down — never read from a path or
	// a body, so a handler cannot mint a credential for an agent it was not
	// authenticated as.
	Agent id.UUID
	// Name labels the credential, 1..80, unique among the agent's LIVE tokens.
	Name string
	// ExpiresIn, when non-nil, is the requested lifetime; nil uses DefaultTokenTTL.
	// A duration is capped at maxTokenLifetime and floored at one second.
	ExpiresIn *time.Duration
	// TraceID joins the mint event to the request's log line.
	TraceID string
	// Now is the service's clock.
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
	// ActorID names the credential that authenticated the request, for the event
	// row's actor_token_id. It is Token.ID — the ROW id — and never the value.
	ActorID id.UUID
}

// Authenticate resolves an agent's presented bearer credential to its principal,
// via OwnerByTokenDigest. It is the agent-surface analogue of currentCaller, and
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
			// Disabled, or a status this build has never seen. Both are refused,
			// and refused identically — the unknown-status case is the fail-closed
			// direction UsableAt states for the same reason.
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

	// Resolve the requested expiry ONCE, before the transaction, so the mint and
	// any refusal about it agree without re-parsing inside.
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

// rotationReason is written on the old token when a rotation revokes it, so the
// audit row and the credential row agree that this revocation was not an incident.
const rotationReason = "rotated"

// Errors the token use cases return. They are values the HTTP layer renders
// distinctly, for the same reasons apikeys' are.
var (
	ErrInvalidTokenName = errors.New("a token name is required and must be between 1 and 80 characters")
	ErrInvalidLifetime  = errors.New("the requested lifetime must be positive and no more than a year")
)
