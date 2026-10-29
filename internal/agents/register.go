package agents

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
)


// ServiceOpt configures a Service at construction.
type ServiceOpt func(*Service)

// WithClaimUI points registration's claim URLs at the screen a human opens.
//
// It is the same arrangement oidc.Provider has for OIDC_LOGIN_UI_URL and for the
// same reason: identity renders no HTML (DECISIONS.md D10), so the claim screen
// is another repository's, and this base is the seam. It carries a PATH stem
// (the screen lives at <base>/agents/claim/<link>); a base with a query, a
// fragment or a userinfo section is refused, because a base that carried a query
// would put a string this service did not write into a URL that also carries a
// 256-bit credential.
//
// An EMPTY base is a construction that cannot register. Register refuses with
// ErrNoClaimUI rather than minting an unclaimable agent, and the route answers
// 503 — a deployment that has not configured the screen will discover it before
// it strands a real user's agent, not after.
func WithClaimUI(base string) ServiceOpt {
	return func(s *Service) {
		s.claimUI = strings.TrimSuffix(strings.TrimSpace(base), "/")
	}
}

// ClaimUIBase returns the configured claim screen base, or "" when none is set.
func (s *Service) ClaimUIBase() string { return s.claimUI }

// ErrNoClaimUI means registration was called with no claim screen configured.
var ErrNoClaimUI = errors.New("no claim UI configured; set the claim UI base before registering agents")

// ClaimUIBaseEnvVar is the variable an operator sets. Exported so a refusal and
// a README can name the same string without one being a literal.
const ClaimUIBaseEnvVar = "AGENT_CLAIM_UI_URL"


// RegisterInput is what a registration needs, and every field says who chose it.
type RegisterInput struct {
	Name string
	Username string
	Device map[string]any
	TraceID string
	Now time.Time
}

// Registered is a successful registration: the principal, the credential and the
// claim link, all as they existed the instant it was written.
//
// THE TOKEN AND THE LINK ARE JSONOMITTED PLAINTEXT and exist only to travel into
// the 201 body. They are NOT fields on Agent or Token — it would be a field a
// careless `%+v` could print — they are separate strings on a result type used
// once and dropped. Token goes into the response and the OS keyring; ClaimLink
// goes into the claim URL. Neither is stored.
type Registered struct {
	Agent Agent
	Token Token
	TokenPlaintext string
	ClaimURL string
	ClaimLinkExpiresAt time.Time
}

// Register mints an unclaimed principal, its first bearer token and its first
// claim link, in one transaction.
//
// THREE WRITES, ONE FACT. The principal, the token and the registration event
// either all commit or none do; a principal that exists with no token is a
// registration the agent cannot use, and the event recording that nobody claimed
// it is what makes the trail whole. The claim link lives ON the principal
// (Store.Create writes its digest), so it is not a fourth write.
//
// THE USERNAME RETRY LOOP, and it is here rather than in the caller. The handle
// is either the caller's (validated, one attempt) or generated (retried to
// maxRegisterAttempts on ErrUsernameTaken). The public ANSWER is never "taken":
// a generated handle simply gets a new suffix and tries again, and a supplied
// handle that exhausts the budget surfaces as ErrUsernameTaken for the route to
// render as a 422 naming `username` — which only a caller who chose a handle
// deliberately can provoke.
func (s *Service) Register(ctx context.Context, in RegisterInput) (Registered, error) {
	if s.claimUI == "" {
		return Registered{}, fmt.Errorf("agents: %w", ErrNoClaimUI)
	}

	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 120 {
		return Registered{}, ErrInvalidName
	}

	wantsOwn := strings.TrimSpace(in.Username) != ""
	candidate := strings.TrimSpace(in.Username)
	if !wantsOwn {
		candidate = appendSuffix(GenerateUsernameBase(name))
	} else if !ValidUsername(candidate) {
		return Registered{}, fmt.Errorf("%w: %q", ErrInvalidUsername, in.Username)
	}

	tokenValue, tokenDigest, err := NewToken()
	if err != nil {
		return Registered{}, err
	}
	linkValue, linkDigest, err := NewToken()
	if err != nil {
		return Registered{}, err
	}
	claimExpiry := in.Now.Add(ClaimLinkTTL)
	tokenExpiry := in.Now.Add(DefaultTokenTTL)

	var (
		agent Agent
		token Token
	)
	err = db.TxRunner{Pool: s.pool}.Do(ctx, func(ctx context.Context, tx db.Querier) error {
		for attempt := 0; ; attempt++ {
			created, createErr := s.store.Create(ctx, tx, NewAgent{
				Name:               name,
				Username:           candidate,
				Device:             in.Device,
				ClaimDigest:        linkDigest,
				ClaimLinkExpiresAt: claimExpiry,
				CreatedAt:          in.Now,
			})
			if createErr == nil {
				agent = created
				break
			}
			if errors.Is(createErr, ErrUsernameTaken) && !wantsOwn && attempt < maxRegisterAttempts-1 {
				candidate = appendSuffix(GenerateUsernameBase(name))
				continue
			}
			return createErr
		}

		minted, tokenErr := s.store.CreateToken(ctx, tx, NewAgentToken{
			AgentID:   agent.ID,
			Name:      defaultTokenName,
			Digest:    tokenDigest,
			CreatedAt: in.Now,
			ExpiresAt: tokenExpiry,
		})
		if tokenErr != nil {
			return tokenErr
		}
		token = minted

		if _, evErr := s.store.AppendEvent(ctx, tx, Event{
			AgentID:    agent.ID,
			Action:     ActionRegistered,
			TraceID:    in.TraceID,
			OccurredAt: in.Now,
		}); evErr != nil {
			return evErr
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrUsernameTaken) {
			return Registered{}, fmt.Errorf("%w: %q", ErrInvalidUsername, in.Username)
		}
		return Registered{}, err
	}

	return Registered{
		Agent:              agent,
		Token:              token,
		TokenPlaintext:     tokenValue,
		ClaimURL:           s.claimLinkURL(linkValue),
		ClaimLinkExpiresAt: claimExpiry,
	}, nil
}

func (s *Service) claimLinkURL(link string) string {
	return s.claimUI + claimLinkPath + url.PathEscape(link)
}

const claimLinkPath = "/agents/claim/"

const maxRegisterAttempts = 5

const defaultTokenName = "bootstrap"

// ErrInvalidName is a registration whose display name is missing or too long.
var ErrInvalidName = fmt.Errorf("a name is required and must be between 1 and 120 characters")


// RefreshClaimInput is what a refresh needs. The presented token is the only
// credential; everything else is the request's own context.
type RefreshClaimInput struct {
	Token string
	TraceID string
	Now time.Time
}

// RefreshedClaim is a successful refresh: the principal, still unclaimed, with a
// new claim link.
type RefreshedClaim struct {
	Agent              Agent
	ClaimURL           string
	ClaimLinkExpiresAt time.Time
}

// RefreshClaimLink gives an agent a fresh claim link without claiming anything.
//
// # THE PROPERTY THE WHOLE METHOD IS FOR: IT DOES NOT CLAIM
//
// The status guard lives in Store.RefreshClaimLink's WHERE — `status = 'unclaimed'`
// — so a refresh against a claimed principal affects zero rows and comes back
// ErrNotFound rather than resurrecting a link for an agent that is somebody's.
// This method refuses it in Go first and for a clearer reason, and the store is
// the second wall. An agent that lost its link gets a new one; an agent that is
// already claimed gets nothing, because it has an owner who manages its access
// now, not a link.
//
// The presented token is resolved through OwnerByTokenDigest, which deliberately
// does NOT require the principal to be claimed — that is the whole reason an
// unclaimed agent can call this at all. What it does establish is that the
// credential is live: a revoked or expired token is ErrNotFound, the same one a
// stranger's guess gets.
//
// # THE IDEMPOTENCY KEY
//
// The refresh accepts an Idempotency-Key and records it on the event's trace
// lineage so a retried burst of the same request is visible as one intent in the
// audit trail. It is NOT a stored-response replay: each refresh mints a NEW link,
// and a retry with the same key gets a new link too. The key is for the audit
// reader and for a client that wants to correlate its retries, not a cache — see
// the caller's contract.
func (s *Service) RefreshClaimLink(ctx context.Context, in RefreshClaimInput) (RefreshedClaim, error) {
	if s.claimUI == "" {
		return RefreshedClaim{}, fmt.Errorf("agents: %w", ErrNoClaimUI)
	}

	digest := Digest(in.Token)
	if digest == "" {
		return RefreshedClaim{}, ErrNotFound
	}

	linkValue, linkDigest, err := NewToken()
	if err != nil {
		return RefreshedClaim{}, err
	}
	claimExpiry := in.Now.Add(ClaimLinkTTL)

	var agent Agent
	err = db.TxRunner{Pool: s.pool}.Do(ctx, func(ctx context.Context, tx db.Querier) error {
		resolved, resolveErr := s.store.OwnerByTokenDigest(ctx, tx, digest, in.Now)
		if resolveErr != nil {
			return ErrNotFound
		}
		if resolved.AgentStatus != StatusUnclaimed {
			return ErrNotFound
		}

		refreshed, refreshErr := s.store.RefreshClaimLink(ctx, tx, resolved.AgentID, linkDigest, claimExpiry, in.Now)
		if refreshErr != nil {
			return refreshErr
		}

		if _, evErr := s.store.AppendEvent(ctx, tx, Event{
			AgentID:    resolved.AgentID,
			Action:     ActionLinkRefreshed,
			TokenID:    resolved.ID,
			TraceID:    in.TraceID,
			OccurredAt: in.Now,
		}); evErr != nil {
			return evErr
		}
		agent = refreshed
		return nil
	})
	if err != nil {
		return RefreshedClaim{}, err
	}

	return RefreshedClaim{
		Agent:              agent,
		ClaimURL:           s.claimLinkURL(linkValue),
		ClaimLinkExpiresAt: claimExpiry,
	}, nil
}
