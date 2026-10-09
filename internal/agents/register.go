package agents

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/cafaye/identity/internal/platform/db"
)

// THE REGISTRATION AND THE CLAIM-LINK REFRESH — the two things a caller with no
// account may do to a principal, and the use cases that own them.
//
// # WHERE THIS SITS IN THE FLOW
//
// AGENTS-FIRST.md's flow, step ①: an agent POSTs to a public endpoint and comes
// away unclaimed, holding a token, with a claim URL for a human to open. This is
// that endpoint's body: registration mints the principal, its first bearer token
// and its first claim link in one transaction, and returns the credential and the
// URL — the only two plaintext secrets that ever leave the process, each exactly
// once, each with no column that could hold them again.
//
// # THE TWO PLAINTEXTS, AND WHY THEY ARE BOTH HERE AND NOWHERE ELSE
//
// The token is stored as a SHA-256 digest in agent_tokens; the claim link as a
// digest on the principal. The mint returns both halves, the route writes the
// plaintext into the 201 body, and NOTHING downstream — not a log line, not an
// event row, not a re-read — can produce either again. TestTheRegistrationWritesNoPlaintextToken
// is the property stated as a check: read the row back and the plaintext is not
// in any column, because there is no column for it.
//
// # THE REFRESH AND THE CLAIM ARE DIFFERENT VERBS ON PURPOSE
//
// A refresh gives an agent whose link it lost a NEW link and changes nothing
// else — the status guard in Store.RefreshClaimLink refuses a claimed principal,
// so "give me a new link" can never act as "claim me". The claim itself W1-P1
// landed and it is the boundary this file must not cross: nothing here binds an
// account or mints a scoped token for a claimed principal. That is W2-P2's, and
// the separation is what makes D4 hold — an agent can refresh a link all it likes
// and still be nobody's.

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

// ClaimLinkTTL comment lives in store.go; re-exported here as the writer of the
// expiry so a reader of the use case sees it without crossing files. The value is
// Store-level because RefreshClaimLink reads the same one.

// RegisterInput is what a registration needs, and every field says who chose it.
type RegisterInput struct {
	// Name is the display label a human reads. Chosen by the caller (the agent's
	// operator via the CLI), 1..120 characters.
	Name string
	// Username is an optional handle. Empty means "generate one"; a non-empty
	// value must be a valid handle or the registration refuses with a 422 naming
	// the field rather than silently normalising it.
	Username string
	// Device is the agent's self-description, written whole. A code fact about
	// which keys are read (00027); this packet passes it through untouched.
	Device map[string]any
	// TraceID joins the registration event to the request's log line.
	TraceID string
	// Now is the service's clock.
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
	// TokenPlaintext is the bearer credential, shown to the caller exactly once.
	TokenPlaintext string
	// ClaimURL is the absolute URL a human opens to claim the agent.
	ClaimURL string
	// ClaimLinkExpiresAt is when the link stops working, rendered alongside the
	// URL so the CLI can say so.
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
		// Fail before minting anything: an unclaimable agent is worse than a
		// refused registration, because it exists and cannot be finished.
		return Registered{}, fmt.Errorf("agents: %w", ErrNoClaimUI)
	}

	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 120 {
		return Registered{}, ErrInvalidName
	}

	// The handle's first attempt. A supplied handle is used verbatim once; a
	// generated one is retried. The distinction is captured in wantsOwn so a
	// supplied handle never silently becomes a generated one.
	wantsOwn := strings.TrimSpace(in.Username) != ""
	candidate := strings.TrimSpace(in.Username)
	if !wantsOwn {
		candidate = appendSuffix(GenerateUsernameBase(name))
	} else if !ValidUsername(candidate) {
		return Registered{}, fmt.Errorf("%w: %q", ErrInvalidUsername, in.Username)
	}

	// The two mints, before the transaction: credentials are minted, not derived,
	// and a failure of crypto/rand here must abort before a row exists. The token
	// is the bearer credential; the claim link is minted by the same primitive
	// for the same 256-bit budget, and its digest goes on the principal.
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
			// ONLY A GENERATED HANDLE RETRIES. A caller who supplied a specific
			// username asked for THAT handle, and silently swapping in a generated
			// one would register them as a principal they did not name — the
			// surprise the CLI's own client-side retry avoided by never retrying a
			// supplied username. So a supplied collision falls straight through to
			// ErrUsernameTaken, and the route renders it as a 422 naming `username`.
			// A generated collision retries up to the budget and then also gives up
			// (a 31-bit suffix meeting another, which does not happen).
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

// claimLinkURL renders the absolute claim URL for a link plaintext.
func (s *Service) claimLinkURL(link string) string {
	return s.claimUI + claimLinkPath + url.PathEscape(link)
}

// claimLinkPath is the path within the claim UI where the screen lives
// (website's /agents/claim/[token]). A constant so a change is one place and a
// test asserts the shape rather than a coincidence.
const claimLinkPath = "/agents/claim/"

// maxRegisterAttempts bounds the username retry loop. It is small because a
// collision is either a caller's deliberate collision (answered quickly) or two
// 31-bit suffixes meeting, which does not happen.
const maxRegisterAttempts = 5

// defaultTokenName is the name given to the bootstrap token a registration mints.
// The agent may mint more under other names and rotate or revoke this one.
const defaultTokenName = "bootstrap"

// ErrInvalidName is a registration whose display name is missing or too long.
var ErrInvalidName = fmt.Errorf("a name is required and must be between 1 and 120 characters")

// ---------------------------------------------------------------------------
// the claim-link refresh
// ---------------------------------------------------------------------------

// RefreshClaimInput is what a refresh needs. The presented token is the only
// credential; everything else is the request's own context.
type RefreshClaimInput struct {
	// Token is the agent's own bearer credential, presented to prove it is the
	// principal asking. NOT a claim link: a refresh that took a link would let a
	// stranger holding a stolen link re-mint links, which is the opposite of the
	// bound the link is meant to place.
	Token string
	// TraceID joins the refresh event to the request's log line.
	TraceID string
	// Now is the service's clock.
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
			// One answer for a revoked, expired or never-issued token — the read a
			// stranger can perform says nothing beyond "this value does not resolve".
			return ErrNotFound
		}
		if resolved.AgentStatus != StatusUnclaimed {
			// Already claimed (or disabled). A stranger holding a link learns the
			// same ErrNotFound a wrong token gets; the owner's agent is not
			// re-linkable by anybody but them through routes this packet does not
			// mount.
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
