package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)

// The store: three tables, and every method here takes a db.Querier rather than
// the pool so the caller chooses the transaction boundary.
//
// THE SHAPE IS COPIED FROM internal/apikeys/store.go, and what is copied is the
// argument rather than the lines: a read that could distinguish "revoked" from
// "never existed" is an oracle, so the reads are CONDITIONAL and the failures are
// INDISTINGUISHABLE. An agent claim is the one flow in this service where a
// stranger presents a credential and gets an answer about whether it worked, so
// every refusal here is one 404 and the 404 never says which of the four things
// was true.
//
// WHAT IS NOT HERE. The minting use cases: no method in this file renders a
// token. That is W1-P2's (registration) and W2-P2's (claim), and a mint is a
// policy decision about lifetimes rather than a row write.

// Postgres SQLSTATE 23505, unique_violation.
const uniqueViolation = "23505"

// errNoRows is pgx's "the query matched nothing", aliased so the intent reads at
// the call site.
var errNoRows = pgx.ErrNoRows

// ClaimLinkTTL is how long a claim link lives from the registration that
// produced it.
//
// LONGER THAN A SESSION LINK'S TEN MINUTES and shorter than an invitation's,
// because of what the holder is doing: they have just watched a CLI print a URL
// and are about to paste it into a browser. A person who left the tab open
// overnight is the case the window is sized against, not an attacker — guessing
// 256 bits is not a search anybody can run, so the TTL bounds human patience
// rather than entropy.
const ClaimLinkTTL = 24 * time.Hour

// DefaultTokenTTL is how long an agent bearer token lives unless a caller asks
// for a different lifetime.
//
// FAR LONGER THAN A SESSION AND BOUNDED, because of what an agent does with
// it: the token goes straight to the OS keyring and is re-presented on every
// request for the life of the agent, which may be months. It is NOT permanent —
// the column's CHECK makes that true — and it is not short either, because a
// credential the agent has to re-fetch every hour is a credential that ends up
// in a transcript, which is invariant 1. Ninety days is the balance: long enough
// that rotation is a deliberate act, short enough that a leaked token dies.
//
// This is a W1-P2 decision the migrations header deferred ("the scope vocabulary
// for an agent token is W1-P2's to declare"); the lifetime is declared here, and
// a caller may ask for less through the create route's expires_in.
const DefaultTokenTTL = 90 * 24 * time.Hour

// maxTokenLifetime caps a requested lifetime so a caller cannot mint an
// effectively-permanent token by asking for a huge duration.
const maxTokenLifetime = 365 * 24 * time.Hour

// TokenTouchWindow is how stale `agent_tokens.last_used_at` may get before a
// resolution writes it again.
//
// The same five minutes api_keys uses, for the same reason: the column says
// "some time in the last five minutes" and a token doing a thousand requests a
// second must not put a thousand UPDATE round trips a second on one row whose
// lock is a queue.
const TokenTouchWindow = 5 * time.Minute

// Errors this store returns. They are distinct values so the code says what
// happened, and the HTTP layer renders two of them differently for a reason that
// is written where it is rendered.
var (
	// ErrNotFound is ONE answer for every way a lookup for a live row can fail:
	// the row never existed, the claim link is spent, the link is expired, the
	// agent is already claimed, the token is revoked, the token is spent, or the
	// principal is disabled.
	//
	// A store that returned ErrExpired and ErrNotFound separately would hand the
	// claim route a 410 to render, and a 410 says "this link was real". That is
	// the enumeration oracle this service refuses to build, and it is why the
	// refusals are one value: the route has nothing to distinguish them WITH.
	ErrNotFound = errors.New("no such agent")

	// ErrAlreadyClaimed means the agent exists and is bound to an account.
	//
	// It is distinct from ErrNotFound for the benefit of a caller who already
	// holds the row — the claim route's own re-read — and NOT for the benefit of a
	// stranger holding a link. The route maps it to the same 404 ErrNotFound gets.
	ErrAlreadyClaimed = errors.New("this agent has already been claimed")

	// ErrUnclaimed means a caller presented a LIVE agent credential for a
	// principal that has never been bound to a human account.
	//
	// IT IS NOT A 401 AND THAT IS THE WHOLE REASON IT EXISTS. The credential
	// resolved: the request is authenticated, the principal is real, and the
	// token is live. What is missing is the CLICK — a human approving the claim
	// link. A 401 would send a client hunting a login problem that does not
	// exist, and the caller's remedy is not a new credential but another party's
	// action.
	//
	// D4 is what makes it a refusal rather than a no-op: an agent that registered
	// itself has done everything an agent can do alone, and "an agent acting
	// alone gets nothing" means the paths that ACT are closed until a human has
	// claimed it. The one path that stays open to an unclaimed principal is the
	// one that asks for its claim link, because closing that would leave an agent
	// nobody can finish claiming.
	ErrUnclaimed = errors.New("this agent is unclaimed")

	// ErrIllegalTransition means the state machine refuses from → to.
	//
	// It is a 422 at the route rather than a 404, and the difference is who is
	// asking: a caller asking to disable an agent has already been authorized
	// against the account that owns it, so the refusal is about the AGENT's
	// history rather than about anything a stranger could learn. There is exactly
	// one transition that produces it — unclaimed → disabled — and it is refused
	// twice, here and in the table's CHECK.
	ErrIllegalTransition = errors.New("that agent cannot move to the requested status")

	// ErrNameTaken means this agent already has a LIVE token with that name.
	//
	// A 409 rather than a 422, on apikeys' argument: the request is well formed
	// and the state it asks for collides with one that exists. The index that
	// raises it is partial on revoked_at IS NULL, so a revoked token of the same
	// name does not collide — which is what makes "revoke the old one, mint the
	// new one" two requests rather than a transaction that finds a free name first.
	ErrNameTaken = errors.New("an active agent token with that name already exists")

	// ErrAlreadyRevoked means the credential exists and has already been
	// withdrawn.
	//
	// Distinct from ErrNotFound so a caller who clicks twice is told so, on
	// apikeys' argument: a caller who believed a revocation succeeded twice has a
	// belief that ends up written in an incident timeline. It is wrapped with the
	// row id rather than returned bare, because a bare sentinel on a route that
	// renders 404 for everything is a distinction nobody asked for.
	ErrAlreadyRevoked = errors.New("agent token is already revoked")

	// ErrUsernameTaken means the globally-unique handle a registration asked for
	// is already held by another principal (migration 00034).
	//
	// Distinct from ErrNotFound and ErrNameTaken because the caller SUPPLIED this
	// value and a 422 needs a field to name. The registration service generates
	// its own handle and retries on this before it ever returns, so the only way
	// a HANDLER sees it is a caller who chose a handle deliberately and lost the
	// retry budget — and the answer there names `username` rather than pretending
	// the request was unparseable.
	ErrUsernameTaken = errors.New("that username is already registered")
)

// agentColumns is the select list, in the order scanAgent expects. One constant,
// so a column added here cannot be present in one query and forgotten in another.
//
// `username` sits right after `name` (migration 00034), and scanAgent reads it in
// the same position: the column and the scan are one thing, and a reorder that
// moved one without the other is a runtime scan error rather than a compile one —
// which is why the constant exists.
const agentColumns = `id, name, username, status, claim_token_digest, claim_link_expires_at, ` +
	`claimed_by_account_id, claimed_at, device, created_at, updated_at`

// tokenColumns is the same for agent_tokens.
const tokenColumns = `id, agent_id, name, token_digest, created_at, expires_at, ` +
	`last_used_at, revoked_at, revoked_reason`

// Store is the agents, agent_tokens and agent_events tables.
type Store struct {
	pool db.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool db.Pool) *Store { return &Store{pool: pool} }

// Pool exposes the pool the store was built with, so a use case can open the
// transaction its own writes belong in without the store choosing the boundary
// for it.
func (s *Store) Pool() db.Querier { return s.pool }

// ---------------------------------------------------------------------------
// agents
// ---------------------------------------------------------------------------

// NewAgent is the input to Store.Create: the row a registration produces.
//
// It carries the claim link's DIGEST and never its plaintext, for the reason
// sessions.NewSession and apikeys.NewKey do: the store has no way to render the
// link, so there is no field a raw credential could be written into.
type NewAgent struct {
	// Name is what the human sees on the claim screen. 1..120 characters, which
	// is the table's CHECK and not this store's opinion.
	Name string
	// Username is the globally-unique handle (migration 00034). The service
	// normalises and, on a collision, retries with a fresh one before this ever
	// reaches the store; the store just writes what it is given and turns a
	// surviving collision into ErrUsernameTaken.
	Username string
	// Device is the agent's own description of itself, written whole as a
	// document. The set of keys is a code fact (migrations/00027's argument), so
	// this is a map and not four columns.
	Device map[string]any
	// ClaimDigest is the SHA-256 of the claim link, the only part of it that
	// reaches the database.
	ClaimDigest string
	// ClaimLinkExpiresAt is when the link stops working, and an unclaimed agent
	// must always have one — the table's agents_unclaimed_has_a_live_link CHECK
	// refuses a row without it.
	ClaimLinkExpiresAt time.Time
	// CreatedAt is the service's clock, passed in so the row and the event
	// announcing it agree and only one of the two is under test control.
	CreatedAt time.Time
}

// Create inserts an unclaimed principal and its first claim link.
//
// ErrUsernameTaken is what a surviving username collision becomes. The service
// retries before this, so the only way to see it is a caller supplying a handle
// that was taken across the retry budget — which the HTTP layer answers without
// ever having rendered the handle as "taken" on an answer an attacker can read.
//
// AN EMPTY USERNAME IS WRITTEN AS NULL, not as the empty string, because the
// column is nullable and `”` is not a legal handle for the shape CHECK — the
// distinction between "no handle" and "an empty handle" is database fact here
// rather than something every caller has to remember to encode. A registration
// through the service always generates a handle before it reaches this method, so
// the NULL path is a caller that constructs NewAgent directly (a test, a repair
// script) and not the production registration.
func (s *Store) Create(ctx context.Context, q db.Querier, n NewAgent) (Agent, error) {
	device, err := marshalDevice(n.Device)
	if err != nil {
		return Agent{}, err
	}

	var username any
	if n.Username != "" {
		username = n.Username
	}

	const query = `
		INSERT INTO agents (name, username, device, claim_token_digest, claim_link_expires_at, created_at, updated_at)
		VALUES ($1, $2, $3::jsonb, $4, $5, $6, $6)
		RETURNING ` + agentColumns

	out, err := scanAgent(q.QueryRow(ctx, query,
		n.Name, username, device, n.ClaimDigest, n.ClaimLinkExpiresAt, n.CreatedAt))
	if err != nil {
		if errors.Is(err, errNoRows) {
			return Agent{}, ErrNotFound
		}
		if isUniqueViolation(err) {
			// The one caller-reachable unique violation on this table is the
			// handle (00034); the claim digest's is a 256-bit bug, not a request.
			return Agent{}, ErrUsernameTaken
		}
		return Agent{}, fmt.Errorf("agents: registering a principal: %w", err)
	}
	return out, nil
}

// ByClaimDigest resolves a presented claim link to the UNCLAIMED agent it
// belongs to.
//
// THREE FILTERS IN ONE STATEMENT, and they are three rather than one because a
// caller must not be able to tell them apart:
//
//	the digest miss          the link was never issued
//	status = 'unclaimed'     it has already been claimed
//	claim_link_expires_at > now   it is too old
//
// All three return ErrNotFound. There is no query here that can answer "was this
// link ever real", which is the only question worth refusing to answer about a
// credential a stranger holds.
//
// now is the caller's instant rather than the database's clock(), for the reason
// apikeys' ByDigest takes one: the service reads time through an injected clock,
// and a link that expires mid-request has to be judged against the same instant
// the response is timestamped with.
func (s *Store) ByClaimDigest(ctx context.Context, q db.Querier, digest string, now time.Time) (Agent, error) {
	// An empty digest never reaches the database. It is not a security boundary —
	// an empty string hashes to a well-formed digest like any other value — it is
	// that the query has one shape and no caller should be able to change it.
	if digest == "" {
		return Agent{}, ErrNotFound
	}

	const query = `
		SELECT ` + agentColumns + `
		FROM agents
		WHERE claim_token_digest = $1
		  AND status = 'unclaimed'
		  AND claim_link_expires_at > $2`

	out, err := scanAgent(q.QueryRow(ctx, query, digest, now))
	if errors.Is(err, errNoRows) {
		return Agent{}, ErrNotFound
	}
	if err != nil {
		return Agent{}, fmt.Errorf("agents: resolving a claim link: %w", err)
	}
	return out, nil
}

// Claim binds an unclaimed agent to an account, and spends the link.
//
// THE CONDITIONAL UPDATE IS THE WHOLE PACKET. The WHERE carries the digest, the
// status AND the expiry, so the database is the thing that decides whether this
// claim is still available:
//
//	WHERE id = $1
//	  AND status = 'unclaimed'
//	  AND claim_token_digest = $2
//	  AND claim_link_expires_at > $4
//
// Zero rows is one 404, and the 404 never says which conjunct failed. Two humans
// clicking the same link in the same second produce one claim and one 404, and
// the second click's account is simply not recorded — there is no window between
// a read and a write for the two to disagree in, because there is no read.
//
// WHAT THE UPDATE CLEARS, AND WHY IT MATTERS MORE THAN WHAT IT SETS. The claim
// link's digest and expiry both go to NULL in the same statement that sets the
// status. A spent link is not a credential: keeping the digest would leave a
// value that resolves to a row nobody can redeem again, which is a 404 that
// looks like a bug. The table's agents_claim_link_only_while_unclaimed CHECK
// says the same thing, so a writer that forgot would be a write error rather
// than a live credential.
//
// The Go-side state machine is consulted BEFORE the statement rather than instead
// of it, and the two are not redundant: the table refuses illegal STATES and this
// function asks about a MOVE, so a caller cannot ask for either.
//
// ErrAlreadyClaimed is returned when the row is there and bound, which the route
// maps to the same 404 ErrNotFound gets — it is for a caller that already holds
// the row and is entitled to know, which is to say the claim use case's own
// re-read and not a stranger.
func (s *Store) Claim(ctx context.Context, q db.Querier, agentID id.UUID, claimDigest string, account id.UUID, at time.Time) (Agent, error) {
	if agentID.IsZero() || account.IsZero() || claimDigest == "" {
		return Agent{}, ErrNotFound
	}
	if !MayTransition(StatusUnclaimed, StatusClaimed) {
		// Unreachable while the state machine above says what it says, and stated
		// because a reader should not have to check: the store refuses the move in
		// Go as well as in the table.
		return Agent{}, ErrIllegalTransition
	}

	const query = `
		UPDATE agents
		SET status = 'claimed',
		    claimed_by_account_id = $3,
		    claimed_at = $4,
		    claim_token_digest = NULL,
		    claim_link_expires_at = NULL,
		    updated_at = $4
		WHERE id = $1
		  AND status = 'unclaimed'
		  AND claim_token_digest = $2
		  AND claim_link_expires_at > $5
		RETURNING ` + agentColumns

	out, err := scanAgent(q.QueryRow(ctx, query, agentID, claimDigest, account, at, at))
	if errors.Is(err, errNoRows) {
		// One read to say WHICH of the failures this was, and it is not the
		// route's answer — it is the use case's, so the event it writes names the
		// real cause. A stranger holding the link gets ErrNotFound either way.
		existing, lookupErr := s.ByID(ctx, q, agentID)
		if errors.Is(lookupErr, ErrNotFound) {
			return Agent{}, ErrNotFound
		}
		if lookupErr != nil {
			return Agent{}, lookupErr
		}
		if existing.IsClaimed() {
			return Agent{}, ErrAlreadyClaimed
		}
		return Agent{}, ErrNotFound
	}
	if err != nil {
		return Agent{}, fmt.Errorf("agents: claiming a principal: %w", err)
	}
	return out, nil
}

// RefreshClaimLink replaces an unclaimed agent's claim link in place.
//
// ONE LIVE LINK PER AGENT, and "refresh" is an UPDATE rather than an insert
// because the link lives on the principal — see the migration header. The
// status guard is the load-bearing half: a claimed agent has no link to refresh
// and the WHERE says so, so a replayed refresh against a claimed row updates
// zero rows and comes back ErrNotFound rather than resurrecting a credential.
//
// IT DOES NOT CLAIM, and that is the whole reason it is a separate method from
// Claim: W1-P2's rotation is the owner of the CLI re-issuing a link it lost, and
// "give me a new link" must never be able to bind an account.
func (s *Store) RefreshClaimLink(ctx context.Context, q db.Querier, agentID id.UUID, claimDigest string, expiresAt, at time.Time) (Agent, error) {
	if agentID.IsZero() || claimDigest == "" {
		return Agent{}, ErrNotFound
	}

	const query = `
		UPDATE agents
		SET claim_token_digest = $2,
		    claim_link_expires_at = $3,
		    updated_at = $4
		WHERE id = $1
		  AND status = 'unclaimed'
		RETURNING ` + agentColumns

	out, err := scanAgent(q.QueryRow(ctx, query, agentID, claimDigest, expiresAt, at))
	if errors.Is(err, errNoRows) {
		return Agent{}, ErrNotFound
	}
	if err != nil {
		return Agent{}, fmt.Errorf("agents: refreshing a claim link: %w", err)
	}
	return out, nil
}

// ByID loads an agent by its row id, whatever its status.
func (s *Store) ByID(ctx context.Context, q db.Querier, agentID id.UUID) (Agent, error) {
	if agentID.IsZero() {
		return Agent{}, ErrNotFound
	}

	const query = `SELECT ` + agentColumns + ` FROM agents WHERE id = $1`

	out, err := scanAgent(q.QueryRow(ctx, query, agentID))
	if errors.Is(err, errNoRows) {
		return Agent{}, ErrNotFound
	}
	if err != nil {
		return Agent{}, fmt.Errorf("agents: loading a principal: %w", err)
	}
	return out, nil
}

// ListForAccount returns every agent an account has claimed, newest first.
//
// DISABLED ONES INCLUDED, and that is the same decision apikeys' ListForAccount
// makes about revoked tokens: "was this withdrawn, or was it always broken?" is a
// support question a deleted row answers for nobody. Unclaimed agents are absent
// by construction — the WHERE is on claimed_by_account_id, which is NULL for
// every one of them.
func (s *Store) ListForAccount(ctx context.Context, q db.Querier, account id.UUID) ([]Agent, error) {
	out := make([]Agent, 0, 4)
	if account.IsZero() {
		return out, nil
	}

	const query = `
		SELECT ` + agentColumns + `
		FROM agents
		WHERE claimed_by_account_id = $1
		ORDER BY created_at DESC, id DESC`

	rows, err := q.Query(ctx, query, account)
	if err != nil {
		return nil, fmt.Errorf("agents: listing an account's principals: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		agent, err := scanAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("agents: reading an account's principals: %w", err)
		}
		out = append(out, agent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("agents: reading an account's principals: %w", err)
	}
	return out, nil
}

// SetStatus moves an agent to to, guarded by the state machine.
//
// THE GUARD IS IN GO AND THE TABLE SAYS IT AGAIN. MayTransition is a total
// function over the closed set, so a caller asking for unclaimed → disabled is
// refused here with ErrIllegalTransition and would be refused by the CHECK if it
// got past. Two layers, and the argument for both is apikeys': the database is
// the one that other writers — a repair script, a future packet, a psql session
// — cannot bypass.
//
// THE CONDITIONAL UPDATE CARRIES THE STATUS IT READ. Write-where-was, so a
// request that read `claimed` and writes `disabled` cannot land on top of a row
// that became claimed again in between. Where the row has moved, the UPDATE
// affects zero rows and the answer is a fresh read rather than a silent
// overwrite.
func (s *Store) SetStatus(ctx context.Context, q db.Querier, agentID id.UUID, to string, at time.Time) (Agent, error) {
	current, err := s.ByID(ctx, q, agentID)
	if err != nil {
		return Agent{}, err
	}
	if !MayTransition(current.Status, to) {
		return Agent{}, fmt.Errorf("%w: %s → %s", ErrIllegalTransition, current.Status, to)
	}

	const query = `
		UPDATE agents
		SET status = $2, updated_at = $3
		WHERE id = $1 AND status = $4
		RETURNING ` + agentColumns

	out, err := scanAgent(q.QueryRow(ctx, query, agentID, to, at, current.Status))
	if errors.Is(err, errNoRows) {
		// The row moved between the read and the write. Load it again and refuse
		// on what it is NOW, rather than reporting a transition that did not
		// happen.
		fresh, rereadErr := s.ByID(ctx, q, agentID)
		if rereadErr != nil {
			return Agent{}, rereadErr
		}
		return Agent{}, fmt.Errorf("%w: the agent is now %s", ErrIllegalTransition, fresh.Status)
	}
	if err != nil {
		return Agent{}, fmt.Errorf("agents: moving a principal to %s: %w", to, err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// agent_tokens
// ---------------------------------------------------------------------------

// NewAgentToken is the input to Store.CreateToken.
//
// It carries the DIGEST and never the token, for the reason NewAgent does: there
// is no field a plaintext credential could be written into.
type NewAgentToken struct {
	AgentID   id.UUID
	Name      string
	Digest    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateToken inserts a credential for an agent.
//
// The only unique constraint a CALLER can collide with is the partial index on
// (agent_id, lower(name)) WHERE revoked_at IS NULL. The digest's index is a
// 256-bit collision on a value this package generated, which is a bug and not a
// request — the same reasoning apikeys' Create uses.
func (s *Store) CreateToken(ctx context.Context, q db.Querier, n NewAgentToken) (Token, error) {
	if n.AgentID.IsZero() {
		return Token{}, ErrNotFound
	}

	const query = `
		INSERT INTO agent_tokens (agent_id, name, token_digest, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING ` + tokenColumns

	out, err := scanToken(q.QueryRow(ctx, query, n.AgentID, n.Name, n.Digest, n.CreatedAt, n.ExpiresAt))
	if err != nil {
		if isUniqueViolation(err) {
			return Token{}, ErrNameTaken
		}
		return Token{}, fmt.Errorf("agents: minting a credential: %w", err)
	}
	return out, nil
}

// Resolved is an agent credential AND the status of the principal it resolved
// against.
//
// The two are returned together because the authority is the pair: a token held
// by a DISABLED agent does not resolve, and a caller that had one without the
// other would have to make a second query to find out. It is the same shape
// apikeys' ByDigest returns — the row and the live role — for the same reason.
type Resolved struct {
	Token
	// AgentStatus is the principal's status at the instant of the resolution.
	AgentStatus string
}

// UsableAt reports whether this credential may be presented at now.
//
// It is Token.UsableAt against the status the resolution read, so the answer a
// caller gets is the one the query already made: a revoked token, a spent token
// and a disabled principal are all unusable, and an unknown status is refused
// rather than treated as live.
func (r Resolved) UsableAt(now time.Time) bool { return r.Token.UsableAt(now, r.AgentStatus) }

// ByTokenDigest resolves a presented agent credential to a live token and the
// principal it belongs to.
//
// FOUR FILTERS IN ONE STATEMENT, on apikeys' argument and with the same four
// reasons:
//
//	the digest miss       never existed
//	revoked_at IS NULL    withdrawn
//	expires_at > now      spent
//	a.status = 'claimed'  the principal is unclaimed or disabled
//
// All four produce ErrNotFound. Splitting them — fetching the row and checking
// the principal afterwards — would answer with one query plan for a revoked
// token and another for an unknown one, which is an oracle for exactly the
// question somebody asks after "does this work".
//
// The join is why the principal's status is in the same round trip: an agent
// credential's authority is not the row's own state alone, and the statement
// that expresses that is here rather than in every caller.
func (s *Store) ByTokenDigest(ctx context.Context, q db.Querier, digest string, now time.Time) (Resolved, error) {
	if digest == "" {
		return Resolved{}, ErrNotFound
	}

	// A var rather than a const, and the reason is prefixed(): a column added to
	// tokenColumns cannot be forgotten in the aliased query, and a constant cannot
	// call a function.
	var query = `
		SELECT ` + prefixed("t", tokenColumns) + `, a.status
		FROM agent_tokens t
		JOIN agents a ON a.id = t.agent_id
		WHERE t.token_digest = $1
		  AND t.revoked_at IS NULL
		  AND t.expires_at > $2
		  AND a.status = 'claimed'`

	var (
		out    Resolved
		status string
	)
	err := q.QueryRow(ctx, query, digest, now).Scan(
		&out.ID, &out.AgentID, &out.Name, &out.TokenDigest,
		&out.CreatedAt, &out.ExpiresAt, &out.LastUsedAt, &out.RevokedAt, &out.RevokedReason,
		&status,
	)
	if errors.Is(err, errNoRows) {
		return Resolved{}, ErrNotFound
	}
	if err != nil {
		return Resolved{}, fmt.Errorf("agents: resolving a credential: %w", err)
	}

	out.AgentStatus = status
	return out, nil
}

// OwnerByTokenDigest resolves a presented credential to its token and the
// principal it belongs to, for the AGENT'S OWN management surface — the routes an
// agent reaches to refresh its claim link and to create/rotate/revoke its own
// bearer tokens.
//
// THE DIFFERENCE FROM ByTokenDigest IS ONE MISSING FILTER, and it is the whole
// reason this is a separate method rather than a boolean on the other. ByTokenDigest
// requires `a.status = 'claimed'`, because it answers "may this credential act on
// the platform" and a principal nobody has claimed may not. This method answers
// "which principal is this, and what tokens does it hold" — a question a caller
// must be able to ask while it is UNCLAIMED, because the first thing a freshly
// registered agent does with its bootstrap token is ask that, and an agent whose
// link expired needs it to mint a fresh one. Requiring claimed here would strand
// exactly the agents the refresh route exists to save.
//
// What it STILL filters on is the pair that says something about the credential
// itself rather than about the principal's place in the world:
//
//	the digest miss       never existed
//	revoked_at IS NULL    withdrawn
//	expires_at > now      spent
//
// A DISABLED principal is refused by the use cases that consult the status, not
// here: the resolution is "who is this", and whether they may act is the next
// question. The three that cannot be told apart from a stranger's guess produce
// ErrNotFound exactly as they do on ByTokenDigest, and that is the property both
// share — the read a stranger can perform tells them nothing beyond "this value
// does not resolve".
//
// RETURNING THE STATUS is what lets the caller apply the right rule without a
// second query: Resolved carries AgentStatus, and UsableAt/refresh check it from
// there.
func (s *Store) OwnerByTokenDigest(ctx context.Context, q db.Querier, digest string, now time.Time) (Resolved, error) {
	if digest == "" {
		return Resolved{}, ErrNotFound
	}

	var query = `
		SELECT ` + prefixed("t", tokenColumns) + `, a.status
		FROM agent_tokens t
		JOIN agents a ON a.id = t.agent_id
		WHERE t.token_digest = $1
		  AND t.revoked_at IS NULL
		  AND t.expires_at > $2`

	var (
		out    Resolved
		status string
	)
	err := q.QueryRow(ctx, query, digest, now).Scan(
		&out.ID, &out.AgentID, &out.Name, &out.TokenDigest,
		&out.CreatedAt, &out.ExpiresAt, &out.LastUsedAt, &out.RevokedAt, &out.RevokedReason,
		&status,
	)
	if errors.Is(err, errNoRows) {
		return Resolved{}, ErrNotFound
	}
	if err != nil {
		return Resolved{}, fmt.Errorf("agents: resolving an owner's credential: %w", err)
	}

	out.AgentStatus = status
	return out, nil
}

// ByTokenID loads a credential by its row id, revoked or not.
//
// The opposite filter from ByTokenDigest on purpose: this is the management
// list's query, and "was this withdrawn, or was it always broken?" is a support
// question a deleted row answers for nobody.
func (s *Store) ByTokenID(ctx context.Context, q db.Querier, rowID id.UUID) (Token, error) {
	if rowID.IsZero() {
		return Token{}, ErrNotFound
	}

	const query = `SELECT ` + tokenColumns + ` FROM agent_tokens WHERE id = $1`

	out, err := scanToken(q.QueryRow(ctx, query, rowID))
	if errors.Is(err, errNoRows) {
		return Token{}, ErrNotFound
	}
	if err != nil {
		return Token{}, fmt.Errorf("agents: loading a credential: %w", err)
	}
	return out, nil
}

// ListTokensForAgent returns every credential an agent holds, newest first,
// revoked ones included — see ByTokenID.
func (s *Store) ListTokensForAgent(ctx context.Context, q db.Querier, agentID id.UUID) ([]Token, error) {
	out := make([]Token, 0, 2)
	if agentID.IsZero() {
		return out, nil
	}

	const query = `
		SELECT ` + tokenColumns + `
		FROM agent_tokens
		WHERE agent_id = $1
		ORDER BY created_at DESC, id DESC`

	rows, err := q.Query(ctx, query, agentID)
	if err != nil {
		return nil, fmt.Errorf("agents: listing an agent's credentials: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		token, err := scanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("agents: reading an agent's credentials: %w", err)
		}
		out = append(out, token)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("agents: reading an agent's credentials: %w", err)
	}
	return out, nil
}

// RevokeToken withdraws a credential and returns the stored row.
//
// SCOPED BY agent_id as well as id, on apikeys' argument: the caller has already
// established which agent they own, and a query that says so again costs nothing
// and refuses a cross-tenant revocation outright.
//
// CONDITIONAL ON revoked_at IS NULL, so a second attempt updates zero rows and
// comes back the row's own state rather than moving the timestamp and overwriting
// the reason. When a credential was actually withdrawn is an incident question,
// and two clicks at the same moment must produce one answer.
func (s *Store) RevokeToken(ctx context.Context, q db.Querier, rowID, agentID id.UUID, at time.Time, reason string) (Token, error) {
	if rowID.IsZero() || agentID.IsZero() {
		return Token{}, ErrNotFound
	}

	const query = `
		UPDATE agent_tokens
		SET revoked_at = $3, revoked_reason = NULLIF($4, '')
		WHERE id = $1 AND agent_id = $2 AND revoked_at IS NULL
		RETURNING ` + tokenColumns

	out, err := scanToken(q.QueryRow(ctx, query, rowID, agentID, at, reason))
	if errors.Is(err, errNoRows) {
		existing, lookupErr := s.ByTokenID(ctx, q, rowID)
		if errors.Is(lookupErr, ErrNotFound) {
			return Token{}, ErrNotFound
		}
		if lookupErr != nil {
			return Token{}, lookupErr
		}
		if existing.AgentID != agentID {
			// Another agent's credential, told apart from this one's revoked one
			// only because the caller already holds the row id. The route maps both
			// to the same 404.
			return Token{}, ErrNotFound
		}
		if existing.IsRevoked() {
			return Token{}, fmt.Errorf("agents: credential %s: %w", rowID, ErrAlreadyRevoked)
		}
		return Token{}, ErrNotFound
	}
	if err != nil {
		return Token{}, fmt.Errorf("agents: revoking a credential: %w", err)
	}
	return out, nil
}

// Touch records that a credential was used, at most once per window.
//
// The condition is in the WHERE rather than read first, so there is no
// read-modify-write and two concurrent requests both deciding to write is a
// non-event. Zero rows updated is a SUCCESS: the column says "some time in the
// last five minutes" and it already does.
//
// A REVOKED TOKEN IS NOT TOUCHED, and the condition says so, because
// `last_used_at` on a dead credential is a column asserting that it was working.
func (s *Store) Touch(ctx context.Context, q db.Querier, rowID id.UUID, at time.Time) error {
	if rowID.IsZero() {
		return nil
	}

	const query = `
		UPDATE agent_tokens
		SET last_used_at = $2
		WHERE id = $1
		  AND revoked_at IS NULL
		  AND (last_used_at IS NULL OR last_used_at < $3)`

	// No RowsAffected check, and the comment is the reason: zero rows is the rate
	// limit working, and reporting it would turn a busy credential into a failing
	// one.
	if _, err := q.Exec(ctx, query, rowID, at, at.Add(-TokenTouchWindow)); err != nil {
		return fmt.Errorf("agents: recording a credential's last use: %w", err)
	}
	return nil
}

// rowScanner is the narrow interface both pgx.Row and pgx.Rows satisfy, so one
// read serves the single-row and the list query.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAgent(row rowScanner) (Agent, error) {
	var (
		a        Agent
		username *string
	)
	err := row.Scan(&a.ID, &a.Name, &username, &a.Status, &a.ClaimTokenDigest, &a.ClaimLinkExpiresAt,
		&a.ClaimedByAccountID, &a.ClaimedAt, &a.Device, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if errors.Is(err, errNoRows) {
			return Agent{}, errNoRows
		}
		return Agent{}, fmt.Errorf("agents: scanning a principal: %w", err)
	}
	// A NULL username folds to the empty string rather than refusing the scan,
	// the same shape scanEvent gives a registration's null actor. The column is
	// nullable (a writer that constructs NewAgent directly — W1-P1's store tests, a
	// repair script — may omit the handle), and "no handle" and "a handle" are
	// distinguished by the empty string here because a registration through the
	// service always generates one and never reaches the NULL case.
	if username != nil {
		a.Username = *username
	}
	return a, nil
}

func scanToken(row rowScanner) (Token, error) {
	var t Token
	err := row.Scan(&t.ID, &t.AgentID, &t.Name, &t.TokenDigest,
		&t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt, &t.RevokedReason)
	if err != nil {
		if errors.Is(err, errNoRows) {
			return Token{}, errNoRows
		}
		return Token{}, fmt.Errorf("agents: scanning a credential: %w", err)
	}
	return t, nil
}

// marshalDevice renders the device document the row stores.
//
// An empty or nil map becomes {} rather than NULL, because "the agent told us
// nothing about itself" is a fact an empty document already says — the column's
// NOT NULL DEFAULT is the database saying the same thing, and two writers that
// disagree about which one applies is how a row ends up with a NULL a CHECK
// later refuses.
func marshalDevice(device map[string]any) (string, error) {
	if len(device) == 0 {
		return "{}", nil
	}
	raw, err := json.Marshal(device)
	if err != nil {
		return "", fmt.Errorf("agents: rendering the device document: %w", err)
	}
	return string(raw), nil
}

// prefixed qualifies a bare column list with a table alias, so the joined
// resolution query and the plain reads can share one column constant. It is the
// same helper internal/apikeys/store.go has, restated because neither package
// imports the other and a shared one would be an edge between two tables that
// have nothing to say to each other.
func prefixed(alias, columns string) string {
	out := make([]byte, 0, len(columns)+len(alias)+8)
	start := 0
	for i := 0; i <= len(columns); i++ {
		if i == len(columns) || columns[i] == ',' {
			out = append(out, alias...)
			out = append(out, '.')
			out = append(out, columns[start:i]...)
			if i < len(columns) {
				out = append(out, ',')
			}
			start = i + 1
		}
	}
	return string(out)
}

// isUniqueViolation reports whether err is a unique_violation.
//
// It matches on the SQLSTATE alone, load-bearing rather than lazy: Postgres
// renames an index when a table is cloned with LIKE ... INCLUDING INDEXES, which
// is exactly what the integration tests do, and a silently mis-detected duplicate
// turns a 409 into a 500.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == uniqueViolation
}
