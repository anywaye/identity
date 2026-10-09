package httpapi

// THE AGENT SURFACE: ONE ROUTE, AND THE CLAIM IS THE WHOLE OF IT.
//
//	POST /v1/accounts/{accountID}/agents/claim  {token}  →  200 {agent}
//
// ONE ROUTE IN THIS PACKET, and the reason is a packet boundary rather than a
// design limit: registration (POST /v1/agents) is W1-P2's, conductor's box
// capabilities are W1-P3's, and minting the scoped token at claim time is W2-P2's.
// What lands here is the route that turns a link into a binding, because that is
// the part every one of those packets is written against — the claim route is what
// makes an agent an account's, and nothing else in the wave means anything until
// it exists.
//
// # WHY THE ACCOUNT IS IN THE PATH AND NOT IN THE BODY
//
// Because "which account claims this" is a decision, and a decision needs an
// authorization check rather than a field. A body carrying `account_id` would put
// a membership read inside a handler — a second place role is checked, in the
// service that insists it is checked in one. The path puts the account where every
// other account write puts it, and `requireAccountRole` answers 404 for an account
// the caller is not in, which is the answer that leaks nothing.
//
// A route with no account in it would have to choose one for the caller, and the
// only one it could choose is their personal account. That is a product decision
// this packet does not get to make.
//
// # WHY THE LINK IS THE ONLY THING IN THE BODY
//
// Because the link names the agent and nothing else does. A body that also carried
// an `agent_id` would be a body that lets the caller name a principal they were
// never given a link for, which is the entire thing the single-use window exists
// to bound.
//
// # THE 404 IS ONE SHAPE AND SAYS NOTHING
//
// A wrong token, an expired link, an already-claimed agent and an agent that never
// existed are the SAME response: one status, one sentence, one body. There is no
// 410 (which would say "this link was real"), no 409 (which would say "this agent
// is taken") and no difference in timing a caller could measure. The one thing a
// stranger learns from a failed claim is that it failed.
//
// WHAT IS DELIBERATELY NOT HERE: a `redirect` or `return_to` parameter.
// `redeemSessionLinkRequest` in sessionlinks.go gives the reason — an open
// redirector with a session attached, on a route with no allow-list. The claim
// screen is a separate origin that knows where to go next.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/agents"
	"github.com/cafaye/identity/internal/platform/id"
)

// Agents is the claim use case, and the reason this route needs nothing else.
//
// It is an interface rather than *agents.Service so a test can build a router
// with a double, the way every other surface here does — and so the httpapi
// package does not gain a dependency on the store's constructor signature.
//
// IT IS THE WHOLE AGENT SURFACE IN ONE INTERFACE, and that is deliberate rather
// than a convenience. The claim (W1-P1) binds a principal to an account; the
// registration, the claim-link refresh and the bearer-token lifecycle (W1-P2) are
// the public and self-service halves of the SAME principal, resolved through the
// SAME service. One interface means one `o.agents` field, which means one entry in
// `conditionalSurfaces`, one set of walk literals to keep whole, and one service a
// fake has to stand in for — five surfaces hung off five fields is five chances
// for the walk to read a smaller service than the one that runs.
type Agents interface {
	Claim(ctx context.Context, in agents.ClaimInput) (agents.Claimed, error)

	// Register mints an unclaimed principal, its bootstrap token and its first
	// claim link. Public and unauthenticated: the caller has no credential, which
	// is the whole of what "self-registration" means.
	Register(ctx context.Context, in agents.RegisterInput) (agents.Registered, error)

	// RefreshClaimLink gives an agent a fresh claim link without claiming it,
	// authenticated by the agent's own bearer token.
	RefreshClaimLink(ctx context.Context, in agents.RefreshClaimInput) (agents.RefreshedClaim, error)

	// Authenticate resolves a presented agent bearer credential to its principal,
	// the agent-surface analogue of currentCaller. A route wraps this in
	// agentCredentialOnly.
	Authenticate(ctx context.Context, presented string, now time.Time) (agents.Owner, error)

	// IssueToken mints a named bearer credential the resolved agent holds.
	IssueToken(ctx context.Context, in agents.TokenInput) (agents.IssuedToken, error)
	// ListTokens returns the resolved agent's credentials, newest first.
	ListTokens(ctx context.Context, agentID id.UUID) ([]agents.Token, error)
	// RevokeToken withdraws one of the resolved agent's credentials.
	RevokeToken(ctx context.Context, agent, tokenID id.UUID, reason, traceID string, now time.Time) (agents.Token, error)
	// RotateToken withdraws a credential and mints a new one of the same name.
	RotateToken(ctx context.Context, agent, tokenID id.UUID, expiresIn *time.Duration, traceID string, now time.Time) (agents.IssuedToken, error)
}

// WithAgents mounts the agent routes.
func WithAgents(a Agents) Option {
	return func(o *options) {
		if a != nil {
			o.agents = a
		}
	}
}

// claimAgentRequest is the body of POST /v1/agents/claim.
//
// ONE FIELD, and its absence set is the design. No `agent_id`: a caller who could
// name the agent would be a caller who can bind one they were never given a link
// for. No `account_id`: the account is the session's. No `redirect`: see the file
// header.
type claimAgentRequest struct {
	Token string `json:"token"`
}

// claimAgentResponse is what a successful claim looks like: the agent, at the
// status it now holds.
//
// NO TOKEN. The mint is W2-P2's, and a response that carried one before the scope
// vocabulary exists would be a credential this service has not decided what it
// may do. `status` is here rather than omitted because the claim screen renders
// against it and a client that has to re-read the agent to learn it succeeded has
// made a second request to find out something the first one knew.
//
// ClaimTokenDigest is absent, and the absence is the same one apikeys.Key makes: a
// response that echoed the digest would tell a client something it has no use for.
type claimAgentResponse struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	// ClaimedAt is when the binding happened, rendered as an RFC 3339 instant. A
	// string rather than a time.Time so the JSON carries no location surprises and
	// the shape is what the document says it is.
	ClaimedAt string `json:"claimed_at"`
}

// claimedAtOr renders the claim's instant, falling back to now.
//
// The nil case is impossible on a row this route just wrote — the table's
// agents_claimed_is_whole CHECK makes claimed_by_account_id and claimed_at a pair,
// so a claim that succeeded without an instant is a claim the database refused.
// The fallback exists so that a future change to that invariant surfaces as a
// slightly-wrong body rather than as a `"<nil>"` in JSON, which is the shape that
// gets past every schema check and breaks a client at runtime.
func claimedAtOr(agent agents.Agent, fallback time.Time) string {
	if agent.ClaimedAt == nil {
		return fallback.UTC().Format(time.RFC3339)
	}
	return agent.ClaimedAt.UTC().Format(time.RFC3339)
}

// registerAgentRoutes mounts the agent surface.
//
// IT IS CALLED FROM `registerTenancyRoutes`, and that is the same arrangement
// `registerAdminRoutes` uses for the same stated reason: an account-scoped route
// mounted anywhere else sits outside `mountedAccountRoutes` and therefore outside
// both `TestEveryMountedRouteIsAnAccountRoute` and `TestEveryRouteIsInTheMatrix`
// — a walk that does not see a route cannot require a row for it. The claim is an
// action on an account, so it belongs in the registrar the two walks read.
//
// THE REGISTRAR ITSELF TAKES NO OPTION. `registerSessionLinkRoutes` sets the
// precedent and the reason is its: both need a database and nothing else, and a
// conditional surface is one more field for `options`, one more entry somebody
// must remember to add to router_walk_test.go's list, and one more way for a walk
// of the router to read a smaller service than the one that runs. The one early
// return here is on the service being absent at all, which is the same fail-closed
// shape every surface on this router has: a misconfiguration is a 404, not a 500
// on every request.
func (o options) registerAgentRoutes(r chiRouter) {
	if o.agents == nil {
		return
	}

	// The claim. The account in the path is the RESOURCE and the link in the body
	// is the credential, and the two are kept apart on purpose — see the file
	// header.
	//
	// `sessionCredentialOnly` runs OUTSIDE `requireAccountRole`, which is the
	// mirror of `requireAdminToken` running outside it on the admin surface: the
	// credential KIND is a property of the surface rather than of the handler, so a
	// route added next to it inherits it by being wrapped. A scoped api key is
	// refused with 403 — the caller is authenticated, so a 401 would send a client
	// hunting a login problem that does not exist.
	//
	// THE MINIMUM ROLE IS MEMBER, and that is the lowest there is: a claim binds an
	// agent to an account and any human in that account may do it. W1-P2's
	// `agent:*` scopes go in `accountRouteScopes` against the routes they gate, and
	// `Allows("")` is false for every granted set — so this route is closed to
	// tokens today, which is the safe direction and the rule.
	r.Post("/v1/accounts/{accountID}/agents/claim",
		o.sessionCredentialOnly(o.requireAccountRole(accounts.RoleMember, o.handleClaimAgent)))
}

// handleClaimAgent redeems a claim link.
//
//	POST /v1/accounts/:id/agents/claim  {token}  →  200 {id, name, status, claimed_at}
//	→  404 the link is wrong, expired, or spent — one answer for all three
//	→  403 a scoped api key presented, refused by sessionCredentialOnly outside
//	→  404 the account in the path is not the caller's
//	→  401 no credential
//
// The claim link is the ONLY thing a stranger ever presents on this surface. The
// account comes from the path, the human from the session, and the agent from the
// link — three different sources, and none of them is the body.
func (o options) handleClaimAgent(w http.ResponseWriter, r *http.Request) {
	account, ok := accountFrom(r.Context())
	if !ok {
		// Unreachable while requireAccountRole runs first, and stated because a
		// handler that read the account out of the URL would be a handler that
		// trusted a caller's spelling of it.
		notFound(w, r)
		return
	}

	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *claimAgentRequest
	if !decodeBody(w, r, &body) {
		return
	}

	// Trimmed here and refused as a 422 rather than digested, for the reason
	// `handleRedeemSessionLink` gives: a value no row can hold is a fact about the
	// caller's own input, not a fact about a link. It is also what keeps a length a
	// matter of refusal rather than of measurement — a 422 for a short token and a
	// 404 for a long one would be a length oracle for nothing at all.
	if strings.TrimSpace(body.Token) == "" {
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: "token", Code: "required"}}))
		return
	}

	claimed, err := o.agents.Claim(r.Context(), agents.ClaimInput{
		Token:   body.Token,
		Account: account.ID,
		User:    user.ID,
		TraceID: traceIDFrom(r.Context()),
		Now:     o.clk.Now(),
	})
	if err != nil {
		o.writeAgentClaimError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, claimAgentResponse{
		ID:     claimed.Agent.ID.String(),
		Name:   claimed.Agent.Name,
		Status: claimed.Agent.Status,
		// The instant the binding happened, and it is rendered rather than omitted
		// because the claim screen shows it. Nil is impossible on a successful
		// claim — the table's CHECK makes the pair whole — and the guard is here so
		// that a future writer cannot render a zero time.
		ClaimedAt: claimedAtOr(claimed.Agent, o.clk.Now()),
	})
}

// writeAgentClaimError maps the claim's refusals.
//
// ONE 404, and there is no second arm to add to it. `agents.ErrNotFound` is what
// the use case returns for a wrong token, an expired link, an already-claimed
// agent and an agent that was never issued — and the sentence is written so it
// does not name which. `agents.ErrIllegalTransition` would be a 422 on a route
// where no caller can reach it, because the claim asks for exactly one transition
// and the store refuses the others before this mapper is consulted.
//
// IT IS NOT `writeTenancyError` and not an arm inside it, for the reason
// `writeSessionLinkRedeemError` stands alone: the two surfaces answer different
// questions, and the tenancy mapper's 410 for a used invitation would be a
// sentence this route must never render.
func (o options) writeAgentClaimError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, agents.ErrNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no agent matches that claim link")

	default:
		unexpected(w, r, o.logger, err)
	}
}

// ===========================================================================
// W1-P2: the public registration, the claim-link refresh, and the bearer-token
// lifecycle. The account-scoped claim above is W1-P1's; everything below is the
// surface an UNCREDENTIALED caller reaches (registration) and the surface an
// AGENT reaches with its own bearer credential (refresh, tokens). Nothing here
// knows an account: an unclaimed agent has none, and that is the whole point of
// the lifecycle.
// ===========================================================================

// registerAgentPublicRoutes mounts the public registration and the self-service
// token surface on the AUTH routes — beside `/v1/users` and the session-links —
// and NOT in registerTenancyRoutes.
//
// WHY NOT THE TENANCY REGISTRAR. `TestEveryMountedRouteIsAnAccountRoute` refuses
// a non-account path in registerTenancyRoutes by name, and none of these routes is
// account-scoped: registration is anonymous, and refresh/tokens act on the
// principal the BEARER credential names, not on any account in a path. So they sit
// on the v1 surface, which is where every other public route already lives.
//
// IT IS CONDITIONAL ON `o.agents` ALONE, and that field is in `conditionalSurfaces`
// with the claim route already, so the drift walk, the authorization walk and the
// anonymous-enumeration walk all see these routes the moment the claim route is
// visible to them — one field, four checks, no new literal to forget. The claim
// route itself stays in registerTenancyRoutes because it IS account-scoped; this
// registrar is its public and self-service sibling, called from the same
// registerRoutes that calls registerTenancyRoutes.
func (o options) registerAgentPublicRoutes(r chiRouter) {
	if o.agents == nil {
		return
	}

	// THE REGISTRATION. Public and unauthenticated, and behind the request-rate
	// limiter on the same terms `/v1/users` is — the key is the client and the
	// route, never an attempted account (there is no account), so the 429 is
	// identical for everybody and discloses nothing. `rateLimit` runs the handler
	// and decides afterwards, so a burst still pays the mint cost before being
	// refused, which is the bound this repository picked over a timing oracle.
	r.Post("/v1/agents", o.rateLimit("/v1/agents", o.handleRegisterAgent))

	// THE REFRESH AND THE TOKENS are the SELF-SERVICE surface: agentCredentialOnly
	// resolves the presented bearer credential to its principal, so each handler
	// acts on the caller's own agent and there is no path id for a caller to point
	// at somebody else's. A stranger's request is one 401 before any handler runs.
	r.Post("/v1/agents/claim-link/refresh", o.agentCredentialOnly(o.handleRefreshAgentClaimLink))

	r.Post("/v1/agents/tokens", o.agentCredentialOnly(o.handleMintAgentToken))
	r.Get("/v1/agents/tokens", o.agentCredentialOnly(o.handleListAgentTokens))
	r.Delete("/v1/agents/tokens/{tokenID}", o.agentCredentialOnly(o.handleRevokeAgentToken))
	r.Post("/v1/agents/tokens/{tokenID}/rotate", o.agentCredentialOnly(o.handleRotateAgentToken))
}

// ---------------------------------------------------------------------------
// the agent credential, and the gate that resolves it
// ---------------------------------------------------------------------------

// agentContextKey carries the resolved owner on the request context.
type agentContextKey struct{}

// agentFrom reads the owner a request's agentCredentialOnly resolved.
func agentFrom(ctx context.Context) (agents.Owner, bool) {
	owner, ok := ctx.Value(agentContextKey{}).(agents.Owner)
	return owner, ok
}

// presentedAgentToken returns the bearer credential a request carries, or "".
//
// IT DOES NOT CHECK THE PREFIX, and that is the point. An agent token and a user
// api key share the one `cafaye_` prefix on purpose (see the agents package
// header), so a shape test could not tell them apart and a magic second prefix
// would be a fact this platform refuses to publish. What tells them apart is
// WHICH TABLE resolves the value: this route resolves it against agent_tokens, and
// a value that is actually an api key simply does not resolve there. So the gate
// is the resolution, not the shape, and a mis-presented credential is the same 401
// an unknown one gets.
func presentedAgentToken(r *http.Request) string {
	return bearerToken(r)
}

// agentCredentialOnly resolves the request's bearer token to its agent, offering
// the handler the owner on the context and answering 401 when it does not resolve.
//
// It is the agent-surface mirror of `currentUser`/`currentCaller`: one gate for
// the surface, so "who is this" has one answer and no handler re-implements the
// lookup. A live-but-unclaimed token resolves — that is the entire reason an agent
// can refresh its claim link and rotate its bootstrap token before anybody claims
// it — while a revoked, expired, disabled or never-issued one is the same 401 a
// guess gets. The service answers ErrNotFound for all of them, and this turns
// that into one 401 rather than a sentence naming which.
func (o options) agentCredentialOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := presentedAgentToken(r)
		if token == "" {
			unauthorized(w, r)
			return
		}
		owner, err := o.agents.Authenticate(r.Context(), token, o.clk.Now())
		if err != nil {
			// One 401 for an unknown, revoked, expired or disabled principal. The
			// service collapses them, and this does not take the collapse apart.
			unauthorized(w, r)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), agentContextKey{}, owner)))
	}
}

// agentTokenIDFrom reads and parses the token id in the path, on accountIDFrom's
// terms: a malformed id is 404, not 422, because the path is part of a resource's
// identity and "not an id this service issued" must be the same answer as "an id
// you cannot see".
func agentTokenIDFrom(r *http.Request) (id.UUID, bool) {
	parsed, err := id.Parse(chi.URLParam(r, agentTokenIDParam))
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}

// agentTokenIDParam is the chi URL parameter naming the credential being acted
// on.
const agentTokenIDParam = "tokenID"

// ---------------------------------------------------------------------------
// the registration
// ---------------------------------------------------------------------------

// registerAgentRequest is the body of POST /v1/agents.
//
// `name` is required and `username` is optional, and the asymmetry is the design:
// a display name is the one thing a human reads on the claim screen, so the agent
// supplies it; the handle is machine-facing bookkeeping the service can generate
// and retry, so it is optional and never refused for being taken — a collision
// simply yields a generated handle. A username the caller DOES supply is validated
// against the handle shape and, on a surviving collision, refuses with a 422
// naming the field, because that caller asked for a specific thing on purpose.
type registerAgentRequest struct {
	Name     string         `json:"name"`
	Username string         `json:"username"`
	Device   map[string]any `json:"device"`
}

// handleRegisterAgent mints an unclaimed agent, its bootstrap token and its claim
// link.
//
//	POST /v1/agents  {name, username?}  →  201 {agent, api_key, claim}
//	→  422 name missing/too long, or username malformed / lost the retry budget
//	→  503 no claim screen configured (a deployment that has not set the base)
//	→  429 rate limited
//
// # THE THREE THINGS IN THE 201, AND WHY EACH IS THERE
//
//	agent     the principal, at status "unclaimed", with its id, name, username
//	api_key   the bootstrap bearer token — `token` appears here and nowhere else,
//	          exactly as on the account api-keys mint. No column holds it.
//	claim     the URL a human opens to claim, and its expiry. The link is the
//	          only thing a stranger ever presents, and this is the only response
//	          that renders it.
//
// # THE TWO PLAINTEXTS LEAVE HERE ONCE
//
// The token and the claim link are minted in internal/agents, digested there, and
// written only as digests; this response is the single place their plaintext
// crosses the boundary. `TestTheRegistrationWritesNoPlaintextToken` reads the row
// back and finds neither, because there is no column for them.
func (o options) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	var body *registerAgentRequest
	if !decodeBody(w, r, &body) {
		return
	}

	registered, err := o.agents.Register(r.Context(), agents.RegisterInput{
		Name:     body.Name,
		Username: body.Username,
		Device:   body.Device,
		TraceID:  traceIDFrom(r.Context()),
		Now:      o.clk.Now(),
	})
	if err != nil {
		o.writeAgentRegistrationError(w, r, err)
		return
	}

	// The name for the bootstrap credential the way apikeys renders its issued
	// shape: id, name, the expiry, the token. No digest, and no scope set — the
	// agent-token scope vocabulary arrives with the routes it will gate.
	writeJSON(w, http.StatusCreated, registerAgentResponse{
		Agent: agentSummary{
			ID:       registered.Agent.ID.String(),
			Name:     registered.Agent.Name,
			Username: registered.Agent.Username,
			Status:   registered.Agent.Status,
		},
		APIKey: issuedAgentToken{
			ID:        registered.Token.ID.String(),
			Name:      registered.Token.Name,
			ExpiresAt: registered.Token.ExpiresAt.UTC().Format(time.RFC3339),
			Token:     registered.TokenPlaintext,
		},
		Claim: agentClaim{
			URL:       registered.ClaimURL,
			ExpiresAt: registered.ClaimLinkExpiresAt.UTC().Format(time.RFC3339),
		},
	})
}

// registerAgentResponse is the 201 from POST /v1/agents, in the shape the CLI's
// register command consumes (`cafaye agents register`):
//
//	{agent:{status:"unclaimed", …}, api_key:{token}, claim:{url}}
//
// The nesting is borrowed from the prior art because a CLI and a claim screen are
// written against it already; everything else about this type is identity's own.
type registerAgentResponse struct {
	Agent  agentSummary     `json:"agent"`
	APIKey issuedAgentToken `json:"api_key"`
	Claim  agentClaim       `json:"claim"`
}

// agentSummary is the principal as a response renders it: no claim digest, no
// device document, and never a token — the same projection rule apiKeyResponse and
// claimAgentResponse follow, one dedicated type per response so a domain field
// cannot reach a body by being added to the struct.
type agentSummary struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Status   string `json:"status"`
}

// agentClaim is the claim link, rendered once.
type agentClaim struct {
	URL       string `json:"url"`
	ExpiresAt string `json:"expires_at"`
}

// issuedAgentToken is a freshly-minted bearer credential: `token` here and only
// here. The shape mirrors issuedAPIKeyResponse and carries the same rule — no
// digest, no re-read, nothing that could print it a second time.
type issuedAgentToken struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expires_at"`
	Token     string `json:"token"`
}

// writeAgentRegistrationError maps the registration's refusals.
//
//	A 503 for no claim screen, and it is NOT a 500: a deployment that has not set
//	AGENT_CLAIM_UI_URL is misconfigured in a specific, fixable way, and naming it
//	(in the problem's detail and the log) is worth more than the generic 500 an
//	unexpected error gets. Refusing rather than minting is the fail-closed
//	direction: an agent registered without a claim URL is an agent nobody can ever
//	claim.
//	A 422 for a name the service refuses, and a 422 naming `username` when the
//	caller supplied a handle that survived every retry — the two refusals are
//	distinct so a client can tell "fix your name" from "pick another handle"
//	without the response having to leak whether any handle is taken.
func (o options) writeAgentRegistrationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, agents.ErrNoClaimUI),
		strings.Contains(err.Error(), agents.ClaimUIBaseEnvVar):
		o.logger.Error("agent registration is unusable: no claim screen configured",
			"env", agents.ClaimUIBaseEnvVar)
		problemFor(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable,
			"this deployment has no claim screen configured, so an agent cannot be registered yet")

	case errors.Is(err, agents.ErrInvalidUsername):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: "username", Code: "invalid"}}))

	case errors.Is(err, agents.ErrInvalidName):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: "name", Code: "required"}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}

// ---------------------------------------------------------------------------
// the claim-link refresh
// ---------------------------------------------------------------------------

// handleRefreshAgentClaimLink gives an agent a fresh claim link.
//
//	POST /v1/agents/claim-link/refresh  (agent bearer)  →  200 {agent, claim}
//	→  401 the credential does not resolve
//	→  404 the agent is already claimed (or was never this token's) — one answer
//
// # IT DOES NOT CLAIM, AND THAT IS THE ONE PROPERTY
//
// The status guard lives in the use case (Store.RefreshClaimLink's WHERE is
// `status = 'unclaimed'`), so a refresh against a claimed principal is a 404, the
// same answer a stranger's wrong token gets. An agent that lost its link before
// the human opened it gets a new one; an agent whose human already claimed it
// gets nothing new, because its access belongs to the account now.
//
// # THE IDEMPOTENCY KEY
//
// The request's Idempotency-Key is recorded on the refresh event's trace lineage
// so a client's retries are visible as one intent in the audit trail. It is NOT a
// stored-response replay: each refresh MINT A NEW LINK, and a retry with the same
// key gets a different link, deliberately — the old one is spent by the refresh
// that replaced it. The key correlates; it does not cache.
func (o options) handleRefreshAgentClaimLink(w http.ResponseWriter, r *http.Request) {
	owner, ok := agentFrom(r.Context())
	if !ok {
		// Unreachable: agentCredentialOnly places the owner before this runs.
		unauthorized(w, r)
		return
	}

	token := presentedAgentToken(r)
	refreshed, err := o.agents.RefreshClaimLink(r.Context(), agents.RefreshClaimInput{
		Token:   token,
		TraceID: traceIDFrom(r.Context()),
		Now:     o.clk.Now(),
	})
	if err != nil {
		if errors.Is(err, agents.ErrNotFound) {
			// Already claimed, or the credential moved. One answer for both, and
			// it is the one a stranger's wrong token gets.
			problemFor(w, r, http.StatusNotFound, CodeNotFound,
				"this agent cannot have its claim link refreshed")
			return
		}
		if errors.Is(err, agents.ErrNoClaimUI) {
			problemFor(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable,
				"this deployment has no claim screen configured")
			return
		}
		unexpected(w, r, o.logger, err)
		return
	}

	writeJSON(w, http.StatusOK, refreshAgentClaimResponse{
		Agent: agentSummary{
			ID:       refreshed.Agent.ID.String(),
			Name:     owner.Agent.Name,
			Username: owner.Agent.Username,
			Status:   refreshed.Agent.Status,
		},
		Claim: agentClaim{
			URL:       refreshed.ClaimURL,
			ExpiresAt: refreshed.ClaimLinkExpiresAt.UTC().Format(time.RFC3339),
		},
	})
}

// refreshAgentClaimResponse is the 200 from the refresh: the principal (still
// unclaimed) and its new claim link. NO token — a refresh never mints a bearer
// credential, it only reissues a link.
type refreshAgentClaimResponse struct {
	Agent agentSummary `json:"agent"`
	Claim agentClaim   `json:"claim"`
}

// ---------------------------------------------------------------------------
// the bearer-token lifecycle
// ---------------------------------------------------------------------------

// mintAgentTokenRequest is the body of POST /v1/agents/tokens. `name` is required
// and `expires_in` is optional seconds-from-now — the same field, name and
// semantics MintAPIKeyRequest uses, for the same reason an OAuth client already
// knows.
type mintAgentTokenRequest struct {
	Name      string `json:"name"`
	ExpiresIn *int64 `json:"expires_in"`
}

// handleMintAgentToken mints a named bearer credential for the calling agent.
//
//	POST /v1/agents/tokens  {name, expires_in?}  →  201 {id, name, expires_at, token}
//	→  409 a live token of that name already exists
//	→  422 name missing/long, or expires_in over the ceiling or ≤ 0
func (o options) handleMintAgentToken(w http.ResponseWriter, r *http.Request) {
	owner, ok := agentFrom(r.Context())
	if !ok {
		unauthorized(w, r)
		return
	}

	var body *mintAgentTokenRequest
	if !decodeBody(w, r, &body) {
		return
	}

	in := agents.TokenInput{
		Agent:   owner.Agent.ID,
		Name:    body.Name,
		TraceID: traceIDFrom(r.Context()),
		Now:     o.clk.Now(),
	}
	if body.ExpiresIn != nil {
		lifetime := time.Duration(*body.ExpiresIn) * time.Second
		in.ExpiresIn = &lifetime
	}

	issued, err := o.agents.IssueToken(r.Context(), in)
	if err != nil {
		o.writeAgentTokenError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, issuedAgentToken{
		ID:        issued.Token.ID.String(),
		Name:      issued.Token.Name,
		ExpiresAt: issued.Token.ExpiresAt.UTC().Format(time.RFC3339),
		Token:     issued.Plaintext,
	})
}

// agentTokenResponse is a credential as the agent's management surface sees it:
// no token, no digest. The same projection apiKeyResponse makes.
type agentTokenResponse struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	ExpiresAt    string  `json:"expires_at"`
	CreatedAt    string  `json:"created_at"`
	LastUsedAt   *string `json:"last_used_at,omitempty"`
	RevokedAt    *string `json:"revoked_at,omitempty"`
	RevokeReason *string `json:"revoke_reason,omitempty"`
}

// agentTokenFrom projects a row onto the wire. RFC 3339 instants so the JSON
// carries no location surprises, and pointers for the three "never" states so an
// omitempty tells "never used" from a present instant.
func agentTokenFrom(t agents.Token) agentTokenResponse {
	out := agentTokenResponse{
		ID:        t.ID.String(),
		Name:      t.Name,
		ExpiresAt: t.ExpiresAt.UTC().Format(time.RFC3339),
		CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339),
	}
	if t.LastUsedAt != nil {
		s := t.LastUsedAt.UTC().Format(time.RFC3339)
		out.LastUsedAt = &s
	}
	if t.RevokedAt != nil {
		s := t.RevokedAt.UTC().Format(time.RFC3339)
		out.RevokedAt = &s
	}
	if t.RevokedReason != nil {
		out.RevokeReason = t.RevokedReason
	}
	return out
}

// handleListAgentTokens returns the calling agent's credentials, newest first,
// revoked ones included.
//
//	GET /v1/agents/tokens  →  200 [{id, name, expires_at, …}]
func (o options) handleListAgentTokens(w http.ResponseWriter, r *http.Request) {
	owner, ok := agentFrom(r.Context())
	if !ok {
		unauthorized(w, r)
		return
	}

	listed, err := o.agents.ListTokens(r.Context(), owner.Agent.ID)
	if err != nil {
		o.writeAgentTokenError(w, r, err)
		return
	}

	items := make([]agentTokenResponse, 0, len(listed))
	for _, t := range listed {
		items = append(items, agentTokenFrom(t))
	}
	writeJSON(w, http.StatusOK, items)
}

// revokeAgentTokenRequest is the optional body of DELETE. The reason is free text
// the agent may supply; an empty body is a revoke with no reason.
type revokeAgentTokenRequest struct {
	Reason string `json:"reason"`
}

// handleRevokeAgentToken withdraws one of the calling agent's credentials.
//
//	DELETE /v1/agents/tokens/{tokenID}  {reason?}  →  204
//	→  409 the credential is already revoked
//	→  404 the id is not this agent's
func (o options) handleRevokeAgentToken(w http.ResponseWriter, r *http.Request) {
	owner, ok := agentFrom(r.Context())
	if !ok {
		unauthorized(w, r)
		return
	}
	tokenID, ok := agentTokenIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	reason := ""
	if r.ContentLength != 0 {
		var body *revokeAgentTokenRequest
		if !decodeBody(w, r, &body) {
			return
		}
		reason = body.Reason
	}

	if _, err := o.agents.RevokeToken(r.Context(), owner.Agent.ID, tokenID, reason,
		traceIDFrom(r.Context()), o.clk.Now()); err != nil {
		o.writeAgentTokenError(w, r, err)
		return
	}

	noContent(w)
}

// rotateAgentTokenRequest is the body of POST …/rotate. `expires_in` is optional
// seconds-from-now for the NEW credential; the name is inherited from the one being
// rotated.
type rotateAgentTokenRequest struct {
	ExpiresIn *int64 `json:"expires_in"`
}

// handleRotateAgentToken withdraws a credential and mints a new one of the SAME
// name in one call.
//
//	POST /v1/agents/tokens/{tokenID}/rotate  {expires_in?}  →  201 {id, name, expires_at, token}
//	→  409 the credential is already revoked
//	→  404 the id is not this agent's
//
// # WHY IT IS ONE CALL AND NOT REVOKE-THEN-MINT
//
// A client that revokes then mints has an instant with NO credential under that
// name and a window in which it can end up with none. The rotation either hands
// back the new token or leaves the old one working — never neither.
func (o options) handleRotateAgentToken(w http.ResponseWriter, r *http.Request) {
	owner, ok := agentFrom(r.Context())
	if !ok {
		unauthorized(w, r)
		return
	}
	tokenID, ok := agentTokenIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	var body *rotateAgentTokenRequest
	if !decodeBody(w, r, &body) {
		return
	}

	var lifetime *time.Duration
	if body.ExpiresIn != nil {
		l := time.Duration(*body.ExpiresIn) * time.Second
		lifetime = &l
	}

	issued, err := o.agents.RotateToken(r.Context(), owner.Agent.ID, tokenID, lifetime,
		traceIDFrom(r.Context()), o.clk.Now())
	if err != nil {
		o.writeAgentTokenError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, issuedAgentToken{
		ID:        issued.Token.ID.String(),
		Name:      issued.Token.Name,
		ExpiresAt: issued.Token.ExpiresAt.UTC().Format(time.RFC3339),
		Token:     issued.Plaintext,
	})
}

// writeAgentTokenError maps the token lifecycle's refusals, on apikeys' argument:
// 404 for an id that is not there or not theirs, 409 for the two conflicts that a
// well-formed request asks for and a live row already holds, 422 for a field the
// caller controls.
func (o options) writeAgentTokenError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, agents.ErrNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no agent token matches that id for this agent")

	case errors.Is(err, agents.ErrAlreadyRevoked):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"this agent token has already been revoked")

	case errors.Is(err, agents.ErrNameTaken):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an active agent token with that name already exists; revoke or rotate it first")

	case errors.Is(err, agents.ErrInvalidTokenName):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: "name", Code: "invalid"}}))

	case errors.Is(err, agents.ErrInvalidLifetime):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: "expires_in", Code: "invalid"}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}
