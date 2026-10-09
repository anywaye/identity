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

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/agents"
)

// Agents is the claim use case, and the reason this route needs nothing else.
//
// It is an interface rather than *agents.Service so a test can build a router
// with a double, the way every other surface here does — and so the httpapi
// package does not gain a dependency on the store's constructor signature.
type Agents interface {
	Claim(ctx context.Context, in agents.ClaimInput) (agents.Claimed, error)
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
