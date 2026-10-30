package httpapi


import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/agents"
	"github.com/anywaye/identity/internal/platform/id"
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

	PreviewClaim(ctx context.Context, in agents.PreviewInput) (agents.ClaimPreview, error)

	Register(ctx context.Context, in agents.RegisterInput) (agents.Registered, error)

	RefreshClaimLink(ctx context.Context, in agents.RefreshClaimInput) (agents.RefreshedClaim, error)

	Authenticate(ctx context.Context, presented string, now time.Time) (agents.Owner, error)

	IssueToken(ctx context.Context, in agents.TokenInput) (agents.IssuedToken, error)
	ListTokens(ctx context.Context, agentID id.UUID) ([]agents.Token, error)
	RevokeToken(ctx context.Context, agent, tokenID id.UUID, reason, traceID string, now time.Time) (agents.Token, error)
	RotateToken(ctx context.Context, agent, tokenID id.UUID, expiresIn *time.Duration, traceID string, now time.Time) (agents.IssuedToken, error)

	ListAgents(ctx context.Context, accountID id.UUID) ([]agents.Agent, error)
}

// WithAgents mounts the agent routes.
func WithAgents(a Agents) Option {
	return func(o *options) {
		if a != nil {
			o.agents = a
		}
	}
}

type claimAgentRequest struct {
	Token string `json:"token"`
}

type claimAgentResponse struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	ClaimedAt string `json:"claimed_at"`
	Token issuedAgentToken `json:"token"`
}

func claimedAtOr(agent agents.Agent, fallback time.Time) string {
	if agent.ClaimedAt == nil {
		return fallback.UTC().Format(time.RFC3339)
	}
	return agent.ClaimedAt.UTC().Format(time.RFC3339)
}

func (o options) registerAgentRoutes(r chiRouter) {
	if o.agents == nil {
		return
	}

	r.Post("/v1/accounts/{accountID}/agents/claim",
		o.sessionCredentialOnly(o.requireAccountRole(accounts.RoleMember, o.handleClaimAgent)))
}

func (o options) handleClaimAgent(w http.ResponseWriter, r *http.Request) {
	account, ok := accountFrom(r.Context())
	if !ok {
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
		ClaimedAt: claimedAtOr(claimed.Agent, o.clk.Now()),
		Token: issuedAgentToken{
			ID:        claimed.Token.ID.String(),
			Name:      claimed.Token.Name,
			ExpiresAt: claimed.Token.ExpiresAt.UTC().Format(time.RFC3339),
			Token:     claimed.TokenPlaintext,
		},
	})
}

func (o options) writeAgentClaimError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, agents.ErrNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no agent matches that claim link")

	default:
		unexpected(w, r, o.logger, err)
	}
}


type agentClaimPreviewResponse struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Status   string `json:"status"`
	CreatedAt string `json:"created_at"`
	Device map[string]any `json:"device"`
	ClaimExpiresAt string `json:"claim_expires_at"`
}

func (o options) handleListAgents(w http.ResponseWriter, r *http.Request) {
	accountID, ok := accountIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}
	agents, err := o.agents.ListAgents(r.Context(), accountID)
	if err != nil {
		problemFor(w, r, http.StatusInternalServerError, CodeInternal, "internal error")
		return
	}
	out := make([]map[string]any, 0, len(agents))
	for _, a := range agents {
		out = append(out, map[string]any{
			"id":       a.ID.String(),
			"name":     a.Name,
			"username": a.Username,
			"status":   a.Status,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (o options) handleAgentClaimPreview(w http.ResponseWriter, r *http.Request) {
	preview, err := o.agents.PreviewClaim(r.Context(), agents.PreviewInput{
		Token:   chi.URLParam(r, agentClaimTokenParam),
		TraceID: traceIDFrom(r.Context()),
		Now:     o.clk.Now(),
	})
	if err != nil {
		o.writeAgentClaimError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, agentClaimPreviewResponse{
		ID:       preview.Agent.ID.String(),
		Name:     preview.Agent.Name,
		Username: preview.Agent.Username,
		Status:   preview.Agent.Status,
		CreatedAt: preview.Agent.CreatedAt.UTC().Format(time.RFC3339),
		Device:         normaliseDevice(preview.Agent.Device),
		ClaimExpiresAt: preview.ClaimLinkExpiresAt.UTC().Format(time.RFC3339),
	})
}

func normaliseDevice(device map[string]any) map[string]any {
	if device == nil {
		return map[string]any{}
	}
	return device
}

const agentClaimTokenParam = "token"


func (o options) registerAgentPublicRoutes(r chiRouter) {
	if o.agents == nil {
		return
	}

	r.Post("/v1/agents", o.rateLimit("/v1/agents", o.handleRegisterAgent))

	r.Get("/v1/agents/claim/{token}",
		o.rateLimit("/v1/agents/claim/{token}", o.handleAgentClaimPreview))

	r.Get("/v1/accounts/{accountID}/agents",
		o.requireAccountRole(accounts.RoleMember, o.handleListAgents))

	r.Get("/v1/agents/home", o.agentCredentialOnly(o.handleAgentHome))

	r.Post("/v1/agents/claim-link/refresh", o.agentCredentialOnly(o.handleRefreshAgentClaimLink))

	r.Post("/v1/agents/tokens", o.agentClaimedOnly(o.handleMintAgentToken))
	r.Get("/v1/agents/tokens", o.agentClaimedOnly(o.handleListAgentTokens))
	r.Delete("/v1/agents/tokens/{tokenID}", o.agentClaimedOnly(o.handleRevokeAgentToken))
	r.Post("/v1/agents/tokens/{tokenID}/rotate", o.agentClaimedOnly(o.handleRotateAgentToken))
}


type agentContextKey struct{}

func agentFrom(ctx context.Context) (agents.Owner, bool) {
	owner, ok := ctx.Value(agentContextKey{}).(agents.Owner)
	return owner, ok
}

func presentedAgentToken(r *http.Request) string {
	return bearerToken(r)
}

func (o options) agentCredentialOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := presentedAgentToken(r)
		if token == "" {
			unauthorized(w, r)
			return
		}
		owner, err := o.agents.Authenticate(r.Context(), token, o.clk.Now())
		if err != nil {
			unauthorized(w, r)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), agentContextKey{}, owner)))
	}
}

func (o options) agentClaimedOnly(next http.HandlerFunc) http.HandlerFunc {
	return o.agentCredentialOnly(func(w http.ResponseWriter, r *http.Request) {
		owner, ok := agentFrom(r.Context())
		if !ok {
			unauthorized(w, r)
			return
		}
		if err := owner.RequireClaimed(); err != nil {
			o.logger.Info("an unclaimed agent presented a live credential to a claimed-only route",
				"agent_id", owner.Agent.ID,
				"route", routeTemplate(r),
				"trace_id", traceIDFrom(r.Context()))
			problemFor(w, r, http.StatusForbidden, CodeAgentUnclaimed, agentClaimedHint)
			return
		}
		next(w, r)
	})
}

const agentClaimedHint = "this agent has not been claimed by a human account, so it may not act yet. " +
	"A human must open its claim link and approve it; while the agent is still unclaimed, " +
	"POST /v1/agents/claim-link/refresh returns the current link"

func agentTokenIDFrom(r *http.Request) (id.UUID, bool) {
	parsed, err := id.Parse(chi.URLParam(r, agentTokenIDParam))
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}

const agentTokenIDParam = "tokenID"


type registerAgentRequest struct {
	Name     string         `json:"name"`
	Username string         `json:"username"`
	Device   map[string]any `json:"device"`
}

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

type registerAgentResponse struct {
	Agent  agentSummary     `json:"agent"`
	APIKey issuedAgentToken `json:"api_key"`
	Claim  agentClaim       `json:"claim"`
}

type agentSummary struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Status   string `json:"status"`
}

type agentClaim struct {
	URL       string `json:"url"`
	ExpiresAt string `json:"expires_at"`
}

type issuedAgentToken struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expires_at"`
	Token     string `json:"token"`
}

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


func (o options) handleRefreshAgentClaimLink(w http.ResponseWriter, r *http.Request) {
	owner, ok := agentFrom(r.Context())
	if !ok {
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

	o.logger.Info("agent claim link refreshed",
		"agent_id", refreshed.Agent.ID,
		"idempotency_key", r.Header.Get("Idempotency-Key"),
		"trace_id", traceIDFrom(r.Context()))

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

type refreshAgentClaimResponse struct {
	Agent agentSummary `json:"agent"`
	Claim agentClaim   `json:"claim"`
}


type agentHomeResponse struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Status string `json:"status"`
	Claimed            bool    `json:"claimed"`
	ClaimedByAccountID *string `json:"claimed_by_account_id,omitempty"`
	ClaimedByHasStaff  *bool   `json:"claimed_by_has_staff,omitempty"`
	ClaimedAt *string `json:"claimed_at,omitempty"`
}

func (o options) handleAgentHome(w http.ResponseWriter, r *http.Request) {
	owner, ok := agentFrom(r.Context())
	if !ok {
		unauthorized(w, r)
		return
	}

	out := agentHomeResponse{
		ID:       owner.Agent.ID.String(),
		Name:     owner.Agent.Name,
		Username: owner.Agent.Username,
		Status:   owner.Agent.Status,
		Claimed:  owner.Agent.IsClaimed(),
	}
	if owner.Agent.IsClaimed() {
		b := owner.ClaimedByHasStaff
		out.ClaimedByHasStaff = &b
	}
	if owner.Agent.ClaimedByAccountID != nil {
		account := owner.Agent.ClaimedByAccountID.String()
		out.ClaimedByAccountID = &account
	}
	if owner.Agent.ClaimedAt != nil {
		at := owner.Agent.ClaimedAt.UTC().Format(time.RFC3339)
		out.ClaimedAt = &at
	}

	writeJSON(w, http.StatusOK, out)
}


type mintAgentTokenRequest struct {
	Name      string `json:"name"`
	ExpiresIn *int64 `json:"expires_in"`
}

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

type agentTokenResponse struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	ExpiresAt    string  `json:"expires_at"`
	CreatedAt    string  `json:"created_at"`
	LastUsedAt   *string `json:"last_used_at,omitempty"`
	RevokedAt    *string `json:"revoked_at,omitempty"`
	RevokeReason *string `json:"revoke_reason,omitempty"`
}

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

type revokeAgentTokenRequest struct {
	Reason string `json:"reason"`
}

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

type rotateAgentTokenRequest struct {
	ExpiresIn *int64 `json:"expires_in"`
}

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
