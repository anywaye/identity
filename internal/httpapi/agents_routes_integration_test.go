package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/agents"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/ratelimit"
)

// THE AGENT SURFACE OVER THE REAL ROUTER AND THE REAL SQL.
//
// internal/agents proves the use cases; this file proves what a CLI and a claim
// screen actually meet on the wire: the 201's three-object shape, that a
// generated-username collision retries WITHOUT the endpoint ever saying "taken",
// that a refresh leaves the agent unclaimed, and that the token lifecycle reads
// and writes through the agent's own bearer credential. The rate limit rides the
// real limiter, so the 429 is the one a deployment answers.

const agentHTTPClaimUI = "https://cafaye.example"

// agentServer is the real service over a private schema, configured the way main
// configures it for the agent surface: the claim UI base and the use case that
// renders claim URLs from it.
type agentServer struct {
	handler http.Handler
	clk     *clock.Fake
}

func newAgentServer(t *testing.T, limiterMax int) *agentServer {
	t.Helper()

	pool, _ := dbtest.SchemaWithOwner(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	opts := []Option{
		WithAuth(authServiceFor(pool, clk)),
		WithAgents(agents.NewService(pool, agents.WithClaimUI(agentHTTPClaimUI))),
		WithClock(clk),
	}
	if limiterMax > 0 {
		opts = append(opts, WithRateLimiter(ratelimit.New(clk, map[string]ratelimit.Limit{
			"/v1/agents": {Max: limiterMax, Window: time.Minute},
		})))
	}
	return &agentServer{handler: New(nil, opts...), clk: clk}
}

// TestTheRegistrationHTTPShapeIsTheContract is the happy path the CLI codes against:
// agent.unclaimed, an api_key.token, a claim.url — three objects, and the claim URL
// points at the configured screen.
func TestTheRegistrationHTTPShapeIsTheContract(t *testing.T) {
	s := newAgentServer(t, 100)

	rec := post(t, s.handler, "/v1/agents", `{"name":"Noel"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/agents = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	var body registerAgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the 201 is not the documented shape: %v; body: %s", err, rec.Body)
	}
	if body.Agent.Status != agents.StatusUnclaimed {
		t.Errorf("agent.status = %q, want %q", body.Agent.Status, agents.StatusUnclaimed)
	}
	if _, err := id.Parse(body.Agent.ID); err != nil {
		t.Errorf("agent.id %q is not a uuid", body.Agent.ID)
	}
	if !agents.ValidUsername(body.Agent.Username) {
		t.Errorf("the generated handle %q is not valid", body.Agent.Username)
	}
	if body.APIKey.Token == "" || len(body.APIKey.Token) < 40 {
		t.Errorf("api_key.token is missing or too short: %q", body.APIKey.Token)
	}
	wantPrefix := agentHTTPClaimUI + "/agents/claim/"
	if len(body.Claim.URL) <= len(wantPrefix) || body.Claim.URL[:len(wantPrefix)] != wantPrefix {
		t.Errorf("claim.url = %q, want it under %s", body.Claim.URL, wantPrefix)
	}
}

// TestTheRegistrationRetriesAUsernameCollisionWithoutSayingTaken is the wire half
// of the conflict-retry property, and the disclosure half is the reason it is
// asserted here too: two registrations of the same name are two 201s with two
// DIFFERENT handles, and no 409 ever appears.
func TestTheRegistrationRetriesAUsernameCollisionWithoutSayingTaken(t *testing.T) {
	s := newAgentServer(t, 100)

	firstRec := post(t, s.handler, "/v1/agents", `{"name":"Noel"}`)
	secondRec := post(t, s.handler, "/v1/agents", `{"name":"Noel"}`)
	if firstRec.Code != http.StatusCreated || secondRec.Code != http.StatusCreated {
		t.Fatalf("two clean registrations of one name = %d and %d, want 201 and 201 (a collision must be retried, not returned)",
			firstRec.Code, secondRec.Code)
	}
	var first, second registerAgentResponse
	if err := json.Unmarshal(firstRec.Body.Bytes(), &first); err != nil {
		t.Fatalf("decoding the first: %v", err)
	}
	if err := json.Unmarshal(secondRec.Body.Bytes(), &second); err != nil {
		t.Fatalf("decoding the second: %v", err)
	}
	if first.Agent.Username == second.Agent.Username {
		t.Errorf("two collisions produced the same generated handle %q — the retry did not mint a new one", first.Agent.Username)
	}
	if first.APIKey.Token == second.APIKey.Token {
		t.Error("two registrations share a bootstrap token, which is impossible for two crypto/rand mints")
	}
}

// TestARegistrationWithNoClaimScreenIsAServiceUnavailable is the fail-closed
// direction on the wire: a deployment with AGENT_CLAIM_UI_URL unset refuses to
// mint an agent it could never let a human claim.
func TestARegistrationWithNoClaimScreenIsAServiceUnavailable(t *testing.T) {
	pool, _ := dbtest.SchemaWithOwner(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
	// No WithClaimUI: the registration route is still mounted, and the use case
	// refuses with ErrNoClaimUI, which the handler renders as a 503.
	handler := New(nil,
		WithAuth(authServiceFor(pool, clk)),
		WithAgents(agents.NewService(pool)),
		WithClock(clk),
	)

	rec := post(t, handler, "/v1/agents", `{"name":"Noel"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("registering with no claim screen = %d, want 503; body: %s", rec.Code, rec.Body)
	}
}

// TestTheRefreshRegeneratesALinkAndKeepsTheAgentUnclaimed is the refresh property
// over the wire: the agent's own token gets a NEW claim URL and the agent stays
// unclaimed — a refresh never claims.
func TestTheRefreshRegeneratesALinkAndKeepsTheAgentUnclaimed(t *testing.T) {
	s := newAgentServer(t, 100)

	regRec := post(t, s.handler, "/v1/agents", `{"name":"Noel"}`)
	if regRec.Code != http.StatusCreated {
		t.Fatalf("registering = %d, want 201; body: %s", regRec.Code, regRec.Body)
	}
	var body registerAgentResponse
	if err := json.Unmarshal(regRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the registration: %v", err)
	}

	rec := sendWith(t, s.handler, http.MethodPost, "/v1/agents/claim-link/refresh", body.APIKey.Token, "", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	var refreshed refreshAgentClaimResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &refreshed); err != nil {
		t.Fatalf("the refresh body is not the documented shape: %v; body: %s", err, rec.Body)
	}
	if refreshed.Agent.Status != agents.StatusUnclaimed {
		t.Errorf("after a refresh the status is %q, want unclaimed — a refresh MUST NOT claim (D4)", refreshed.Agent.Status)
	}
	if refreshed.Claim.URL == body.Claim.URL || refreshed.Claim.URL == "" {
		t.Error("the refresh did not return a new claim URL")
	}
}

// TestTheAgentTokenLifecycleOverHTTP drives create, list, rotate and revoke through
// the agent's own credential, proving the credential is shown only at mint/rotate
// and that a duplicate live name is a 409.
func TestTheAgentTokenLifecycleOverHTTP(t *testing.T) {
	s := newAgentServer(t, 100)

	regRec := post(t, s.handler, "/v1/agents", `{"name":"Noel"}`)
	if regRec.Code != http.StatusCreated {
		t.Fatalf("registering = %d, want 201; body: %s", regRec.Code, regRec.Body)
	}
	var body registerAgentResponse
	if err := json.Unmarshal(regRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the registration: %v", err)
	}
	tok := body.APIKey.Token

	// Mint a named credential; the plaintext is here once.
	mint := sendWith(t, s.handler, http.MethodPost, "/v1/agents/tokens", tok, "", `{"name":"deploy"}`)
	if mint.Code != http.StatusCreated {
		t.Fatalf("minting = %d, want 201; body: %s", mint.Code, mint.Body)
	}
	var issued issuedAgentToken
	if err := json.Unmarshal(mint.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decoding the mint: %v", err)
	}
	if issued.Token == "" {
		t.Fatal("the mint returned no token, so the lifecycle would prove nothing")
	}
	tokenID := issued.ID

	// A duplicate live name is a 409.
	dup := sendWith(t, s.handler, http.MethodPost, "/v1/agents/tokens", tok, "", `{"name":"deploy"}`)
	if dup.Code != http.StatusConflict {
		t.Errorf("a second live token of one name = %d, want 409; body: %s", dup.Code, dup.Body)
	}

	// List: two credentials (bootstrap + deploy), and no body carries a token.
	list := sendWith(t, s.handler, http.MethodGet, "/v1/agents/tokens", tok, "", "")
	if list.Code != http.StatusOK {
		t.Fatalf("listing = %d, want 200; body: %s", list.Code, list.Body)
	}
	var listed []agentTokenResponse
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decoding the list: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("the agent holds %d tokens, want 2 (bootstrap + deploy)", len(listed))
	}
	if strings.Contains(list.Body.String(), issued.Token) {
		t.Error("the list body carries a plaintext token, and no list endpoint may re-read one")
	}

	// Rotate: a new plaintext, same name, one call.
	rot := sendWith(t, s.handler, http.MethodPost, "/v1/agents/tokens/"+tokenID+"/rotate", tok, "", `{}`)
	if rot.Code != http.StatusCreated {
		t.Fatalf("rotating = %d, want 201; body: %s", rot.Code, rot.Body)
	}
	var rotated issuedAgentToken
	if err := json.Unmarshal(rot.Body.Bytes(), &rotated); err != nil {
		t.Fatalf("decoding the rotation: %v", err)
	}
	if rotated.Token == "" || rotated.Token == issued.Token {
		t.Error("the rotation did not mint a distinct new token")
	}

	// Revoke the rotated token by its id.
	del := sendWith(t, s.handler, http.MethodDelete, "/v1/agents/tokens/"+rotated.ID, tok, "", "")
	if del.Code != http.StatusNoContent {
		t.Fatalf("revoking the rotated token = %d, want 204; body: %s", del.Code, del.Body)
	}
}

// TestTheAgentRegistrationRateLimitRidesTheRealLimiter is the rate-limit proof:
// one limiter, Max:1, and the second registration over it is a 429.
func TestTheAgentRegistrationRateLimitRidesTheRealLimiter(t *testing.T) {
	s := newAgentServer(t, 1)

	firstRec := post(t, s.handler, "/v1/agents", `{"name":"Noel"}`)
	if firstRec.Code != http.StatusCreated {
		t.Fatalf("the first registration under the limit = %d, want 201; body: %s", firstRec.Code, firstRec.Body)
	}

	second := post(t, s.handler, "/v1/agents", `{"name":"Marc"}`)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("the second registration over the limit = %d, want 429; body: %s", second.Code, second.Body)
	}
	if p := decodeProblem(t, second); p.Code != CodeRateLimited {
		t.Errorf("the 429's code = %q, want %q", p.Code, CodeRateLimited)
	}
}

// TestTheAgentSelfServiceRoutesRefuseAStranger is the anonymous half of the
// enumeration audit: the self-service routes answer 401 with no credential, so no
// token id or claim link arrives from a stranger.
func TestTheAgentSelfServiceRoutesRefuseAStranger(t *testing.T) {
	s := newAgentServer(t, 100)

	someID := id.MustNew().String()
	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodPost, "/v1/agents/claim-link/refresh", `{}`},
		{http.MethodGet, "/v1/agents/tokens", ""},
		{http.MethodPost, "/v1/agents/tokens", `{"name":"x"}`},
		{http.MethodDelete, "/v1/agents/tokens/" + someID, ""},
		{http.MethodPost, "/v1/agents/tokens/" + someID + "/rotate", `{}`},
	} {
		rec := sendWith(t, s.handler, tc.method, tc.path, "", "", tc.body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with no credential = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
}
