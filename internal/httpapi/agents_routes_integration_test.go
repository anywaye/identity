package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/agents"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/ratelimit"
)


const agentHTTPClaimUI = "https://anywaye.example"

type agentServer struct {
	handler http.Handler
	clk     *clock.Fake
	pool *pgxpool.Pool
}

func newAgentServer(t *testing.T, limiterMax int) *agentServer {
	t.Helper()

	pool, _ := dbtest.SchemaWithOwner(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	opts := []Option{
		WithAuth(authServiceFor(pool, clk)),
		WithTenancy(realTenancy(pool, clk)),
		WithAgents(agents.NewService(pool, agents.WithClaimUI(agentHTTPClaimUI))),
		WithClock(clk),
	}
	if limiterMax > 0 {
		opts = append(opts, WithRateLimiter(ratelimit.New(clk, map[string]ratelimit.Limit{
			"/v1/agents": {Max: limiterMax, Window: time.Minute},
			"/v1/agents/claim/{token}": {Max: limiterMax, Window: time.Minute},
		})))
	}
	return &agentServer{handler: New(nil, opts...), clk: clk, pool: pool}
}

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

func TestARegistrationWithNoClaimScreenIsAServiceUnavailable(t *testing.T) {
	pool, _ := dbtest.SchemaWithOwner(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
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

func TestTheAgentTokenLifecycleOverHTTP(t *testing.T) {
	w := newClaimWorld(t)
	s := w.handler
	reg, claimed, _ := w.claimOne(t, "Noel")
	tok := claimed.Token.Token
	if tok == "" {
		t.Fatal("the claim minted no token, so the lifecycle below would prove nothing")
	}
	_ = reg

	mint := sendWith(t, s, http.MethodPost, "/v1/agents/tokens", tok, "", `{"name":"deploy"}`)
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

	dup := sendWith(t, s, http.MethodPost, "/v1/agents/tokens", tok, "", `{"name":"deploy"}`)
	if dup.Code != http.StatusConflict {
		t.Errorf("a second live token of one name = %d, want 409; body: %s", dup.Code, dup.Body)
	}

	list := sendWith(t, s, http.MethodGet, "/v1/agents/tokens", tok, "", "")
	if list.Code != http.StatusOK {
		t.Fatalf("listing = %d, want 200; body: %s", list.Code, list.Body)
	}
	var listed []agentTokenResponse
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decoding the list: %v", err)
	}
	if len(listed) != 3 {
		t.Fatalf("the agent holds %d tokens, want 3 (bootstrap + the claim's + deploy)", len(listed))
	}
	if strings.Contains(list.Body.String(), issued.Token) {
		t.Error("the list body carries a plaintext token, and no list endpoint may re-read one")
	}

	rot := sendWith(t, s, http.MethodPost, "/v1/agents/tokens/"+tokenID+"/rotate", tok, "", `{}`)
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

	del := sendWith(t, s, http.MethodDelete, "/v1/agents/tokens/"+rotated.ID, tok, "", "")
	if del.Code != http.StatusNoContent {
		t.Fatalf("revoking the rotated token = %d, want 204; body: %s", del.Code, del.Body)
	}
}

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
