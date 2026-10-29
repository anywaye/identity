package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/agents"
)


func newPreviewWorld(t *testing.T) *claimWorld {
	t.Helper()
	return newClaimWorld(t)
}

func registerAgent(t *testing.T, w *claimWorld, name, deviceJSON string) registration {
	t.Helper()

	body := `{"name":"` + name + `"`
	if deviceJSON != "" {
		body += `,"device":` + deviceJSON
	}
	body += `}`

	rec := post(t, w.handler, "/v1/agents", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering %q: %d; body: %s", name, rec.Code, rec.Body)
	}
	var reg registerAgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil {
		t.Fatalf("the registration body is not JSON: %v", err)
	}
	return registration{
		id:    reg.Agent.ID,
		token: reg.APIKey.Token,
		link:  strings.TrimPrefix(reg.Claim.URL, agentHTTPClaimUI+"/agents/claim/"),
	}
}

func getPreview(t *testing.T, w *claimWorld, link string) *httptest.ResponseRecorder {
	t.Helper()
	return send(t, w.handler, http.MethodGet, "/v1/agents/claim/"+link, "")
}

func getHome(t *testing.T, w *claimWorld, token string) *httptest.ResponseRecorder {
	t.Helper()
	return requestAs(t, w.handler, token, http.MethodGet, "/v1/agents/home", "")
}


func TestThePreviewRendersTheShapeTheClaimScreenReads(t *testing.T) {
	w := newPreviewWorld(t)

	reg := registerAgent(t, w, "Noel", `{"host":"noels-macbook","os":"darwin","arch":"arm64"}`)

	rec := getPreview(t, w, reg.link)
	if rec.Code != http.StatusOK {
		t.Fatalf("previewing a live claim link = %d, want 200 — this is the route the claim "+
			"screen's whole first frame is built from; body: %s", rec.Code, rec.Body)
	}
	if got, want := rec.Header().Get("Content-Type"), "application/json; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	var got agentClaimPreviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("the preview body is not the documented shape: %v; body: %s", err, rec.Body)
	}

	if got.ID != reg.id {
		t.Errorf("id = %q, want the agent the link named %q", got.ID, reg.id)
	}
	if got.Name != "Noel" {
		t.Errorf("name = %q, want Noel", got.Name)
	}
	if got.Username == "" {
		t.Error("username is empty, and the screen's reader defaults it to \"\" — which renders a blank fact")
	}
	if got.Status != agents.StatusUnclaimed {
		t.Errorf("status = %q, want %q", got.Status, agents.StatusUnclaimed)
	}
	if got.CreatedAt == "" {
		t.Error("created_at is empty, and the screen renders \"—\" where a registration instant should be")
	}
	if got.ClaimExpiresAt == "" {
		t.Error("claim_expires_at is empty, so the screen drops the \"Link works until\" fact entirely")
	}
	if len(got.Device) != 3 {
		t.Errorf("device carries %d entries, want the 3 the agent registered (%v)", len(got.Device), got.Device)
	}
	if got.Device["host"] != "noels-macbook" {
		t.Errorf("device.host = %v, want noels-macbook — the agent's own vocabulary is passed "+
			"through, not projected", got.Device["host"])
	}

	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("the preview body is not an object: %v", err)
	}
	if len(raw) != 7 {
		t.Errorf("the preview body carries %d fields (%v), want the 7 the claim screen reads", len(raw), raw)
	}
	for _, absent := range []string{"claimed_at", "claimed_by_account_id", "token", "claim_token_digest"} {
		if _, present := raw[absent]; present {
			t.Errorf("the preview body carries %q, and a live link names an UNCLAIMED agent — "+
				"a field that is always null is a field a client starts reading as a signal", absent)
		}
	}

	blank := registerAgent(t, w, "Marc", "")
	blankRec := getPreview(t, w, blank.link)
	if blankRec.Code != http.StatusOK {
		t.Fatalf("previewing an agent with no device = %d, want 200", blankRec.Code)
	}
	if !strings.Contains(blankRec.Body.String(), `"device":{}`) {
		t.Errorf("an agent with no device document renders %s, want \"device\":{}", blankRec.Body)
	}
}


func TestThePreviewCannotTellTheFourWaysALinkIsDeadApart(t *testing.T) {
	w := newPreviewWorld(t)

	live := registerAgent(t, w, "Noel", `{"host":"laptop"}`)
	spent := registerAgent(t, w, "Marc", "")

	h := w.signUp(t)
	if rec := w.claim(t, h, h.account, spent.link); rec.Code != http.StatusOK {
		t.Fatalf("claiming Marc's link for the third row: %d; body: %s", rec.Code, rec.Body)
	}

	for _, tc := range []struct {
		name string
		link string
	}{
		{name: "a wrong token", link: live.link[:len(live.link)-1] + "x"},
		{name: "an already-claimed agent", link: spent.link},
		{name: "a token that never existed", link: agents.Prefix + strings.Repeat("z", 43)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := getPreview(t, w, tc.link)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("previewing %s = %d, want 404; body: %s", tc.name, rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeNotFound {
				t.Errorf("code = %q, want %q — a distinct code would tell a stranger which "+
					"guess was close", p.Code, CodeNotFound)
			}
			if p.Detail != "no agent matches that claim link" {
				t.Errorf("detail = %q, want the claim route's own sentence — a reader must not "+
					"be able to tell which of the four it was", p.Detail)
			}
		})
	}

	wrong := getPreview(t, w, live.link[:len(live.link)-1]+"x")
	spentRec := getPreview(t, w, spent.link)
	wrongProblem := decodeProblem(t, wrong)
	spentProblem := decodeProblem(t, spentRec)
	if wrong.Code != spentRec.Code {
		t.Errorf("a wrong token and a spent link answer %d and %d", wrong.Code, spentRec.Code)
	}
	if wrongProblem.Code != spentProblem.Code || wrongProblem.Detail != spentProblem.Detail {
		t.Errorf("a wrong token and a spent link answer:\n  %s: %q\n  %s: %q",
			wrongProblem.Code, wrongProblem.Detail, spentProblem.Code, spentProblem.Detail)
	}
}


func TestThePreviewClaimsNothingAndMintsNothing(t *testing.T) {
	w := newPreviewWorld(t)

	reg := registerAgent(t, w, "Noel", `{"host":"laptop"}`)

	tokens := w.rows(t, `select count(*) from agent_tokens`)
	if tokens != 1 {
		t.Fatalf("a fresh registration left %d rows in agent_tokens, want 1 (its bootstrap)", tokens)
	}
	events := w.rows(t, `select count(*) from agent_events`)
	if events != 1 {
		t.Fatalf("a fresh registration wrote %d rows to agent_events, want 1 (the registration itself)", events)
	}

	if rec := getPreview(t, w, reg.link); rec.Code != http.StatusOK {
		t.Fatalf("previewing: %d; body: %s", rec.Code, rec.Body)
	}

	if after := w.rows(t, `select count(*) from agent_tokens`); after != tokens {
		t.Errorf("the preview left %d rows in agent_tokens, want %d unchanged — a preview "+
			"must not mint", after, tokens)
	}
	if after := w.rows(t, `select count(*) from agent_events`); after != events {
		t.Errorf("the preview wrote %d rows to agent_events, want %d — a preview is a page "+
			"load and not an act", after, events)
	}

	h := w.signUp(t)
	rec := w.claim(t, h, h.account, reg.link)
	if rec.Code != http.StatusOK {
		t.Fatalf("claiming a link that was previewed = %d, want 200 — the preview spent "+
			"something a stranger could have used; body: %s", rec.Code, rec.Body)
	}
	var claimed claimAgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &claimed); err != nil {
		t.Fatalf("the claim body is not JSON: %v", err)
	}
	if claimed.Token.Token == "" {
		t.Error("the claim after the preview minted no credential, so the agent has nothing to present")
	}
}


func TestTheHomeIsWhoTheCredentialIs(t *testing.T) {
	w := newPreviewWorld(t)

	reg, claimed, human := w.claimOne(t, "Noel")

	rec := getHome(t, w, claimed.Token.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/agents/home = %d, want 200 — `caf agent whoami` has nothing else to "+
			"ask; body: %s", rec.Code, rec.Body)
	}
	if got, want := rec.Header().Get("Content-Type"), "application/json; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	var got agentHomeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("the home body is not the documented shape: %v; body: %s", err, rec.Body)
	}

	if got.ID != reg.id {
		t.Errorf("id = %q, want the agent behind the credential %q", got.ID, reg.id)
	}
	if got.Name != "Noel" {
		t.Errorf("name = %q, want Noel", got.Name)
	}
	if got.Username == "" {
		t.Error("username is empty, and the CLI's own document carries it")
	}
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("the home body is not an object: %v", err)
	}
	if _, flat := raw["status"]; !flat {
		t.Errorf("the home body has no top-level `status` (%v) — the CLI reads exactly that "+
			"field and a nested one would leave `caf agent whoami` trusting a stale cache", raw)
	}
	if got.Status != agents.StatusClaimed {
		t.Errorf("status = %q, want %q", got.Status, agents.StatusClaimed)
	}
	if !got.Claimed {
		t.Error("claimed = false, want true for a human's claim")
	}
	if got.ClaimedByAccountID == nil {
		t.Fatal("claimed_by_account_id is absent, and the brief names it as what the home answers")
	}
	if *got.ClaimedByAccountID != human.account {
		t.Errorf("claimed_by_account_id = %q, want the claiming account %q", *got.ClaimedByAccountID, human.account)
	}
	if got.ClaimedAt == nil || *got.ClaimedAt == "" {
		t.Error("claimed_at is absent, and a bound principal has an instant for it")
	}

	if len(raw) != 7 {
		t.Errorf("the home body carries %d fields (%v), want the 7 documented ones — more "+
			"would be this route saying something about the ACCOUNT rather than about the agent",
			len(raw), raw)
	}
	for _, absent := range []string{"token", "token_digest", "account_name", "account_slug", "members", "device"} {
		if _, present := raw[absent]; present {
			t.Errorf("the home body carries %q, which is not a fact about the agent itself", absent)
		}
	}
}

func TestTheHomeAnswersAnUnclaimedAgentAboutItself(t *testing.T) {
	w := newPreviewWorld(t)

	reg := registerAgent(t, w, "Noel", `{"host":"laptop"}`)

	rec := getHome(t, w, reg.token)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/agents/home with an unclaimed agent = %d, want 200 — a 403 here would "+
			"answer \"you are not claimed\" by refusing to say who is asking; body: %s",
			rec.Code, rec.Body)
	}

	var got agentHomeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("the home body is not the documented shape: %v; body: %s", err, rec.Body)
	}
	if got.ID != reg.id {
		t.Errorf("id = %q, want the agent behind the credential %q", got.ID, reg.id)
	}
	if got.Status != agents.StatusUnclaimed {
		t.Errorf("status = %q, want %q — this is the answer `caf agent whoami` exists to read",
			got.Status, agents.StatusUnclaimed)
	}
	if got.Claimed {
		t.Error("claimed = true, want false for an agent nobody has bound")
	}
	if got.ClaimedByAccountID != nil {
		t.Errorf("claimed_by_account_id = %q, want absent while unclaimed", *got.ClaimedByAccountID)
	}
	if got.ClaimedAt != nil {
		t.Errorf("claimed_at = %q, want absent while unclaimed", *got.ClaimedAt)
	}
}

func TestTheHomeRefusesEverythingThatIsNotALiveAgentCredential(t *testing.T) {
	w := newPreviewWorld(t)

	h := w.signUp(t)

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"no credential", ""},
		{"a browser session", h.session},
		{"a value that is not a token", agents.Prefix + "not-a-token"},
		{"a 256-bit guess", agents.Prefix + strings.Repeat("z", 43)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := getHome(t, w, tc.token)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("GET /v1/agents/home with %s = %d, want 401; body: %s",
					tc.name, rec.Code, rec.Body)
			}
			if strings.Contains(rec.Body.String(), "agent") && rec.Code != http.StatusUnauthorized {
				t.Errorf("the refusal names a principal: %s", rec.Body)
			}
		})
	}
}

func TestThePreviewIsRateLimitedOnTheRegistrationsOwnTerms(t *testing.T) {
	s := newAgentServer(t, 1)

	regRec := post(t, s.handler, "/v1/agents", `{"name":"Noel"}`)
	if regRec.Code != http.StatusCreated {
		t.Fatalf("registering: %d; body: %s", regRec.Code, regRec.Body)
	}
	var reg registerAgentResponse
	if err := json.Unmarshal(regRec.Body.Bytes(), &reg); err != nil {
		t.Fatalf("the registration body is not JSON: %v", err)
	}
	link := strings.TrimPrefix(reg.Claim.URL, agentHTTPClaimUI+"/agents/claim/")

	first := send(t, s.handler, http.MethodGet, "/v1/agents/claim/"+link, "")
	if first.Code != http.StatusOK {
		t.Fatalf("the first preview under the limit = %d, want 200 — a limiter is a bound "+
			"and not a gate; body: %s", first.Code, first.Body)
	}
	second := send(t, s.handler, http.MethodGet, "/v1/agents/claim/"+link, "")
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("the second preview over the limit = %d, want 429 — an unauthenticated "+
			"database read with no bound is how an endpoint nobody signs in to finds the "+
			"database; body: %s", second.Code, second.Body)
	}
	if p := decodeProblem(t, second); p.Code != CodeRateLimited {
		t.Errorf("the 429's code = %q, want %q", p.Code, CodeRateLimited)
	}
}
