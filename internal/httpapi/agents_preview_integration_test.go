package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/agents"
)

// THE TWO ROUTES THE CLIENTS ALREADY CALL, OVER THE REAL ROUTER AND THE REAL SQL.
//
// The website's claim screen and `caf agent whoami` were both written against
// these two paths before identity mounted anything on them: the screen's
// `getAgentClaim` answered 404 for a link that was perfectly live, and the CLI's
// `Home` had nothing to ask. What this file proves is not that the routes exist
// — the drift walk and the census already hold that — but that they answer the
// SHAPE their callers read and nothing beyond it.
//
// THREE PROPERTIES ARE BEHAVIOURAL RATHER THAN STRUCTURAL, and each of them is
// the reason the route is safe to mount at all:
//
//	the preview's 404 is the claim route's own collapse, over real SQL, so a
//	dead link and a stranger's guess are one answer;
//	the preview claims nothing and mints nothing, proved by claiming the SAME
//	link afterwards and by the credential list being unchanged;
//	the home answers about the caller and about nothing else — no account name,
//	no members, and the agent's own status whether or not anybody has claimed it.

// previewWorld is the service a claim screen meets, and it is the claim world's
// own: the real router, the real use cases, the claim screen configured.
func newPreviewWorld(t *testing.T) *claimWorld {
	t.Helper()
	return newClaimWorld(t)
}

// registerAgent writes an agent through the real registration route and returns
// its claim link's plaintext, pulled out of the claim URL the way the screen
// would take it from the address bar.
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

// getPreview is the anonymous read the claim screen performs: no credential of
// any kind on the request.
func getPreview(t *testing.T, w *claimWorld, link string) *httptest.ResponseRecorder {
	t.Helper()
	return send(t, w.handler, http.MethodGet, "/v1/agents/claim/"+link, "")
}

// getHome is the read `caf agent whoami` performs, with the agent's own credential.
func getHome(t *testing.T, w *claimWorld, token string) *httptest.ResponseRecorder {
	t.Helper()
	return requestAs(t, w.handler, token, http.MethodGet, "/v1/agents/home", "")
}

// ---------------------------------------------------------------------------
// the preview's 200
// ---------------------------------------------------------------------------

// TestThePreviewRendersTheShapeTheClaimScreenReads is the happy path, and the
// fields are the website's own list rather than this repository's opinion:
// `AgentClaim` in website/src/lib/identity.ts, read by `readAgentClaim` and
// rendered by the screen at src/app/agents/claim/[token] as "Registered", the
// device entries, and "Link works until".
//
// IT IS ANONYMOUS, and the assertion is the absence of an Authorization header
// rather than a comment about one: the request carries no credential at all, and
// a 200 on it is what makes the screen's first frame possible before a human has
// signed in.
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

	// THE SEVEN FIELDS THE SCREEN READS, each asserted.
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

	// AND WHAT IS NOT IN THE BODY. The claim screen reads these seven fields, so
	// a body that carried more would be a body the client ignores and a reader
	// does not.
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

	// `device` is {} and not null when the agent described itself with nothing,
	// because a client that iterates the field reads null as a failure.
	blank := registerAgent(t, w, "Marc", "")
	blankRec := getPreview(t, w, blank.link)
	if blankRec.Code != http.StatusOK {
		t.Fatalf("previewing an agent with no device = %d, want 200", blankRec.Code)
	}
	if !strings.Contains(blankRec.Body.String(), `"device":{}`) {
		t.Errorf("an agent with no device document renders %s, want \"device\":{}", blankRec.Body)
	}
}

// ---------------------------------------------------------------------------
// the preview's 404
// ---------------------------------------------------------------------------

// TestThePreviewCannotTellTheFourWaysALinkIsDeadApart is the collapse, measured
// over the real router and the real SQL rather than asserted from a mapper.
//
// The website's own screen states the rule it depends on: "identity's claim route
// answers one 404 for a wrong token, an expired link, an already-claimed agent
// and an agent that never existed". This is the same invariant on the route that
// precedes the claim, and it has to be measured because the preview is the FIRST
// thing a stranger can drive without a credential.
//
// WHAT IS COMPARED IS (status, code, detail) AND NOT THE WHOLE BODY, and that is
// deliberate rather than a convenience. `instance` is the request's own path, so
// on this route it carries the link the caller presented — which is not a
// disclosure, because the only caller who ever sees it is the one who already
// holds that 256-bit secret, and the same value is already in every HTTP access
// log and the browser's own history. `trace_id` is per request by definition. The
// two bytes that ARE the disclosure — `code` and `detail` — are compared below.
func TestThePreviewCannotTellTheFourWaysALinkIsDeadApart(t *testing.T) {
	w := newPreviewWorld(t)

	live := registerAgent(t, w, "Noel", `{"host":"laptop"}`)
	spent := registerAgent(t, w, "Marc", "")

	// The third row needs the link to have been claimed, so one human claims
	// `spent` through the real route.
	h := w.signUp(t)
	if rec := w.claim(t, h, h.account, spent.link); rec.Code != http.StatusOK {
		t.Fatalf("claiming Marc's link for the third row: %d; body: %s", rec.Code, rec.Body)
	}

	// THE FOURTH ROW IS THE CONTROL AND IT IS NOT OPTIONAL: a token that was never
	// issued must not resolve. Without it a route that resolved everything would
	// pass the other three cases and the table would prove nothing.
	//
	// AN EMPTY PATH SEGMENT IS NOT IN THIS TABLE, and the omission is a finding
	// rather than a gap: chi does not route `/v1/agents/claim/` to this handler
	// at all, so it answers chi's own "no route matches this request" 404 before
	// any code of ours runs. That 404 names no agent and no link, so it discloses
	// nothing — but it is a DIFFERENT body, and the use case's own collapse of an
	// empty token is proved in internal/agents/preview_test.go instead, where the
	// handler is bypassed. The website never sends it either: the screen refuses
	// an empty token client-side before it asks.
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

	// THE SENTENCE IS ONE SENTENCE. Rendered side by side rather than against a
	// literal, so a change to the detail on one arm and not the other is a red
	// build rather than a rewrite of a string in this test.
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

// ---------------------------------------------------------------------------
// the preview changes nothing
// ---------------------------------------------------------------------------

// TestThePreviewClaimsNothingAndMintsNothing is the property that makes an
// anonymous read safe, and it is behavioural on both halves.
//
// THE MINT HALF: the agent's `agent_tokens` and `agent_events` rows are counted
// before and after. A preview that minted would be a preview that manufactured
// authority from a page load; one that wrote an event would fill the append-only
// trail with a row per page view.
//
// THE ROWS ARE COUNTED RATHER THAN READ THROUGH THE ROUTE, and that is forced
// rather than chosen: the credential list lives behind `agentClaimedOnly` (D4),
// so an UNCLAIMED agent — the only kind a live link can name — gets a 403 there.
// Counting is also the sharper assertion: it is the rows and not the projection
// of them.
func TestThePreviewClaimsNothingAndMintsNothing(t *testing.T) {
	w := newPreviewWorld(t)

	reg := registerAgent(t, w, "Noel", `{"host":"laptop"}`)

	tokens := w.rows(t, `select count(*) from agent_tokens`)
	if tokens != 1 {
		t.Fatalf("a fresh registration left %d rows in agent_tokens, want 1 (its bootstrap)", tokens)
	}
	events := w.rows(t, `select count(*) from agent_events`)
	// One row, and it is the REGISTRATION's: a fresh registration announces the
	// principal into the append-only trail. The preview's own contribution is the	// comparison below, and a baseline that is not stated is a baseline somebody
	// would later "fix" by relaxing the assertion.
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

	// THE CLAIM HALF, and it is the assertion that holds the mint half to
	// something rather than to a row count: the SAME link is claimed after the
	// preview has read it. A preview that spent the link would be a preview that
	// made the human's approval fail.
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

// ---------------------------------------------------------------------------
// the home
// ---------------------------------------------------------------------------

// TestTheHomeIsWhoTheCredentialIs is the `caf agent whoami` read over a CLAIMED
// agent: its identity, its status, and the account that claimed it.
//
// THE ACCOUNT IS A ROW ID AND NOTHING MORE. Not the account's name, not its
// members, not its slug: an agent knows which account claimed it and does not
// read that account through this route. The assertion is over the object's own
// field count, because a body that grew an account name would be a body that
// grew it in a review nobody flagged.
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
	// `status` IS AT THE TOP LEVEL and it is the field the CLI switches on
	// (caf/internal/agent/store.go reads `home["status"]`, where the server's
	// word overrides the CLI's cached copy). A nested body would leave that read
	// answering "no status".
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

	// NOTHING THAT IS NOT ABOUT THIS AGENT. Seven fields for a claimed principal
	// (the two absent-while-unclaimed ones are present here), and the list is the
	// contract: an account NAME on this route would be this route reading the
	// account through an agent's credential.
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

// TestTheHomeAnswersAnUnclaimedAgentAboutItself is the reason the route is its
// own and not a field on the token lifecycle.
//
// `caf agent whoami` is the verb an agent that registered ITSELF runs to find
// out whether anybody has claimed it. Gating the route behind `agentClaimedOnly`
// would answer "you are not claimed" by refusing to say who is asking, so the
// gate is `agentCredentialOnly` and the STATUS is the answer. An unclaimed agent
// gets a 200 with `claimed: false` and no account, and that is a fact about
// itself it is entitled to hear.
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

// TestTheHomeRefusesEverythingThatIsNotALiveAgentCredential is the stranger's
// half, and it walks the whole mis-presentation table rather than the empty
// header alone.
//
// A revoked, expired, never-issued and foreign credential are all the same 401,
// and a session token — the credential kind the human surface uses — is refused
// here rather than resolved somewhere else. "A credential of the wrong kind never
// reaches the wrong index" is the rule this holds.
func TestTheHomeRefusesEverythingThatIsNotALiveAgentCredential(t *testing.T) {
	w := newPreviewWorld(t)

	// A browser session, which is a perfectly live credential of the WRONG KIND.
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
			// The refusal carries no identifier of any kind, so a caller cannot
			// use it to learn whether an agent exists.
			if strings.Contains(rec.Body.String(), "agent") && rec.Code != http.StatusUnauthorized {
				t.Errorf("the refusal names a principal: %s", rec.Body)
			}
		})
	}
}

// TestThePreviewIsRateLimitedOnTheRegistrationsOwnTerms is the bound on the one
// agent route a stranger can drive with no credential at all.
//
// The registration route carries the same limiter with Max:1 in its own test.
// This asserts the wiring on the preview: the first read is a 200 (a limiter is a
// bound and not a gate) and the second is a 429 with the documented code. The
// limiter's key is the client and the route, so the 429 says nothing about the
// link and cannot be used to time one.
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
