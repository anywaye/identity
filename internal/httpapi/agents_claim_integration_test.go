package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/agents"
	"github.com/anywaye/identity/internal/platform/dbtest"
)


type claimWorld struct {
	handler http.Handler
	pool *pgxpool.Pool
}

func newClaimWorld(t *testing.T) *claimWorld {
	t.Helper()

	s := newAgentServer(t, 100)
	return &claimWorld{handler: s.handler, pool: s.pool}
}

func (w *claimWorld) rows(t *testing.T, query string, args ...any) int {
	t.Helper()

	var n int
	if err := w.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("counting rows (%s): %v", query, err)
	}
	return n
}

type human struct {
	session string
	account string
}

func (w *claimWorld) signUp(t *testing.T) human {
	t.Helper()

	email := dbtest.UniqueEmail(t)
	rec := post(t, w.handler, "/v1/users", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering the human: %d; body: %s", rec.Code, rec.Body)
	}

	login := post(t, w.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("signing in: %d; body: %s", login.Code, login.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}

	list := requestAs(t, w.handler, session.Token, http.MethodGet, "/v1/accounts", "")
	if list.Code != http.StatusOK {
		t.Fatalf("listing the human's accounts: %d; body: %s", list.Code, list.Body)
	}
	var accounts []accountListItem
	if err := json.Unmarshal(list.Body.Bytes(), &accounts); err != nil {
		t.Fatalf("the account list is not JSON: %v", err)
	}
	if len(accounts) == 0 {
		t.Fatal("a registered human has no account to claim into")
	}
	return human{session: session.Token, account: accounts[0].ID}
}

type registration struct {
	id    string
	token string
	link string
}

func (w *claimWorld) register(t *testing.T, name string) registration {
	t.Helper()

	rec := post(t, w.handler, "/v1/agents", `{"name":"`+name+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering %q: %d; body: %s", name, rec.Code, rec.Body)
	}
	var body registerAgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the registration body is not JSON: %v", err)
	}
	return registration{
		id:    body.Agent.ID,
		token: body.APIKey.Token,
		link:  strings.TrimPrefix(body.Claim.URL, agentHTTPClaimUI+"/agents/claim/"),
	}
}

func (w *claimWorld) claim(t *testing.T, h human, accountID, link string) *httptest.ResponseRecorder {
	t.Helper()

	payload, err := json.Marshal(claimAgentRequest{Token: link})
	if err != nil {
		t.Fatalf("marshaling the claim body: %v", err)
	}
	return requestAs(t, w.handler, h.session, http.MethodPost,
		"/v1/accounts/"+accountID+"/agents/claim", string(payload))
}

func (w *claimWorld) claimOne(t *testing.T, name string) (registration, claimAgentResponse, human) {
	t.Helper()

	h := w.signUp(t)
	reg := w.register(t, name)
	rec := w.claim(t, h, h.account, reg.link)
	if rec.Code != http.StatusOK {
		t.Fatalf("claiming %q = %d, want 200; body: %s", name, rec.Code, rec.Body)
	}
	var claimed claimAgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &claimed); err != nil {
		t.Fatalf("the claim body is not the documented shape: %v; body: %s", err, rec.Body)
	}
	return reg, claimed, h
}

func TestTheClaimAHumanCompletesRendersTheCredentialTheAgentPresents(t *testing.T) {
	w := newClaimWorld(t)

	h := w.signUp(t)
	reg := w.register(t, "Noel")

	rec := w.claim(t, h, h.account, reg.link)
	if rec.Code != http.StatusOK {
		t.Fatalf("claiming = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	var body claimAgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the claim body is not the documented shape: %v; body: %s", err, rec.Body)
	}

	if body.ID != reg.id {
		t.Errorf("the claim bound agent %s, want the one the link named %s", body.ID, reg.id)
	}
	if body.Status != agents.StatusClaimed {
		t.Errorf("status = %q, want %q", body.Status, agents.StatusClaimed)
	}
	if body.ClaimedAt == "" {
		t.Error("claimed_at is empty, and the claim screen renders it")
	}
	if body.Token.Token == "" {
		t.Fatal("the claim rendered no token, so the agent has no credential to present")
	}
	if body.Token.Token == reg.token {
		t.Error("the claim returned the registration's bootstrap token rather than minting one")
	}

	get := requestAs(t, w.handler, body.Token.Token, http.MethodGet, "/v1/agents/tokens", "")
	if get.Code != http.StatusOK {
		t.Fatalf("the claim-minted credential on GET /v1/agents/tokens = %d, want 200 — "+
			"a credential the claim renders but the agent cannot use is a decoration; body: %s",
			get.Code, get.Body)
	}

	var listed []agentTokenResponse
	if err := json.Unmarshal(get.Body.Bytes(), &listed); err != nil {
		t.Fatalf("the token list is not JSON: %v", err)
	}
	if len(listed) != 2 {
		t.Errorf("the claimed agent holds %d credentials, want 2 (the registration's bootstrap + the claim's)", len(listed))
	}
	if strings.Contains(get.Body.String(), body.Token.Token) {
		t.Error("the list carries a plaintext token, and no list endpoint may re-read one")
	}
}

func TestTheSameClaimLinkCannotBeSpentTwice(t *testing.T) {
	w := newClaimWorld(t)

	h := w.signUp(t)
	reg := w.register(t, "Noel")

	first := w.claim(t, h, h.account, reg.link)
	if first.Code != http.StatusOK {
		t.Fatalf("the first claim = %d, want 200; body: %s", first.Code, first.Body)
	}

	second := w.claim(t, h, h.account, reg.link)
	if second.Code != http.StatusNotFound {
		t.Fatalf("the second claim = %d, want 404 — a spent link must not bind anything again", second.Code)
	}
	if p := decodeProblem(t, second); p.Code != CodeNotFound {
		t.Errorf("the replay's code = %q, want %q", p.Code, CodeNotFound)
	}

	guessed := w.claim(t, h, h.account, reg.link[:len(reg.link)-1]+"x")
	if guessed.Code != http.StatusNotFound {
		t.Errorf("a wrong link = %d, want 404", guessed.Code)
	}
	if p := decodeProblem(t, guessed); p.Code != CodeNotFound {
		t.Errorf("a wrong link and a spent link answered different codes (%q vs %q)", p.Code, CodeNotFound)
	}

	read := requestAs(t, w.handler, parseTokenFrom(t, first), http.MethodGet, "/v1/agents/tokens", "")
	if read.Code != http.StatusOK {
		t.Fatalf("the first claim's credential after the replay = %d, want 200; body: %s", read.Code, read.Body)
	}
}

func TestAClaimByAHumanWhoIsNotInThatAccountIsRefused(t *testing.T) {
	w := newClaimWorld(t)

	owner := w.signUp(t)
	stranger := w.signUp(t)
	reg := w.register(t, "Noel")

	rec := w.claim(t, stranger, owner.account, reg.link)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("a stranger's claim = %d, want 404 — the account is not theirs and the "+
			"answer must not say so; body: %s", rec.Code, rec.Body)
	}

	retry := w.claim(t, owner, owner.account, reg.link)
	if retry.Code != http.StatusOK {
		t.Fatalf("the owner's claim after the refusal = %d, want 200; body: %s", retry.Code, retry.Body)
	}
}

func TestAnUnclaimedAgentGetsNothing(t *testing.T) {
	w := newClaimWorld(t)

	reg := w.register(t, "Noel")

	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"mint a token", http.MethodPost, "/v1/agents/tokens", `{"name":"deploy"}`},
		{"list tokens", http.MethodGet, "/v1/agents/tokens", ""},
		{"rotate a token", http.MethodPost, "/v1/agents/tokens/" + reg.id + "/rotate", `{}`},
		{"revoke a token", http.MethodDelete, "/v1/agents/tokens/" + reg.id, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := requestAs(t, w.handler, reg.token, tc.method, tc.path, tc.body)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s with an unclaimed agent = %d, want 403 — "+
					"an agent acting alone gets nothing (D4)", tc.method, tc.path, rec.Code)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeAgentUnclaimed {
				t.Fatalf("the code = %q, want %q — a client that cannot tell this from "+
					"`forbidden` has been told it lost and nothing about what to do",
					p.Code, CodeAgentUnclaimed)
			}
			if !strings.Contains(strings.ToLower(p.Detail), "claim") {
				t.Errorf("the 403's detail does not name the remedy: %q", p.Detail)
			}
		})
	}

	refresh := requestAs(t, w.handler, reg.token, http.MethodPost, "/v1/agents/claim-link/refresh", `{}`)
	if refresh.Code != http.StatusOK {
		t.Fatalf("an unclaimed agent refreshing its claim link = %d, want 200 — "+
			"closing this would leave an agent nobody can finish claiming; body: %s",
			refresh.Code, refresh.Body)
	}
}

func TestTheClaimRefusesACredentialThatIsNotABrowserSession(t *testing.T) {
	w := newClaimWorld(t)

	h := w.signUp(t)
	reg := w.register(t, "Noel")

	rec := requestAs(t, w.handler, agents.Prefix+"not-a-session", http.MethodPost,
		"/v1/accounts/"+h.account+"/agents/claim", `{"token":"`+reg.link+`"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("claiming with a bearer that is not a browser session = %d, want 403", rec.Code)
	}

	anon := requestAs(t, w.handler, "", http.MethodPost,
		"/v1/accounts/"+h.account+"/agents/claim", `{"token":"`+reg.link+`"}`)
	if anon.Code != http.StatusUnauthorized {
		t.Errorf("claiming with no credential = %d, want 401", anon.Code)
	}
}

func parseTokenFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	var body claimAgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the claim: %v", err)
	}
	return body.Token.Token
}
