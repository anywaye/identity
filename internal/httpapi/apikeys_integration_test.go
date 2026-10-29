package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/users"
)


type apiKeyServer struct {
	handler http.Handler
	pool    *pgxpool.Pool
	owner *pgxpool.Pool
	clk   *clock.Fake
	keys  *apikeys.Service
	logs  *recordingHandler

	session string
	token   string
	keyID id.UUID

	user    users.User
	email   string
	account id.UUID
	elsewhere id.UUID
}

func newAPIKeyServer(t *testing.T) *apiKeyServer {
	t.Helper()

	pool, owner := dbtest.SchemaWithOwner(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
	tenancy := realTenancy(pool, clk)
	authSvc := authServiceFor(pool, clk)
	keys := matrixAPIKeys(pool, clk, tenancy)
	logs := &recordingHandler{}

	s := &apiKeyServer{
		pool: pool, owner: owner, clk: clk, keys: keys, logs: logs,
		handler: New(nil,
			WithAuth(authSvc),
			WithTenancy(tenancy),
			WithOIDCClients(matrixOIDCClients(t, pool, clk)),
			WithOIDC(newFakeOIDC()),
			WithAPIKeys(keys),
			WithAPIKeyCaller(keys),
			WithIntrospection(keys),
			WithClock(clk),
			WithLogger(slogLogger(logs)),
		),
	}

	email := dbtest.UniqueEmail(t)
	registered := post(t, s.handler, "/v1/users",
		`{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if registered.Code != http.StatusCreated {
		t.Fatalf("registering: %d; body: %s", registered.Code, registered.Body)
	}
	var created userResponse
	if err := json.Unmarshal(registered.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding the registration: %v", err)
	}
	parsed, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("the service returned an id that does not parse: %v", err)
	}
	s.user = users.User{ID: parsed, Email: created.Email}
	s.email = created.Email

	login := post(t, s.handler, "/v1/session",
		`{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("signing in: %d; body: %s", login.Code, login.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatalf("decoding the login: %v", err)
	}
	s.session = session.Token

	list := apiKeyGet(t, s.handler, "/v1/accounts", s.session)
	if list.Code != http.StatusOK {
		t.Fatalf("listing accounts: %d; body: %s", list.Code, list.Body)
	}
	var listed []accountListItem
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decoding the account list: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("a fresh registration holds %d accounts, want 1", len(listed))
	}
	if s.account, err = id.Parse(listed[0].ID); err != nil {
		t.Fatalf("parsing the account id: %v", err)
	}

	second, err := tenancy.Create(context.Background(), accounts.CreateInput{
		Name: "Second account", Owner: s.user.ID,
	})
	if err != nil {
		t.Fatalf("creating the second account: %v", err)
	}
	s.elsewhere = second.Account.ID

	return s
}

func (s *apiKeyServer) mint(t *testing.T, name string, scopes ...string) (id.UUID, string) {
	t.Helper()

	body := fmt.Sprintf(`{"name":%q,"scopes":[`, name)
	for i, scope := range scopes {
		if i > 0 {
			body += ","
		}
		body += fmt.Sprintf("%q", scope)
	}
	body += `]}`

	rec := apiKeyPost(t, s.handler, apiKeyPath(s.account), s.session, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("minting %q: %d; body: %s", name, rec.Code, rec.Body)
	}

	var issued issuedAPIKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decoding the issued key: %v\n%s", err, rec.Body)
	}
	parsed, err := id.Parse(issued.ID)
	if err != nil {
		t.Fatalf("the service returned an id that does not parse: %v", err)
	}
	return parsed, issued.Token
}

func (s *apiKeyServer) bearer(t *testing.T, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return apiKeySend(t, s.handler, method, path, token, body)
}


func TestTheSecretIsOnTheWireOnceAndNowhereElse(t *testing.T) {
	s := newAPIKeyServer(t)

	keyID, secret := s.mint(t, "ci-deploy", apikeys.ScopeAccountsRead)
	s.keyID, s.token = keyID, secret

	if !strings.HasPrefix(secret, apikeys.Prefix) {
		t.Fatalf("the issued token does not carry the %q prefix", apikeys.Prefix)
	}

	withoutPrefix := strings.TrimPrefix(secret, apikeys.Prefix)
	for _, tt := range []struct {
		name string
		do   func() *httptest.ResponseRecorder
	}{
		{"the list", func() *httptest.ResponseRecorder {
			return apiKeyGet(t, s.handler, apiKeyPath(s.account), s.session)
		}},
		{"the account", func() *httptest.ResponseRecorder {
			return apiKeyGet(t, s.handler, "/v1/accounts/"+s.account.String(), s.session)
		}},
		{"the members", func() *httptest.ResponseRecorder {
			return apiKeyGet(t, s.handler, "/v1/accounts/"+s.account.String()+"/members", s.session)
		}},
		{"introspection of itself", func() *httptest.ResponseRecorder {
			return apiKeySend(t, s.handler, http.MethodPost, "/v1/introspections", s.session,
				`{"token":"`+secret+`"}`)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := tt.do()
			for _, forbidden := range []string{secret, withoutPrefix} {
				if strings.Contains(rec.Body.String(), forbidden) {
					t.Errorf("the %s response carries the secret: %s", tt.name, rec.Body)
				}
			}
		})
	}

	digest := apikeys.Digest(secret)
	rendered := s.renderEverywhere(t, keyID)
	for _, forbidden := range []string{secret, withoutPrefix, strings.ToLower(secret)} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("the plaintext is at rest somewhere; the rendered row, table and outbox contain %q", forbidden)
		}
	}
	if !strings.Contains(rendered, digest) {
		t.Errorf("the digest is not in the row, so the search above proves nothing:\n%s", rendered)
	}
	if digest == secret {
		t.Error("the digest IS the secret")
	}
}

func (s *apiKeyServer) renderEverywhere(t *testing.T, keyID id.UUID) string {
	t.Helper()
	ctx := context.Background()

	var row string
	if err := s.pool.QueryRow(ctx,
		`SELECT row_to_json(api_keys)::text FROM api_keys WHERE id = $1`, keyID).Scan(&row); err != nil {
		t.Fatalf("rendering the row: %v", err)
	}

	var table string
	if err := s.pool.QueryRow(ctx,
		`SELECT coalesce(string_agg(row_to_json(api_keys)::text, E'\n'), '') FROM api_keys`).Scan(&table); err != nil {
		t.Fatalf("rendering the table: %v", err)
	}

	var events string
	if err := s.pool.QueryRow(ctx,
		`SELECT coalesce(string_agg(envelope::text, E'\n'), '') FROM outbox_events`).Scan(&events); err != nil {
		t.Fatalf("rendering the outbox: %v", err)
	}

	return "ROW:\n" + row + "\nTABLE:\n" + table + "\nOUTBOX:\n" + events
}


func TestARemovedMembershipStopsTheTokenOnTheNextRequest(t *testing.T) {
	s := newAPIKeyServer(t)
	keyID, secret := s.mint(t, "deploy", apikeys.ScopeAccountsRead)
	s.keyID, s.token = keyID, secret

	read := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")
	if read.Code != http.StatusOK {
		t.Fatalf("a fresh token reading its account = %d, want 200; body: %s", read.Code, read.Body)
	}

	helper := s.promoteHelper(t, s.account)
	if err := s.removeMember(t, s.account, s.user.ID, helper); err != nil {
		t.Fatalf("removing the membership: %v", err)
	}

	refused := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")
	if refused.Code != http.StatusUnauthorized {
		t.Fatalf("after the membership was removed the token got %d, want 401; body: %s",
			refused.Code, refused.Body)
	}
	if p := decodeProblem(t, refused); p.Code != CodeUnauthorized {
		t.Errorf("code = %q, want %q", p.Code, CodeUnauthorized)
	}

	if err := s.readmit(t, helper); err != nil {
		t.Fatalf("re-inviting: %v", err)
	}
	resurrected := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")
	if resurrected.Code == http.StatusOK {
		t.Error("the token works again after the user was re-invited. Its authority was " +
			"snapshotted somewhere, or a removed contractor's credential revives with a " +
			"membership — which is the resurrection this packet exists to prevent")
	}
	if resurrected.Code != http.StatusUnauthorized {
		t.Errorf("after re-invitation the token got %d, want 401; body: %s", resurrected.Code, resurrected.Body)
	}

	stored := s.row(t, s.keyID)
	if stored == "" {
		t.Fatal("the row was deleted; an operator asking whether a credential was revoked " +
			"or the membership was removed has no answer")
	}
	if strings.Contains(stored, `"revoked_at":null`) {
		t.Errorf("the row is not marked revoked, so the removal did not revoke it and the "+
			"token is only dead while the membership is missing — which is the "+
			"resurrection:\n%s", stored)
	}
	if !strings.Contains(stored, "membership removed") {
		t.Errorf("the row does not say the membership was removed:\n%s", stored)
	}
}

func TestADemotionStopsTheTokenOnOwnerOnlyRoutes(t *testing.T) {
	s := newAPIKeyServer(t)
	_, secret := s.mint(t, "deploy", apikeys.ScopeOIDCClientsWrite, apikeys.ScopeAccountsRead)

	before := s.bearer(t, http.MethodGet,
		"/v1/accounts/"+s.account.String()+"/oidc-clients", secret, "")
	if before.Code != http.StatusOK {
		t.Fatalf("an owner's token listing clients = %d, want 200; body: %s", before.Code, before.Body)
	}

	if err := s.demote(t, s.account, s.user.ID, accounts.RoleMember); err != nil {
		t.Fatalf("demoting: %v", err)
	}

	after := s.bearer(t, http.MethodGet,
		"/v1/accounts/"+s.account.String()+"/oidc-clients", secret, "")
	if after.Code != http.StatusForbidden {
		t.Fatalf("after the demotion the same request got %d, want 403; body: %s", after.Code, after.Body)
	}
	if p := decodeProblem(t, after); p.Code != CodeForbidden {
		t.Errorf("code = %q, want %q", p.Code, CodeForbidden)
	}

	stillWorks := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")
	if stillWorks.Code != http.StatusOK {
		t.Errorf("a demoted member's token lost a member-level route too: %d; body: %s",
			stillWorks.Code, stillWorks.Body)
	}
}

func TestATokenIsBoundToTheAccountItWasMintedFor(t *testing.T) {
	s := newAPIKeyServer(t)
	_, secret := s.mint(t, "deploy", everyAccountScope()...)

	own := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")
	if own.Code != http.StatusOK {
		t.Fatalf("= %d, want 200; body: %s", own.Code, own.Body)
	}

	other := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.elsewhere.String(), secret, "")
	if other.Code != http.StatusNotFound {
		t.Fatalf("a token for one account reaching another = %d, want 404; body: %s", other.Code, other.Body)
	}

	otherWrite := s.bearer(t, http.MethodPatch, "/v1/accounts/"+s.elsewhere.String(), secret, `{"name":"x"}`)
	if otherWrite.Code != http.StatusNotFound {
		t.Errorf("a cross-tenant write = %d, want 404; body: %s", otherWrite.Code, otherWrite.Body)
	}
}


func TestScopeEnforcementIsWiredToTheRoutes(t *testing.T) {
	type routeCase struct {
		method string
		path   string
		body   string
	}

	for _, scope := range everyAccountScope() {
		t.Run(scope, func(t *testing.T) {
			s := newAPIKeyServer(t)
			account := s.account.String()

			routes := []routeCase{
				{http.MethodGet, "/v1/accounts", ""},
				{http.MethodGet, "/v1/accounts/" + account, ""},
				{http.MethodGet, "/v1/accounts/" + account + "/members", ""},
				{http.MethodPatch, "/v1/accounts/" + account, `{"name":"Renamed"}`},
				{http.MethodPost, "/v1/accounts/" + account + "/invitations",
					`{"email":"` + dbtest.UniqueEmail(t) + `","role":"member"}`},
				{http.MethodGet, "/v1/accounts/" + account + "/oidc-clients", ""},
				{http.MethodPost, "/v1/accounts/" + account + "/oidc-clients",
					`{"name":"c","redirect_uris":["https://c.example.com/cb"],"grant_types":["authorization_code"],"scopes":["openid"]}`},
				{http.MethodGet, apiKeyPath(s.account), ""},
				{http.MethodPost, apiKeyPath(s.account), `{"name":"nested","scopes":["accounts:read"]}`},
			}

			_, secret := s.mint(t, "only-"+strings.ReplaceAll(scope, ":", "-"), scope)

			for _, route := range routes {
				s.expectScopeAnswer(t, route.method, route.path, route.body, scope, secret)
			}

			own := newAPIKeyServer(t)
			_, deleteSecret := own.mint(t, "only-delete", scope)
			own.expectScopeAnswer(t, http.MethodDelete, "/v1/accounts/"+own.account.String(), "",
				scope, deleteSecret)
		})
	}
}

func (s *apiKeyServer) expectScopeAnswer(t *testing.T, method, path, body, held, secret string) {
	t.Helper()

	required := s.requiredScope(method, path)
	rec := s.bearer(t, method, path, secret, body)

	switch required {
	case "":
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with %q = %d, want 403: no scope reaches this route",
				method, path, held, rec.Code)
		}
	case held:
		if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "does not carry the") {
			t.Errorf("%s %s refused a token holding %q", method, path, held)
		}
	default:
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with only %q = %d, want 403; body: %s",
				method, path, held, rec.Code, rec.Body)
			return
		}
		if !strings.Contains(rec.Body.String(), required) {
			t.Errorf("%s %s refused without naming %q: %s", method, path, required, rec.Body)
		}
	}
}

func (s *apiKeyServer) requiredScope(method, path string) string {
	for route, scope := range accountRouteScopes {
		parts := strings.SplitN(route, " ", 2)
		if len(parts) != 2 || parts[0] != method {
			continue
		}
		pattern := parts[1]
		if matchesPattern(pattern, path) {
			return scope
		}
	}
	return ""
}

func matchesPattern(pattern, path string) bool {
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	if len(patternParts) != len(pathParts) {
		return false
	}
	for i, want := range patternParts {
		got := pathParts[i]
		if strings.HasPrefix(want, "{") && strings.HasSuffix(want, "}") {
			if _, err := id.Parse(got); err != nil {
				return false
			}
			continue
		}
		if want != got {
			return false
		}
	}
	return true
}

func TestATokenCannotManageTheCredentialSurfaceOverTheRealRouter(t *testing.T) {
	s := newAPIKeyServer(t)
	_, secret := s.mint(t, "everything", everyAccountScope()...)

	for _, tt := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, apiKeyPath(s.account), ""},
		{http.MethodPost, apiKeyPath(s.account), `{"name":"nested","scopes":["accounts:read"]}`},
		{http.MethodDelete, apiKeyPath(s.account) + "/" + s.keyID.String(), ""},
	} {
		rec := s.bearer(t, tt.method, tt.path, secret, tt.body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with every scope = %d, want 403; body: %s",
				tt.method, tt.path, rec.Code, rec.Body)
		}
	}
	if n := s.countKeys(t); n != 1 {
		t.Errorf("a refused mint left %d keys, want 1", n)
	}
}

func TestATokenCannotReachTheSecondFactor(t *testing.T) {
	s := newAPIKeyServer(t)
	_, secret := s.mint(t, "deploy", everyAccountScope()...)

	for _, tt := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/v1/mfa", ""},
		{http.MethodPost, "/v1/mfa/enrollments", `{}`},
		{http.MethodPost, "/v1/mfa/recovery-codes", `{"code":"000000"}`},
		{http.MethodDelete, "/v1/mfa", `{"code":"000000"}`},
		{http.MethodDelete, "/v1/session", ""},
	} {
		rec := s.bearer(t, tt.method, tt.path, secret, tt.body)
		if rec.Code == http.StatusOK || rec.Code == http.StatusCreated || rec.Code == http.StatusNoContent {
			t.Errorf("%s %s with every scope = %d; a machine credential reached a surface "+
				"it has no scope for", tt.method, tt.path, rec.Code)
		}
	}
}


func TestEveryRefusalIsTheSameResponse(t *testing.T) {
	s := newAPIKeyServer(t)
	revokedID, revokedSecret := s.mint(t, "to-revoke", apikeys.ScopeAccountsRead)
	if rec := s.bearer(t, http.MethodDelete, apiKeyPath(s.account)+"/"+revokedID.String(), s.session, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("revoking: %d; body: %s", rec.Code, rec.Body)
	}

	shortRec := apiKeyPost(t, s.handler, apiKeyPath(s.account), s.session,
		`{"name":"to-expire","scopes":["accounts:read"],"expires_in":86400}`)
	if shortRec.Code != http.StatusCreated {
		t.Fatalf("minting a short-lived key: %d; body: %s", shortRec.Code, shortRec.Body)
	}
	var short issuedAPIKeyResponse
	if err := json.Unmarshal(shortRec.Body.Bytes(), &short); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	shortSecret := short.Token
	s.clk.Advance(25 * time.Hour)

	cases := []struct {
		name  string
		token string
	}{
		{name: "a revoked token", token: revokedSecret},
		{name: "an expired token", token: shortSecret},
		{name: "a token that never existed", token: apikeys.Prefix + strings.Repeat("Z", 43)},
		{name: "a truncated paste", token: revokedSecret[:20]},
		{name: "the prefix alone", token: apikeys.Prefix},
		{name: "an empty bearer", token: ""},
		{name: "a session token", token: s.session},
		{name: "an OIDC-shaped JWT", token: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"},
		{name: "the digest, presented as a token", token: apikeys.Digest(revokedSecret)},
		{name: "binary noise", token: "\x00\x01\x02\x03"},
	}

	var reference *httptest.ResponseRecorder
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			rec := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), tt.token, "")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("= %d, want 401; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeUnauthorized {
				t.Errorf("code = %q, want %q", p.Code, CodeUnauthorized)
			}
			if reference == nil {
				reference = rec
				return
			}
			if rec.Header().Get("Content-Type") != reference.Header().Get("Content-Type") {
				t.Errorf("Content-Type = %q, want the same as every other refusal (%q)",
					rec.Header().Get("Content-Type"), reference.Header().Get("Content-Type"))
			}
			var got, want Problem
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decoding: %v", err)
			}
			if err := json.Unmarshal(reference.Body.Bytes(), &want); err != nil {
				t.Fatalf("decoding the reference: %v", err)
			}
			if got.Type != want.Type || got.Title != want.Title || got.Status != want.Status ||
				got.Code != want.Code || got.Detail != want.Detail {
				t.Errorf("the refusal differs from every other refusal:\n got %+v\nwant %+v", got, want)
			}
		})
	}

}


func TestNoCredentialReachesTheLogs(t *testing.T) {
	s := newAPIKeyServer(t)
	keyID, secret := s.mint(t, "ci-deploy", apikeys.ScopeAccountsRead, apikeys.ScopeAccountsWrite)
	s.keyID, s.token = keyID, secret

	s.bearer(t, http.MethodGet, "/v1/accounts", secret, "")
	s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")
	s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String()+"/members", secret, "")
	s.bearer(t, http.MethodGet, apiKeyPath(s.account), s.session, "")
	s.bearer(t, http.MethodPost, "/v1/introspections", s.session, `{"token":"`+secret+`"}`)
	s.bearer(t, http.MethodPost, "/v1/introspections", secret, `{"token":"`+secret+`"}`)
	if rec := s.bearer(t, http.MethodDelete, apiKeyPath(s.account)+"/"+keyID.String(), s.session, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("revoking: %d; body: %s", rec.Code, rec.Body)
	}

	s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")

	if _, err := s.owner.Exec(context.Background(), `DROP TABLE api_keys`); err != nil {
		t.Fatalf("dropping api_keys: %v", err)
	}
	rec := apiKeyGet(t, s.handler, apiKeyPath(s.account), s.session)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("the store failure = %d, want 500; body: %s", rec.Code, rec.Body)
	}

	logs := s.logs.rendered()
	if strings.TrimSpace(logs) == "" {
		t.Fatal("nothing was logged at all, so every absence assertion below would pass " +
			"vacuously. The store failure above is the request that should have logged, " +
			"so an empty log means the harness is wrong rather than the code.")
	}

	for _, forbidden := range []string{
		secret,
		strings.TrimPrefix(secret, apikeys.Prefix),
		apikeys.Digest(secret),
		apikeys.Prefix,
	} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("the rendered logs contain %q, which is the credential or a container for it.\nRendered logs:\n%s",
				forbidden, logs)
		}
	}

	for _, word := range []string{"digest", "secret", "password", apikeys.Prefix} {
		if strings.Contains(strings.ToLower(logs), word) {
			t.Errorf("the rendered logs mention %q, which is the vocabulary of a credential "+
				"even with no value attached.\nRendered logs:\n%s", word, logs)
		}
	}
}


func (s *apiKeyServer) removeMember(t *testing.T, account, member, actor id.UUID) error {
	t.Helper()
	return realTenancy(s.pool, s.clk).RemoveMember(context.Background(), accounts.RemoveMemberInput{
		AccountID: account,
		UserID:    member,
		Actor:     actor,
	})
}

func (s *apiKeyServer) promoteHelper(t *testing.T, account id.UUID) id.UUID {
	t.Helper()
	ctx := context.Background()

	email := dbtest.UniqueEmail(t)
	registered := post(t, s.handler, "/v1/users",
		`{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if registered.Code != http.StatusCreated {
		t.Fatalf("registering the helper: %d; body: %s", registered.Code, registered.Body)
	}
	var created userResponse
	if err := json.Unmarshal(registered.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	helper, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("parsing the helper's id: %v", err)
	}
	if _, err := accounts.NewStore(s.pool).AddMember(ctx, s.pool, accounts.Membership{
		AccountID: account, UserID: helper, Role: accounts.RoleOwner,
	}); err != nil {
		t.Fatalf("promoting the helper: %v", err)
	}
	return helper
}

func (s *apiKeyServer) readmit(t *testing.T, actor id.UUID) error {
	t.Helper()
	ctx := context.Background()
	tenancy := realTenancy(s.pool, s.clk)

	invited, err := tenancy.Invite(ctx, accounts.InviteInput{
		AccountID: s.account,
		Email:     dbtest.UniqueEmail(t),
		Role:      accounts.RoleMember,
		InvitedBy: actor,
	})
	if err != nil {
		return err
	}
	if _, err := tenancy.Accept(ctx, accounts.AcceptInput{Token: invited.Token, User: s.user.ID}); err != nil {
		return err
	}
	_, err = accounts.NewStore(s.pool).SetRole(ctx, s.pool, s.account, s.user.ID, accounts.RoleOwner)
	return err
}

func (s *apiKeyServer) demote(t *testing.T, account, member id.UUID, to accounts.Role) error {
	t.Helper()
	_, err := accounts.NewStore(s.pool).SetRole(context.Background(), s.pool, account, member, to)
	return err
}

func (s *apiKeyServer) row(t *testing.T, keyID id.UUID) string {
	t.Helper()
	var out string
	if err := s.pool.QueryRow(context.Background(),
		`SELECT coalesce(row_to_json(api_keys)::text, '') FROM api_keys WHERE id = $1`, keyID).Scan(&out); err != nil {
		t.Fatalf("reading the row: %v", err)
	}
	return out
}

func (s *apiKeyServer) countKeys(t *testing.T) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM api_keys`).Scan(&n); err != nil {
		if errors.Is(err, context.Canceled) {
			t.Fatalf("counting keys: %v", err)
		}
		t.Fatalf("counting keys: %v", err)
	}
	return n
}

var (
	_ = oidc.ScopeOpenID
	_ = clock.System{}
)
