package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
)


const (
	oidcTestIssuer   = "https://identity.test"
	oidcTestKeyID    = "anywaye-test-key"
	oidcTestRedirect = "https://app.example.com/cb"
	oidcTestPassword = "correct horse battery staple"
	oidcTestUserAgent = "identity-oidc-test/1"
	oidcTestLoginUI = "https://login.example.com/sign-in/oidc"
)

type oidcFixture struct {
	handler  http.Handler
	pool     *pgxpool.Pool
	provider *oidc.Provider
	storage  *oidc.Storage
	clients  *oidc.Service
	account  id.UUID
	owner    id.UUID
	email    string
	tenancy *accounts.Service
	jar *cookieJar
}

func (f *oidcFixture) signOut() {
	delete(f.jar.cookies, SessionCookieName)
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	key := generateTestKey(t)

	clk := clock.System{}

	store := oidc.NewStore(pool)
	storage := oidc.NewStorage(store, oidc.NewProfileReader(), oauth.NewStore(pool), key, clk, db.Direct{Pool: pool}, oidc.PathLogin)

	provider, err := oidc.NewProvider(oidc.Config{
		Issuer:     oidcTestIssuer,
		SigningKey: key,
		LoginUIURL: oidcTestLoginUI,
	}, storage)
	if err != nil {
		t.Fatalf("building the provider: %v", err)
	}

	tenancy := realTenancy(pool, clk)
	f := &oidcFixture{tenancy: tenancy}
	authSvc := authServiceFor(pool, clk)
	clients := oidc.NewService(db.TxRunner{Pool: pool}, store, outbox.NewStore(pool), storage, clk, db.Direct{Pool: pool})

	handler := New(nil,
		WithAuth(authSvc),
		WithTenancy(tenancy),
		WithOIDC(provider),
		WithOIDCClients(clients),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)

	f.handler = handler
	f.pool = pool
	f.provider = provider
	f.storage = storage
	f.clients = clients
	f.jar = &cookieJar{}

	email := dbtest.UniqueEmail(t)
	rec := f.do(t, http.MethodPost, "/v1/users", `{"email":"`+email+`","password":"`+oidcTestPassword+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering a user: %d; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	mustJSON(t, rec.Body.Bytes(), &created)

	login := f.do(t, http.MethodPost, "/v1/session", `{"email":"`+email+`","password":"`+oidcTestPassword+`"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("signing in: %d; body: %s", login.Code, login.Body)
	}
	var session sessionResponse
	mustJSON(t, login.Body.Bytes(), &session)
	f.jar.set(session.Token)

	parsed, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("the service returned an id that does not parse: %v", err)
	}
	f.owner = parsed
	f.email = email

	mine, err := tenancy.ListMine(t.Context(), f.owner)
	if err != nil {
		t.Fatalf("listing the personal account: %v", err)
	}
	if len(mine) != 1 {
		t.Fatalf("a fresh registration has %d accounts, want 1", len(mine))
	}
	f.account = mine[0].Account.ID

	return f
}

func (f *oidcFixture) tenantAccount(t *testing.T, owner id.UUID) (id.UUID, error) {
	t.Helper()

	created, err := f.tenancy.Create(t.Context(), accounts.CreateInput{
		Name:  "OIDC test " + owner.String()[:8],
		Owner: owner,
	})
	if err != nil {
		return id.UUID{}, err
	}
	return created.Account.ID, nil
}

func generateTestKey(t *testing.T) *oidc.SigningKey {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, priv)})

	key, err := oidc.LoadSigningKey(string(encoded), oidcTestKeyID)
	if err != nil {
		t.Fatalf("loading the signing key: %v", err)
	}
	return key
}

func mustPKCS8(t *testing.T, priv *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := marshalPKCS8Key(priv)
	if err != nil {
		t.Fatalf("marshaling the signing key: %v", err)
	}
	return der
}

type registered struct {
	ID           string
	ClientID     string
	ClientSecret string
	Email        string
	Password     string
}

func (f *oidcFixture) registerClient(t *testing.T) registered {
	t.Helper()

	body := fmt.Sprintf(`{"name":"Anytalk","redirect_uris":[%q],"grant_types":["authorization_code"],`+
		`"scopes":["openid","email","profile","accounts"]}`, oidcTestRedirect)

	rec := f.do(t, http.MethodPost, "/v1/accounts/"+f.account.String()+"/oidc-clients", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering a client: %d; body: %s", rec.Code, rec.Body)
	}

	var created oidcClientCreatedResponse
	mustJSON(t, rec.Body.Bytes(), &created)
	if created.ClientSecret == "" {
		t.Fatal("the 201 carried no client_secret; it exists exactly once, here")
	}
	if created.ClientID == "" || created.ID == "" {
		t.Fatalf("the 201 is missing the identifiers: %s", rec.Body)
	}

	return registered{
		ID:           created.ID,
		ClientID:     created.ClientID,
		ClientSecret: created.ClientSecret,
		Email:        f.email,
		Password:     oidcTestPassword,
	}
}

func codeVerifier(t *testing.T) (verifier, challenge string) {
	t.Helper()

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("generating a code verifier: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func (f *oidcFixture) authorize(t *testing.T, client registered, challenge, state, nonce string, extra url.Values) string {
	t.Helper()

	query := url.Values{
		"client_id":             []string{client.ClientID},
		"redirect_uri":          []string{oidcTestRedirect},
		"response_type":         []string{"code"},
		"scope":                 []string{"openid email profile accounts"},
		"state":                 []string{state},
		"nonce":                 []string{nonce},
		"code_challenge":        []string{challenge},
		"code_challenge_method": []string{"S256"},
	}
	for key, values := range extra {
		query[key] = values
	}

	rec := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("GET /oidc/authorize = %d, want 302; body: %s", rec.Code, rec.Body)
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, oidc.PathLogin+"/") {
		t.Fatalf("the browser was sent to %q, want the login page", location)
	}
	return location
}

func (f *oidcFixture) login(t *testing.T, loginURL, email, password string) *oidcResponse {
	t.Helper()

	f.signOut()

	form := f.do(t, http.MethodGet, loginURL, "", nil)
	redirect := mustRedirectToLoginUI(t, form)
	if got := redirect.Query().Get(oidc.LoginParamClientName); got != "Anytalk" {
		t.Errorf("%s = %q, want the product asking; a sign-in form that cannot name the "+
			"application is a credential-phishing page", oidc.LoginParamClientName, got)
	}
	if got := redirect.Query().Get(oidc.LoginParamStep); got != oidc.LoginStepPassword {
		t.Errorf("%s = %q, want %q", oidc.LoginParamStep, got, oidc.LoginStepPassword)
	}

	post := url.Values{
		"state":    []string{interactionState(t, form)},
		"email":    []string{email},
		"password": []string{password},
	}
	rec := f.do(t, http.MethodPost, loginURL, "", post)
	f.jar.absorb(rec.Result().Cookies())
	return rec
}

func (f *oidcFixture) exchange(t *testing.T, client registered, code, verifier, redirectURI string) *oidcResponse {
	t.Helper()

	form := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{redirectURI},
		"code_verifier": []string{verifier},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+basicAuth(client.ClientID, client.ClientSecret))

	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return newResponse(rec)
}

func (f *oidcFixture) roundTrip(t *testing.T, client registered) map[string]any {
	t.Helper()

	verifier, challenge := codeVerifier(t)
	const state, nonce = "state-round-trip", "nonce-round-trip"

	loginURL := f.authorize(t, client, challenge, state, nonce, nil)

	rec := f.login(t, loginURL, client.Email, client.Password)
	if rec.Code != http.StatusFound {
		t.Fatalf("POST the login form = %d, want 302; body: %s", rec.Code, rec.Body)
	}

	redirect, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("the login redirect is not a URL: %v", err)
	}
	if got := redirect.Scheme + "://" + redirect.Host + redirect.Path; got != oidcTestRedirect {
		t.Fatalf("the browser was returned to %q, want the registered %q", got, oidcTestRedirect)
	}
	if got := redirect.Query().Get("state"); got != state {
		t.Errorf("the redirect carried state %q, want %q; the client's CSRF value must come back untouched", got, state)
	}
	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatalf("the redirect carried no code: %s", redirect)
	}

	tokens := f.exchange(t, client, code, verifier, oidcTestRedirect)
	if tokens.Code != http.StatusOK {
		t.Fatalf("the token exchange = %d, want 200; body: %s", tokens.Code, tokens.Body)
	}

	var body map[string]any
	mustJSON(t, tokens.Body.Bytes(), &body)
	return body
}

func (f *oidcFixture) verify(t *testing.T, token string) map[string]any {
	t.Helper()

	rec := f.do(t, http.MethodGet, oidc.PathJWKS, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET the jwks = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	var set jose.JSONWebKeySet
	mustJSON(t, rec.Body.Bytes(), &set)

	parsed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("the token is not an RS256 JWS: %v", err)
	}
	payload, err := parsed.Verify(set.Keys[0].Key)
	if err != nil {
		t.Fatalf("the token does not verify against the published key set: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("the token payload is not JSON: %v", err)
	}
	return claims
}

func (f *oidcFixture) do(t *testing.T, method, target, body string, form url.Values) *oidcResponse {
	t.Helper()

	return f.doWithSession(t, "", method, target, body, form)
}

func (f *oidcFixture) doWithSession(t *testing.T, session, method, target, body string, form url.Values) *oidcResponse {
	t.Helper()

	var reader io.Reader
	switch {
	case form != nil:
		reader = strings.NewReader(form.Encode())
	case body != "":
		reader = strings.NewReader(body)
	default:
		reader = strings.NewReader("")
	}

	req := httptest.NewRequestWithContext(context.Background(), method, target, reader)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", oidcTestUserAgent)
	if session != "" {
		req.Header.Set("Authorization", "Bearer "+session)
	} else if cookie := f.jar.header(); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	f.jar.absorb(rec.Result().Cookies())
	return newResponse(rec)
}

type cookieJar struct {
	cookies map[string]*http.Cookie
}

func (j *cookieJar) absorb(cookies []*http.Cookie) {
	if j.cookies == nil {
		j.cookies = map[string]*http.Cookie{}
	}
	for _, c := range cookies {
		if c.MaxAge < 0 || c.Value == "" {
			delete(j.cookies, c.Name)
			continue
		}
		j.cookies[c.Name] = c
	}
}

func (j *cookieJar) set(token string) {
	if j.cookies == nil {
		j.cookies = map[string]*http.Cookie{}
	}
	j.cookies[SessionCookieName] = &http.Cookie{Name: SessionCookieName, Value: token}
}

func (j *cookieJar) header() string {
	names := make([]string, 0, len(j.cookies))
	for name := range j.cookies {
		names = append(names, name)
	}
	sortStrings(names)

	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+j.cookies[name].Value)
	}
	return strings.Join(parts, "; ")
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for k := i; k > 0 && values[k] < values[k-1]; k-- {
			values[k], values[k-1] = values[k-1], values[k]
		}
	}
}

func basicAuth(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(user) + ":" + url.QueryEscape(password)))
}

func interactionState(t *testing.T, rec *oidcResponse) string {
	t.Helper()

	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatalf("the response carried no Location; it was %d with body:\n%s", rec.Code, rec.Body)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("the redirect %q is not a URL: %v", location, err)
	}
	state := parsed.Query().Get(oidc.LoginParamState)
	if state == "" {
		t.Fatalf("the redirect %q carried no %q", location, oidc.LoginParamState)
	}
	return state
}

func interactionParams(t *testing.T, rec *oidcResponse) url.Values {
	t.Helper()

	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatalf("the response carried no Location; it was %d with body:\n%s", rec.Code, rec.Body)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("the redirect %q is not a URL: %v", location, err)
	}
	return parsed.Query()
}

func mustRedirectToLoginUI(t *testing.T, rec *oidcResponse) *url.URL {
	t.Helper()

	if rec.Code != http.StatusFound {
		t.Fatalf("= %d, want 302 to the login UI; body:\n%s", rec.Code, rec.Body)
	}
	parsed, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != oidcTestLoginUI {
		t.Fatalf("the browser was sent to %q, want the configured login UI %q", got, oidcTestLoginUI)
	}
	return parsed
}

func mustJSON(t *testing.T, data []byte, into any) {
	t.Helper()

	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, data)
	}
}

func marshalPKCS8Key(priv *rsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(priv)
}
