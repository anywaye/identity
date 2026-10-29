package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/mfa"
	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
)


type oidcMFAFixture struct {
	handler  http.Handler
	pool     *pgxpool.Pool
	clock    *clock.Fake
	second   *mfa.Service
	email    string
	userID   id.UUID
	secret   string
	recovery string
	requestID string
	jar       *cookieJar
}

func newOIDCMFAFixture(t *testing.T, withMFA bool) *oidcMFAFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	key := generateTestKey(t)
	store := oidc.NewStore(pool)
	storage := oidc.NewStorage(store, oidc.NewProfileReader(), oauth.NewStore(pool), key, clock.System{},
		db.Direct{Pool: pool}, oidc.PathLogin)
	provider, err := oidc.NewProvider(oidc.Config{
		Issuer:     oidcTestIssuer,
		SigningKey: key,
		LoginUIURL: oidcTestLoginUI,
	}, storage)
	if err != nil {
		t.Fatalf("building the provider: %v", err)
	}

	second := testMFAService(pool, clk)
	authSvc := authServiceFor(pool, clk)
	clients := oidc.NewService(db.TxRunner{Pool: pool}, store, outbox.NewStore(pool), storage,
		clock.System{}, db.Direct{Pool: pool})

	f := &oidcMFAFixture{
		pool: pool, clock: clk, second: second, jar: &cookieJar{},
		handler: New(nil,
			WithAuth(authSvc),
			WithMFA(second),
			WithOIDC(provider),
			WithOIDCClients(clients),
			WithLogger(slogLogger(&recordingHandler{})),
		),
	}

	email := dbtest.UniqueEmail(t)
	rec := f.send(t, http.MethodPost, "/v1/users",
		`{"email":"`+email+`","password":"`+oidcTestPassword+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering a user: %d; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	mustJSON(t, rec.Body.Bytes(), &created)
	parsed, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("parsing the registered id: %v", err)
	}
	f.userID, f.email = parsed, email

	mine, err := realTenancy(pool, clk).ListMine(t.Context(), f.userID)
	if err != nil || len(mine) != 1 {
		t.Fatalf("listing the personal account: %v (%d accounts)", err, len(mine))
	}

	if withMFA {
		started, err := second.StartEnrollment(t.Context(), mfa.StartEnrollmentInput{UserID: f.userID})
		if err != nil {
			t.Fatalf("StartEnrollment: %v", err)
		}
		f.secret = started.Secret
		confirmed, err := second.Confirm(t.Context(), mfa.ConfirmInput{
			UserID:       f.userID,
			EnrollmentID: started.Credential.ID,
			Factor:       mustTOTPCode(t, started.Secret, clk.Now()),
		})
		if err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		f.recovery = confirmed.RecoveryCodes[0]
	}

	registered, err := clients.Register(t.Context(), oidc.RegisterInput{
		AccountID:    mine[0].Account.ID,
		Name:         "Anytalk",
		RedirectURIs: []string{oidcTestRedirect},
		GrantTypes:   []string{oidc.GrantAuthorizationCode},
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeEmail},
		RegisteredBy: f.userID,
	})
	if err != nil {
		t.Fatalf("registering a relying party: %v", err)
	}

	f.requestID = seedAuthRequest(t, pool, store, registered.Client)
	return f
}

func (f *oidcMFAFixture) send(t *testing.T, method, target, body string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()

	var reader = strings.NewReader("")
	contentType := ""
	switch {
	case form != nil:
		reader = strings.NewReader(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	case body != "":
		reader = strings.NewReader(body)
		contentType = "application/json"
	}

	req := httptest.NewRequestWithContext(context.Background(), method, target, reader)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", oidcTestUserAgent)
	if cookie := f.jar.header(); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	f.jar.absorb(rec.Result().Cookies())
	return rec
}

func (f *oidcMFAFixture) loginPage(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	delete(f.jar.cookies, SessionCookieName)
	return f.send(t, http.MethodGet, oidc.PathLogin+"/"+f.requestID, "", nil)
}

func (f *oidcMFAFixture) submit(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return f.send(t, http.MethodPost, oidc.PathLogin+"/"+f.requestID, "", form)
}

func (f *oidcMFAFixture) signIn(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()

	page := f.loginPage(t)
	form := url.Values{
		"state":    {stateFromRedirect(t, page)},
		"email":    {f.email},
		"password": {oidcTestPassword},
	}
	return f.submit(t, form)
}

func (f *oidcMFAFixture) presentCode(t *testing.T, fromChallengeStep *httptest.ResponseRecorder, code string) *httptest.ResponseRecorder {
	t.Helper()
	return f.submit(t, url.Values{"state": {stateFromRedirect(t, fromChallengeStep)}, "code": {code}})
}

func (f *oidcMFAFixture) advance(d time.Duration) { f.clock.Advance(d) }

func stateFromRedirect(t *testing.T, rec *httptest.ResponseRecorder) string {
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

func redirectQuery(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()

	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatalf("the response carried no Location; it was %d with body:\n%s", rec.Code, rec.Body)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("the redirect %q is not a URL: %v", location, err)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != oidcTestLoginUI {
		t.Fatalf("the browser was sent to %q, want the configured login UI %q", got, oidcTestLoginUI)
	}
	return parsed.Query()
}

func seedAuthRequest(t *testing.T, pool *pgxpool.Pool, store *oidc.Store, client oidc.Client) string {
	t.Helper()

	now := time.Now().UTC()
	created, err := store.CreateAuthRequest(t.Context(), pool, oidc.NewAuthRequest{
		ClientRowID:         client.ID,
		RedirectURI:         client.RedirectURIs[0],
		State:               "state-value-for-the-login-page-test",
		Nonce:               "nonce-value-for-the-login-page-test",
		ResponseType:        "code",
		ResponseMode:        "query",
		Scopes:              client.Scopes,
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		LoginHint:           "",
		CreatedAt:           now,
		ExpiresAt:           now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("seeding an authorization request: %v", err)
	}
	return created.ID.String()
}


func TestTheOIDCLoginInteractionChallengesAnMFAUser(t *testing.T) {
	f := newOIDCMFAFixture(t, true)

	rec := f.signIn(t)

	if rec.Code != http.StatusFound {
		t.Fatalf("the password step = %d, want 302 to the login UI; body:\n%s", rec.Code, rec.Body)
	}
	query := redirectQuery(t, rec)
	if got := query.Get(oidc.LoginParamStep); got != oidc.LoginStepChallenge {
		t.Errorf("%s = %q, want %q; a login UI rendering the password box again is a "+
			"sign-in that can never be finished", oidc.LoginParamStep, got, oidc.LoginStepChallenge)
	}
	if got := query.Get(oidc.LoginParamError); got != "" {
		t.Errorf("the password step reported %s = %q; a correct password is not a failure",
			oidc.LoginParamError, got)
	}
	if cookie := cookieNamed(rec, SessionCookieName); cookie != nil && cookie.Value != "" {
		t.Error("the password step set a session cookie for an account with a second factor")
	}
	if strings.Contains(rec.Header().Get("Location"), oidcTestRedirect) {
		t.Errorf("the password step redirected to the product (%q), which means an "+
			"authorization code was minted for an account with a second factor",
			rec.Header().Get("Location"))
	}
	challenge := cookieNamed(rec, OIDCChallengeCookiePrefix+f.requestID)
	if challenge == nil || challenge.Value == "" {
		t.Errorf("the password step kept no challenge cookie; cookies: %v", cookieNames(rec.Result().Cookies()))
	} else if challenge.SameSite != http.SameSiteNoneMode {
		t.Errorf("the challenge cookie is SameSite=%v; the code form is a cross-site POST "+
			"and a Lax cookie is not sent on one", challenge.SameSite)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestTheOIDCLoginInteractionSignsInAnAccountWithNoSecondFactor(t *testing.T) {
	f := newOIDCMFAFixture(t, false)

	rec := f.signIn(t)
	if rec.Code < 300 || rec.Code >= 400 {
		t.Fatalf("the password step = %d, want a redirect to the product; body:\n%s", rec.Code, rec.Body)
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, oidcTestRedirect) {
		t.Errorf("Location = %q, want the product's redirect_uri", location)
	}
	if !strings.Contains(location, "code=") {
		t.Errorf("Location = %q carries no authorization code", location)
	}
	if cookie := cookieNamed(rec, SessionCookieName); cookie == nil || cookie.Value == "" {
		t.Error("the password step set no session cookie for a user with no second factor")
	}
}


func TestTheOIDCChallengeStepFinishesTheFlow(t *testing.T) {
	f := newOIDCMFAFixture(t, true)

	challengeForm := f.signIn(t)
	f.advance(mfa.Period + time.Second)
	rec := f.presentCode(t, challengeForm, mustTOTPCode(t, f.secret, f.clock.Now()))

	if rec.Code < 300 || rec.Code >= 400 {
		t.Fatalf("the challenge step = %d, want a redirect to the product; body:\n%s", rec.Code, rec.Body)
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, oidcTestRedirect) || !strings.Contains(location, "code=") {
		t.Errorf("Location = %q, want the product's redirect_uri carrying a code", location)
	}
	if cookie := cookieNamed(rec, SessionCookieName); cookie == nil || cookie.Value == "" {
		t.Error("the challenge step set no session cookie")
	}
	if cookie := cookieNamed(rec, "__Host-oidc-mfa-"+f.requestID); cookie == nil || cookie.Value != "" {
		t.Error("the challenge cookie was not cleared")
	}
}

func TestTheOIDCChallengeStepAcceptsARecoveryCode(t *testing.T) {
	f := newOIDCMFAFixture(t, true)

	challengeForm := f.signIn(t)
	rec := f.presentCode(t, challengeForm, f.recovery)

	if rec.Code < 300 || rec.Code >= 400 {
		t.Fatalf("a recovery code = %d, want a redirect to the product; body:\n%s", rec.Code, rec.Body)
	}
	if cookie := cookieNamed(rec, SessionCookieName); cookie == nil || cookie.Value == "" {
		t.Error("a recovery code did not produce a session")
	}
}

func TestTheOIDCChallengeStepRefusesAWrongCode(t *testing.T) {
	f := newOIDCMFAFixture(t, true)
	challengeStep := f.signIn(t)

	rec := f.presentCode(t, challengeStep, "000000")

	if rec.Code != http.StatusFound {
		t.Fatalf("a wrong code = %d, want 302 back to the login UI; body:\n%s", rec.Code, rec.Body)
	}
	query := redirectQuery(t, rec)
	if got := query.Get(oidc.LoginParamStep); got != oidc.LoginStepChallenge {
		t.Errorf("%s = %q, want %q: a refused code has to send the user back to the code "+
			"box, not the password box", oidc.LoginParamStep, got, oidc.LoginStepChallenge)
	}
	if got := query.Get(oidc.LoginParamError); got != oidc.LoginErrorChallengeRejected {
		t.Errorf("%s = %q, want %q", oidc.LoginParamError, got, oidc.LoginErrorChallengeRejected)
	}
	if query.Get(oidc.LoginParamErrorDetail) == "" {
		t.Error("the refusal carried no sentence; the user is told a code failed and not why")
	}
	if cookie := cookieNamed(rec, SessionCookieName); cookie != nil && cookie.Value != "" {
		t.Error("a wrong code set a session cookie")
	}
	second := f.presentCode(t, rec, "000000")
	if second.Code != http.StatusFound {
		t.Fatalf("a second wrong code = %d, want 302 back to the login UI; body:\n%s",
			second.Code, second.Body)
	}
	again := redirectQuery(t, second)
	if got := again.Get(oidc.LoginParamError); got != oidc.LoginErrorChallengeRejected {
		t.Errorf("the second wrong code answered %s = %q, want %q; the first one spent the "+
			"challenge, which resets the per-factor lockout on every attempt",
			oidc.LoginParamError, got, oidc.LoginErrorChallengeRejected)
	}
	if got := again.Get(oidc.LoginParamStep); got != oidc.LoginStepChallenge {
		t.Errorf("the second wrong code landed on %s = %q, want %q", oidc.LoginParamStep,
			got, oidc.LoginStepChallenge)
	}
	if strings.Contains(rec.Header().Get("Location"), oidcTestRedirect) {
		t.Errorf("a wrong code redirected to the product, which means an authorization code "+
			"was minted: %s", rec.Header().Get("Location"))
	}
}

func TestTheOIDCChallengeStepRefusesAReplay(t *testing.T) {
	f := newOIDCMFAFixture(t, true)

	challengeStep := f.signIn(t)
	f.advance(mfa.Period + time.Second)
	captured := mustTOTPCode(t, f.secret, f.clock.Now())

	if rec := f.presentCode(t, challengeStep, captured); rec.Code < 300 || rec.Code >= 400 {
		t.Fatalf("the first use = %d, want a redirect; body:\n%s", rec.Code, rec.Body)
	}

	second := f.signIn(t)
	rec := f.presentCode(t, second, captured)
	if rec.Code != http.StatusFound {
		t.Errorf("a replayed code = %d, want 302 back to the login UI; body:\n%s", rec.Code, rec.Body)
	}
	query := redirectQuery(t, rec)
	if got := query.Get(oidc.LoginParamError); got != oidc.LoginErrorChallengeRejected {
		t.Errorf("%s = %q, want %q", oidc.LoginParamError, got, oidc.LoginErrorChallengeRejected)
	}
	if strings.Contains(rec.Header().Get("Location"), oidcTestRedirect) {
		t.Error("a replayed code redirected to the product, which means an authorization " +
			"code was minted")
	}
}

func TestTheOIDCChallengeStepWithoutAChallengeGoesBackToThePasswordStep(t *testing.T) {
	f := newOIDCMFAFixture(t, true)
	page := f.loginPage(t)
	delete(f.jar.cookies, OIDCChallengeCookiePrefix+f.requestID)

	rec := f.submit(t, url.Values{"state": {stateFromRedirect(t, page)}, "code": {"123456"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("a code with no challenge = %d, want 302 back to the login UI; body:\n%s", rec.Code, rec.Body)
	}
	query := redirectQuery(t, rec)
	if got := query.Get(oidc.LoginParamError); got != oidc.LoginErrorInteractionExpired {
		t.Errorf("%s = %q, want %q", oidc.LoginParamError, got, oidc.LoginErrorInteractionExpired)
	}
	if got := query.Get(oidc.LoginParamStep); got != oidc.LoginStepPassword {
		t.Errorf("%s = %q, want %q", oidc.LoginParamStep, got, oidc.LoginStepPassword)
	}
}

func TestTheOIDCChallengeStepLockoutCarriesItsWaitToTheLoginUI(t *testing.T) {
	f := newOIDCMFAFixture(t, true)

	for range 5 {
		step := f.signIn(t)
		if rec := f.presentCode(t, step, "000000"); rec.Code != http.StatusFound {
			t.Fatalf("a wrong code = %d, want 302 back to the login UI", rec.Code)
		}
	}

	step := f.signIn(t)
	rec := f.presentCode(t, step, "000000")
	if rec.Code != http.StatusFound {
		t.Fatalf("the attempt past the threshold = %d, want 302 back to the login UI; body:\n%s",
			rec.Code, rec.Body)
	}
	query := redirectQuery(t, rec)
	if got := query.Get(oidc.LoginParamError); got != oidc.LoginErrorAccountLocked {
		t.Errorf("%s = %q, want %q", oidc.LoginParamError, got, oidc.LoginErrorAccountLocked)
	}
	if got := query.Get(oidc.LoginParamStep); got != oidc.LoginStepChallenge {
		t.Errorf("%s = %q, want %q; the lockout is on the second factor, so the user is "+
			"still on the code step", oidc.LoginParamStep, got, oidc.LoginStepChallenge)
	}
	if query.Get(oidc.LoginParamErrorDetail) == "" {
		t.Error("the lockout carried no sentence")
	}
	wait := query.Get(oidc.LoginParamRetryAfter)
	if wait == "" {
		t.Errorf("the lockout carried no %s; the user is not told how long to wait",
			oidc.LoginParamRetryAfter)
	} else if seconds, err := strconv.Atoi(wait); err != nil || seconds <= 0 {
		t.Errorf("%s = %q, want a positive whole number of seconds", oidc.LoginParamRetryAfter, wait)
	}
	if cookie := cookieNamed(rec, SessionCookieName); cookie != nil && cookie.Value != "" {
		t.Error("a locked second factor produced a session")
	}
}

func TestTheChallengeStepIsReachableOnlyThroughTheOIDCPath(t *testing.T) {
	f := newOIDCMFAFixture(t, true)
	_ = f.signIn(t)

	rec := f.send(t, http.MethodPost, "/oidc/session/mfa", "", url.Values{"code": {"123456"}})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/oidc/session/mfa = %d, want 404; body: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", got)
	}
}

var (
	_ = dbtest.Pool
	_ = outbox.NewStore
)
