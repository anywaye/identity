package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/useraudit"
	"github.com/anywaye/identity/internal/users"
)


func newTestServer(t *testing.T) (http.Handler, *pgxpool.Pool, *clock.Fake) {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	return New(nil, WithAuth(authServiceFor(pool, clk)), WithTenancy(realTenancy(pool, clk))), pool, clk
}

func authServiceFor(pool *pgxpool.Pool, clk clock.Clock) *auth.Service {
	return authServiceWithSessionTTL(pool, clk, 24*time.Hour)
}

func authServiceWithSessionTTL(pool *pgxpool.Pool, clk clock.Clock, sessionTTL time.Duration) *auth.Service {
	return auth.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		outbox.NewStore(pool),
		realTenancy(pool, clk),
		testMFAService(pool, clk),
		oidc.NewStore(pool),
		useraudit.NewStore(pool),
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		clk,
		sessionTTL,
		false,
	)
}

const validPassword = "correct horse battery staple"

func registerThrough(t *testing.T, h http.Handler, email string) userResponse {
	t.Helper()

	rec := post(t, h, "/v1/users", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/users = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	var out userResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("the registration body is not JSON: %v\n%s", err, rec.Body)
	}
	return out
}

func TestEndToEndRegisterLoginMeLogout(t *testing.T) {
	h, pool, _ := newTestServer(t)
	email := dbtest.UniqueEmail(t)

	registered := registerThrough(t, h, email)
	if registered.Email != email {
		t.Errorf("registered email = %q, want %q", registered.Email, email)
	}

	assertUserCreatedEvent(t, pool, registered.ID, email, false)

	loginRec := post(t, h, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", loginRec.Code, loginRec.Body)
	}

	var login sessionResponse
	if err := json.Unmarshal(loginRec.Body.Bytes(), &login); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}
	if login.Token == "" {
		t.Fatal("the login returned no token")
	}
	if want := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC); !login.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %s, want %s — 24h after the injected clock", login.ExpiresAt, want)
	}

	cookies := loginRec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != SessionCookieName || c.Value != login.Token {
		t.Errorf("cookie = %s=%s, want %s carrying the token", c.Name, c.Value, SessionCookieName)
	}
	if !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("the session cookie is not hardened: %+v", c)
	}

	meRec := httptest.NewRecorder()
	meReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	meReq.AddCookie(c)
	h.ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusOK {
		t.Fatalf("GET /v1/me = %d, want 200; body: %s", meRec.Code, meRec.Body)
	}
	var me userResponse
	if err := json.Unmarshal(meRec.Body.Bytes(), &me); err != nil {
		t.Fatalf("the /v1/me body is not JSON: %v", err)
	}
	if me.ID != registered.ID || me.Email != email {
		t.Errorf("GET /v1/me = %+v, want the registered user %s/%s", me, registered.ID, email)
	}

	bearerRec := httptest.NewRecorder()
	bearerReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	bearerReq.Header.Set("Authorization", "Bearer "+login.Token)
	h.ServeHTTP(bearerRec, bearerReq)

	if bearerRec.Code != http.StatusOK {
		t.Errorf("GET /v1/me with a bearer token = %d, want 200; body: %s", bearerRec.Code, bearerRec.Body)
	}

	logoutRec := httptest.NewRecorder()
	logoutReq := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/v1/session", nil)
	logoutReq.AddCookie(c)
	h.ServeHTTP(logoutRec, logoutReq)

	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /v1/session = %d, want 204; body: %s", logoutRec.Code, logoutRec.Body)
	}

	for _, surface := range []string{"cookie", "bearer"} {
		t.Run("the revoked token no longer works via "+surface, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
			if surface == "cookie" {
				req.AddCookie(c)
			} else {
				req.Header.Set("Authorization", "Bearer "+login.Token)
			}
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("GET /v1/me after logout = %d, want 401; body: %s", rec.Code, rec.Body)
			}
		})
	}

	var sessions int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM sessions`).Scan(&sessions); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}
	if sessions != 0 {
		t.Errorf("sessions has %d rows after logout, want 0", sessions)
	}
}

func TestEndToEndDuplicateRegistrationIs409AndWritesNoEvent(t *testing.T) {
	h, pool, _ := newTestServer(t)
	email := dbtest.UniqueEmail(t)

	first := registerThrough(t, h, email)
	before := countEvents(t, pool)

	rec := post(t, h, "/v1/users", `{"email":"`+email+`","password":"another good passphrase"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("the second registration = %d, want 409; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeConflict {
		t.Errorf("code = %q, want %q", p.Code, CodeConflict)
	}

	if after := countEvents(t, pool); after != before {
		t.Errorf("outbox_events went from %d to %d; a rejected registration wrote an event", before, after)
	}
	var users int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM users`).Scan(&users); err != nil {
		t.Fatalf("counting users: %v", err)
	}
	if users != 1 {
		t.Errorf("users has %d rows, want 1", users)
	}
	_ = first
}

func TestEndToEndRegisterValidation(t *testing.T) {
	h, _, _ := newTestServer(t)

	tests := []struct {
		name      string
		body      string
		wantField string
		wantCode  string
	}{
		{name: "a short password", body: `{"email":"a@example.com","password":"short"}`, wantField: "password", wantCode: "too_short"},
		{name: "a missing password", body: `{"email":"a@example.com"}`, wantField: "password", wantCode: "required"},
		{name: "a malformed address", body: `{"email":"not an address","password":"` + validPassword + `"}`, wantField: "email", wantCode: "invalid_format"},
		{name: "a missing address", body: `{"password":"` + validPassword + `"}`, wantField: "email", wantCode: "required"},
		{name: "nothing at all", body: `{}`, wantField: "email", wantCode: "required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := post(t, h, "/v1/users", tt.body)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeValidationFailed {
				t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
			}

			found := false
			for _, fe := range p.Errors {
				if fe.Field == tt.wantField && fe.Code == tt.wantCode {
					found = true
				}
			}
			if !found {
				t.Errorf("errors = %+v, want an entry for %s/%s", p.Errors, tt.wantField, tt.wantCode)
			}
			if strings.Contains(rec.Body.String(), validPassword) {
				t.Errorf("the 422 echoes the submitted password: %s", rec.Body)
			}
		})
	}
}

func TestEndToEndLockoutMatrix(t *testing.T) {
	h, pool, clk := newTestServer(t)
	email := dbtest.UniqueEmail(t)
	registerThrough(t, h, email)

	for attempt := 1; attempt < sessions.MaxFailedAttempts; attempt++ {
		rec := post(t, h, "/v1/session", `{"email":"`+email+`","password":"wrong"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401; body: %s", attempt, rec.Code, rec.Body)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("attempt %d set a cookie", attempt)
		}
	}

	fifth := post(t, h, "/v1/session", `{"email":"`+email+`","password":"wrong"}`)
	if fifth.Code != http.StatusUnauthorized {
		t.Fatalf("the fifth attempt = %d, want 401", fifth.Code)
	}

	locked := post(t, h, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if locked.Code != http.StatusLocked {
		t.Fatalf("the sixth attempt = %d, want 423; body: %s", locked.Code, locked.Body)
	}
	p := decodeProblem(t, locked)
	if p.Code != CodeAccountLocked {
		t.Errorf("code = %q, want %q", p.Code, CodeAccountLocked)
	}
	if want := "900"; locked.Header().Get(RetryAfterHeader) != want {
		t.Errorf("%s = %q, want %q seconds", RetryAfterHeader, locked.Header().Get(RetryAfterHeader), want)
	}
	if p.Errors != nil {
		t.Errorf("errors = %v on a 423; core scopes errors[] to 422", p.Errors)
	}
	if len(locked.Result().Cookies()) != 0 {
		t.Error("a locked login set a cookie")
	}

	var lockedUntil time.Time
	if err := pool.QueryRow(t.Context(), `SELECT locked_until FROM users WHERE email = $1`, email).Scan(&lockedUntil); err != nil {
		t.Fatalf("reading the lock: %v", err)
	}
	if want := clk.Now().Add(sessions.LockoutDuration); !lockedUntil.Equal(want) {
		t.Errorf("locked_until = %s, want %s", lockedUntil, want)
	}

	clk.Advance(sessions.LockoutDuration - time.Second)
	stillLocked := post(t, h, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if stillLocked.Code != http.StatusLocked {
		t.Fatalf("one second before expiry = %d, want 423", stillLocked.Code)
	}
	if want := "1"; stillLocked.Header().Get(RetryAfterHeader) != want {
		t.Errorf("%s = %q, want %q", RetryAfterHeader, stillLocked.Header().Get(RetryAfterHeader), want)
	}

	clk.Advance(time.Second)
	unlocked := post(t, h, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if unlocked.Code != http.StatusOK {
		t.Fatalf("after the window closed = %d, want 200; body: %s", unlocked.Code, unlocked.Body)
	}

	var failures int
	if err := pool.QueryRow(t.Context(), `SELECT failed_login_attempts FROM users WHERE email = $1`, email).Scan(&failures); err != nil {
		t.Fatalf("reading the counter: %v", err)
	}
	if failures != 0 {
		t.Errorf("failed_login_attempts = %d after a successful login, want 0", failures)
	}
}

func TestEndToEndLoginDoesNotEnumerate(t *testing.T) {
	h, _, _ := newTestServer(t)
	email := dbtest.UniqueEmail(t)
	registerThrough(t, h, email)

	wrongPassword := post(t, h, "/v1/session", `{"email":"`+email+`","password":"not the right password"}`)
	unknownAddress := post(t, h, "/v1/session", `{"email":"`+dbtest.UniqueEmail(t)+`","password":"not the right password"}`)

	if wrongPassword.Code != http.StatusUnauthorized || unknownAddress.Code != http.StatusUnauthorized {
		t.Fatalf("statuses = %d and %d, want both 401", wrongPassword.Code, unknownAddress.Code)
	}

	stripTrace := func(rec *httptest.ResponseRecorder) string {
		var p Problem
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatalf("the body is not JSON: %v", err)
		}
		p.TraceID = ""
		out, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("re-marshaling: %v", err)
		}
		return string(out)
	}

	if a, b := stripTrace(wrongPassword), stripTrace(unknownAddress); a != b {
		t.Errorf("the two refusals differ:\n  wrong password: %s\n  unknown address: %s", a, b)
	}
	if ct1, ct2 := wrongPassword.Header().Get("Content-Type"), unknownAddress.Header().Get("Content-Type"); ct1 != ct2 {
		t.Errorf("content types differ: %q vs %q", ct1, ct2)
	}
}

func TestEndToEndNoResponseCarriesTheDigest(t *testing.T) {
	h, pool, _ := newTestServer(t)
	email := dbtest.UniqueEmail(t)
	registered := registerThrough(t, h, email)

	var digest string
	if err := pool.QueryRow(t.Context(), `SELECT password_digest FROM users WHERE email = $1`, email).Scan(&digest); err != nil {
		t.Fatalf("reading the digest: %v", err)
	}
	if digest == "" {
		t.Fatal("the digest is empty, so this test would prove nothing")
	}

	loginRec := post(t, h, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	var login sessionResponse
	if err := json.Unmarshal(loginRec.Body.Bytes(), &login); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}

	meReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+login.Token)
	meRec := httptest.NewRecorder()
	h.ServeHTTP(meRec, meReq)

	bodies := map[string]string{
		"register":     registerThrough(t, h, dbtest.UniqueEmail(t)).Email,
		"login":        loginRec.Body.String(),
		"me":           meRec.Body.String(),
		"login cookie": cookieValue(t, loginRec),
	}

	for name, body := range bodies {
		for _, secret := range []string{digest, "$argon2id$", "password_digest", "argon2id"} {
			if strings.Contains(body, secret) {
				t.Errorf("the %s response carries %q: %s", name, secret, body)
			}
		}
	}
	_ = registered
}

func TestEndToEndOutboxRowIsClaimableAndUnpublished(t *testing.T) {
	h, pool, _ := newTestServer(t)
	email := dbtest.UniqueEmail(t)
	registered := registerThrough(t, h, email)

	assertUserCreatedEvent(t, pool, registered.ID, email, false)

	store := outbox.NewStore(pool)
	batch, err := store.Claim(t.Context(), 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	defer batch.Release(t.Context())

	claimed := batch.Events()
	if len(claimed) == 0 {
		t.Fatal("the event was written but nothing can claim it")
	}

	found := false
	for _, e := range claimed {
		if e.Subject != registered.ID {
			continue
		}
		found = true
		if err := e.Validate(); err != nil {
			t.Errorf("the claimed event fails core's schema: %v", err)
		}
		if e.Type != outbox.EventUserCreated {
			t.Errorf("type = %q, want %q", e.Type, outbox.EventUserCreated)
		}
		if e.Source != outbox.SourceIdentity {
			t.Errorf("source = %q, want %q", e.Source, outbox.SourceIdentity)
		}
	}
	if !found {
		t.Error("the event for this registration was not among the claimed batch")
	}
}

func TestEndToEndDeletedUserCannotAuthenticate(t *testing.T) {
	h, pool, _ := newTestServer(t)
	email := dbtest.UniqueEmail(t)
	registered := registerThrough(t, h, email)

	loginRec := post(t, h, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	var login sessionResponse
	if err := json.Unmarshal(loginRec.Body.Bytes(), &login); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}

	if _, err := pool.Exec(t.Context(), `DELETE FROM users WHERE id = $1`, registered.ID); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+login.Token)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /v1/me after the user was deleted = %d, want 401; body: %s", rec.Code, rec.Body)
	}
}

func TestEndToEndExpiredSessionIs401(t *testing.T) {
	h, _, clk := newTestServer(t)
	email := dbtest.UniqueEmail(t)
	registerThrough(t, h, email)

	loginRec := post(t, h, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	var login sessionResponse
	if err := json.Unmarshal(loginRec.Body.Bytes(), &login); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}

	clk.Advance(24*time.Hour - time.Nanosecond)
	if rec := meWithToken(t, h, login.Token); rec.Code != http.StatusOK {
		t.Fatalf("just before expiry = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	clk.Advance(time.Nanosecond)
	if rec := meWithToken(t, h, login.Token); rec.Code != http.StatusUnauthorized {
		t.Errorf("at expiry = %d, want 401; body: %s", rec.Code, rec.Body)
	}
}

func TestEndToEndWriteFailureIs500AndLeaksNothing(t *testing.T) {
	logs := &recordingHandler{}
	pool, owner := dbtest.SchemaWithOwner(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	svc := auth.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		outbox.NewStore(pool),
		realTenancy(pool, clk),
		testMFAService(pool, clk),
		oidc.NewStore(pool),
		useraudit.NewStore(pool),
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		clk,
		24*time.Hour,
		false,
	)
	h := New(nil, WithAuth(svc), WithTenancy(realTenancy(pool, clk)), WithLogger(slogLogger(logs)))

	if _, err := owner.Exec(t.Context(), `DROP TABLE outbox_events`); err != nil {
		t.Fatalf("dropping outbox_events: %v", err)
	}

	rec := post(t, h, "/v1/users", `{"email":"`+dbtest.UniqueEmail(t)+`","password":"`+validPassword+`"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeInternal {
		t.Errorf("code = %q, want %q", p.Code, CodeInternal)
	}
	if p.TraceID == "" {
		t.Error("trace_id is empty")
	}
	for _, secret := range []string{"outbox_events", "pgconn", "SQLSTATE", "relation"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("the body leaks %q: %s", secret, rec.Body)
		}
	}
	if logs.find("request failed") == "" {
		t.Error("nothing was logged")
	}

	var users int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM users`).Scan(&users); err != nil {
		t.Fatalf("counting users: %v", err)
	}
	if users != 0 {
		t.Errorf("users has %d rows after a failed registration, want 0", users)
	}
}


func TestEndToEndThemeSetGetSwitchAndClear(t *testing.T) {
	h, _, _ := newTestServer(t)
	email := dbtest.UniqueEmail(t)
	registerThrough(t, h, email)
	token := loginToken(t, h, email)

	if theme := themeOf(t, meWithToken(t, h, token)); theme != nil {
		t.Errorf("a new user's theme = %q, want the key absent (the system theme)", *theme)
	}

	rec := patchMeWithToken(t, h, token, `{"theme":"dark"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH theme=dark = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if theme := themeOf(t, rec); theme == nil || *theme != "dark" {
		t.Errorf("the PATCH response theme = %v, want dark", theme)
	}
	if theme := themeOf(t, meWithToken(t, h, token)); theme == nil || *theme != "dark" {
		t.Errorf("GET after the write = %v, want dark", theme)
	}

	rec = patchMeWithToken(t, h, token, `{"theme":"light"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH theme=light = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if theme := themeOf(t, meWithToken(t, h, token)); theme == nil || *theme != "light" {
		t.Errorf("GET after switching = %v, want light", theme)
	}

	rec = patchMeWithToken(t, h, token, `{"display_name":"Kaka"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH without a theme = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if theme := themeOf(t, rec); theme != nil {
		t.Errorf("the PATCH response theme = %v, want the key absent after the omission cleared it", *theme)
	}
	if theme := themeOf(t, meWithToken(t, h, token)); theme != nil {
		t.Errorf("GET after the omission = %v, want the key absent", *theme)
	}
}

func TestEndToEndThemeIsPerUser(t *testing.T) {
	h, _, _ := newTestServer(t)

	firstEmail := dbtest.UniqueEmail(t)
	secondEmail := dbtest.UniqueEmail(t)
	registerThrough(t, h, firstEmail)
	registerThrough(t, h, secondEmail)
	first := loginToken(t, h, firstEmail)
	second := loginToken(t, h, secondEmail)

	if theme := themeOf(t, meWithToken(t, h, first)); theme != nil {
		t.Errorf("the first user's theme = %q, want absent", *theme)
	}
	if theme := themeOf(t, meWithToken(t, h, second)); theme != nil {
		t.Errorf("the second user's theme = %q, want absent", *theme)
	}

	if rec := patchMeWithToken(t, h, first, `{"theme":"dark"}`); rec.Code != http.StatusOK {
		t.Fatalf("the first user's PATCH = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if theme := themeOf(t, meWithToken(t, h, first)); theme == nil || *theme != "dark" {
		t.Errorf("the first user's GET = %v, want dark", theme)
	}
	if theme := themeOf(t, meWithToken(t, h, second)); theme != nil {
		t.Errorf("the second user's GET = %v, want absent — the first user's theme crossed into it", *theme)
	}

	if rec := patchMeWithToken(t, h, second, `{"theme":"light"}`); rec.Code != http.StatusOK {
		t.Fatalf("the second user's PATCH = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if theme := themeOf(t, meWithToken(t, h, first)); theme == nil || *theme != "dark" {
		t.Errorf("the first user's GET = %v, want dark, untouched by the second user's write", theme)
	}
	if theme := themeOf(t, meWithToken(t, h, second)); theme == nil || *theme != "light" {
		t.Errorf("the second user's GET = %v, want light", theme)
	}
}

func TestEndToEndInvalidThemeLeavesTheStoredPreferenceUnchanged(t *testing.T) {
	h, _, _ := newTestServer(t)
	email := dbtest.UniqueEmail(t)
	registerThrough(t, h, email)
	token := loginToken(t, h, email)

	if rec := patchMeWithToken(t, h, token, `{"theme":"dark"}`); rec.Code != http.StatusOK {
		t.Fatalf("PATCH theme=dark = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	for _, give := range []string{"blue", ""} {
		rec := patchMeWithToken(t, h, token, `{"theme":"`+give+`"}`)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("PATCH theme=%q = %d, want 422; body: %s", give, rec.Code, rec.Body)
		}
		p := decodeProblem(t, rec)
		if p.Code != CodeValidationFailed {
			t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
		}
		if len(p.Errors) != 1 || p.Errors[0].Field != "theme" || p.Errors[0].Code != users.CodeInvalidFormat {
			t.Errorf("errors = %v, want one entry naming theme/%s", p.Errors, users.CodeInvalidFormat)
		}
		if theme := themeOf(t, meWithToken(t, h, token)); theme == nil || *theme != "dark" {
			t.Errorf("GET after the refused write = %v, want dark — the stored preference changed", theme)
		}
	}

	rec := patchMeWithToken(t, h, token, `{"theme":42}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PATCH theme=42 = %d, want 400; body: %s", rec.Code, rec.Body)
	}
	if p := decodeProblem(t, rec); p.Code != CodeInvalidJSON {
		t.Errorf("code = %q, want %q", p.Code, CodeInvalidJSON)
	}
	if theme := themeOf(t, meWithToken(t, h, token)); theme == nil || *theme != "dark" {
		t.Errorf("GET after the refused write = %v, want dark", theme)
	}
}


func assertUserCreatedEvent(t *testing.T, pool *pgxpool.Pool, userID, email string, published bool) {
	t.Helper()

	var (
		eventType   string
		subject     string
		payload     []byte
		publishedAt *time.Time
	)
	err := pool.QueryRow(t.Context(), `
		SELECT type, subject, payload, published_at
		FROM outbox_events WHERE subject = $1`, userID).
		Scan(&eventType, &subject, &payload, &publishedAt)
	if err != nil {
		t.Fatalf("reading the outbox row for %s: %v", userID, err)
	}

	if eventType != outbox.EventUserCreated {
		t.Errorf("type = %q, want %q", eventType, outbox.EventUserCreated)
	}
	if subject != userID {
		t.Errorf("subject = %q, want the user id %q", subject, userID)
	}
	if !strings.Contains(string(payload), email) {
		t.Errorf("payload = %s, want it to carry the email", payload)
	}
	if published && publishedAt == nil {
		t.Error("published_at is NULL, want a timestamp")
	}
	if !published && publishedAt != nil {
		t.Errorf("published_at = %v, want NULL; nothing publishes in this packet", *publishedAt)
	}
}

func countEvents(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()

	var n int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM outbox_events`).Scan(&n); err != nil {
		t.Fatalf("counting outbox_events: %v", err)
	}
	return n
}

func meWithToken(t *testing.T, h http.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(rec, req)
	return rec
}

func patchMeWithToken(t *testing.T, h http.Handler, token, body string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/v1/me", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(rec, req)
	return rec
}

func loginToken(t *testing.T, h http.Handler, email string) string {
	t.Helper()

	rec := post(t, h, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	var login sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &login); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}
	if login.Token == "" {
		t.Fatal("the login returned no token")
	}
	return login.Token
}

func themeOf(t *testing.T, rec *httptest.ResponseRecorder) *string {
	t.Helper()

	var me userResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatalf("the /v1/me body is not JSON: %v\n%s", err, rec.Body)
	}
	return me.Theme
}

func cookieValue(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		return ""
	}
	return cookies[0].Value
}

func realTenancy(pool *pgxpool.Pool, clk clock.Clock) *accounts.Service {
	return accounts.NewService(
		db.TxRunner{Pool: pool},
		accounts.NewStore(pool),
		users.NewStore(pool),
		outbox.NewStore(pool),
		apikeys.NewStore(pool),
		clk,
		db.Direct{Pool: pool},
		nil,
	)
}
