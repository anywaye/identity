package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/config"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/signup"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}


func testDatabaseURL(t *testing.T) string {
	t.Helper()

	dsn := os.Getenv(dbtest.EnvVar)
	if dsn == "" {
		t.Skipf("%s is not set; skipping the wiring test", dbtest.EnvVar)
	}
	return dsn
}

func TestNewAppServesTheAuthSurfaceWithADatabase(t *testing.T) {
	dsn := testDatabaseURL(t)
	ctx := context.Background()

	cfg := withSignupKey(config.Config{Port: "0", LogLevel: "error", DatabaseURL: dsn})
	a, err := newApp(ctx, cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	email := dbtest.UniqueEmail(t)
	const password = "correct horse battery staple"

	pairRec := serveBody(t, a, http.MethodPost, "/v1/signup-timestamp", "", nil)
	if pairRec.Code != http.StatusOK {
		t.Fatalf("POST /v1/signup-timestamp = %d, want 200; body: %s", pairRec.Code, pairRec.Body)
	}
	var pair struct {
		Timestamp int64  `json:"timestamp"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(pairRec.Body.Bytes(), &pair); err != nil {
		t.Fatalf("the minted pair is not JSON: %v\n%s", err, pairRec.Body)
	}

	time.Sleep(signup.MinAge + 500*time.Millisecond)

	rec := serveBody(t, a, http.MethodPost, "/v1/users", `{"email":"`+email+`","password":"`+password+
		`","timestamp":`+strconv.FormatInt(pair.Timestamp, 10)+`,"signature":"`+pair.Signature+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/users = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	loginRec := serveBody(t, a, http.MethodPost, "/v1/session", `{"email":"`+email+`","password":"`+password+`"}`, nil)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", loginRec.Code, loginRec.Body)
	}

	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &login); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}
	if login.Token == "" {
		t.Fatal("the login returned no token")
	}

	cookies := loginRec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-session" {
		t.Errorf("the login set cookies %+v, want one __Host-session", cookies)
	}

	meRec := serveBody(t, a, http.MethodGet, "/v1/me", "", map[string]string{
		"Authorization": "Bearer " + login.Token,
	})
	if meRec.Code != http.StatusOK {
		t.Fatalf("GET /v1/me = %d, want 200; body: %s", meRec.Code, meRec.Body)
	}

	logoutRec := serveBody(t, a, http.MethodDelete, "/v1/session", "", map[string]string{
		"Authorization": "Bearer " + login.Token,
	})
	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /v1/session = %d, want 204; body: %s", logoutRec.Code, logoutRec.Body)
	}

	afterLogout := serveBody(t, a, http.MethodGet, "/v1/me", "", map[string]string{
		"Authorization": "Bearer " + login.Token,
	})
	if afterLogout.Code != http.StatusUnauthorized {
		t.Errorf("GET /v1/me after logout = %d, want 401; body: %s", afterLogout.Code, afterLogout.Body)
	}
}

func TestNewAppWithoutADatabaseStillServesTheProbes(t *testing.T) {
	cfg := withSignupKey(config.Config{Port: "0", LogLevel: "error"})

	a, err := newApp(context.Background(), cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	for _, target := range []string{"/healthz", "/readyz"} {
		rec := serveBody(t, a, http.MethodGet, target, "", nil)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200; body: %s", target, rec.Code, rec.Body)
		}
	}

	readyRec := serveBody(t, a, http.MethodGet, "/readyz", "", nil)
	if !strings.Contains(readyRec.Body.String(), `"deps":"none"`) {
		t.Errorf("/readyz = %s, want deps none with no database", readyRec.Body)
	}

	for _, route := range []struct{ method, target string }{
		{http.MethodPost, "/v1/users"},
		{http.MethodPost, "/v1/session"},
		{http.MethodDelete, "/v1/session"},
		{http.MethodGet, "/v1/me"},
	} {
		rec := serveBody(t, a, route.method, route.target, `{}`, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404 without a database", route.method, route.target, rec.Code)
		}
	}
}

func TestNewAppWithAnUnreachableDatabaseStillBuilds(t *testing.T) {
	cfg := config.Config{
		Port:        "0",
		LogLevel:    "error",
		DatabaseURL: "postgres://identity:identity@127.0.0.1:1/identity?sslmode=disable&connect_timeout=1",
	}

	a, err := newApp(context.Background(), cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v; the pool is lazy, so an unreachable database is a probe failure, not a startup failure", err)
	}
	defer a.Close()

	rec := serveBody(t, a, http.MethodGet, "/healthz", "", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200 with an unreachable database; body: %s", rec.Code, rec.Body)
	}
}

func registerUserWithPair(t *testing.T, a *app, email, password string) {
	t.Helper()

	pair := signup.New(a.cfg.SignupSigningKeyValue).Mint(time.Now().Add(-30 * time.Second))
	rec := serveBody(t, a, http.MethodPost, "/v1/users", `{"email":"`+email+`","password":"`+password+
		`","timestamp":`+strconv.FormatInt(pair.Timestamp, 10)+`,"signature":"`+pair.Signature+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/users = %d; body: %s", rec.Code, rec.Body.String())
	}
}

func serveBody(t *testing.T, a *app, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(context.Background(), method, target, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	rec := httptest.NewRecorder()
	a.srv.Handler.ServeHTTP(rec, req)
	return rec
}
