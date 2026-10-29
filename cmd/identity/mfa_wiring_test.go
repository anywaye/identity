package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/config"
	"github.com/anywaye/identity/internal/mfa"
	"github.com/anywaye/identity/internal/platform/dbtest"
)


func mfaKey(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte("identity-cmd-mfa-wiring-key-32!!"))
}

func TestNewAppMountsMFAWithAKey(t *testing.T) {
	dsn := testDatabaseURL(t)
	ctx := context.Background()

	cfg := config.Config{
		Port: "0", LogLevel: "error", DatabaseURL: dsn,
		MFAEncryptionKeyValue: mustDecodeKey(t, mfaKey(t)),
		MFAIssuerLabel:        config.DefaultMFAIssuer,
		SignupSigningKeyValue: signupKeyValue,
	}
	a, err := newApp(ctx, cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	email := dbtest.UniqueEmail(t)
	registerUserWithPair(t, a, email, "correct horse battery staple")

	login := serveBody(t, a, http.MethodPost, "/v1/session",
		`{"email":"`+email+`","password":"correct horse battery staple"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", login.Code, login.Body.String())
	}
	var session struct {
		Token string `json:"token"`
	}
	decodeJSON(t, login, &session)
	if session.Token == "" {
		t.Fatal("the login body carries no token")
	}

	enroll := serveBody(t, a, http.MethodPost, "/v1/mfa/enrollments", `{}`, bearer(session.Token))
	if enroll.Code != http.StatusCreated {
		t.Fatalf("POST /v1/mfa/enrollments = %d, want 201; body: %s", enroll.Code, enroll.Body.String())
	}
	var started struct {
		EnrollmentID string `json:"enrollment_id"`
		Secret       string `json:"secret"`
	}
	decodeJSON(t, enroll, &started)
	if started.EnrollmentID == "" || started.Secret == "" {
		t.Fatalf("the enrollment response is missing a field: %s", enroll.Body.String())
	}

	code, err := mfa.Code(started.Secret, time.Now())
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	confirm := serveBody(t, a, http.MethodPost,
		"/v1/mfa/enrollments/"+started.EnrollmentID+"/confirm", `{"code":"`+code+`"}`, bearer(session.Token))
	if confirm.Code != http.StatusOK {
		t.Fatalf("confirm = %d, want 200; body: %s", confirm.Code, confirm.Body.String())
	}

	chained := serveBody(t, a, http.MethodPost, "/v1/session",
		`{"email":"`+email+`","password":"correct horse battery staple"}`, nil)
	if chained.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/session for an enrolled user = %d, want 202; body: %s",
			chained.Code, chained.Body.String())
	}
	if strings.Contains(chained.Body.String(), `"token"`) {
		t.Errorf("the 202 carries a token key: %s", chained.Body.String())
	}

	step := serveBody(t, a, http.MethodPost, "/v1/session/mfa", `{"challenge":"not-a-challenge","code":"123456"}`, nil)
	if step.Code != http.StatusNotFound {
		t.Errorf("POST /v1/session/mfa with a bogus challenge = %d, want 404; body: %s",
			step.Code, step.Body.String())
	}
}

func TestNewAppWithoutMFAKeyMountsNoManagementRoutesAndStillChallenges(t *testing.T) {
	dsn := testDatabaseURL(t)
	ctx := context.Background()

	cfg := config.Config{Port: "0", LogLevel: "error", DatabaseURL: dsn, SignupSigningKeyValue: signupKeyValue}
	a, err := newApp(ctx, cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	email := dbtest.UniqueEmail(t)
	registerUserWithPair(t, a, email, "correct horse battery staple")
	login := serveBody(t, a, http.MethodPost, "/v1/session",
		`{"email":"`+email+`","password":"correct horse battery staple"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", login.Code, login.Body.String())
	}
	var session struct {
		Token string `json:"token"`
	}
	decodeJSON(t, login, &session)

	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/mfa", ""},
		{http.MethodPost, "/v1/mfa/enrollments", `{}`},
		{http.MethodPost, "/v1/mfa/recovery-codes", `{"code":"123456"}`},
		{http.MethodDelete, "/v1/mfa", `{"code":"123456"}`},
	} {
		got := serveBody(t, a, c.method, c.path, c.body, bearer(session.Token))
		if got.Code != http.StatusNotFound {
			t.Errorf("%s %s without a key = %d, want 404", c.method, c.path, got.Code)
		}
	}

	step := serveBody(t, a, http.MethodPost, "/v1/session/mfa", `{"challenge":"x","code":"123456"}`, nil)
	if step.Code != http.StatusNotFound {
		t.Errorf("POST /v1/session/mfa = %d, want 404 for a bogus challenge", step.Code)
	}
	if got := step.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type = %q, want the problem envelope", got)
	}
}

func TestNewAppRefusesAnMFAKeyOfTheWrongLength(t *testing.T) {
	dsn := testDatabaseURL(t)

	cfg := config.Config{
		Port: "0", LogLevel: "error", DatabaseURL: dsn,
		MFAEncryptionKeyValue: []byte("sixteen bytes ok"),
	}
	if _, err := newApp(context.Background(), cfg, discardLogger()); err == nil {
		t.Fatal("newApp accepted a 16-byte MFA key")
	}
}

func TestMFAEncryptionKeyIsNeverGenerated(t *testing.T) {
	cfg := config.Config{Port: "0"}
	key, err := cfg.MFAEncryptionKey()
	if err == nil {
		t.Fatalf("MFAEncryptionKey() with nothing configured returned %q, want ErrNoMFAEncryptionKey", key)
	}
	if cfg.MFAEncryptionKeyConfigured() {
		t.Error("MFAEncryptionKeyConfigured() is true with no key configured")
	}
	if cfg.MFAIssuer() != config.DefaultMFAIssuer {
		t.Errorf("MFAIssuer() = %q, want the default label", cfg.MFAIssuer())
	}
}

func mustDecodeKey(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decoding the fixture key: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("the fixture key is %d bytes, want 32", len(decoded))
	}
	return decoded
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}
}
