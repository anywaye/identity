package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/mfa"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
)


type mfaServer struct {
	handler http.Handler
	pool    *pgxpool.Pool
	owner  *pgxpool.Pool
	clock  *clock.Fake
	second *mfa.Service
	token string
	userID id.UUID
	user enrolledUser
	pendingID   string
	pendingCode string
	logs *recordingHandler
	email string
}

func newMFAServer(t *testing.T) *mfaServer {
	t.Helper()

	pool, owner := dbtest.SchemaWithOwner(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
	second := testMFAService(pool, clk)
	svc := authServiceFor(pool, clk)

	logs := &recordingHandler{}
	return &mfaServer{
		handler: New(nil,
			WithAuth(svc),
			WithMFA(second),
			WithLogger(slogLogger(logs)),
		),
		pool: pool,
		owner:  owner,
		clock:  clk,
		second: second,
		logs:   logs,
	}
}

func newCanaryServer(t *testing.T) *mfaServer {
	t.Helper()

	s := newMFAServer(t)
	s.email, s.token = s.signUp(t)
	return s
}

func (h *recordingHandler) rendered() string {
	var b strings.Builder
	for _, entry := range h.entries {
		b.WriteString(entry)
		b.WriteString("\n")
	}
	return b.String()
}

func (s *mfaServer) signUp(t *testing.T) (email, token string) {
	t.Helper()

	email = dbtest.UniqueEmail(t)
	s.email = email
	s.token = ""
	s.userID = id.UUID{}
	rec := post(t, s.handler, "/v1/users",
		`{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/users = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("the registration body is not JSON: %v", err)
	}

	login := post(t, s.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", login.Code, login.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}
	s.token = session.Token
	parsed, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("parsing the registered id: %v", err)
	}
	s.userID = parsed
	return email, session.Token
}

func (s *mfaServer) signInWithFactor(t *testing.T, email string, user enrolledUser) string {
	t.Helper()

	rec := post(t, s.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/session = %d, want 202; body: %s", rec.Code, rec.Body)
	}
	var challengeBody challengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &challengeBody); err != nil {
		t.Fatalf("the 202 body is not JSON: %v", err)
	}

	s.clock.Advance(mfa.Period + time.Second)
	finished := s.post(t, "/v1/session/mfa", "",
		`{"challenge":"`+challengeBody.Challenge+`","code":"`+user.code(t, s.clock.Now())+`"}`)
	if finished.Code != http.StatusOK {
		t.Fatalf("POST /v1/session/mfa = %d, want 200; body: %s", finished.Code, finished.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(finished.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}
	s.token = session.Token
	return session.Token
}


func TestACorrectPasswordAnswers202WithAChallengeAndNoSession(t *testing.T) {
	s := newMFAServer(t)
	email, token := s.signUp(t)

	created := s.post(t, "/v1/mfa/enrollments", token, `{}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /v1/mfa/enrollments = %d, want 201; body: %s", created.Code, created.Body)
	}
	var started struct {
		EnrollmentID    string `json:"enrollment_id"`
		Secret          string `json:"secret"`
		ProvisioningURI string `json:"provisioning_uri"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &started); err != nil {
		t.Fatalf("the enrollment body is not JSON: %v\n%s", err, created.Body)
	}
	if started.EnrollmentID == "" || started.Secret == "" || started.ProvisioningURI == "" {
		t.Fatalf("the enrollment response is missing a field: %s", created.Body)
	}
	code, err := mfa.Code(started.Secret, s.clock.Now())
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	confirmed := s.post(t, "/v1/mfa/enrollments/"+started.EnrollmentID+"/confirm", token,
		`{"code":"`+code+`"}`)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirm = %d, want 200; body: %s", confirmed.Code, confirmed.Body)
	}

	rec := post(t, s.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/session = %d, want 202; body: %s", rec.Code, rec.Body)
	}

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("the 202 body is not JSON: %v\n%s", err, rec.Body)
	}
	if _, present := raw["token"]; present {
		t.Errorf("the 202 body carries a `token` key: %s", rec.Body)
	}
	if raw["mfa_required"] != true {
		t.Errorf("mfa_required = %v, want true", raw["mfa_required"])
	}
	challenge, _ := raw["challenge"].(string)
	if challenge == "" {
		t.Fatalf("the 202 body carries no challenge: %s", rec.Body)
	}

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == SessionCookieName {
			t.Fatal("the 202 set a session cookie; a challenge is not a session")
		}
		if cookie.Value == "" {
			t.Errorf("cookie %q is empty, which clears it rather than setting it", cookie.Name)
		}
	}
	if !hasCookie(rec, MFAChallengeCookieName, challenge) {
		t.Errorf("the 202 did not set the %s cookie to the challenge token", MFAChallengeCookieName)
	}

	if got := s.totalSessions(t); got != 0 {
		t.Errorf("%d session rows exist after a login waiting on a second factor", got)
	}
}

func TestTheChallengeIsACookieAndNotASessionOnDisk(t *testing.T) {
	s := newMFAServer(t)
	email, token := s.signUp(t)
	user := s.enrollAndConfirmFor(t, email, token)

	rec := post(t, s.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/session = %d, want 202", rec.Code)
	}
	var body challengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the 202 body is not JSON: %v", err)
	}

	me := sendWith(t, s.handler, http.MethodGet, "/v1/me", body.Challenge, "", "")
	if me.Code != http.StatusUnauthorized {
		t.Errorf("GET /v1/me with the challenge token = %d, want 401", me.Code)
	}
	before := s.sessionsForID(t, s.userIDFor(t))
	finished := s.post(t, "/v1/session/mfa", "", `{"challenge":"`+body.Challenge+`","code":"000000"}`)
	if finished.Code == http.StatusOK {
		t.Error("a wrong code produced a session")
	}
	if got := s.sessionsForID(t, s.userIDFor(t)); got != before {
		t.Errorf("%d sessions after a wrong code, want the fixture's %d", got, before)
	}

	s.clock.Advance(mfa.Period + time.Second)
	ok := s.post(t, "/v1/session/mfa", "",
		`{"challenge":"`+body.Challenge+`","code":"`+user.code(t, s.clock.Now())+`"}`)
	if ok.Code != http.StatusOK {
		t.Fatalf("POST /v1/session/mfa = %d, want 200; body: %s", ok.Code, ok.Body)
	}
	if cookie := cookieNamed(ok, SessionCookieName); cookie == nil || cookie.Value == "" {
		t.Error("the 200 did not set a session cookie")
	}
	if cookie := cookieNamed(ok, MFAChallengeCookieName); cookie == nil || cookie.Value != "" {
		t.Error("the 200 did not clear the challenge cookie")
	}
	if got := s.sessionsForID(t, s.userIDFor(t)); got != before+1 {
		t.Errorf("%d sessions after a completed login, want %d", got, before+1)
	}
	var session sessionResponse
	if err := json.Unmarshal(ok.Body.Bytes(), &session); err != nil {
		t.Fatalf("the 200 body is not a session: %v\n%s", err, ok.Body)
	}
	if session.Token == "" {
		t.Fatal("the 200 body carries no token")
	}
}

func (s *mfaServer) totalSessions(t *testing.T) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(t.Context(), `SELECT count(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}
	return n
}

func hasCookie(rec *httptest.ResponseRecorder, name, value string) bool {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name && cookie.Value == value {
			return true
		}
	}
	return false
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func (s *mfaServer) post(t *testing.T, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return sendWith(t, s.handler, http.MethodPost, path, token, "", body)
}

func (s *mfaServer) del(t *testing.T, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return sendWith(t, s.handler, http.MethodDelete, path, token, "", body)
}

func (s *mfaServer) get(t *testing.T, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	return sendWith(t, s.handler, http.MethodGet, path, token, "", "")
}

func (s *mfaServer) enrollAndConfirmFor(t *testing.T, email, token string) enrolledUser {
	t.Helper()

	if token == "" {
		_, token = s.signUp(t)
	}
	_ = email

	created := s.post(t, "/v1/mfa/enrollments", token, `{}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /v1/mfa/enrollments = %d; body: %s", created.Code, created.Body)
	}
	var started struct {
		EnrollmentID string `json:"enrollment_id"`
		Secret       string `json:"secret"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &started); err != nil {
		t.Fatalf("the enrollment body is not JSON: %v\n%s", err, created.Body)
	}

	code, err := mfa.Code(started.Secret, s.clock.Now())
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	confirmed := s.post(t, "/v1/mfa/enrollments/"+started.EnrollmentID+"/confirm", token,
		`{"code":"`+code+`"}`)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirm = %d, want 200; body: %s", confirmed.Code, confirmed.Body)
	}
	var body struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(confirmed.Body.Bytes(), &body); err != nil {
		t.Fatalf("the confirmation body is not JSON: %v", err)
	}
	if len(body.RecoveryCodes) != mfa.RecoveryCodeCount {
		t.Fatalf("%d recovery codes, want %d", len(body.RecoveryCodes), mfa.RecoveryCodeCount)
	}

	holds := enrolledUser{User: s.userID, Secret: started.Secret, RecoveryCode: body.RecoveryCodes[0]}
	s.user = holds

	s.signInWithFactor(t, email, holds)
	return holds
}
