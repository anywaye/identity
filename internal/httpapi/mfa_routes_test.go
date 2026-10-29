package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/mfa"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
)


func TestTheBrowserCookieFinishesTheLoginToo(t *testing.T) {
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

	s.clock.Advance(mfa.Period + time.Second)
	finished := sendWith(t, s.handler, http.MethodPost, "/v1/session/mfa", "", body.Challenge,
		`{"code":"`+user.code(t, s.clock.Now())+`"}`)
	if finished.Code != http.StatusOK {
		t.Fatalf("POST /v1/session/mfa with the cookie = %d, want 200; body: %s", finished.Code, finished.Body)
	}
	if got := s.sessionsForID(t, s.userIDFor(t)); got != 2 {
		t.Errorf("%d sessions, want 2 (the fixture's own plus this one)", got)
	}
}

func TestNoChallengeIs401WhateverTheBodySays(t *testing.T) {
	s := newMFAServer(t)
	email, token := s.signUp(t)
	user := s.enrollAndConfirmFor(t, email, token)
	token = s.token

	rec := s.post(t, "/v1/session/mfa", "", `{"code":"`+user.code(t, s.clock.Now())+`"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body)
	}
	if got := decodeProblem(t, rec).Code; got != CodeUnauthorized {
		t.Errorf("code = %q, want %q", got, CodeUnauthorized)
	}
	if got, want := s.sessionsForID(t, s.userIDFor(t)), 1; got != want {
		t.Errorf("%d sessions after a challenge-less code submission, want %d (the fixture's own)", got, want)
	}
	_ = token
}

func TestAWrongCodeIs401AndIsNotDistinguishableFromASpentOne(t *testing.T) {
	s := newMFAServer(t)
	email, token := s.signUp(t)
	user := s.enrollAndConfirmFor(t, email, token)
	token = s.token

	s.clock.Advance(mfa.Period + time.Second)
	captured := user.code(t, s.clock.Now())

	before := s.sessionsForID(t, s.userIDFor(t))

	first := s.challenge(t, email)
	spent := s.finish(t, first.Challenge, captured)
	if spent.Code != http.StatusOK {
		t.Fatalf("the first use = %d, want 200; body: %s", spent.Code, spent.Body)
	}

	wrong := s.finish(t, s.challenge(t, email).Challenge, "000000")
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong code = %d, want 401", wrong.Code)
	}

	replay := s.finish(t, s.challenge(t, email).Challenge, captured)
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("a replayed code = %d, want 401", replay.Code)
	}

	wrongProblem, replayProblem := decodeProblem(t, wrong), decodeProblem(t, replay)
	if wrongProblem.Code != replayProblem.Code {
		t.Errorf("a wrong code and a replay report different codes (%q vs %q), which tells an attacker which was which",
			wrongProblem.Code, replayProblem.Code)
	}
	if wrongProblem.Detail != replayProblem.Detail {
		t.Errorf("a wrong code and a replay have different details, which tells an attacker which was which:\nwrong:  %q\nreplay: %q",
			wrongProblem.Detail, replayProblem.Detail)
	}
	if got := s.sessionsForID(t, s.userIDFor(t)); got != before+1 {
		t.Errorf("%d sessions after a replay, want %d: a code was accepted twice", got, before+1)
	}
	_ = token
}

func TestTheSecondFactorLockoutIs423WithRetryAfter(t *testing.T) {
	s := newMFAServer(t)
	email, token := s.signUp(t)
	s.enrollAndConfirmFor(t, email, token)
	token = s.token

	for range sessions.MaxFailedAttempts {
		rec := s.finish(t, s.challenge(t, email).Challenge, "000000")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("a wrong code = %d, want 401; body: %s", rec.Code, rec.Body)
		}
	}
	locked := s.finish(t, s.challenge(t, email).Challenge, "000000")
	if locked.Code != http.StatusLocked {
		t.Fatalf("the attempt past the threshold = %d, want 423; body: %s", locked.Code, locked.Body)
	}
	if got := decodeProblem(t, locked).Code; got != CodeAccountLocked {
		t.Errorf("code = %q, want %q", got, CodeAccountLocked)
	}
	if got := locked.Header().Get(RetryAfterHeader); got != "900" {
		t.Errorf("Retry-After = %q, want 900 seconds", got)
	}

	login := post(t, s.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if login.Code != http.StatusAccepted {
		t.Errorf("the password login = %d, want 202; the second factor's lockout leaked into it", login.Code)
	}
	_ = token
}

func TestTheMFARoutesNeedASession(t *testing.T) {
	s := newMFAServer(t)

	cases := []struct {
		name, method, path, body string
	}{
		{"read the status", http.MethodGet, "/v1/mfa", ""},
		{"start an enrollment", http.MethodPost, "/v1/mfa/enrollments", `{}`},
		{"confirm an enrollment", http.MethodPost, "/v1/mfa/enrollments/" + id.UUID{}.String() + "/confirm", `{"code":"123456"}`},
		{"regenerate the recovery codes", http.MethodPost, "/v1/mfa/recovery-codes", `{"code":"123456"}`},
		{"disable", http.MethodDelete, "/v1/mfa", `{"code":"123456"}`},
		{"complete a second factor", http.MethodPost, "/v1/session/mfa", `{"code":"123456"}`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := sendWith(t, s.handler, c.method, c.path, "", "", c.body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body)
			}
			if got := decodeProblem(t, rec).Code; got != CodeUnauthorized {
				t.Errorf("code = %q, want %q", got, CodeUnauthorized)
			}
		})
	}
}

func TestGetMFAStatus(t *testing.T) {
	s := newMFAServer(t)
	email, token := s.signUp(t)

	before := s.get(t, "/v1/mfa", token)
	if before.Code != http.StatusOK {
		t.Fatalf("GET /v1/mfa before enrolling = %d, want 200; body: %s", before.Code, before.Body)
	}
	var off mfaStatusResponse
	if err := json.Unmarshal(before.Body.Bytes(), &off); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if off.Enabled {
		t.Error("a user with no second factor reports enabled: true")
	}
	if off.RecoveryCodesRemaining != nil {
		t.Error("the status carries a recovery-code count for a user with no codes")
	}
	_ = email

	user := s.enrollAndConfirmFor(t, email, token)
	token = s.token
	after := s.get(t, "/v1/mfa", token)
	if after.Code != http.StatusOK {
		t.Fatalf("GET /v1/mfa = %d, want 200", after.Code)
	}
	var on mfaStatusResponse
	if err := json.Unmarshal(after.Body.Bytes(), &on); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if !on.Enabled || on.Method != mfa.MethodTOTP {
		t.Errorf("status = %+v, want enabled totp", on)
	}
	if on.EnrolledAt == nil {
		t.Error("the status carries no enrolled_at")
	}
	if on.RecoveryCodesRemaining == nil || *on.RecoveryCodesRemaining != mfa.RecoveryCodeCount {
		t.Errorf("recovery_codes_remaining = %v, want %d", on.RecoveryCodesRemaining, mfa.RecoveryCodeCount)
	}

	if _, err := s.second.VerifyFactor(t.Context(), s.userIDFor(t), user.RecoveryCode, s.clock.Now()); err != nil {
		t.Fatalf("spending a recovery code: %v", err)
	}
	spent := s.get(t, "/v1/mfa", token)
	var afterSpend mfaStatusResponse
	if err := json.Unmarshal(spent.Body.Bytes(), &afterSpend); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if afterSpend.RecoveryCodesRemaining == nil ||
		*afterSpend.RecoveryCodesRemaining != mfa.RecoveryCodeCount-1 {
		t.Errorf("recovery_codes_remaining = %v, want %d", afterSpend.RecoveryCodesRemaining, mfa.RecoveryCodeCount-1)
	}
}

func TestTheDestructiveRoutesRequireAFactor(t *testing.T) {
	t.Run("disable", func(t *testing.T) {
		s := newMFAServer(t)
		email, token := s.signUp(t)
		user := s.enrollAndConfirmFor(t, email, token)
		token = s.token

		for _, body := range []string{`{}`, `{"code":""}`, `{"code":"000000"}`, `{"code":"not-a-code"}`} {
			rec := s.del(t, "/v1/mfa", token, body)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("disable with %s = %d, want 401; body: %s", body, rec.Code, rec.Body)
			}
		}
		if !reportsEnabled(t, s.get(t, "/v1/mfa", token)) {
			t.Error("a refused disable turned MFA off anyway")
		}
		if got := s.sessionsForID(t, s.userIDFor(t)); got != 1 {
			t.Errorf("%d sessions after four refused disables, want the fixture's 1", got)
		}
		_ = user

		s.clock.Advance(mfa.Period + time.Second)
		ok := s.del(t, "/v1/mfa", token, `{"code":"`+user.code(t, s.clock.Now())+`"}`)
		if ok.Code != http.StatusNoContent {
			t.Fatalf("disable with a factor = %d, want 204; body: %s", ok.Code, ok.Body)
		}
		if cookie := cookieNamed(ok, SessionCookieName); cookie == nil || cookie.Value != "" {
			t.Error("the 204 did not clear the session cookie")
		}
		if got := s.sessionsForID(t, s.userIDFor(t)); got != 0 {
			t.Errorf("%d sessions survived the disable, want 0: every session is revoked", got)
		}

		relogin := post(t, s.handler, "/v1/session",
			`{"email":"`+email+`","password":"`+matrixPassword+`"}`)
		if relogin.Code != http.StatusOK {
			t.Fatalf("signing in after a disable = %d, want 200 and NOT 202", relogin.Code)
		}
		var session sessionResponse
		if err := json.Unmarshal(relogin.Body.Bytes(), &session); err != nil {
			t.Fatalf("the login body is not JSON: %v", err)
		}
		if reportsEnabled(t, s.get(t, "/v1/mfa", session.Token)) {
			t.Error("MFA is still enabled after a valid disable")
		}
	})

	t.Run("regenerate the recovery codes", func(t *testing.T) {
		s := newMFAServer(t)
		email, token := s.signUp(t)
		user := s.enrollAndConfirmFor(t, email, token)
		token = s.token

		if rec := s.post(t, "/v1/mfa/recovery-codes", token, `{}`); rec.Code != http.StatusUnauthorized {
			t.Errorf("regenerating with no code = %d, want 401", rec.Code)
		}

		s.clock.Advance(mfa.Period + time.Second)
		rec := s.post(t, "/v1/mfa/recovery-codes", token, `{"code":"`+user.code(t, s.clock.Now())+`"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("regenerating with a factor = %d, want 200; body: %s", rec.Code, rec.Body)
		}
		var body recoveryCodesResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("the body is not JSON: %v", err)
		}
		if len(body.RecoveryCodes) != mfa.RecoveryCodeCount {
			t.Errorf("%d codes issued, want %d", len(body.RecoveryCodes), mfa.RecoveryCodeCount)
		}
		if body.RecoveryCodesRemaining != mfa.RecoveryCodeCount {
			t.Errorf("remaining = %d, want %d", body.RecoveryCodesRemaining, mfa.RecoveryCodeCount)
		}
		for _, old := range []string{user.RecoveryCode} {
			if _, err := s.second.VerifyFactor(t.Context(), s.userIDFor(t), old, s.clock.Now()); !errors.Is(err, mfa.ErrInvalidFactor) {
				t.Errorf("an old recovery code still works: %v", err)
			}
		}
		if _, err := s.second.VerifyFactor(t.Context(), s.userIDFor(t), body.RecoveryCodes[0], s.clock.Now()); err != nil {
			t.Errorf("a new recovery code does not work: %v", err)
		}
	})

	t.Run("rotating the secret", func(t *testing.T) {
		s := newMFAServer(t)
		email, token := s.signUp(t)
		user := s.enrollAndConfirmFor(t, email, token)
		token = s.token

		if rec := s.post(t, "/v1/mfa/enrollments", token, `{}`); rec.Code != http.StatusUnauthorized {
			t.Errorf("rotating with no code = %d, want 401; body: %s", rec.Code, rec.Body)
		}

		oldSecret := user.Secret
		s.clock.Advance(mfa.Period + time.Second)
		started := s.post(t, "/v1/mfa/enrollments", token, `{"code":"`+user.code(t, s.clock.Now())+`"}`)
		if started.Code != http.StatusCreated {
			t.Fatalf("rotating = %d, want 201; body: %s", started.Code, started.Body)
		}
		var body struct {
			EnrollmentID string `json:"enrollment_id"`
			Secret       string `json:"secret"`
			Replaced     bool   `json:"replaced"`
		}
		if err := json.Unmarshal(started.Body.Bytes(), &body); err != nil {
			t.Fatalf("the body is not JSON: %v", err)
		}
		if !body.Replaced {
			t.Error("the rotation does not say it replaced a live credential")
		}

		s.clock.Advance(mfa.Period + time.Second)
		confirmed := s.post(t, "/v1/mfa/enrollments/"+body.EnrollmentID+"/confirm", token,
			`{"code":"`+mustTOTPCode(t, body.Secret, s.clock.Now())+`"}`)
		if confirmed.Code != http.StatusOK {
			t.Fatalf("confirming the rotation = %d, want 200; body: %s", confirmed.Code, confirmed.Body)
		}
		var confirmBody confirmedEnrollmentResponse
		if err := json.Unmarshal(confirmed.Body.Bytes(), &confirmBody); err != nil {
			t.Fatalf("the body is not JSON: %v", err)
		}
		if !confirmBody.ReplacedExistingSecret {
			t.Error("the confirmation does not say it replaced an existing secret")
		}

		s.clock.Advance(mfa.Period + time.Second)
		if _, err := s.second.VerifyFactor(t.Context(), s.userIDFor(t),
			mustTOTPCode(t, oldSecret, s.clock.Now()), s.clock.Now()); !errors.Is(err, mfa.ErrInvalidFactor) {
			t.Errorf("the rotated-away secret still works: %v", err)
		}
	})
}

func TestAnExpiredEnrollmentIs404(t *testing.T) {
	s := newMFAServer(t)
	email, token := s.signUp(t)

	created := s.post(t, "/v1/mfa/enrollments", token, `{}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /v1/mfa/enrollments = %d; body: %s", created.Code, created.Body)
	}
	var started struct {
		EnrollmentID string `json:"enrollment_id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &started); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}

	s.clock.Advance(mfa.EnrollmentTTL + time.Second)
	rec := s.post(t, "/v1/mfa/enrollments/"+started.EnrollmentID+"/confirm", token,
		`{"code":"123456"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("confirming an expired enrollment = %d, want 404; body: %s", rec.Code, rec.Body)
	}
	if got := decodeProblem(t, rec).Code; got != CodeNotFound {
		t.Errorf("code = %q, want %q", got, CodeNotFound)
	}
	_ = email
}

func TestConfirmWithoutACodeIs422(t *testing.T) {
	s := newMFAServer(t)
	email, token := s.signUp(t)

	created := s.post(t, "/v1/mfa/enrollments", token, `{}`)
	var started struct {
		EnrollmentID string `json:"enrollment_id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &started); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}

	rec := s.post(t, "/v1/mfa/enrollments/"+started.EnrollmentID+"/confirm", token, `{}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("confirm with no code = %d, want 422; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeValidationFailed {
		t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
	}
	if len(p.Errors) != 1 || p.Errors[0].Field != "code" || p.Errors[0].Code != mfa.CodeRequired {
		t.Errorf("errors[] = %+v, want one entry for `code`", p.Errors)
	}
	_ = email
}

func TestAnEnrollmentIdThatIsNotTheCallersIs404(t *testing.T) {
	s := newMFAServer(t)
	email, token := s.signUp(t)

	created := s.post(t, "/v1/mfa/enrollments", token, `{}`)
	var started struct {
		EnrollmentID string `json:"enrollment_id"`
		Secret       string `json:"secret"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &started); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}

	_, otherToken := s.signUp(t)
	rec := s.post(t, "/v1/mfa/enrollments/"+started.EnrollmentID+"/confirm", otherToken,
		`{"code":"`+mustTOTPCode(t, started.Secret, s.clock.Now())+`"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("confirming somebody else's enrollment = %d, want 404; body: %s", rec.Code, rec.Body)
	}
	_ = email
}

func TestDisablingMFAThatIsNotEnabledIs409(t *testing.T) {
	s := newMFAServer(t)
	_, token := s.signUp(t)

	rec := s.del(t, "/v1/mfa", token, `{"code":"123456"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("disabling with MFA off = %d, want 409; body: %s", rec.Code, rec.Body)
	}
	if got := decodeProblem(t, rec).Code; got != CodeConflict {
		t.Errorf("code = %q, want %q", got, CodeConflict)
	}
}

func TestTheMFARoutesAreAbsentWithoutAService(t *testing.T) {
	s := newMFAServer(t)
	email, token := s.signUp(t)

	reduced := New(nil,
		WithAuth(authServiceFor(s.pool, s.clock)),
		WithLogger(slogLogger(&recordingHandler{})),
	)

	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/mfa", ""},
		{http.MethodPost, "/v1/mfa/enrollments", `{}`},
		{http.MethodPost, "/v1/mfa/recovery-codes", `{"code":"123456"}`},
		{http.MethodDelete, "/v1/mfa", `{"code":"123456"}`},
	} {
		rec := sendWith(t, reduced, c.method, c.path, token, "", c.body)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s without the MFA service = %d, want 404", c.method, c.path, rec.Code)
		}
	}
	_ = email
}


func (s *mfaServer) challenge(t *testing.T, email string) challengeResponse {
	t.Helper()
	rec := post(t, s.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/session = %d, want 202; body: %s", rec.Code, rec.Body)
	}
	var body challengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the 202 body is not JSON: %v", err)
	}
	if body.Challenge == "" {
		t.Fatal("the 202 body carries no challenge token")
	}
	return body
}

func (s *mfaServer) finish(t *testing.T, challenge, code string) *httptest.ResponseRecorder {
	t.Helper()
	return s.post(t, "/v1/session/mfa", "", `{"challenge":"`+challenge+`","code":"`+code+`"}`)
}

func (s *mfaServer) userIDFor(t *testing.T) id.UUID {
	t.Helper()
	if s.userID.IsZero() {
		t.Fatal("no fixture user: call signUp first")
	}
	return s.userID
}

func (s *mfaServer) sessionsForID(t *testing.T, userID id.UUID) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM sessions WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}
	return n
}

func mustTOTPCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := mfa.Code(secret, at)
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	return code
}

func reportsEnabled(t *testing.T, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/mfa = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	var body mfaStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	return body.Enabled
}
