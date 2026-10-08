package httpapi

// THE PASSWORD-RESET-THEN-FRESH-MFA-LOGIN WALK (m127).
//
// The local A-to-Z acceptance run found a real failure: after a password
// reset, sign-in with the new password correctly answers 202 with a fresh MFA
// challenge, but submitting a freshly generated TOTP code against that
// challenge answers 401 instead of 200.
//
// This file replays that walk at the narrowest realistic layer — the real
// router, the real auth/recovery/MFA use cases, the real SQL over a private
// schema — and holds BOTH halves of the answer:
//
//   - a code from a TOTP step this credential has already spent is refused
//     (401), even across a password reset. That is the replay guard doing its
//     job, not the reset breaking the login: "freshly generated" and "a fresh
//     step" are different claims inside one 30-second window.
//   - advancing past the spent step and presenting the next code finishes the
//     login (200) with a session that resolves.
//
// The corrected journey assumption is therefore "wait for the next code", and
// the fixture advances the fake clock exactly the way signInWithFactor does
// rather than reusing a value the service has already seen.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/recovery"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/useraudit"
	"github.com/cafaye/identity/internal/users"
)

// postresetMFAFixture is the whole walk over ONE private schema: the real auth
// service with the real second factor, the real recovery service delivering
// into a captured mailer, and the real MFA management surface for enrollment.
type postresetMFAFixture struct {
	handler http.Handler
	pool    *pgxpool.Pool
	clk     *clock.Fake
	mailer  *captureMailer
}

func newPostresetMFAFixture(t *testing.T) *postresetMFAFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	second := testMFAService(pool, clk)
	mailer := &captureMailer{}
	cheap := users.NewHasherWithParams(&argon2id.Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})

	authSvc := auth.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		outbox.NewStore(pool),
		realTenancy(pool, clk),
		second,
		oidc.NewStore(pool),
		useraudit.NewStore(pool),
		cheap,
		clk,
		24*time.Hour,
		false,
	)

	links := recovery.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		recovery.NewStore(pool),
		users.NewStore(pool),
		sessions.NewStore(pool),
		&captureAccessRevoker{revoked: map[string]time.Time{}},
		outbox.NewStore(pool),
		mailer,
		cheap,
		clk,
		second,
	)

	return &postresetMFAFixture{
		handler: New(nil,
			WithAuth(authSvc),
			WithMFA(second),
			WithRecovery(links),
			WithLogger(slogLogger(&recordingHandler{})),
		),
		pool:   pool,
		clk:    clk,
		mailer: mailer,
	}
}

// register creates an account and returns its address.
func (f *postresetMFAFixture) register(t *testing.T) string {
	t.Helper()

	email := dbtest.UniqueEmail(t)
	registerThrough(t, f.handler, email)
	return email
}

// loginChallenge is POST /v1/session expecting the MFA branch: 202 plus a
// challenge, and no session behind it.
func (f *postresetMFAFixture) loginChallenge(t *testing.T, email, password string) challengeResponse {
	t.Helper()

	rec := post(t, f.handler, "/v1/session", `{"email":"`+email+`","password":"`+password+`"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/session = %d, want 202; body: %s", rec.Code, rec.Body)
	}
	var body challengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the 202 body is not JSON: %v\n%s", err, rec.Body)
	}
	if body.Challenge == "" {
		t.Fatal("the 202 body carries no challenge token")
	}
	return body
}

// finishMFA is POST /v1/session/mfa with the challenge in the body, as an API
// client sends it.
func (f *postresetMFAFixture) finishMFA(t *testing.T, challenge, code string) *httptest.ResponseRecorder {
	t.Helper()

	return post(t, f.handler, "/v1/session/mfa", `{"challenge":"`+challenge+`","code":"`+code+`"}`)
}

// me resolves a session token through GET /v1/me.
func (f *postresetMFAFixture) me(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()

	return sendWith(t, f.handler, http.MethodGet, "/v1/me", token, "", "")
}

// liveSessions counts every live session row behind an address.
func (f *postresetMFAFixture) liveSessions(t *testing.T, email string) int {
	t.Helper()

	var n int
	if err := f.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.email = $1`,
		email).Scan(&n); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}
	return n
}

// TestPasswordResetFollowedByFreshPasswordPlusMFALogin is the m127 walk.
func TestPasswordResetFollowedByFreshPasswordPlusMFALogin(t *testing.T) {
	f := newPostresetMFAFixture(t)
	email := f.register(t)

	const newPassword = "a completely new password"

	// Sign in once, so there is a pre-reset session to kill later.
	first := post(t, f.handler, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if first.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", first.Code, first.Body)
	}
	var firstSession sessionResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstSession); err != nil {
		t.Fatalf("the login body is not JSON: %v\n%s", err, first.Body)
	}

	// Enroll and confirm a second factor over HTTP, as the walk does.
	created := sendWith(t, f.handler, http.MethodPost, "/v1/mfa/enrollments", firstSession.Token, "", `{}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /v1/mfa/enrollments = %d, want 201; body: %s", created.Code, created.Body)
	}
	var started struct {
		EnrollmentID string `json:"enrollment_id"`
		Secret       string `json:"secret"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &started); err != nil {
		t.Fatalf("the enrollment body is not JSON: %v\n%s", err, created.Body)
	}
	confirmed := sendWith(t, f.handler, http.MethodPost,
		"/v1/mfa/enrollments/"+started.EnrollmentID+"/confirm", firstSession.Token, "",
		`{"code":"`+mustTOTPCode(t, started.Secret, f.clk.Now())+`"}`)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirm = %d, want 200; body: %s", confirmed.Code, confirmed.Body)
	}

	// The initial MFA challenge completion: this spends the current TOTP step
	// against the credential, which is the fact the rest of the test turns on.
	initial := f.loginChallenge(t, email, validPassword)
	spentCode := mustTOTPCode(t, started.Secret, f.clk.Now())
	finished := f.finishMFA(t, initial.Challenge, spentCode)
	if finished.Code != http.StatusOK {
		t.Fatalf("POST /v1/session/mfa = %d, want 200; body: %s", finished.Code, finished.Body)
	}
	var preReset sessionResponse
	if err := json.Unmarshal(finished.Body.Bytes(), &preReset); err != nil {
		t.Fatalf("the MFA completion body is not JSON: %v\n%s", err, finished.Body)
	}

	// Reset the password through the two anonymous routes, as the walk does.
	if rec := post(t, f.handler, "/v1/password-resets", `{"email":"`+email+`"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/password-resets = %d, want 202; body: %s", rec.Code, rec.Body)
	}
	redeemed := sendWith(t, f.handler, http.MethodPost, "/v1/password-resets/confirm", "",
		"", `{"token":"`+tokenIn(t, f.mailer.last(t))+`","password":"`+newPassword+`"}`)
	if redeemed.Code != http.StatusNoContent {
		t.Fatalf("POST /v1/password-resets/confirm = %d, want 204; body: %s", redeemed.Code, redeemed.Body)
	}

	// The pre-reset session is dead: the reset invalidates old sessions.
	if got := f.liveSessions(t, email); got != 0 {
		t.Fatalf("%d sessions survived a password reset, want 0", got)
	}
	if me := f.me(t, preReset.Token); me.Code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/me with the pre-reset token = %d, want 401; body: %s", me.Code, me.Body)
	}

	// Sign in with the NEW password, immediately — the same TOTP step is
	// still current, exactly as in the walk that reported the failure.
	fresh := f.loginChallenge(t, email, newPassword)

	// The code the authenticator shows NOW is the value the initial login
	// already spent. It is refused, and it must be: a spent step is a spent
	// step, and a password reset is not a second-factor reset.
	replay := f.finishMFA(t, fresh.Challenge, mustTOTPCode(t, started.Secret, f.clk.Now()))
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("POST /v1/session/mfa with the spent step = %d, want 401; body: %s", replay.Code, replay.Body)
	}
	if got := decodeProblem(t, replay).Code; got != CodeUnauthorized {
		t.Errorf("the replay's problem code = %q, want %q", got, CodeUnauthorized)
	}
	if got := f.liveSessions(t, email); got != 0 {
		t.Errorf("%d sessions after a refused second factor, want 0", got)
	}

	// The corrected journey: wait for the next code. A fresh step against the
	// fresh challenge finishes the login, and the session resolves.
	f.clk.Advance(mfa.Period + time.Second)
	after := f.loginChallenge(t, email, newPassword)
	ok := f.finishMFA(t, after.Challenge, mustTOTPCode(t, started.Secret, f.clk.Now()))
	if ok.Code != http.StatusOK {
		t.Fatalf("POST /v1/session/mfa with the next step = %d, want 200; body: %s", ok.Code, ok.Body)
	}
	var postReset sessionResponse
	if err := json.Unmarshal(ok.Body.Bytes(), &postReset); err != nil {
		t.Fatalf("the MFA completion body is not JSON: %v\n%s", err, ok.Body)
	}
	if postReset.Token == "" {
		t.Fatal("the 200 body carries no session token")
	}
	if me := f.me(t, postReset.Token); me.Code != http.StatusOK {
		t.Errorf("GET /v1/me with the post-reset MFA session = %d, want 200; body: %s", me.Code, me.Body)
	}
}
