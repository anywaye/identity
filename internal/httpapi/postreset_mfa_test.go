package httpapi

import (
	"encoding/json"
	"net/http"
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

// PACKET m127 — RED STEP.
//
// The merged site-stack walk reports: after a password reset, signing in with
// the new password answers 202 with a fresh MFA challenge, but completing that
// challenge with a freshly generated TOTP code answers 401 instead of 200.
//
// This test replays the walk's exact expectation at the narrowest realistic
// layer — the real router, the real auth/recovery/MFA use cases and the real
// SQL over a private schema — with NO clock movement between the two MFA
// completions, exactly as a fast end-to-end walk behaves. It asserts the walk's
// expected 200, so a failure here IS the walk's failure, reproduced
// deterministically against a parked clock.
type postResetMFAFixture struct {
	handler http.Handler
	pool    *pgxpool.Pool
	clk     *clock.Fake
	second  *mfa.Service
	mailer  *captureMailer
}

func newPostResetMFAFixture(t *testing.T) *postResetMFAFixture {
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
		recovery.RedeemedSessionTTL,
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

	return &postResetMFAFixture{
		handler: New(nil,
			WithAuth(authSvc),
			WithMFA(second),
			WithRecovery(links),
			WithLogger(slogLogger(&recordingHandler{})),
		),
		pool:   pool,
		clk:    clk,
		second: second,
		mailer: mailer,
	}
}

// loginWithFactor completes a password+MFA login over HTTP and returns the
// session token, using whatever code the enrolled secret produces AT THE
// CURRENT CLOCK INSTANT — i.e. what a walk's "freshly generated code" is.
func (f *postResetMFAFixture) loginWithFactor(t *testing.T, email, password string, secret string) (challenge string, session string, challengeStatus, sessionStatus int) {
	t.Helper()

	rec := post(t, f.handler, "/v1/session", `{"email":"`+email+`","password":"`+password+`"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/session = %d, want 202; body: %s", rec.Code, rec.Body)
	}
	var body challengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the 202 body is not JSON: %v", err)
	}

	code, err := mfa.Code(secret, f.clk.Now())
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	finished := post(t, f.handler, "/v1/session/mfa",
		`{"challenge":"`+body.Challenge+`","code":"`+code+`"}`)
	var sess sessionResponse
	if finished.Code == http.StatusOK {
		if err := json.Unmarshal(finished.Body.Bytes(), &sess); err != nil {
			t.Fatalf("the 200 body is not JSON: %v", err)
		}
	}
	return body.Challenge, sess.Token, rec.Code, finished.Code
}

const postResetMFANewPassword = "a different horse battery staple"

func TestPostResetImmediateSecondFactorReturnsASession(t *testing.T) {
	f := newPostResetMFAFixture(t)
	email := dbtest.UniqueEmail(t)

	// Signup and first signin: no second factor yet.
	registerThrough(t, f.handler, email)
	login := post(t, f.handler, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", login.Code, login.Body)
	}
	var first sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &first); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}

	// TOTP enrollment and confirmation.
	created := sendWith(t, f.handler, http.MethodPost, "/v1/mfa/enrollments", first.Token, "", `{}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /v1/mfa/enrollments = %d, want 201; body: %s", created.Code, created.Body)
	}
	var started struct {
		EnrollmentID string `json:"enrollment_id"`
		Secret       string `json:"secret"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &started); err != nil {
		t.Fatalf("the enrollment body is not JSON: %v", err)
	}
	enrollCode, err := mfa.Code(started.Secret, f.clk.Now())
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	confirmed := sendWith(t, f.handler, http.MethodPost,
		"/v1/mfa/enrollments/"+started.EnrollmentID+"/confirm", first.Token, "",
		`{"code":"`+enrollCode+`"}`)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirm = %d, want 200; body: %s", confirmed.Code, confirmed.Body)
	}

	// Initial MFA challenge completion, as the walk does.
	_, oldSession, _, mfaStatus := f.loginWithFactor(t, email, validPassword, started.Secret)
	if mfaStatus != http.StatusOK {
		t.Fatalf("initial POST /v1/session/mfa = %d, want 200", mfaStatus)
	}

	// Reset mail and redeem with a new password.
	requested := post(t, f.handler, "/v1/password-resets", `{"email":"`+email+`"}`)
	if requested.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/password-resets = %d, want 202; body: %s", requested.Code, requested.Body)
	}
	redeemed := sendWith(t, f.handler, http.MethodPost, "/v1/password-resets/confirm", "", "",
		`{"token":"`+tokenIn(t, f.mailer.last(t))+`","password":"`+postResetMFANewPassword+`"}`)
	if redeemed.Code != http.StatusNoContent {
		t.Fatalf("POST /v1/password-resets/confirm = %d, want 204; body: %s", redeemed.Code, redeemed.Body)
	}

	// The pre-reset session is dead: the reset's documented promise.
	me := sendWith(t, f.handler, http.MethodGet, "/v1/me", oldSession, "", "")
	if me.Code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/me with the pre-reset session = %d, want 401; body: %s", me.Code, me.Body)
	}

	// Sign in with the NEW password: 202 with a fresh challenge, as the walk saw.
	_, _, challengeStatus, sessionStatus := f.loginWithFactor(t, email, postResetMFANewPassword, started.Secret)
	if challengeStatus != http.StatusAccepted {
		t.Fatalf("POST /v1/session after reset = %d, want 202", challengeStatus)
	}
	// THE WALK'S EXPECTATION: a freshly generated code against the fresh
	// challenge mints a session.
	if sessionStatus != http.StatusOK {
		t.Fatalf("POST /v1/session/mfa after reset = %d, want 200: the merged walk stops here", sessionStatus)
	}
}
