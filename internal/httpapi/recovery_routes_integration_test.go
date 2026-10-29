package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/recovery"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/users"
)


type recoveryServerFixture struct {
	handler http.Handler
	pool    *pgxpool.Pool
	clk     *clock.Fake
	mailer  *captureMailer
	access  *captureAccessRevoker
	svc     *recovery.Service
}

type captureMailer struct {
	mu   sync.Mutex
	sent []recovery.Message
}

func (m *captureMailer) Ready(context.Context) error { return nil }

func (m *captureMailer) Send(_ context.Context, msg recovery.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

func (m *captureMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func (m *captureMailer) last(t *testing.T) recovery.Message {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		t.Fatal("no message was delivered")
	}
	return m.sent[len(m.sent)-1]
}

type captureAccessRevoker struct {
	mu      sync.Mutex
	revoked map[string]time.Time
}

func (r *captureAccessRevoker) RevokeAccessTokensForUser(
	_ context.Context, _ db.Querier, userID id.UUID, at time.Time,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[userID.String()] = at
	return nil
}

func (r *captureAccessRevoker) swept(userID id.UUID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.revoked[userID.String()]
	return ok
}

func newRecoveryServerFixture(t *testing.T) *recoveryServerFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	mailer := &captureMailer{}
	access := &captureAccessRevoker{revoked: map[string]time.Time{}}
	hasher := users.NewHasherWithParams(&argon2id.Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})

	svc := recovery.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		recovery.NewStore(pool),
		users.NewStore(pool),
		sessions.NewStore(pool),
		access,
		outbox.NewStore(pool),
		mailer,
		hasher,
		clk,
		noEnrolledSecondFactor{},
	)

	return &recoveryServerFixture{
		handler: New(nil, WithAuth(authServiceFor(pool, clk)), WithRecovery(svc)),
		pool:    pool,
		clk:     clk,
		mailer:  mailer,
		access:  access,
		svc:     svc,
	}
}

func (f *recoveryServerFixture) signUp(t *testing.T) (string, string) {
	t.Helper()

	email := dbtest.UniqueEmail(t)
	registerThrough(t, f.handler, email)

	rec := post(t, f.handler, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}
	return email, session.Token
}

func tokenIn(t *testing.T, m recovery.Message) string {
	t.Helper()
	for _, line := range strings.Split(m.Body, "\n") {
		candidate := strings.TrimSpace(line)
		if len(candidate) == 43 && !strings.ContainsAny(candidate, " \t") {
			return candidate
		}
	}
	t.Fatalf("no token in the delivered message:\n%s", m.Body)
	return ""
}

func (f *recoveryServerFixture) sessionsFor(t *testing.T, email string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(t.Context(), `
		SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.email = $1`,
		email).Scan(&n); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}
	return n
}

func (f *recoveryServerFixture) userIDFor(t *testing.T, email string) id.UUID {
	t.Helper()
	var out id.UUID
	if err := f.pool.QueryRow(t.Context(), `SELECT id FROM users WHERE email = $1`, email).Scan(&out); err != nil {
		t.Fatalf("resolving %s: %v", email, err)
	}
	return out
}

func (f *recoveryServerFixture) verifyAddress(t *testing.T, email string) {
	t.Helper()

	requested := post(t, f.handler, "/v1/email-verifications", `{"email":"`+email+`"}`)
	if requested.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/email-verifications = %d, want 202; body: %s", requested.Code, requested.Body)
	}
	confirmed := sendWith(t, f.handler, http.MethodPost, "/v1/email-verifications/confirm", "",
		"", `{"token":"`+tokenIn(t, f.mailer.last(t))+`"}`)
	if confirmed.Code != http.StatusNoContent {
		t.Fatalf("the confirmation = %d, want 204; body: %s", confirmed.Code, confirmed.Body)
	}
	if got := verificationState(t, f, email); got != "verified" {
		t.Fatalf("the address is %s after a confirmation, want verified", got)
	}
}

func verificationState(t *testing.T, f *recoveryServerFixture, email string) string {
	t.Helper()
	var at *time.Time
	if err := f.pool.QueryRow(t.Context(),
		`SELECT email_verified_at FROM users WHERE email = $1`, email).Scan(&at); err != nil {
		t.Fatalf("reading the verification state of %s: %v", email, err)
	}
	if at == nil {
		return "unverified"
	}
	return "verified"
}

func TestTheWholeResetFlowOverHTTP(t *testing.T) {
	f := newRecoveryServerFixture(t)
	email, token := f.signUp(t)

	requested := post(t, f.handler, "/v1/password-resets", `{"email":"`+email+`"}`)
	if requested.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/password-resets = %d, want 202; body: %s", requested.Code, requested.Body)
	}

	redeemed := sendWith(t, f.handler, http.MethodPost, "/v1/password-resets/confirm", "",
		"", `{"token":"`+tokenIn(t, f.mailer.last(t))+`","password":"a completely new password"}`)
	if redeemed.Code != http.StatusNoContent {
		t.Fatalf("the confirmation = %d, want 204; body: %s", redeemed.Code, redeemed.Body)
	}

	if got := f.sessionsFor(t, email); got != 0 {
		t.Errorf("%d sessions survived a password reset, want 0", got)
	}
	me := sendWith(t, f.handler, http.MethodGet, "/v1/me", token, "", "")
	if me.Code != http.StatusUnauthorized {
		t.Errorf("GET /v1/me with the pre-reset token = %d, want 401", me.Code)
	}

	if rec := post(t, f.handler, "/v1/session",
		`{"email":"`+email+`","password":"a completely new password"}`); rec.Code != http.StatusOK {
		t.Errorf("signing in with the new password = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if rec := post(t, f.handler, "/v1/session",
		`{"email":"`+email+`","password":"`+validPassword+`"}`); rec.Code == http.StatusOK {
		t.Error("the old password still signs in after a reset")
	}
}

func TestTheTwoRequestRoutesAnswerIdenticallyOverHTTP(t *testing.T) {
	f := newRecoveryServerFixture(t)
	known, _ := f.signUp(t)
	unknown := dbtest.UniqueEmail(t)

	for _, address := range []string{known, unknown} {
		reset := post(t, f.handler, "/v1/password-resets", `{"email":"`+address+`"}`)
		if reset.Code != http.StatusAccepted {
			t.Fatalf("a reset request for %s = %d, want 202; body: %s", address, reset.Code, reset.Body)
		}
		if got := reset.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Errorf("Content-Type = %q", got)
		}
	}

	first := post(t, f.handler, "/v1/password-resets", `{"email":"`+known+`"}`)
	if first.Code != http.StatusAccepted {
		t.Fatalf("the known-address request = %d, want 202", first.Code)
	}
	second := post(t, f.handler, "/v1/password-resets", `{"email":"`+unknown+`"}`)
	if first.Body.String() != second.Body.String() {
		t.Errorf("the two answers differ:\nknown:   %s\nunknown: %s", first.Body, second.Body)
	}

	if got := f.mailer.count(); got != 1 {
		t.Errorf("%d messages for one known address and one unknown, want 1", got)
	}
	if got := f.mailer.last(t).To; got != known {
		t.Errorf("the message went to %q, want the known address %q", got, known)
	}
}

func TestATruncatedTokenAnswers404Not422(t *testing.T) {
	f := newRecoveryServerFixture(t)
	email, _ := f.signUp(t)

	post(t, f.handler, "/v1/email-verifications", `{"email":"`+email+`"}`)
	live := tokenIn(t, f.mailer.last(t))
	if want := 43; len(live) != want {
		t.Fatalf("the token this service mailed is %d characters, and RecoveryTokenRequest "+
			"declares minLength and maxLength %d. Fix the document or the mint; this test "+
			"truncates on the declared length", len(live), want)
	}

	routes := []struct{ path, body string }{
		{"/v1/email-verifications/confirm", `{"token":%q}`},
		{"/v1/email-changes/current-address", `{"token":%q}`},
		{"/v1/email-changes/new-address", `{"token":%q}`},
	}
	shapes := []struct{ name, token string }{
		{"truncated by one", live[:len(live)-1]},
		{"far too short", "t"},
		{"one too long", live + "x"},
		{"never existed", strings.Repeat("z", len(live))},
	}

	for _, route := range routes {
		reference := ""
		for _, shape := range shapes {
			body := fmt.Sprintf(route.body, shape.token)
			rec := sendWith(t, f.handler, http.MethodPost, route.path, "", "", body)
			if rec.Code != http.StatusNotFound {
				t.Errorf("POST %s with a token %s = %d, want 404; body: %s",
					route.path, shape.name, rec.Code, rec.Body)
				continue
			}

			p := decodeProblem(t, rec)
			if p.Code != CodeNotFound {
				t.Errorf("POST %s with a token %s: code = %q, want %q",
					route.path, shape.name, p.Code, CodeNotFound)
			}
			p.TraceID = ""
			rendered, err := json.Marshal(p)
			if err != nil {
				t.Fatalf("re-marshaling the problem: %v", err)
			}
			switch {
			case reference == "":
				reference = string(rendered)
			case string(rendered) != reference:
				t.Errorf("POST %s answers differently for a token %s than for one %s:\n  %s\n  %s",
					route.path, shape.name, shapes[0].name, rendered, reference)
			}
		}
		if reference == "" {
			t.Errorf("POST %s produced no comparable answer at all, so the comparison above "+
				"passed vacuously", route.path)
		}
	}

	typo := sendWith(t, f.handler, http.MethodPost, "/v1/email-verifications/confirm", "", "",
		`{"token":"`+live+`","emial":"x"}`)
	if typo.Code != http.StatusUnprocessableEntity {
		t.Errorf("a misspelled field on the confirm route = %d, want 422; body: %s", typo.Code, typo.Body)
	}
}

func TestTheWholeEmailChangeFlowOverHTTP(t *testing.T) {
	f := newRecoveryServerFixture(t)
	email, token := f.signUp(t)
	target := dbtest.UniqueEmail(t)

	requested := sendWith(t, f.handler, http.MethodPost, "/v1/email-changes", token, "",
		`{"email":"`+target+`"}`)
	if requested.Code != http.StatusCreated {
		t.Fatalf("POST /v1/email-changes = %d, want 201; body: %s", requested.Code, requested.Body)
	}

	first := sendWith(t, f.handler, http.MethodPost, "/v1/email-changes/current-address", "",
		"", `{"token":"`+tokenIn(t, f.mailer.last(t))+`"}`)
	if first.Code != http.StatusAccepted {
		t.Fatalf("the current-address confirmation = %d, want 202; body: %s", first.Code, first.Body)
	}
	if got := f.mailer.last(t).To; got != target {
		t.Errorf("the second message went to %q, want the new address %q", got, target)
	}

	second := sendWith(t, f.handler, http.MethodPost, "/v1/email-changes/new-address", "",
		"", `{"token":"`+tokenIn(t, f.mailer.last(t))+`"}`)
	if second.Code != http.StatusOK {
		t.Fatalf("the new-address confirmation = %d, want 200; body: %s", second.Code, second.Body)
	}

	var moved string
	if err := f.pool.QueryRow(t.Context(),
		`SELECT email FROM users WHERE email = $1`, target).Scan(&moved); err != nil {
		t.Fatalf("the new address does not hold the account: %v", err)
	}
	if got := f.sessionsFor(t, target); got != 0 {
		t.Errorf("%d sessions survived an email change, want 0", got)
	}
	if !f.access.swept(f.userIDFor(t, target)) {
		t.Error("an email change revoked no access tokens")
	}
	if got := f.sessionsFor(t, email); got != 0 {
		t.Errorf("%d sessions exist under the old address", got)
	}
}

func TestTheWholeVerificationFlowOverHTTP(t *testing.T) {
	f := newRecoveryServerFixture(t)
	email, token := f.signUp(t)

	before := sendWith(t, f.handler, http.MethodGet, "/v1/email-verification", token, "", "")
	if before.Code != http.StatusOK {
		t.Fatalf("the status read = %d, want 200; body: %s", before.Code, before.Body)
	}
	var off verificationStatusResponse
	if err := json.Unmarshal(before.Body.Bytes(), &off); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if off.EmailVerified {
		t.Error("a brand new account reports a verified address")
	}

	requested := post(t, f.handler, "/v1/email-verifications", `{"email":"`+email+`"}`)
	if requested.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/email-verifications = %d, want 202; body: %s", requested.Code, requested.Body)
	}

	confirmed := sendWith(t, f.handler, http.MethodPost, "/v1/email-verifications/confirm", "",
		"", `{"token":"`+tokenIn(t, f.mailer.last(t))+`"}`)
	if confirmed.Code != http.StatusNoContent {
		t.Fatalf("the confirmation = %d, want 204; body: %s", confirmed.Code, confirmed.Body)
	}

	after := sendWith(t, f.handler, http.MethodGet, "/v1/email-verification", token, "", "")
	var on verificationStatusResponse
	if err := json.Unmarshal(after.Body.Bytes(), &on); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if !on.EmailVerified || on.EmailVerifiedAt == nil {
		t.Errorf("after confirming: %+v, want a verified address with an instant", on)
	}

	if got := f.sessionsFor(t, email); got != 1 {
		t.Errorf("%d sessions after a verification, want 1: confirming an address must not sign "+
			"the user out", got)
	}
}

func TestTheVerificationRequestCannotBeToldApartOverHTTP(t *testing.T) {
	f := newRecoveryServerFixture(t)

	unverified, _ := f.signUp(t)
	verified, _ := f.signUp(t)
	f.verifyAddress(t, verified)
	unknown := dbtest.UniqueEmail(t)

	f.clk.Advance(recovery.RequestWindow + time.Second)

	answers := make(map[string]*httptest.ResponseRecorder, 3)
	sentBefore := f.mailer.count()
	for _, address := range []string{unknown, unverified, verified} {
		rec := post(t, f.handler, "/v1/email-verifications", `{"email":"`+address+`"}`)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("POST /v1/email-verifications for %s = %d, want 202; body: %s",
				address, rec.Code, rec.Body)
		}
		answers[address] = rec
	}

	for _, address := range []string{unverified, verified} {
		got, want := answers[address], answers[unknown]
		if got.Body.String() != want.Body.String() {
			t.Errorf("the answer for a %s account differs from the answer for an address with "+
				"no account:\n%s: %s\nunknown: %s", verificationState(t, f, address), address,
				got.Body, want.Body)
		}
		if ct1, ct2 := got.Header().Get("Content-Type"), want.Header().Get("Content-Type"); ct1 != ct2 {
			t.Errorf("Content-Type for %s = %q, unknown = %q", address, ct1, ct2)
		}
		if h1, h2 := got.Header().Get("Retry-After"), want.Header().Get("Retry-After"); h1 != h2 {
			t.Errorf("Retry-After for %s = %q, unknown = %q", address, h1, h2)
		}
	}

	if got, want := f.mailer.count()-sentBefore, 2; got != want {
		t.Errorf("the three requests sent %d messages, want %d: one per address that has an "+
			"account, and none for the address that has not", got, want)
	}
	if got := f.mailer.last(t).To; got != verified {
		t.Errorf("the last message went to %q, want the verified address %q: a verified "+
			"account is treated exactly as an unverified one", got, verified)
	}
}

func TestTheOIDCEmailVerifiedClaimFollowsTheColumn(t *testing.T) {
	f := newRecoveryServerFixture(t)
	email, _ := f.signUp(t)

	reader := oidc.NewProfileReader()
	before, err := reader.Profile(t.Context(), f.pool, f.userIDFor(t, email))
	if err != nil {
		t.Fatalf("Profile before verifying: %v", err)
	}
	if before.EmailVerified {
		t.Error("the profile claims a verified address before any verification")
	}

	post(t, f.handler, "/v1/email-verifications", `{"email":"`+email+`"}`)
	confirmed := sendWith(t, f.handler, http.MethodPost, "/v1/email-verifications/confirm", "",
		"", `{"token":"`+tokenIn(t, f.mailer.last(t))+`"}`)
	if confirmed.Code != http.StatusNoContent {
		t.Fatalf("the confirmation = %d, want 204; body: %s", confirmed.Code, confirmed.Body)
	}

	after, err := reader.Profile(t.Context(), f.pool, f.userIDFor(t, email))
	if err != nil {
		t.Fatalf("Profile after verifying: %v", err)
	}
	if !after.EmailVerified {
		t.Error("the profile still claims the address is unverified after it was proved")
	}
}

func TestAResetEndsTheAccessTokensIssuedBeforeIt(t *testing.T) {
	f := newRecoveryServerFixture(t)
	email, _ := f.signUp(t)
	userID := f.userIDFor(t, email)

	accountID := id.MustNew()
	if err := f.pool.QueryRow(t.Context(), `
		SELECT au.account_id FROM account_users au
		JOIN accounts a ON a.id = au.account_id
		WHERE au.user_id = $1 ORDER BY a.created_at, a.id LIMIT 1`,
		userID).Scan(&accountID); err != nil {
		t.Fatalf("finding the user's account: %v", err)
	}

	client, err := oidc.NewStore(f.pool).CreateClient(t.Context(), f.pool, oidc.CreateClientParams{
		AccountID:    accountID,
		ClientID:     "reset-fixture-" + id.MustNew().String(),
		Name:         "reset fixture",
		SecretDigest: oidc.SecretDigest(strings.Repeat("a", 64)),
		RedirectURIs: []string{"https://example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "email"},
		CreatedBy:    userID,
		CreatedAt:    f.clk.Now(),
	})
	if err != nil {
		t.Fatalf("creating the fixture client: %v", err)
	}
	clientID := client.ID
	tokenID := id.MustNew()
	if _, err := f.pool.Exec(t.Context(), `
		INSERT INTO oidc_access_tokens (id, client_row_id, subject, scopes, issued_at, expires_at)
		VALUES ($1, $2, $3, ARRAY['openid','email'], $4, $5)`,
		tokenID, clientID, userID, f.clk.Now(), f.clk.Now().Add(15*time.Minute)); err != nil {
		t.Fatalf("creating the fixture access token: %v", err)
	}

	if err := oidc.NewStore(f.pool).RevokeAccessTokensForUser(t.Context(), f.pool, userID, f.clk.Now()); err != nil {
		t.Fatalf("RevokeAccessTokensForUser: %v", err)
	}

	var revokedAt *time.Time
	if err := f.pool.QueryRow(t.Context(),
		`SELECT revoked_at FROM oidc_access_tokens WHERE id = $1`, tokenID).Scan(&revokedAt); err != nil {
		t.Fatalf("reading the access token: %v", err)
	}
	if revokedAt == nil {
		t.Fatal("the access token issued before the reset is still live")
	}

	other, _ := f.signUp(t)
	otherID := f.userIDFor(t, other)
	otherToken := id.MustNew()
	var otherAccount id.UUID
	if err := f.pool.QueryRow(t.Context(), `
		SELECT au.account_id FROM account_users au
		JOIN accounts a ON a.id = au.account_id
		WHERE au.user_id = $1 ORDER BY a.created_at, a.id LIMIT 1`,
		otherID).Scan(&otherAccount); err != nil {
		t.Fatalf("finding the second user's account: %v", err)
	}
	otherClientRow, err := oidc.NewStore(f.pool).CreateClient(t.Context(), f.pool, oidc.CreateClientParams{
		AccountID:    otherAccount,
		ClientID:     "other-fixture-" + id.MustNew().String(),
		Name:         "other fixture",
		SecretDigest: oidc.SecretDigest(strings.Repeat("b", 64)),
		RedirectURIs: []string{"https://example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "email"},
		CreatedBy:    otherID,
		CreatedAt:    f.clk.Now(),
	})
	if err != nil {
		t.Fatalf("creating the second fixture client: %v", err)
	}
	otherClient := otherClientRow.ID
	if _, err := f.pool.Exec(t.Context(), `
		INSERT INTO oidc_access_tokens (id, client_row_id, subject, scopes, issued_at, expires_at)
		VALUES ($1, $2, $3, ARRAY['openid','email'], $4, $5)`,
		otherToken, otherClient, otherID, f.clk.Now(), f.clk.Now().Add(15*time.Minute)); err != nil {
		t.Fatalf("creating the second access token: %v", err)
	}
	if err := oidc.NewStore(f.pool).RevokeAccessTokensForUser(t.Context(), f.pool, userID, f.clk.Now()); err != nil {
		t.Fatalf("RevokeAccessTokensForUser: %v", err)
	}
	if err := f.pool.QueryRow(t.Context(),
		`SELECT revoked_at FROM oidc_access_tokens WHERE id = $1`, otherToken).Scan(&revokedAt); err != nil {
		t.Fatalf("reading the second access token: %v", err)
	}
	if revokedAt != nil {
		t.Error("the sweep revoked another user's access token")
	}
}

func TestNoRecoveryTokenReachesTheLogs(t *testing.T) {
	pool, owner := dbtest.SchemaWithOwner(t)
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	mailer := &captureMailer{}
	logs := &recordingHandler{}

	svc := recovery.NewService(
		db.TxRunner{Pool: pool}, db.Direct{Pool: pool},
		recovery.NewStore(pool), users.NewStore(pool), sessions.NewStore(pool),
		&captureAccessRevoker{revoked: map[string]time.Time{}},
		outbox.NewStore(pool), mailer,
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		clk,
		noEnrolledSecondFactor{},
	)
	handler := New(nil, WithAuth(authServiceFor(pool, clk)), WithRecovery(svc),
		WithLogger(slogLogger(logs)))

	email := dbtest.UniqueEmail(t)
	registerThrough(t, handler, email)
	login := post(t, handler, "/v1/session",
		`{"email":"`+email+`","password":"`+validPassword+`"}`)
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}

	post(t, handler, "/v1/password-resets", `{"email":"`+email+`"}`)
	resetToken := tokenIn(t, mailer.last(t))
	post(t, handler, "/v1/email-verifications", `{"email":"`+email+`"}`)
	sendWith(t, handler, http.MethodPost, "/v1/email-changes", session.Token, "",
		`{"email":"`+dbtest.UniqueEmail(t)+`"}`)
	changeToken := tokenIn(t, mailer.last(t))
	sendWith(t, handler, http.MethodPost, "/v1/email-changes/current-address", "", "",
		`{"token":"`+changeToken+`"}`)

	for _, bad := range []string{"a-token-that-is-not-one", resetToken} {
		sendWith(t, handler, http.MethodPost, "/v1/email-verifications/confirm", "", "",
			`{"token":"`+bad+`"}`)
	}

	silent := logs.rendered()
	if strings.TrimSpace(silent) != "" {
		t.Errorf("the recovery flows logged something, and nothing on this surface should:\n%s", silent)
	}

	if _, err := owner.Exec(t.Context(), `DROP TABLE recovery_tokens`); err != nil {
		t.Fatalf("dropping recovery_tokens: %v", err)
	}
	if rec := sendWith(t, handler, http.MethodPost, "/v1/password-resets/confirm", "", "",
		`{"token":"`+resetToken+`","password":"a brand new password"}`); rec.Code != http.StatusInternalServerError {
		t.Fatalf("the store failure = %d, want 500; body: %s", rec.Code, rec.Body)
	}

	rendered := logs.rendered()
	if strings.TrimSpace(rendered) == "" {
		t.Fatal("the forced 500 logged nothing, so the assertions below would pass vacuously: " +
			"the logger is not proving it works")
	}

	for _, token := range []string{resetToken, changeToken} {
		for _, form := range []string{token, sessions.Digest(token), sessions.Digest(token)[:16]} {
			if strings.Contains(rendered, form) {
				t.Errorf("the rendered logs contain %q… of a recovery token:\n%s", form[:12], rendered)
			}
		}
	}
}
