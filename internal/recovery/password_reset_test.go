package recovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/tenancy"
)


func TestAResetForAnUnknownAddressSendsNothingAndWritesNothing(t *testing.T) {
	h := newHarness(t, false)

	if err := h.svc.RequestPasswordReset(t.Context(), dbtest.UniqueEmail(t)); err != nil {
		t.Fatalf("RequestPasswordReset for an unknown address = %v, want nil", err)
	}

	if got := h.mailer.count(); got != 0 {
		t.Errorf("%d messages delivered for an address with no account, want 0", got)
	}
	private := newHarness(t, true)
	if err := private.svc.RequestPasswordReset(t.Context(), dbtest.UniqueEmail(t)); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if got := countRows(t, private, `SELECT count(*) FROM recovery_tokens`); got != 0 {
		t.Errorf("%d recovery_tokens rows exist after a request for an address with no account", got)
	}
}

func TestAResetForAKnownAddressWritesExactlyOneRowAndOneMessage(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	if err := h.svc.RequestPasswordReset(t.Context(), who.email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	if got := h.mailer.count(); got != 1 {
		t.Errorf("%d messages delivered, want exactly 1", got)
	}
	if got := h.tokenRowCount(who.id, PurposePasswordReset); got != 1 {
		t.Errorf("%d password_reset rows, want 1", got)
	}

	message := h.mailer.last(t)
	if message.To != who.email {
		t.Errorf("the message went to %q, want the account's own address %q", message.To, who.email)
	}
}

func TestAResetRequestInsideTheWindowSendsNothing(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	if err := h.svc.RequestPasswordReset(t.Context(), who.email); err != nil {
		t.Fatalf("the first request: %v", err)
	}

	for i := range 20 {
		h.clk.Advance(time.Second)
		if err := h.svc.RequestPasswordReset(t.Context(), who.email); err != nil {
			t.Fatalf("request %d inside the window = %v, want nil", i+2, err)
		}
	}

	if got := h.mailer.count(); got != 1 {
		t.Errorf("%d messages after 21 requests inside a %s window, want 1", got, RequestWindow)
	}
	if got := h.tokenRowCount(who.id, PurposePasswordReset); got != 1 {
		t.Errorf("%d rows after 21 requests, want 1", got)
	}

	h.clk.Advance(RequestWindow - 21*time.Second - time.Second)
	if err := h.svc.RequestPasswordReset(t.Context(), who.email); err != nil {
		t.Fatalf("a request one second short of the window: %v", err)
	}
	if got := h.mailer.count(); got != 1 {
		t.Errorf("%d messages one second short of the window, want 1", got)
	}

	h.clk.Advance(2 * time.Second)
	if err := h.svc.RequestPasswordReset(t.Context(), who.email); err != nil {
		t.Fatalf("the request after the window: %v", err)
	}
	if got := h.mailer.count(); got != 2 {
		t.Errorf("%d messages after a request outside the window, want 2", got)
	}
	if got := h.tokenRowCount(who.id, PurposePasswordReset); got != 2 {
		t.Errorf("%d rows after two requests outside the window, want 2 — a later request must "+
			"not invalidate the link already sitting in somebody's inbox", got)
	}
}

func TestAReusedResetTokenIsRefused(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	token := h.requestReset(t, who)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "a brand new password",
	}); err != nil {
		t.Fatalf("the first redemption: %v", err)
	}

	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "a third password entirely",
	}); err == nil {
		t.Fatal("a reset token was accepted twice")
	}

	assertPasswordIs(t, h, who, "a brand new password")
	assertPasswordIsNot(t, h, who, "a third password entirely")
}

func TestAnExpiredResetTokenIsRefused(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	token := h.requestReset(t, who)

	row := h.storedTokenRow(h.newestTokenID(who.id, PurposePasswordReset))
	wantExpiry := h.now().Add(PasswordResetTTL)
	if !row["expires_at"].(time.Time).Equal(wantExpiry) {
		t.Errorf("the row expires at %v, want %v", row["expires_at"], wantExpiry)
	}

	h.clk.Advance(PasswordResetTTL - time.Second)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "still inside the window",
	}); err != nil {
		t.Fatalf("a token one second before its own expiry was refused: %v", err)
	}

	h.clk.Advance(2 * time.Second)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "past the window",
	}); err == nil {
		t.Fatal("an expired reset token was accepted")
	}
	assertPasswordIs(t, h, who, "still inside the window")
}

func TestATokenMintedForOneAccountDoesNotTouchAnother(t *testing.T) {
	h := newHarness(t, false)
	alice := h.registerSimple()
	bob := h.registerSimple()

	bobSessionsBefore := h.sessionsFor(bob.id)
	bobDigestBefore := digestOf(t, h, bob)

	token := h.requestReset(t, alice)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "alice's new password",
	}); err != nil {
		t.Fatalf("the redemption: %v", err)
	}

	assertPasswordIs(t, h, alice, "alice's new password")
	assertPasswordIsNot(t, h, alice, "correct horse battery staple")

	if got := digestOf(t, h, bob); got != bobDigestBefore {
		t.Error("redeeming one account's reset token changed another account's password")
	}
	if got := h.sessionsFor(bob.id); got != bobSessionsBefore {
		t.Errorf("redeeming one account's reset token ended %d of another account's sessions",
			bobSessionsBefore-got)
	}
	if _, swept := h.access.swept(bob.id); swept {
		t.Error("redeeming one account's reset token revoked another account's access tokens")
	}
	if got := h.tokenRowCount(bob.id, PurposePasswordReset); got != 0 {
		t.Errorf("%d reset tokens exist for the account that never asked for one", got)
	}
}

func TestAResetRevokesEverySessionAndEveryAccessToken(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	_, second, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("minting a second session: %v", err)
	}
	if _, err := sessions.NewStore(h.pool).Create(t.Context(), h.pool, sessions.NewSession{
		UserID: who.id, TokenDigest: second,
		ExpiresAt: h.now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("creating a second session: %v", err)
	}
	if got := h.sessionsFor(who.id); got != 2 {
		t.Fatalf("%d sessions before the reset, want 2", got)
	}

	token := h.requestReset(t, who)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "the recovered password",
	}); err != nil {
		t.Fatalf("the redemption: %v", err)
	}

	if got := h.sessionsFor(who.id); got != 0 {
		t.Errorf("%d sessions survived a password reset, want 0: a reset that leaves the old "+
			"session alive is not a reset", got)
	}
	at, swept := h.access.swept(who.id)
	if !swept {
		t.Error("no access tokens were revoked")
	} else if !at.Equal(h.now()) {
		t.Errorf("the access tokens were revoked at %s, want the service clock's %s", at, h.now())
	}
}

func TestAResetDoesNotRevokeAScopedAPIKey(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	accountID, keyID := id.MustNew(), id.MustNew()
	_, keyDigest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("minting the fixture key's digest: %v", err)
	}
	runner := db.TxRunner{Pool: h.pool}
	if err := runner.Do(t.Context(), func(ctx context.Context, q db.Querier) error {
		if _, err := q.Exec(ctx,
			`INSERT INTO accounts (id, name, slug, personal) VALUES ($1, 'Reset Fixture', $2, false)`,
			accountID, "reset-fixture-"+strings.ReplaceAll(accountID.String(), "-", "")[:8]); err != nil {
			return fmt.Errorf("creating the fixture account: %w", err)
		}
		if err := tenancy.BeginAccount(ctx, q, accountID); err != nil {
			return fmt.Errorf("beginning as the fixture account: %w", err)
		}
		if _, err := q.Exec(ctx, `
			INSERT INTO account_users (account_id, user_id, role) VALUES ($1, $2, 'owner')`,
			accountID, who.id); err != nil {
			return fmt.Errorf("creating the fixture membership: %w", err)
		}
		if _, err := q.Exec(ctx, `
			INSERT INTO api_keys (id, user_id, account_id, name, token_digest, scopes, created_at, expires_at)
			VALUES ($1, $2, $3, 'reset-fixture', $4, ARRAY['accounts:read'], $5, $6)`,
			keyID, who.id, accountID, keyDigest, h.now(), h.now().Add(90*24*time.Hour)); err != nil {
			return fmt.Errorf("creating the fixture api key: %w", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("building the account-scoped fixture: %v", err)
	}

	token := h.requestReset(t, who)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "the recovered password",
	}); err != nil {
		t.Fatalf("the redemption: %v", err)
	}

	var revokedAt *time.Time
	readRunner := db.TxRunner{Pool: h.pool}
	if err := readRunner.Do(t.Context(), func(ctx context.Context, q db.Querier) error {
		if err := tenancy.BeginAccount(ctx, q, accountID); err != nil {
			return fmt.Errorf("beginning as the fixture account to read it: %w", err)
		}
		return q.QueryRow(ctx, `SELECT revoked_at FROM api_keys WHERE id = $1`, keyID).Scan(&revokedAt)
	}); err != nil {
		t.Fatalf("reading the api key: %v", err)
	}
	if revokedAt != nil {
		t.Errorf("the api key was revoked at %s by a password reset. README.md records the decision "+
			"not to sweep machine credentials here: a CI job stops working with nothing in the "+
			"response saying why", revokedAt)
	}
}

func TestAResetClearsALockout(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	if _, err := h.pool.Exec(t.Context(), `
		UPDATE users SET failed_login_attempts = 5, locked_until = $2 WHERE id = $1`,
		who.id, h.now().Add(15*time.Minute)); err != nil {
		t.Fatalf("locking the account: %v", err)
	}

	token := h.requestReset(t, who)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "the recovered password",
	}); err != nil {
		t.Fatalf("the redemption: %v", err)
	}

	var attempts int
	var lockedUntil *time.Time
	if err := h.pool.QueryRow(t.Context(),
		`SELECT failed_login_attempts, locked_until FROM users WHERE id = $1`, who.id).
		Scan(&attempts, &lockedUntil); err != nil {
		t.Fatalf("reading the lockout state: %v", err)
	}
	if attempts != 0 || lockedUntil != nil {
		t.Errorf("after a reset: %d attempts, locked until %v; want 0 and no lock — somebody else's "+
			"five wrong guesses must not survive a proof of mailbox control", attempts, lockedUntil)
	}
}

func TestAResetTokenIsStoredAsADigestAndThePlaintextIsNowhere(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	token := h.requestReset(t, who)
	digest := sessions.Digest(token)

	row := h.storedTokenRow(h.newestTokenID(who.id, PurposePasswordReset))
	stored, _ := row["token_digest"].(string)
	if stored != digest {
		t.Errorf("token_digest = %q, want sessions.Digest of the mailed token", stored)
	}
	if strings.Contains(stored, token) {
		t.Error("token_digest contains the token")
	}

	table := dumpTable(t, h, `SELECT * FROM recovery_tokens`)
	for _, forbidden := range []string{token, token[:20]} {
		if strings.Contains(table, forbidden) {
			t.Errorf("the recovery_tokens table contains the plaintext token (%q)", forbidden)
		}
	}
	if !strings.Contains(table, digest) {
		t.Error("the digest is not in the table either, so this test would pass on a table that " +
			"stored nothing at all")
	}

	events := dumpTable(t, h, `SELECT * FROM outbox_events`)
	if strings.Contains(events, token) {
		t.Error("the token reached the outbox")
	}
}

func TestAResetTokenIsNotAVerificationToken(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	reset := h.requestReset(t, who)
	h.clk.Advance(RequestWindow + time.Second)
	if err := h.svc.RequestVerification(t.Context(), who.email); err != nil {
		t.Fatalf("RequestVerification: %v", err)
	}
	verify := tokenFrom(t, h.mailer.last(t))

	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: reset}); err == nil {
		t.Error("a password reset token was accepted by the verification redemption")
	}
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: verify, Password: "a new password",
	}); err == nil {
		t.Error("a verification token was accepted by the password reset redemption")
	}

	assertPasswordIs(t, h, who, "correct horse battery staple")
	assertNotVerified(t, h, who)
}

func TestADeploymentWithNoMailerRefusesBeforeItLearnsAnything(t *testing.T) {
	h := newHarness(t, true)
	known := h.registerSimple()
	h.mailer.mu.Lock()
	h.mailer.readyErr = ErrNoMailer
	h.mailer.mu.Unlock()

	unknown := dbtest.UniqueEmail(t)
	for _, address := range []string{known.email, unknown, "not-an-address", ""} {
		if err := h.svc.RequestPasswordReset(t.Context(), address); !errors.Is(err, ErrNoMailer) {
			t.Errorf("RequestPasswordReset(%q) = %v, want ErrNoMailer", address, err)
		}
		if err := h.svc.RequestVerification(t.Context(), address); !errors.Is(err, ErrNoMailer) {
			t.Errorf("RequestVerification(%q) = %v, want ErrNoMailer", address, err)
		}
	}
	if _, err := h.svc.RequestEmailChange(t.Context(), RequestEmailChangeInput{
		UserID: known.id, Email: dbtest.UniqueEmail(t),
	}); !errors.Is(err, ErrNoMailer) {
		t.Errorf("RequestEmailChange = %v, want ErrNoMailer", err)
	}

	if got := countRows(t, h, `SELECT count(*) FROM recovery_tokens`); got != 0 {
		t.Errorf("%d rows were written by requests this deployment cannot deliver", got)
	}
	if got := h.mailer.count(); got != 0 {
		t.Errorf("%d messages were sent by a deployment that reported it could not send any", got)
	}
}

func TestUnavailableRefusesEveryEntryPoint(t *testing.T) {
	var m Mailer = Unavailable{}

	if err := m.Ready(t.Context()); !errors.Is(err, ErrNoMailer) {
		t.Errorf("Ready = %v, want ErrNoMailer", err)
	}
	if err := m.Send(t.Context(), Message{To: "kaka@example.com", Body: "hello"}); !errors.Is(err, ErrNoMailer) {
		t.Errorf("Send = %v, want ErrNoMailer", err)
	}
}

func TestAMalformedAddressIsRefusedAndNoRowIsWritten(t *testing.T) {
	h := newHarness(t, true)

	for _, address := range []string{"", "   ", "not-an-address", "a@b", "no dot@here"} {
		err := h.svc.RequestPasswordReset(t.Context(), address)
		if !errIsFieldError(err, "email") {
			t.Errorf("RequestPasswordReset(%q) = %v, want a field error naming email", address, err)
		}
	}
	if got := countRows(t, h, `SELECT count(*) FROM recovery_tokens`); got != 0 {
		t.Errorf("%d rows exist after four malformed requests", got)
	}
}


func (h *harness) requestReset(t *testing.T, who account) string {
	t.Helper()
	if err := h.svc.RequestPasswordReset(t.Context(), who.email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	return tokenFrom(t, h.mailer.last(t))
}

func assertPasswordIs(t *testing.T, h *harness, who account, plaintext string) {
	t.Helper()
	if !testHasher().Verify(digestOf(t, h, who), plaintext) {
		t.Errorf("the account's password is not %q any more", plaintext)
	}
}

func assertPasswordIsNot(t *testing.T, h *harness, who account, plaintext string) {
	t.Helper()
	if testHasher().Verify(digestOf(t, h, who), plaintext) {
		t.Errorf("the account's password is still %q", plaintext)
	}
}

func digestOf(t *testing.T, h *harness, who account) string {
	t.Helper()
	var digest string
	if err := h.pool.QueryRow(t.Context(),
		`SELECT password_digest FROM users WHERE id = $1`, who.id).Scan(&digest); err != nil {
		t.Fatalf("reading the password digest: %v", err)
	}
	return digest
}

func assertNotVerified(t *testing.T, h *harness, who account) {
	t.Helper()
	var at *time.Time
	if err := h.pool.QueryRow(t.Context(),
		`SELECT email_verified_at FROM users WHERE id = $1`, who.id).Scan(&at); err != nil {
		t.Fatalf("reading the verification state: %v", err)
	}
	if at != nil {
		t.Errorf("the address is verified as of %s; a refused token marked it proved", at)
	}
}

func assertVerified(t *testing.T, h *harness, who account) {
	t.Helper()
	var at *time.Time
	if err := h.pool.QueryRow(t.Context(),
		`SELECT email_verified_at FROM users WHERE id = $1`, who.id).Scan(&at); err != nil {
		t.Fatalf("reading the verification state: %v", err)
	}
	if at == nil {
		t.Fatal("the address is not verified")
	}
	if !at.Equal(h.now()) {
		t.Errorf("verified at %s, want the service clock's %s", at, h.now())
	}
}

func countRows(t *testing.T, h *harness, query string, args ...any) int {
	t.Helper()
	var n int
	if err := h.pool.QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatalf("counting (%s): %v", query, err)
	}
	return n
}

func dumpTable(t *testing.T, h *harness, query string, args ...any) string {
	t.Helper()
	rows, err := h.pool.Query(t.Context(), query, args...)
	if err != nil {
		t.Fatalf("dumping (%s): %v", query, err)
	}
	defer rows.Close()

	var b strings.Builder
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			t.Fatalf("reading a dumped row: %v", err)
		}
		for _, v := range values {
			b.WriteString(stringify(v))
			b.WriteByte('\n')
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("dumping rows: %v", err)
	}
	return b.String()
}

func stringify(v any) string {
	switch typed := v.(type) {
	case nil:
		return "<nil>"
	case []byte:
		return string(typed)
	case time.Time:
		return typed.Format(time.RFC3339Nano)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}
