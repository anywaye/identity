package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/mfa"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/useraudit"
	"github.com/anywaye/identity/internal/users"
)


type mfaHarness struct {
	t      *testing.T
	svc    *Service
	second *mfa.Service
	pool   *pgxpool.Pool
	clk    *clock.Fake
	user   users.User
	email  string
	holds enrolledFactor
}

type enrolledFactor struct {
	Secret       string
	RecoveryCode string
}

func (e enrolledFactor) code(t *testing.T, at time.Time) string {
	t.Helper()
	code, err := mfa.Code(e.Secret, at)
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	return code
}

func newMFAHarness(t *testing.T) *mfaHarness {
	t.Helper()

	svc, pool, clk, second := newIntegrationServiceWithMFA(t)
	email := dbtest.UniqueEmail(t)

	registered, err := svc.Register(context.Background(), RegisterInput{
		Email: email, Password: "correct horse battery",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	parsed, err := id.Parse(registered.ID.String())
	if err != nil {
		t.Fatalf("parsing the registered id: %v", err)
	}

	return &mfaHarness{
		t: t, svc: svc, second: second, pool: pool, clk: clk,
		user:  users.User{ID: parsed, Email: registered.Email},
		email: registered.Email,
	}
}

func (h *mfaHarness) enroll() enrolledFactor {
	h.t.Helper()
	ctx := context.Background()

	started, err := h.second.StartEnrollment(ctx, mfa.StartEnrollmentInput{UserID: h.user.ID})
	if err != nil {
		h.t.Fatalf("StartEnrollment: %v", err)
	}
	holds := enrolledFactor{Secret: started.Secret}

	confirmed, err := h.second.Confirm(ctx, mfa.ConfirmInput{
		UserID:       h.user.ID,
		EnrollmentID: started.Credential.ID,
		Factor:       holds.code(h.t, h.clk.Now()),
	})
	if err != nil {
		h.t.Fatalf("Confirm: %v", err)
	}
	holds.RecoveryCode = confirmed.RecoveryCodes[0]
	h.holds = holds
	return holds
}

func (h *mfaHarness) login() LoginResult {
	h.t.Helper()
	result, err := h.svc.Login(context.Background(), LoginInput{
		Email: h.email, Password: "correct horse battery", UserAgent: "Test/1.0",
	})
	if err != nil {
		h.t.Fatalf("Login: %v", err)
	}
	return result
}

func (h *mfaHarness) sessions() int {
	h.t.Helper()
	var n int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1`, h.user.ID).Scan(&n); err != nil {
		h.t.Fatalf("counting sessions: %v", err)
	}
	return n
}


func TestACorrectPasswordMintsNoSessionForAnAccountWithASecondFactor(t *testing.T) {
	h := newMFAHarness(t)
	h.enroll()

	result := h.login()

	if !result.MFARequired {
		t.Fatal("a correct password for an account with MFA returned a session")
	}
	if result.Token != "" {
		t.Errorf("LoginResult.Token = %q; it must be EMPTY, because a caller that ignores MFARequired reads this field", result.Token)
	}
	if result.Challenge == nil || result.Challenge.Token == "" {
		t.Fatal("LoginResult carries no challenge token, so the login cannot be finished")
	}
	if result.ExpiresAt != result.Challenge.ExpiresAt {
		t.Error("LoginResult.ExpiresAt is not the challenge's; a client reading it would be holding a session's deadline")
	}
	if got := h.sessions(); got != 0 {
		t.Errorf("%d sessions were written for a login that has not presented a second factor", got)
	}
}

func TestTheSessionExistsOnlyAfterTheSecondFactor(t *testing.T) {
	h := newMFAHarness(t)
	h.enroll()

	challenge := h.login().Challenge.Token

	h.clk.Advance(mfa.Period + time.Second)
	result, err := h.svc.CompleteSecondFactor(context.Background(), CompleteSecondFactorInput{
		ChallengeToken: challenge,
		Code:           h.holds.code(t, h.clk.Now()),
	})
	if err != nil {
		t.Fatalf("CompleteSecondFactor: %v", err)
	}

	if result.MFARequired {
		t.Error("a completed login still says a second factor is required")
	}
	if result.Token == "" {
		t.Fatal("a completed login returned no token")
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions after a completed second-factor login, want exactly 1", got)
	}

	user, err := h.svc.Authenticate(context.Background(), result.Token)
	if err != nil {
		t.Fatalf("the token from a second-factor login does not authenticate: %v", err)
	}
	if user.ID != h.user.ID {
		t.Errorf("the token belongs to %s, want %s", user.ID, h.user.ID)
	}
}

func TestARecoveryCodeFinishesTheLoginToo(t *testing.T) {
	h := newMFAHarness(t)
	holds := h.enroll()

	challenge := h.login().Challenge.Token
	result, err := h.svc.CompleteSecondFactor(context.Background(), CompleteSecondFactorInput{
		ChallengeToken: challenge,
		Code:           holds.RecoveryCode,
	})
	if err != nil {
		t.Fatalf("a recovery code did not finish the login: %v", err)
	}
	if result.Token == "" {
		t.Fatal("a completed login returned no token")
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions, want 1", got)
	}

	h.clk.Advance(mfa.Period + time.Second)
	next := h.login().Challenge.Token
	if _, err := h.svc.CompleteSecondFactor(context.Background(), CompleteSecondFactorInput{
		ChallengeToken: next,
		Code:           holds.RecoveryCode,
	}); !errors.Is(err, mfa.ErrInvalidFactor) {
		t.Errorf("a spent recovery code = %v, want ErrInvalidFactor", err)
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions after a replayed recovery code, want 1", got)
	}
}

func TestAReplayedCodeIsRefusedAndNoSecondSessionAppears(t *testing.T) {
	h := newMFAHarness(t)
	h.enroll()

	captured := h.holds.code(t, h.clk.Now())

	if _, err := h.svc.CompleteSecondFactor(context.Background(),
		CompleteSecondFactorInput{ChallengeToken: h.login().Challenge.Token, Code: captured}); err != nil {
		t.Fatalf("the first use was refused: %v", err)
	}
	if got := h.sessions(); got != 1 {
		t.Fatalf("%d sessions after the first use, want 1", got)
	}

	h.clk.Advance(time.Second)
	if _, err := h.svc.CompleteSecondFactor(context.Background(),
		CompleteSecondFactorInput{ChallengeToken: h.login().Challenge.Token, Code: captured}); !errors.Is(err, mfa.ErrInvalidFactor) {
		t.Errorf("a replayed code = %v, want ErrInvalidFactor", err)
	}

	h.clk.Advance(mfa.Period + time.Second)
	if _, err := h.svc.CompleteSecondFactor(context.Background(),
		CompleteSecondFactorInput{ChallengeToken: h.login().Challenge.Token, Code: captured}); !errors.Is(err, mfa.ErrInvalidFactor) {
		t.Errorf("a replayed code a step later = %v, want ErrInvalidFactor", err)
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions after two replays, want 1: a code was accepted twice", got)
	}
}

func TestAWrongCodeProducesNoSession(t *testing.T) {
	h := newMFAHarness(t)
	h.enroll()

	for i := range sessions.MaxFailedAttempts - 1 {
		if _, err := h.svc.CompleteSecondFactor(context.Background(),
			CompleteSecondFactorInput{ChallengeToken: h.login().Challenge.Token, Code: "000000"}); !errors.Is(err, mfa.ErrInvalidFactor) {
			t.Fatalf("attempt %d = %v, want ErrInvalidFactor", i+1, err)
		}
		if got := h.sessions(); got != 0 {
			t.Fatalf("%d sessions after a wrong code", got)
		}
	}

	user, err := users.NewStore(h.pool).ByID(context.Background(), h.pool, h.user.ID)
	if err != nil {
		t.Fatalf("reading the user: %v", err)
	}
	if user.FailedLoginAttempts != 0 || user.LockedUntil != nil {
		t.Errorf("the password's counter moved: %d attempts, locked until %v", user.FailedLoginAttempts, user.LockedUntil)
	}

	h.clk.Advance(mfa.Period + time.Second)
	if _, err := h.svc.CompleteSecondFactor(context.Background(),
		CompleteSecondFactorInput{ChallengeToken: h.login().Challenge.Token, Code: h.holds.code(t, h.clk.Now())}); err != nil {
		t.Errorf("a correct code after four wrong ones was refused: %v", err)
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions, want 1", got)
	}
}

func TestTheSecondFactorsLockoutIsSeparateFromThePasswords(t *testing.T) {
	h := newMFAHarness(t)
	h.enroll()
	ctx := context.Background()

	for range sessions.MaxFailedAttempts {
		if _, err := h.svc.Login(ctx, LoginInput{Email: h.email, Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("a wrong password = %v, want ErrInvalidCredentials", err)
		}
	}

	status, err := h.second.StatusFor(ctx, h.user.ID)
	if err != nil {
		t.Fatalf("StatusFor: %v", err)
	}
	if !status.Enabled {
		t.Error("the password lockout turned the second factor off")
	}
	if status.RecoveryCodesRemaining != mfa.RecoveryCodeCount {
		t.Errorf("%d recovery codes, want %d", status.RecoveryCodesRemaining, mfa.RecoveryCodeCount)
	}

	var locked *LockedError
	if _, err := h.svc.Login(ctx, LoginInput{Email: h.email, Password: "correct horse battery"}); !errors.As(err, &locked) {
		t.Errorf("the password lockout did not take: %v", err)
	}
}

func TestNoSecondFactorConfiguredStillLogsYouIn(t *testing.T) {
	h := newMFAHarness(t)

	result := h.login()
	if result.MFARequired {
		t.Error("an account with no second factor was asked for one")
	}
	if result.Token == "" {
		t.Fatal("Login returned no token for an account with no second factor")
	}
	if result.Challenge != nil {
		t.Error("Login returned a challenge for an account with no second factor")
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions, want 1", got)
	}
}

func TestAPendingEnrollmentDoesNotChangeTheLogin(t *testing.T) {
	h := newMFAHarness(t)
	ctx := context.Background()

	if _, err := h.second.StartEnrollment(ctx, mfa.StartEnrollmentInput{UserID: h.user.ID}); err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}

	result := h.login()
	if result.MFARequired {
		t.Error("an unconfirmed enrollment was treated as a second factor")
	}
	if result.Token == "" {
		t.Error("an unconfirmed enrollment blocked the login entirely")
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions, want 1", got)
	}
}

func TestAServiceWithNoSecondFactorDependencyRefusesToLogIn(t *testing.T) {
	svc, pool, clk, _ := newIntegrationServiceWithMFA(t)
	ctx := context.Background()

	unwired := NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		outbox.NewStore(pool),
		realTenancy(pool, clk),
		nil,
		oidc.NewStore(pool),
		useraudit.NewStore(pool),
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		clk,
		24*time.Hour,
		false,
	)

	email := dbtest.UniqueEmail(t)
	if _, err := svc.Register(ctx, RegisterInput{Email: email, Password: "correct horse battery"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := unwired.Login(ctx, LoginInput{Email: email, Password: "correct horse battery"}); !errors.Is(err, ErrNoSecondFactor) {
		t.Errorf("a login with no second-factor dependency = %v, want ErrNoSecondFactor", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}
	if n != 0 {
		t.Errorf("%d sessions were written by a service that could not check for MFA", n)
	}

}

func TestACompletedLoginClearsBOTHCounters(t *testing.T) {
	h := newMFAHarness(t)
	h.enroll()
	ctx := context.Background()

	for range 3 {
		if _, err := h.svc.Login(ctx, LoginInput{Email: h.email, Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("a wrong password = %v, want ErrInvalidCredentials", err)
		}
	}
	for range 3 {
		if _, err := h.svc.CompleteSecondFactor(ctx, CompleteSecondFactorInput{
			ChallengeToken: h.login().Challenge.Token, Code: "000000",
		}); !errors.Is(err, mfa.ErrInvalidFactor) {
			t.Fatalf("a wrong code = %v, want ErrInvalidFactor", err)
		}
	}

	h.clk.Advance(2 * mfa.Period)
	if _, err := h.svc.CompleteSecondFactor(ctx, CompleteSecondFactorInput{
		ChallengeToken: h.login().Challenge.Token, Code: h.holds.code(t, h.clk.Now()),
	}); err != nil {
		t.Fatalf("the login was refused: %v", err)
	}

	user, err := users.NewStore(h.pool).ByID(ctx, h.pool, h.user.ID)
	if err != nil {
		t.Fatalf("reading the user: %v", err)
	}
	if user.FailedLoginAttempts != 0 || user.LockedUntil != nil {
		t.Errorf("the password's run survived a completed login: %d attempts, locked until %v",
			user.FailedLoginAttempts, user.LockedUntil)
	}
	status, err := h.second.StatusFor(ctx, h.user.ID)
	if err != nil {
		t.Fatalf("StatusFor: %v", err)
	}
	_ = status
	for range sessions.MaxFailedAttempts {
		if _, err := h.svc.CompleteSecondFactor(ctx, CompleteSecondFactorInput{
			ChallengeToken: h.login().Challenge.Token, Code: "000000",
		}); !errors.Is(err, mfa.ErrInvalidFactor) {
			t.Fatalf("a wrong code after the reset = %v, want ErrInvalidFactor", err)
		}
	}
	var locked *LockedError
	if _, err := h.svc.CompleteSecondFactor(ctx, CompleteSecondFactorInput{
		ChallengeToken: h.login().Challenge.Token, Code: "000000",
	}); !errors.As(err, &locked) {
		t.Errorf("the factor did not lock after %d failures post-reset: %v", sessions.MaxFailedAttempts, err)
	}
}
