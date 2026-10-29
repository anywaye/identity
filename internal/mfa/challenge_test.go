package mfa

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/users"
)

func (h *harness) challengeAt() NewChallenge {
	h.t.Helper()
	challenge, err := h.svc.CreateChallenge(h.t.Context(), CreateChallengeInput{
		UserID:    h.user.ID,
		UserAgent: "Test/1.0",
	})
	if err != nil {
		h.t.Fatalf("CreateChallenge: %v", err)
	}
	return challenge
}

func (h *harness) complete(challenge NewChallenge, code string) (Claim, error) {
	h.t.Helper()

	claim, err := h.svc.VerifyChallenge(h.t.Context(), challenge.Token, code, h.now())
	if err != nil {
		return Claim{}, err
	}

	token, digest, err := sessions.NewToken()
	if err != nil {
		h.t.Fatalf("NewToken: %v", err)
	}
	runner := h.svc.uow
	if err := runner.Do(h.t.Context(), func(ctx context.Context, q db.Querier) error {
		if err := h.svc.Commit(ctx, q, claim, h.now()); err != nil {
			return err
		}
		_, err := sessions.NewStore(h.pool).Create(ctx, q, sessions.NewSession{
			UserID:      claim.UserID(),
			TokenDigest: digest,
			ExpiresAt:   h.now().Add(24 * time.Hour),
		})
		return err
	}); err != nil {
		return Claim{}, err
	}
	_ = token
	return claim, nil
}

func TestACorrectPasswordIsFollowedByAChallengeAndNotASession(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	if got := h.liveSessions(); got != 0 {
		t.Fatalf("%d sessions exist before the login, want 0", got)
	}

	challenge := h.challengeAt()

	if challenge.Token == "" {
		t.Fatal("the challenge carries no token")
	}
	if !challenge.ExpiresAt.After(h.now()) {
		t.Errorf("the challenge expires at %s, which is not after %s", challenge.ExpiresAt, h.now())
	}
	if got := challenge.ExpiresAt.Sub(h.now()); got != ChallengeTTL {
		t.Errorf("the challenge is good for %s, want %s", got, ChallengeTTL)
	}

	if got := h.liveSessions(); got != 0 {
		t.Errorf("%d sessions exist after a challenge was created; a challenge is not a session", got)
	}
	if !challenge.Challenge.Live(h.now()) {
		t.Error("a fresh challenge does not report itself as live")
	}

	if _, err := sessions.NewStore(h.pool).ByToken(t.Context(), h.pool, challenge.Token, h.now()); !errors.Is(err, sessions.ErrNotFound) {
		t.Errorf("a challenge token resolved as a session token: %v", err)
	}
}

func TestAReplayedCodeIsRefused(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	challenge := h.challengeAt()
	captured := h.code()

	first, err := h.complete(challenge, captured)
	if err != nil {
		t.Fatalf("the first use of a code was refused: %v", err)
	}
	if first.Method() != MethodTOTP {
		t.Errorf("Method = %q, want %q", first.Method(), MethodTOTP)
	}

	h.clk.Advance(time.Second)
	if _, err := h.complete(h.challengeAt(), captured); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("a replayed code = %v, want ErrInvalidFactor", err)
	}

	h.clk.Advance(Period + time.Second)
	if _, err := h.complete(h.challengeAt(), captured); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("a code replayed a whole step later = %v, want ErrInvalidFactor", err)
	}

	h.clk.Advance(Period + time.Second)
	if _, err := h.complete(h.challengeAt(), captured); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("a code from two steps ago = %v, want ErrInvalidFactor", err)
	}
}

func TestAReplayCountsAgainstTheSecondFactor(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	challenge := h.challengeAt()
	code := h.code()
	if _, err := h.complete(challenge, code); err != nil {
		t.Fatalf("the first use was refused: %v", err)
	}

	for i := range 2 {
		if _, err := h.complete(h.challengeAt(), code); !errors.Is(err, ErrInvalidFactor) {
			t.Fatalf("replay %d = %v, want ErrInvalidFactor", i+1, err)
		}
	}

	credential, err := h.store.ConfirmedCredential(t.Context(), h.pool, h.user.ID)
	if err != nil {
		t.Fatalf("reading the credential: %v", err)
	}
	if credential.FailedAttempts != 2 {
		t.Errorf("the second factor's counter is %d after two replays, want 2", credential.FailedAttempts)
	}
	user, err := users.NewStore(h.pool).ByID(t.Context(), h.pool, h.user.ID)
	if err != nil {
		t.Fatalf("reading the user: %v", err)
	}
	if user.FailedLoginAttempts != 0 || user.LockedUntil != nil {
		t.Errorf("the password's counter moved: %d attempts, locked until %v", user.FailedLoginAttempts, user.LockedUntil)
	}
}

func TestTheSkewWindowIsTheSameAtTheChallenge(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	secret := h.secret

	for _, c := range []struct {
		name  string
		steps int64
		want  bool
	}{
		{"two steps back is refused", -2, false},
		{"one step back is accepted", -1, true},
		{"the current step is accepted", 0, true},
		{"one step forward is accepted", 1, true},
		{"two steps forward is refused", 2, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h.clk.Advance(Period * 10)
			base := StepAt(h.now(), Period)
			code := codeFor(t, secret, base+c.steps)

			_, err := h.complete(h.challengeAt(), code)
			if c.want && err != nil {
				t.Errorf("a code %d steps from now was refused: %v", c.steps, err)
			}
			if !c.want && !errors.Is(err, ErrInvalidFactor) {
				t.Errorf("a code %d steps from now = %v, want ErrInvalidFactor", c.steps, err)
			}
		})
	}
}

func TestTheChallengeIsSpentByASecondFactorAndNotByAWrongCode(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	challenge := h.challengeAt()

	for i := range sessions.MaxFailedAttempts {
		if _, err := h.complete(challenge, "000000"); !errors.Is(err, ErrInvalidFactor) {
			t.Fatalf("wrong code %d = %v, want ErrInvalidFactor", i+1, err)
		}
	}

	var locked *sessions.LockedError
	if _, err := h.complete(challenge, h.code()); !errors.As(err, &locked) {
		t.Errorf("attempt past the threshold = %v, want a *sessions.LockedError", err)
	}
	if _, err := h.store.LiveChallenge(t.Context(), h.pool, challenge.Token, h.now()); err != nil {
		t.Errorf("a wrong code consumed the challenge: %v", err)
	}

	h.clk.Advance(sessions.LockoutDuration + time.Second)
	if _, err := h.complete(challenge, h.code()); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("a challenge that outlived its own TTL was accepted: %v", err)
	}

	fresh := h.challengeAt()
	h.clk.Advance(2 * Period)
	if _, err := h.complete(fresh, h.code()); err != nil {
		t.Errorf("a login that started after the lockout was refused: %v", err)
	}
	h.clk.Advance(2 * Period)
	if _, err := h.complete(fresh, h.code()); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("a spent challenge was accepted: %v", err)
	}
}

func TestFourChallengeAnswersAreOneAnswer(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	if _, err := h.complete(NewChallenge{Token: "not-a-token"}, "123456"); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("an unknown token = %v, want ErrChallengeNotFound", err)
	}

	spent := h.challengeAt()
	if _, err := h.complete(spent, h.code()); err != nil {
		t.Fatalf("completing a challenge: %v", err)
	}
	h.clk.Advance(2 * Period)
	if _, err := h.complete(spent, h.code()); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("a consumed token = %v, want ErrChallengeNotFound", err)
	}

	expiring := h.challengeAt()
	h.clk.Advance(ChallengeTTL + time.Second)
	if _, err := h.complete(expiring, h.code()); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("an expired token = %v, want ErrChallengeNotFound", err)
	}

	deleted := h.challengeAt()
	if _, err := h.pool.Exec(t.Context(), `DELETE FROM users WHERE id = $1`, h.user.ID); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}
	if _, err := h.complete(deleted, "123456"); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("a challenge for a deleted user = %v, want ErrChallengeNotFound", err)
	}
}

func TestASecondSignInSupersedesTheFirst(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	first := h.challengeAt()
	h.clk.Advance(time.Second)
	second := h.challengeAt()

	h.clk.Advance(2 * Period)
	if _, err := h.complete(first, h.code()); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("the superseded challenge was accepted: %v", err)
	}
	if _, err := h.complete(second, h.code()); err != nil {
		t.Errorf("the current challenge was refused: %v", err)
	}
}

func TestALoginHalfwayThroughWhenTheUserChangesMFA(t *testing.T) {
	t.Run("the user disabled MFA on another device", func(t *testing.T) {
		h := newHarness(t)
		h.enroll()
		challenge := h.challengeAt()

		if err := h.svc.Disable(t.Context(), DisableInput{UserID: h.user.ID, Factor: h.code()}); err != nil {
			t.Fatalf("Disable: %v", err)
		}

		if _, err := h.complete(challenge, h.code()); !errors.Is(err, ErrNotEnabled) {
			t.Errorf("verifying against a credential that is gone = %v, want ErrNotEnabled", err)
		}
		if got := h.liveSessions(); got != 0 {
			t.Errorf("%d sessions exist after a challenge against a disabled credential", got)
		}
	})

	t.Run("the user rotated the secret on another device", func(t *testing.T) {
		h := newHarness(t)
		h.enroll()
		challenge := h.challengeAt()
		oldCode := h.code()

		started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID, Factor: oldCode})
		if err != nil {
			t.Fatalf("rotating: %v", err)
		}
		h.secret = started.Secret
		h.clk.Advance(Period)
		if _, err := h.svc.Confirm(t.Context(), ConfirmInput{
			UserID: h.user.ID, EnrollmentID: started.Credential.ID, Factor: h.code(),
		}); err != nil {
			t.Fatalf("Confirm: %v", err)
		}

		h.clk.Advance(2 * Period)
		if _, err := h.complete(challenge, oldCode); !errors.Is(err, ErrInvalidFactor) {
			t.Errorf("a code from the rotated-away secret = %v, want ErrInvalidFactor", err)
		}
		if _, err := h.complete(h.challengeAt(), h.code()); err != nil {
			t.Errorf("the new secret does not work against a challenge made before the rotation: %v", err)
		}
	})

	t.Run("the user enabled MFA on another device", func(t *testing.T) {
		h := newHarness(t)
		if enabled, err := h.svc.Enabled(t.Context(), h.pool, h.user.ID); err != nil || enabled {
			t.Fatalf("Enabled before enrollment = (%v, %v), want (false, nil)", enabled, err)
		}
		started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID})
		if err != nil {
			t.Fatalf("StartEnrollment: %v", err)
		}
		h.secret = started.Secret
		if enabled, _ := h.svc.Enabled(t.Context(), h.pool, h.user.ID); enabled {
			t.Error("an unconfirmed enrollment reports MFA as enabled")
		}
		if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.code(), h.now()); !errors.Is(err, ErrNotEnabled) {
			t.Errorf("verifying against an unconfirmed secret = %v, want ErrNotEnabled", err)
		}
		if _, err := h.svc.Confirm(t.Context(), ConfirmInput{
			UserID: h.user.ID, EnrollmentID: started.Credential.ID, Factor: h.code(),
		}); err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		if enabled, _ := h.svc.Enabled(t.Context(), h.pool, h.user.ID); !enabled {
			t.Error("a confirmed credential does not report MFA as enabled")
		}
	})
}

func TestCommitConsumesTheChallengeInsideTheCallersTransaction(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	challenge := h.challengeAt()

	claim, err := h.svc.VerifyChallenge(t.Context(), challenge.Token, h.code(), h.now())
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if _, err := h.store.LiveChallenge(t.Context(), h.pool, challenge.Token, h.now()); err != nil {
		t.Fatalf("the challenge was consumed before Commit: %v", err)
	}

	runner := h.svc.uow
	if err := runner.Do(t.Context(), func(ctx context.Context, q db.Querier) error {
		if err := h.svc.Commit(ctx, q, claim, h.now()); err != nil {
			return err
		}
		return errors.New("the session write failed")
	}); err == nil {
		t.Fatal("the transaction was expected to fail")
	}

	if _, err := h.store.LiveChallenge(t.Context(), h.pool, challenge.Token, h.now()); err != nil {
		t.Errorf("a rolled-back Commit consumed the challenge anyway: %v", err)
	}

	h.clk.Advance(Period + time.Second)
	if _, err := h.complete(challenge, h.code()); err != nil {
		t.Errorf("the challenge did not survive the rolled-back Commit: %v", err)
	}
}

func TestCommitClearsTheSecondFactorsFailureRun(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	for range sessions.MaxFailedAttempts - 1 {
		if _, err := h.complete(h.challengeAt(), "000000"); !errors.Is(err, ErrInvalidFactor) {
			t.Fatalf("a wrong code = %v, want ErrInvalidFactor", err)
		}
	}
	if credential, _ := h.store.ConfirmedCredential(t.Context(), h.pool, h.user.ID); credential.FailedAttempts == 0 {
		t.Fatal("the failures were not counted")
	}

	h.clk.Advance(2 * Period)
	if _, err := h.complete(h.challengeAt(), h.code()); err != nil {
		t.Fatalf("a correct code after four wrong ones was refused: %v", err)
	}

	cleared, _ := h.store.ConfirmedCredential(t.Context(), h.pool, h.user.ID)
	if cleared.FailedAttempts != 0 || cleared.LockedUntil != nil {
		t.Errorf("after acceptance: %d attempts, locked until %v; want 0 and no lock",
			cleared.FailedAttempts, cleared.LockedUntil)
	}

	for range sessions.MaxFailedAttempts {
		if _, err := h.complete(h.challengeAt(), "000000"); !errors.Is(err, ErrInvalidFactor) {
			t.Fatalf("a wrong code after the reset = %v, want ErrInvalidFactor", err)
		}
	}
	var locked *sessions.LockedError
	if _, err := h.complete(h.challengeAt(), "000000"); !errors.As(err, &locked) {
		t.Errorf("the attempt after %d wrong ones = %v, want a *sessions.LockedError",
			sessions.MaxFailedAttempts, err)
	}
}

func TestTheSpentStepTableStaysSmall(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	for i := range 25 {
		h.clk.Advance(Period + time.Second)
		if _, err := h.complete(h.challengeAt(), h.code()); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}

	credential, _ := h.store.ConfirmedCredential(t.Context(), h.pool, h.user.ID)
	var rows int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM mfa_used_totp_steps WHERE credential_id = $1`, credential.ID).Scan(&rows); err != nil {
		t.Fatalf("counting spent steps: %v", err)
	}
	if rows > 2*SkewSteps+2 {
		t.Errorf("%d spent-step rows after 25 logins, want at most %d: the prune is not keeping up",
			rows, 2*SkewSteps+2)
	}
	if rows == 0 {
		t.Error("no spent-step rows at all; the prune is discarding the window it must keep")
	}
}

func TestAValueThatIsNeitherShapeIsRefusedWithoutTouchingTheDatabase(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	for _, value := range []string{"", "   ", "abcdef", "12345", "12345678901", "not a code", "🙂"} {
		h.clearFactorFailures()
		h.clk.Advance(Period + time.Second)
		if _, err := h.complete(h.challengeAt(), value); !errors.Is(err, ErrInvalidFactor) {
			t.Errorf("a value of %q = %v, want ErrInvalidFactor", value, err)
		}
	}
	h.clearFactorFailures()
}

func TestTheTokenIsStoredAsADigestAndTheRowIsBoundedByOneUser(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	challenge := h.challengeAt()
	var stored string
	if err := h.pool.QueryRow(t.Context(),
		`SELECT token_digest FROM mfa_challenges WHERE id = $1`, challenge.Challenge.ID).Scan(&stored); err != nil {
		t.Fatalf("reading the challenge: %v", err)
	}
	if stored == challenge.Token {
		t.Fatal("the row holds the challenge token in the clear")
	}
	if stored != sessions.Digest(challenge.Token) {
		t.Error("the stored digest is not the one the sessions package produces")
	}
	if strings.Contains(stored, challenge.Token) {
		t.Error("the stored digest contains the token")
	}

	for range 4 {
		if _, err := h.svc.CreateChallenge(t.Context(), CreateChallengeInput{UserID: h.user.ID}); err != nil {
			t.Fatalf("CreateChallenge: %v", err)
		}
	}
	var rows int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM mfa_challenges WHERE user_id = $1`, h.user.ID).Scan(&rows); err != nil {
		t.Fatalf("counting challenges: %v", err)
	}
	if rows != 1 {
		t.Errorf("%d challenges for one user, want 1", rows)
	}
}
