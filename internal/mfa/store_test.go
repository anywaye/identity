package mfa

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/users"
)


var issuedAt = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func newTestUser(t *testing.T, pool *pgxpool.Pool) users.User {
	t.Helper()
	u, err := users.NewStore(pool).Create(context.Background(), pool, users.CreateParams{
		Email:          dbtest.UniqueEmail(t),
		PasswordDigest: "$argon2id$fake",
	})
	if err != nil {
		t.Fatalf("creating a user: %v", err)
	}
	return u
}

func newCredential(t *testing.T, pool *pgxpool.Pool, user users.User) Credential {
	t.Helper()
	ctx := context.Background()
	expires := issuedAt.Add(EnrollmentTTL)
	row, err := NewStore(pool).CreateCredential(ctx, pool, CreateCredentialParams{
		UserID:           user.ID,
		Method:           MethodTOTP,
		SecretCiphertext: SealPrefix + "ZmFrZS1zZWNyZXQ",
		Digits:           Digits,
		PeriodSeconds:    int(Period / time.Second),
		Algorithm:        AlgorithmSHA1,
		Label:            "anywaye",
		ExpiresAt:        &expires,
		CreatedAt:        issuedAt,
	})
	if err != nil {
		t.Fatalf("creating a credential: %v", err)
	}
	return row
}

func confirm(t *testing.T, pool *pgxpool.Pool, row Credential) Credential {
	t.Helper()
	confirmed, won, err := NewStore(pool).ConfirmCredential(context.Background(), pool, row.ID, issuedAt)
	if err != nil {
		t.Fatalf("confirming: %v", err)
	}
	if !won {
		t.Fatal("confirming a pending credential did not win")
	}
	return confirmed
}

func TestStoreConfirmMakesACredentialLiveAndOnlyOnce(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	ctx := context.Background()

	pending := newCredential(t, pool, user)
	if pending.IsConfirmed() {
		t.Fatal("a newly created credential is already confirmed")
	}

	if _, err := store.ConfirmedCredential(ctx, pool, user.ID); !errors.Is(err, ErrNotEnabled) {
		t.Errorf("a pending credential was returned by the login read: %v", err)
	}

	live, won, err := store.ConfirmCredential(ctx, pool, pending.ID, issuedAt)
	if err != nil || !won {
		t.Fatalf("ConfirmCredential = (%v, %v, %v), want a win", live, won, err)
	}
	if !live.IsConfirmed() {
		t.Error("the confirmed row does not say it is confirmed")
	}
	if live.ExpiresAt != nil {
		t.Error("the confirmed row kept its enrollment expiry; the CHECK requires it cleared")
	}

	if _, won, err := store.ConfirmCredential(ctx, pool, pending.ID, issuedAt); err != nil || won {
		t.Errorf("a second ConfirmCredential = (%v, %v), want (false, nil)", won, err)
	}
}

func TestAUserCannotHoldTwoLiveCredentials(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	ctx := context.Background()

	first := confirm(t, pool, newCredential(t, pool, user))
	second := newCredential(t, pool, user)

	if _, won, err := store.ConfirmCredential(ctx, pool, second.ID, issuedAt); err == nil {
		t.Fatalf("confirming a second credential succeeded (won=%v); the unique index did not fire", won)
	}

	reread, err := store.ConfirmedCredential(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("rereading the live credential: %v", err)
	}
	if reread.ID != first.ID {
		t.Errorf("the live credential is %s, want the original %s", reread.ID, first.ID)
	}

	if err := store.DeleteUnconfirmedFor(ctx, pool, user.ID); err != nil {
		t.Fatalf("deleting pending rows: %v", err)
	}
}

func TestClaimStepIsTheReplayGuard(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	ctx := context.Background()
	credential := confirm(t, pool, newCredential(t, pool, user))

	step := StepAt(issuedAt, Period)

	first, err := store.ClaimStep(ctx, pool, credential.ID, step, issuedAt)
	if err != nil || !first {
		t.Fatalf("the first claim of step %d = (%v, %v), want (true, nil)", step, first, err)
	}
	second, err := store.ClaimStep(ctx, pool, credential.ID, step, issuedAt)
	if err != nil {
		t.Fatalf("claiming a spent step: %v", err)
	}
	if second {
		t.Error("a step was claimed twice; the replay guard did not fire")
	}
}

func TestClaimStepIsAtomicUnderConcurrency(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	step := StepAt(issuedAt, Period)

	const racers = 50
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
		errs    []error
	)
	start := make(chan struct{})

	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := store.ClaimStep(context.Background(), pool, credential.ID, step, issuedAt)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
			if ok {
				winners++
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("%d of the claims errored, first: %v", len(errs), errs[0])
	}
	if winners != 1 {
		t.Errorf("%d of %d concurrent claims of one step succeeded, want exactly 1", winners, racers)
	}
}

func TestStepsAreASetAndNotAHighWaterMark(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()
	base := StepAt(issuedAt, Period)

	for _, step := range []int64{base, base + 1} {
		if ok, err := store.ClaimStep(ctx, pool, credential.ID, step, issuedAt); err != nil || !ok {
			t.Fatalf("claiming step %d = (%v, %v), want (true, nil)", step, ok, err)
		}
	}

	if ok, err := store.ClaimStep(ctx, pool, credential.ID, base-1, issuedAt); err != nil || !ok {
		t.Errorf("an unspent earlier step = (%v, %v), want (true, nil): a high-water mark refuses this", ok, err)
	}

	for _, step := range []int64{base, base + 1, base - 1} {
		if ok, _ := store.ClaimStep(ctx, pool, credential.ID, step, issuedAt); ok {
			t.Errorf("step %d was claimed a second time", step)
		}
	}
}

func TestPruneStepsKeepsTheTableBounded(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()

	for step := int64(1); step <= 50; step++ {
		if _, err := store.ClaimStep(ctx, pool, credential.ID, step, issuedAt); err != nil {
			t.Fatalf("claiming step %d: %v", step, err)
		}
	}

	countSteps := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM mfa_used_totp_steps WHERE credential_id = $1`, credential.ID).Scan(&n); err != nil {
			t.Fatalf("counting spent steps: %v", err)
		}
		return n
	}
	if got := countSteps(); got != 50 {
		t.Fatalf("before pruning there are %d rows, want 50", got)
	}

	if err := store.PruneSteps(ctx, pool, credential.ID, 40); err != nil {
		t.Fatalf("pruning: %v", err)
	}
	if got := countSteps(); got != 10 {
		t.Errorf("after pruning there are %d rows, want 10", got)
	}

	if ok, err := store.ClaimStep(ctx, pool, credential.ID, 5, issuedAt); err != nil || !ok {
		t.Errorf("claiming a pruned step = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestARecoveryCodeIsSingleUse(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()

	digests := []string{RecoveryDigest("7KQF4W2X5DTRM3HN"), RecoveryDigest("AAAA2222BBBB3333")}
	if err := store.InsertRecoveryCodes(ctx, pool, credential.ID, digests, issuedAt); err != nil {
		t.Fatalf("inserting recovery codes: %v", err)
	}

	if got, err := store.CountUnusedRecoveryCodes(ctx, pool, credential.ID); err != nil || got != 2 {
		t.Fatalf("CountUnusedRecoveryCodes = (%d, %v), want (2, nil)", got, err)
	}

	if _, err := store.UnusedRecoveryCode(ctx, pool, credential.ID, RecoveryDigest("ZZZZ2222YYYY3333")); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("an unknown code = %v, want ErrInvalidFactor", err)
	}

	codeID, err := store.UnusedRecoveryCode(ctx, pool, credential.ID, digests[0])
	if err != nil {
		t.Fatalf("looking up a fresh code: %v", err)
	}
	spent, err := store.ConsumeRecoveryCode(ctx, pool, codeID, issuedAt)
	if err != nil || !spent {
		t.Fatalf("ConsumeRecoveryCode = (%v, %v), want (true, nil)", spent, err)
	}
	spent, err = store.ConsumeRecoveryCode(ctx, pool, codeID, issuedAt)
	if err != nil {
		t.Fatalf("consuming a spent code: %v", err)
	}
	if spent {
		t.Error("a recovery code was spent twice")
	}
	if _, err := store.UnusedRecoveryCode(ctx, pool, credential.ID, digests[0]); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("a spent code was found as unused: %v", err)
	}
	if got, _ := store.CountUnusedRecoveryCodes(ctx, pool, credential.ID); got != 1 {
		t.Errorf("%d codes are left, want 1", got)
	}
}

func TestARecoveryCodeIsSingleUseUnderConcurrency(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()

	digest := RecoveryDigest("7KQF4W2X5DTRM3HN")
	if err := store.InsertRecoveryCodes(ctx, pool, credential.ID, []string{digest}, issuedAt); err != nil {
		t.Fatalf("inserting a recovery code: %v", err)
	}
	codeID, err := store.UnusedRecoveryCode(ctx, pool, credential.ID, digest)
	if err != nil {
		t.Fatalf("looking up the code: %v", err)
	}

	const racers = 20
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	start := make(chan struct{})
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := store.ConsumeRecoveryCode(context.Background(), pool, codeID, issuedAt)
			mu.Lock()
			defer mu.Unlock()
			if err == nil && ok {
				winners++
			}
		}()
	}
	close(start)
	wg.Wait()

	if winners != 1 {
		t.Errorf("%d of %d concurrent consumptions of one code succeeded, want exactly 1", winners, racers)
	}
}

func TestAChallengeIsLiveOnce(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	ctx := context.Background()

	other := newTestUser(t, pool)
	addr := netip.MustParseAddr("203.0.113.9")

	token, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	row, err := store.CreateChallenge(ctx, pool, NewChallengeParams{
		UserID:      user.ID,
		TokenDigest: digest,
		UserAgent:   "Test/1.0",
		IP:          &addr,
		CreatedAt:   issuedAt,
		ExpiresAt:   issuedAt.Add(ChallengeTTL),
	})
	if err != nil {
		t.Fatalf("creating a challenge: %v", err)
	}
	if row.IP == nil || *row.IP != addr || row.UserAgent != "Test/1.0" {
		t.Errorf("the challenge recorded %q / %v, want the values it was given", row.UserAgent, row.IP)
	}
	if !row.Live(issuedAt) || !row.Live(issuedAt.Add(ChallengeTTL-time.Second)) {
		t.Error("a fresh challenge is not live")
	}
	if row.Live(issuedAt.Add(ChallengeTTL + time.Second)) {
		t.Error("a challenge is live past its expiry")
	}

	if _, err := store.LiveChallenge(ctx, pool, token, issuedAt); err != nil {
		t.Fatalf("resolving a live challenge: %v", err)
	}
	if _, err := store.LiveChallenge(ctx, pool, "not-the-token", issuedAt); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("an unknown token = %v, want ErrChallengeNotFound", err)
	}
	if _, err := store.LiveChallenge(ctx, pool, token, issuedAt.Add(ChallengeTTL)); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("an expired token = %v, want ErrChallengeNotFound", err)
	}

	consumed, err := store.ConsumeChallenge(ctx, pool, row.ID, issuedAt)
	if err != nil || !consumed {
		t.Fatalf("ConsumeChallenge = (%v, %v), want (true, nil)", consumed, err)
	}
	if consumed, _ := store.ConsumeChallenge(ctx, pool, row.ID, issuedAt); consumed {
		t.Error("a challenge was consumed twice")
	}
	if _, err := store.LiveChallenge(ctx, pool, token, issuedAt); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("a consumed token = %v, want ErrChallengeNotFound", err)
	}

	replacement, _, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if _, err := store.CreateChallenge(ctx, pool, NewChallengeParams{
		UserID:      user.ID,
		TokenDigest: sessions.Digest(replacement),
		CreatedAt:   issuedAt,
		ExpiresAt:   issuedAt.Add(ChallengeTTL),
	}); err != nil {
		t.Fatalf("creating the superseding challenge: %v", err)
	}
	if err := store.DeleteSupersededChallenges(ctx, pool, user.ID, id.UUID{}); err != nil {
		t.Fatalf("deleting superseded challenges: %v", err)
	}
	if _, err := store.LiveChallenge(ctx, pool, replacement, issuedAt); !errors.Is(err, ErrChallengeNotFound) {
		t.Error("a challenge was deleted even though it was the one to keep")
	}
	if _, err := store.CreateChallenge(ctx, pool, NewChallengeParams{
		UserID:      other.ID,
		TokenDigest: digest,
		CreatedAt:   issuedAt,
		ExpiresAt:   issuedAt.Add(ChallengeTTL),
	}); err != nil {
		t.Fatalf("creating another user's challenge: %v", err)
	}
}

func TestDeletingACredentialTakesItsCodesAndItsSpentStepsWithIt(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()

	if err := store.InsertRecoveryCodes(ctx, pool, credential.ID, []string{RecoveryDigest("7KQF4W2X5DTRM3HN")}, issuedAt); err != nil {
		t.Fatalf("inserting a recovery code: %v", err)
	}
	if _, err := store.ClaimStep(ctx, pool, credential.ID, 7, issuedAt); err != nil {
		t.Fatalf("claiming a step: %v", err)
	}
	if err := store.DeleteCredential(ctx, pool, credential.ID); err != nil {
		t.Fatalf("deleting the credential: %v", err)
	}

	for _, table := range []string{"mfa_recovery_codes", "mfa_used_totp_steps"} {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE credential_id = $1`, credential.ID).Scan(&n); err != nil {
			t.Fatalf("counting %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s still has %d rows for a deleted credential", table, n)
		}
	}
}

func TestTheSecondFactorsCounterIsNotThePasswords(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()

	locked := issuedAt.Add(15 * time.Minute)
	if err := store.RecordFactorFailure(ctx, pool, credential.ID, 0, &locked); err != nil {
		t.Fatalf("recording a factor failure: %v", err)
	}

	reread, err := users.NewStore(pool).ByID(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("rereading the user: %v", err)
	}
	if reread.FailedLoginAttempts != 0 || reread.LockedUntil != nil {
		t.Errorf("the user's password counter moved: %d attempts, locked until %v", reread.FailedLoginAttempts, reread.LockedUntil)
	}

	lock := sessions.Lockout{}
	for range 10 {
		lock = lock.Failed(issuedAt)
	}
	if err := users.NewStore(pool).RecordFailedLogin(ctx, pool, user.ID, lock.FailedAttempts, lock.LockedUntil); err != nil {
		t.Fatalf("recording a failed password: %v", err)
	}
	fresh, err := store.ConfirmedCredential(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("rereading the credential: %v", err)
	}
	if !fresh.IsLocked(issuedAt) {
		t.Error("the factor is not locked after the failure that was recorded against it")
	}
	if fresh.FailedAttempts != 0 {
		t.Errorf("the factor's failure run is %d, want 0", fresh.FailedAttempts)
	}

	if err := store.ClearFactorFailures(ctx, pool, credential.ID); err != nil {
		t.Fatalf("clearing the factor's failures: %v", err)
	}
	cleared, err := store.ConfirmedCredential(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("rereading the credential: %v", err)
	}
	if cleared.IsLocked(issuedAt) || cleared.FailedAttempts != 0 {
		t.Errorf("after clearing: %d attempts, locked until %v", cleared.FailedAttempts, cleared.LockedUntil)
	}
	reread, _ = users.NewStore(pool).ByID(ctx, pool, user.ID)
	if !reread.IsLocked(issuedAt) {
		t.Error("clearing the factor's failures lifted the password's lock")
	}
}

func TestTheSchemaRefusesWhatTheGoCodeRefuses(t *testing.T) {
	pool := dbtest.Schema(t)
	user := newTestUser(t, pool)
	ctx := context.Background()
	expires := issuedAt.Add(EnrollmentTTL)

	const insert = `INSERT INTO mfa_credentials
		(user_id, method, secret_ciphertext, digits, period_seconds, algorithm, label, expires_at, confirmed_at, failed_attempts)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	cases := []struct {
		name                                     string
		method, digits, period, algorithm, label string
		expires, confirmed, attempts             any
	}{
		{
			name:   "a method this service does not implement",
			method: "sms", digits: "6", period: "30", algorithm: "SHA1", label: "anywaye",
			expires: expires, attempts: 0,
		},
		{
			name:   "a digit count no verifier can handle",
			method: "totp", digits: "7", period: "30", algorithm: "SHA1", label: "anywaye",
			expires: expires, attempts: 0,
		},
		{
			name:   "a digit count far outside the spec",
			method: "totp", digits: "60", period: "30", algorithm: "SHA1", label: "anywaye",
			expires: expires, attempts: 0,
		},
		{
			name:   "an algorithm no authenticator app speaks",
			method: "totp", digits: "6", period: "30", algorithm: "SHA512", label: "anywaye",
			expires: expires, attempts: 0,
		},
		{
			name:   "a period of zero, which divides by zero in the counter arithmetic",
			method: "totp", digits: "6", period: "0", algorithm: "SHA1", label: "anywaye",
			expires: expires, attempts: 0,
		},
		{
			name:   "a period long enough that a code is a day old",
			method: "totp", digits: "6", period: "86400", algorithm: "SHA1", label: "anywaye",
			expires: expires, attempts: 0,
		},
		{
			name:   "a negative failure count",
			method: "totp", digits: "6", period: "30", algorithm: "SHA1", label: "anywaye",
			expires: expires, attempts: -1,
		},
		{
			name:   "a confirmation that kept its enrollment expiry",
			method: "totp", digits: "6", period: "30", algorithm: "SHA1", label: "anywaye",
			expires: expires, confirmed: issuedAt, attempts: 0,
		},
		{
			name:   "an enrollment with no deadline at all",
			method: "totp", digits: "6", period: "30", algorithm: "SHA1", label: "anywaye",
			expires: nil, attempts: 0,
		},
		{
			name:   "an empty label, which an authenticator app would display as nothing",
			method: "totp", digits: "6", period: "30", algorithm: "SHA1", label: "",
			expires: expires, attempts: 0,
		},
		{
			name:   "a label longer than an authenticator app has room for",
			method: "totp", digits: "6", period: "30", algorithm: "SHA1", label: strings.Repeat("anywaye", 100),
			expires: expires, attempts: 0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, insert,
				user.ID, c.method, "mfa1.c2VhbGVk", c.digits, c.period, c.algorithm, c.label,
				c.expires, c.confirmed, c.attempts,
			); err == nil {
				t.Error("the database accepted a value the Go code refuses")
			}
		})
	}

	t.Run("a credential with no sealed secret at all", func(t *testing.T) {
		const withoutSecret = `INSERT INTO mfa_credentials
			(user_id, method, secret_ciphertext, digits, period_seconds, algorithm, label, expires_at)
			VALUES ($1, 'totp', '', 6, 30, 'SHA1', 'anywaye', $2)`
		if _, err := pool.Exec(ctx, withoutSecret, user.ID, expires); err == nil {
			t.Error("the database accepted a credential with no sealed secret")
		}
	})
}

func TestADatabaseDumpYieldsNoWorkingSecondFactor(t *testing.T) {
	pool := dbtest.Schema(t)
	user := newTestUser(t, pool)
	store := NewStore(pool)
	ctx := context.Background()

	vault, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	sealed, err := vault.Seal(user.ID, secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	expires := issuedAt.Add(EnrollmentTTL)
	credential, err := store.CreateCredential(ctx, pool, CreateCredentialParams{
		UserID: user.ID, Method: MethodTOTP, SecretCiphertext: sealed,
		Digits: Digits, PeriodSeconds: int(Period / time.Second),
		Algorithm: AlgorithmSHA1, Label: "anywaye", ExpiresAt: &expires, CreatedAt: issuedAt,
	})
	if err != nil {
		t.Fatalf("creating a credential: %v", err)
	}
	credential, _, _ = store.ConfirmCredential(ctx, pool, credential.ID, issuedAt)

	codes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatalf("NewRecoveryCodes: %v", err)
	}
	digests := make([]string, 0, len(codes))
	for _, code := range codes {
		digests = append(digests, RecoveryDigest(code))
	}
	if err := store.InsertRecoveryCodes(ctx, pool, credential.ID, digests, issuedAt); err != nil {
		t.Fatalf("inserting recovery codes: %v", err)
	}

	rows, err := pool.Query(ctx, `SELECT secret_ciphertext FROM mfa_credentials WHERE user_id = $1`, user.ID)
	if err != nil {
		t.Fatalf("reading the credentials: %v", err)
	}
	defer rows.Close()
	var stored []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		stored = append(stored, value)
	}
	rows.Close()
	if len(stored) != 1 {
		t.Fatalf("a dump shows %d credentials, want 1", len(stored))
	}

	if stored[0] != sealed {
		t.Fatalf("the row does not hold the sealed value; the assertions below would be vacuous")
	}
	if stored[0] == secret {
		t.Fatal("the row holds the secret in the clear")
	}
	if !isTOTPCode(codeFor(t, secret, StepAt(issuedAt, Period))) {
		t.Fatal("the fixture code is not a real code, so the dump test proves nothing")
	}

	if _, ok := MatchStep(stored[0], codeFor(t, secret, StepAt(issuedAt, Period)), issuedAt, DigitSix, AlgorithmSHA1, Period, SkewSteps); ok {
		t.Error("the stored ciphertext was accepted as a TOTP secret")
	}
	if IsRecoveryCode(stored[0]) {
		t.Error("the stored ciphertext is shaped like a recovery code")
	}

	codeRows, err := pool.Query(ctx, `SELECT code_digest FROM mfa_recovery_codes WHERE credential_id = $1`, credential.ID)
	if err != nil {
		t.Fatalf("reading the recovery codes: %v", err)
	}
	defer codeRows.Close()
	var seen int
	for codeRows.Next() {
		var digest string
		if err := codeRows.Scan(&digest); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		seen++
		for _, code := range codes {
			if digest == code || IsRecoveryCode(digest) {
				t.Error("a stored recovery digest is itself a usable code")
			}
		}
	}
	codeRows.Close()
	if seen != RecoveryCodeCount {
		t.Errorf("a dump shows %d recovery codes, want %d", seen, RecoveryCodeCount)
	}
}

func TestTheDatabaseTierActuallyRan(t *testing.T) {
	if os.Getenv(dbtest.EnvVar) == "" {
		t.Fatalf("%s is not set, so every database test in this package skipped. "+
			"A green run without it verifies nothing: `docker compose up -d postgres`, "+
			"`goose -dir migrations postgres \"$DATABASE_URL\" up`, and re-run with %s set.",
			dbtest.EnvVar, dbtest.EnvVar)
	}
	pool := dbtest.Pool(t)
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("the test database is not reachable: %v", err)
	}
}

func TestTheStoreTakesAQuerierAndRunsInsideTheCallersTransaction(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()

	rolledBack := db.TxRunner{Pool: pool}.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := store.DeleteCredential(ctx, q, credential.ID); err != nil {
			return err
		}
		if _, err := store.ConfirmedCredential(ctx, q, user.ID); !errors.Is(err, ErrNotEnabled) {
			t.Errorf("the delete did not take effect inside the transaction: %v", err)
		}
		return fmt.Errorf("the second write failed")
	})
	if rolledBack == nil {
		t.Fatal("the transaction was expected to fail")
	}

	survived, err := store.ConfirmedCredential(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("the credential did not survive the rollback: %v", err)
	}
	if survived.ID != credential.ID {
		t.Errorf("the surviving credential is %s, want %s", survived.ID, credential.ID)
	}

	runner := db.TxRunner{Pool: pool}
	if err := runner.Do(ctx, func(ctx context.Context, q db.Querier) error {
		return store.DeleteCredential(ctx, q, credential.ID)
	}); err != nil {
		t.Fatalf("committing a deletion: %v", err)
	}
	if _, err := store.ConfirmedCredential(ctx, pool, user.ID); !errors.Is(err, ErrNotEnabled) {
		t.Errorf("a committed delete did not take effect: %v", err)
	}
}
