package sessions

import (
	"testing"
	"time"
)


var start = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func TestAFreshAccountIsUnlocked(t *testing.T) {
	t.Parallel()

	l := Lockout{}

	if l.Locked(start) {
		t.Error("a zero Lockout reports Locked")
	}
	if got := l.RetryAfter(start); got != 0 {
		t.Errorf("RetryAfter = %s, want 0", got)
	}
}

func TestLockTakesEffectOnTheFifthConsecutiveFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		failures   int
		wantLocked bool
	}{
		{name: "after 1", failures: 1, wantLocked: false},
		{name: "after 2", failures: 2, wantLocked: false},
		{name: "after 3", failures: 3, wantLocked: false},
		{name: "after 4", failures: 4, wantLocked: false},
		{name: "after 5", failures: 5, wantLocked: true},
		{name: "after 6 attempts were possible", failures: 6, wantLocked: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			l := Lockout{}
			for range tt.failures {
				l = l.Failed(start)
			}

			if got := l.Locked(start); got != tt.wantLocked {
				t.Errorf("after %d failures Locked = %v, want %v", tt.failures, got, tt.wantLocked)
			}
		})
	}
}

func TestLockExpiresExactlyFifteenMinutesLater(t *testing.T) {
	t.Parallel()

	l := fiveFailures(start)

	if got, want := l.RetryAfter(start), 15*time.Minute; got != want {
		t.Errorf("RetryAfter at the moment of the lock = %s, want %s", got, want)
	}
	if !l.Locked(start.Add(15*time.Minute - time.Nanosecond)) {
		t.Error("unlocked one nanosecond before the window closes")
	}
	if l.Locked(start.Add(15 * time.Minute)) {
		t.Error("still locked exactly at the end of the window; the window is 15 minutes, not 15 minutes and a nanosecond")
	}
	if !l.Locked(start.Add(14 * time.Minute)) {
		t.Error("unlocked a minute before the window closes")
	}
}

func TestRetryAfterCountsDown(t *testing.T) {
	t.Parallel()

	l := fiveFailures(start)

	if got, want := l.RetryAfter(start.Add(5*time.Minute)), 10*time.Minute; got != want {
		t.Errorf("RetryAfter five minutes in = %s, want %s", got, want)
	}
	if got, want := l.RetryAfter(start.Add(14*time.Minute+59*time.Second)), time.Second; got != want {
		t.Errorf("RetryAfter one second before expiry = %s, want %s", got, want)
	}
	if got := l.RetryAfter(start.Add(time.Hour)); got != 0 {
		t.Errorf("RetryAfter after expiry = %s, want 0", got)
	}
}

func TestSuccessResetsTheConsecutiveRun(t *testing.T) {
	t.Parallel()

	l := Lockout{}
	for range 4 {
		l = l.Failed(start)
	}
	if l.Locked(start) {
		t.Fatal("locked after 4 failures")
	}

	l = l.Succeeded()
	if l.FailedAttempts != 0 {
		t.Errorf("FailedAttempts after success = %d, want 0", l.FailedAttempts)
	}
	if l.LockedUntil != nil {
		t.Errorf("LockedUntil after success = %v, want nil", *l.LockedUntil)
	}

	for range 4 {
		l = l.Failed(start)
	}
	if l.Locked(start) {
		t.Error("locked after 4 more failures that were not consecutive with the first 4")
	}
}

func TestSuccessLiftsAnActiveLock(t *testing.T) {
	t.Parallel()

	l := fiveFailures(start).Succeeded()

	if l.Locked(start) {
		t.Error("still locked after a success")
	}
	if got := l.RetryAfter(start); got != 0 {
		t.Errorf("RetryAfter after a success = %s, want 0", got)
	}
}

func TestAnExpiredLockStartsAFreshRun(t *testing.T) {
	t.Parallel()

	l := fiveFailures(start)
	after := start.Add(15 * time.Minute)

	if l.Locked(after) {
		t.Fatal("still locked after the window")
	}

	l = l.Failed(after)
	if l.FailedAttempts != 1 {
		t.Errorf("FailedAttempts on the first failure after expiry = %d, want 1", l.FailedAttempts)
	}
	if l.Locked(after) {
		t.Error("re-locked on the first failure after the window closed")
	}
}

func TestAFullRunAfterExpiryLocksAgain(t *testing.T) {
	t.Parallel()

	l := fiveFailures(start)
	after := start.Add(15 * time.Minute)

	for range 5 {
		l = l.Failed(after)
	}

	if !l.Locked(after) {
		t.Error("not locked after five fresh failures in the new window")
	}
}

func TestFailureWhileLockedDoesNotExtendTheLock(t *testing.T) {
	t.Parallel()

	l := fiveFailures(start)

	for range 10 {
		l = l.Failed(start.Add(time.Minute))
	}

	if got, want := l.RetryAfter(start), 15*time.Minute; got != want {
		t.Errorf("RetryAfter after ten attempts during the lock = %s, want %s", got, want)
	}
	if l.FailedAttempts != 0 {
		t.Errorf("FailedAttempts = %d, want 0 while locked", l.FailedAttempts)
	}
}

func TestLockoutRoundTripsThroughItsTags(t *testing.T) {
	t.Parallel()

	locked := fiveFailures(start)

	if got, want := locked.FailedAttempts, 0; got != want {
		t.Errorf("FailedAttempts on a freshly locked account = %d, want %d", got, want)
	}
	if locked.LockedUntil == nil {
		t.Fatal("LockedUntil is nil after five failures")
	}
	if !locked.LockedUntil.Equal(start.Add(15 * time.Minute)) {
		t.Errorf("LockedUntil = %s, want %s", locked.LockedUntil, start.Add(15*time.Minute))
	}
}

func TestLockoutFromAnUnlockedRow(t *testing.T) {
	t.Parallel()

	l := Lockout{FailedAttempts: 2}

	if l.Locked(start) {
		t.Error("a row with no locked_until reports Locked")
	}
	if got := l.RetryAfter(start); got != 0 {
		t.Errorf("RetryAfter = %s, want 0", got)
	}
	if l.LockedUntil != nil {
		t.Error("LockedUntil is not nil")
	}
}

func fiveFailures(now time.Time) Lockout {
	l := Lockout{}
	for range MaxFailedAttempts {
		l = l.Failed(now)
	}
	return l
}
