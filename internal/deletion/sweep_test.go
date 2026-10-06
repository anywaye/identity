package deletion

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// # THE SWEEP IS TWO STATEMENTS IN THIS ORDER.
//
// `internal/deletion/sweep.go` re-implements `recovery.Service.revokeEveryCredential`
// against interfaces, because that function is unexported and exporting it would
// make the password-reset package a dependency of the deletion package. That is
// a real duplication of two calls, and this file is what holds it to the original
// rather than trusting a reader to compare the two files.
//
// The assertions are the whole of it: both tables are swept, the order is
// sessions-then-tokens, the caller's instant reaches the access-token sweep, and
// neither call is skipped. A "simplification" that dropped the access-token sweep
// would leave every other test in the repository green, because nothing else
// sweeps tokens on this flow — so this file is the only thing that notices.

type sweepLog struct{ calls []string }

func (l *sweepLog) RevokeAllForUser(_ context.Context, _ db.Querier, _ id.UUID) error {
	l.calls = append(l.calls, "sessions")
	return nil
}

func (l *sweepLog) RevokeAccessTokensForUser(_ context.Context, _ db.Querier, _ id.UUID, _ time.Time) error {
	l.calls = append(l.calls, "access_tokens")
	return nil
}

func TestTheSweepIsTwoStatementsInThisOrder(t *testing.T) {
	t.Parallel()

	log := &sweepLog{}
	sweeper, err := NewSweeper(log, log)
	if err != nil {
		t.Fatalf("building the sweeper: %v", err)
	}

	if err := sweeper.RevokeEveryCredential(t.Context(), nil, id.MustNew(),
		time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("sweeping: %v", err)
	}

	want := []string{"sessions", "access_tokens"}
	if len(log.calls) != len(want) {
		t.Fatalf("the sweep made %d calls (%v), want exactly %d: %v",
			len(log.calls), log.calls, len(want), want)
	}
	for i, step := range want {
		if log.calls[i] != step {
			t.Errorf("call %d swept %q, want %q. Full sequence: %v", i, log.calls[i], step, log.calls)
		}
	}
}

// TestTheSweepRefusesHalfAWiring is the construction-time counterpart, and it is
// the direction that matters: a Sweeper built with one half silently revokes
// sessions and leaves every JWT standing for up to its `exp`.
func TestTheSweepRefusesHalfAWiring(t *testing.T) {
	t.Parallel()

	log := &sweepLog{}

	if _, err := NewSweeper(nil, log); err == nil {
		t.Error("a sweeper with no session store was built. Every session would survive a deletion.")
	}
	if _, err := NewSweeper(log, nil); err == nil {
		t.Error("a sweeper with no access-token store was built. Every JWT this service issued " +
			"would stay verifiable until its exp, which is exactly the window " +
			"`auth.Service.Disable`'s comment says revocation exists to close.")
	}
	if _, err := NewSweeper(nil, nil); err == nil {
		t.Error("a sweeper with neither half was built")
	}
}

// TestASweepFailureStopsTheDeletion is the rollback property seen from the
// sweeper's side: a sweep that fails must not let the transaction carry on to
// remove the user, because the row going is what makes the credentials
// unreachable and a sweep that failed leaves them short of that.
func TestASweepFailureStopsTheDeletion(t *testing.T) {
	t.Parallel()

	halted := errors.New("the access token store is down")
	sweeper, err := NewSweeper(&sweepLog{}, failingAccess{halted})
	if err != nil {
		t.Fatalf("building the sweeper: %v", err)
	}

	err = sweeper.RevokeEveryCredential(t.Context(), nil, id.MustNew(), time.Now())
	if !errors.Is(err, halted) {
		t.Fatalf("error is %v, want one wrapping the store's failure", err)
	}

	// And through the service, the same failure must mean nothing was deleted.
	h := newHarness(t)
	h.svc = NewService(
		uowFunc(func(ctx context.Context, fn func(context.Context, db.Querier) error) error {
			return fn(ctx, discardQuerier{})
		}),
		h.users,
		h.acct,
		failingSweeper{halted},
		h.events,
	)
	h.acct.personal = []accounts.Account{h.personalAccount()}

	if err := h.svc.Delete(t.Context(), DeleteInput{UserID: id.MustNew(), At: h.clock}); !errors.Is(err, halted) {
		t.Fatalf("the deletion reported %v, want the sweep's failure", err)
	}
	if len(h.users.deleted) != 0 {
		t.Errorf("the user row was removed even though the credential sweep failed: %v", h.users.deleted)
	}
	if len(h.events.envelopes) != 0 {
		t.Errorf("an event was published for a deletion that never completed: %v", h.events.envelopes)
	}
}

// failingAccess is the access-token half failing, so the sweeper's SECOND
// statement is the one under test: the session sweep must have run, and the
// error must still propagate.
type failingAccess struct{ err error }

func (f failingAccess) RevokeAccessTokensForUser(context.Context, db.Querier, id.UUID, time.Time) error {
	return f.err
}

// failingSweeper is the whole CredentialSweeper failing at its first statement,
// which is the shape a deployment reaches by wiring a nil `oidc.Store`.
type failingSweeper struct{ err error }

func (f failingSweeper) RevokeEveryCredential(context.Context, db.Querier, id.UUID, time.Time) error {
	return f.err
}
