package deletion

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)


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

type failingAccess struct{ err error }

func (f failingAccess) RevokeAccessTokensForUser(context.Context, db.Querier, id.UUID, time.Time) error {
	return f.err
}

type failingSweeper struct{ err error }

func (f failingSweeper) RevokeEveryCredential(context.Context, db.Querier, id.UUID, time.Time) error {
	return f.err
}
