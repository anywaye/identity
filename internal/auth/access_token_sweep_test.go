package auth


import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
)

var errSweepInjected = errors.New("the access token sweep refused, on purpose")

func TestADisableSweepsTheAccessTokensInsideTheTransaction(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")

	if err := f.svc.Disable(context.Background(), disableFor(u.ID, f.clock.Now())); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	if len(f.access.sweeps) != 1 {
		t.Fatalf("the access token store was called %d times, want exactly 1: every "+
			"assertion below is about that one call", len(f.access.sweeps))
	}

	sweep := f.access.sweeps[0]

	if sweep.userID != u.ID {
		t.Errorf("the sweep was asked about %v, want the user being disabled (%v): a sweep "+
			"about somebody else revokes somebody else's tokens and leaves this account's live",
			sweep.userID, u.ID)
	}

	if got, want := sweep.querier, db.Querier(markerQuerier{name: "transaction"}); got != want {
		t.Errorf("the sweep went through the %v querier, want %v: a sweep on the pool is a "+
			"sweep outside the transaction that ends the sessions, so a failure in either "+
			"would leave the other committed", got, want)
	}

	if !sweep.at.Equal(f.clock.Now()) {
		t.Errorf("the sweep stamped %v, want the instant Disable was given (%v)", sweep.at, f.clock.Now())
	}
}

func TestAFailedAccessTokenSweepLeavesNothingAfterIt(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")
	f.access.err = errSweepInjected

	err := f.svc.Disable(context.Background(), disableFor(u.ID, f.clock.Now()))

	if !errors.Is(err, errSweepInjected) {
		t.Fatalf("Disable = %v, want the error the sweep raised (%v). A rollback caused by "+
			"something else would satisfy the assertions below and prove nothing about the "+
			"sweep being in the transaction", err, errSweepInjected)
	}

	if len(f.access.sweeps) != 1 {
		t.Fatalf("the sweep ran %d times, want 1", len(f.access.sweeps))
	}

	if read, ok := f.users.byID[u.ID]; !ok {
		t.Fatal("the registered user vanished from the double, which is not a state this test can reason about")
	} else if read.DisabledAt != nil {
		t.Errorf("DisabledAt = %v even though the sweep failed, want nothing: the state change "+
			"is the last statement, so a failure before it leaves it absent", read.DisabledAt)
	}
}

func TestADisableWithNoAccessTokenRevokerWiredRefusesAndWritesNothing(t *testing.T) {
	t.Parallel()

	f := newFixtureWithoutAccessRevoker()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")

	f.seedSession(u.ID)

	err := f.svc.Disable(context.Background(), disableFor(u.ID, f.clock.Now()))

	if !errors.Is(err, ErrNoAccessTokenRevoker) {
		t.Fatalf("Disable with no access token revoker = %v, want ErrNoAccessTokenRevoker. "+
			"A nil check that skipped the sweep would answer nil and leave fifteen-minute "+
			"access tokens live in every third party that holds one", err)
	}

	if len(f.sessions.live) == 0 {
		t.Fatal("the fixture seeded no session, so 'the sessions survive' would pass by " +
			"having nothing to survive")
	}
	if len(f.sessions.live) != 1 {
		t.Errorf("%d sessions remain, want 1: the refusal is checked BEFORE the transaction, "+
			"so a nil sweeper cannot end a user's sessions and then report failure",
			len(f.sessions.live))
	}

	if read := f.users.byID[u.ID]; read.DisabledAt != nil {
		t.Errorf("DisabledAt = %v after the refusal, want nothing written", read.DisabledAt)
	}
	if f.uow.ran != 0 {
		t.Errorf("the unit of work ran %d times, want 0: a wiring bug should not open a "+
			"transaction and then abort it", f.uow.ran)
	}
}

func TestADisableAsksForTheSweepExactlyOncePerCall(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")

	for range 3 {
		if err := f.svc.Disable(context.Background(), disableFor(u.ID, f.clock.Now())); err != nil {
			t.Fatalf("Disable: %v", err)
		}
	}

	if len(f.access.sweeps) != 3 {
		t.Errorf("three disables made %d sweeps, want 3: one per call, not one per client "+
			"and not one for the first only", len(f.access.sweeps))
	}
}

func TestASecondDisableSweepsAgainWithItsOwnInstantAndStillSucceeds(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")

	firstAt := f.clock.Now()
	if err := f.svc.Disable(context.Background(), disableFor(u.ID, firstAt)); err != nil {
		t.Fatalf("the first Disable: %v", err)
	}

	later := firstAt.Add(5 * time.Minute)
	if err := f.svc.Disable(context.Background(), disableFor(u.ID, later)); err != nil {
		t.Fatalf("the second Disable = %v, want success: revoking zero tokens is a success", err)
	}

	if len(f.access.sweeps) != 2 {
		t.Fatalf("the sweep ran %d times, want 2", len(f.access.sweeps))
	}
	if got := f.access.sweeps[0].at; !got.Equal(firstAt) {
		t.Errorf("the first sweep stamped %v, want %v: a double that reported its last "+
			"argument for every call would pass the second assertion below", got, firstAt)
	}
	if got := f.access.sweeps[1].at; !got.Equal(later) {
		t.Errorf("the second sweep stamped %v, want %v: each call stamps its own instant, "+
			"and a sweep stamped at the first instant would make the second call a lie "+
			"about when the revocation happened", got, later)
	}
}
