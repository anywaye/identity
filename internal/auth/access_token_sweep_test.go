package auth

// PACKET identity-disabled-03: THE OIDC HALF OF A DISABLE.
//
// # WHAT THIS FILE IS FOR, AND WHY IT IS NOT A COMMENT
//
// disabled-01 shipped `Service.Disable` as two statements — the session DELETE and
// the column write — and its commit message named the hole rather than implying it
// away:
//
//	"still leaves fifteen-minute access tokens valid in third parties' hands"
//
// A JWT is the credential this service cannot take back by deleting a row. It
// verifies against the published JWKS from the moment it is minted until `exp`, by
// anybody holding it, and this service is not the verifier. So a token minted
// before a disable keeps working for up to fifteen minutes after the deployment
// decided the person is off, and the `oidc_access_tokens` row behind it is the only
// place that fact can be changed.
//
// The mechanism already existed — `oidc.Store.RevokeAccessTokensForUser`, one
// idempotent UPDATE, put on the Store rather than on the Storage adapter
// specifically so a package that is not the OIDC provider could reach it — and
// `internal/recovery` already called it in the same transaction as its own session
// revocation. What was missing is the call from here.
//
// # THREE PROPERTIES, EACH PROVEN IN BOTH PLACES
//
//	IT IS IN THE SAME TRANSACTION   the rollback is proven against real Postgres in
//	                                disabled_integration_test.go, because
//	                                fakeUnitOfWork cannot roll anything back; here
//	                                the same property is proven the only way a double
//	                                CAN prove it — the sweep received the TRANSACTION's
//	                                Querier and not the pool's.
//	IT IS IDEMPOTENT               the store is asked once per call and a second
//	                                disable is not an error; the integration suite
//	                                asserts against the table that revoked_at did not
//	                                MOVE.
//	IT IS NOT SKIPPABLE            a nil sweeper is an error, and the negative
//	                                direction of that error is asserted: nothing at
//	                                all was written.
//
// Every test here asserts the double actually recorded what the test reasons
// about. A check over nothing is green — `len(f.access.sweeps) != 1` appears before
// every claim about "the one sweep" for that reason, and the nil-sweeper test
// asserts a session existed to lose.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
)

// errSweepInjected is the failure this file programs at the sweep, and it is
// DISTINCT from every other error the fixture can produce so that "the error came
// from the sweep" is a fact and not an inference from the fact that something
// failed.
//
// A rollback caused by anything else — a failed session DELETE, a failed column
// write, a nil dereference — proves nothing about the sweep being inside the
// transaction, and a test that accepts any of those is a test that has never
// failed.
var errSweepInjected = errors.New("the access token sweep refused, on purpose")

// The sweep is ASKED FOR, and it is asked through the TRANSACTION.
//
// The querier identity is the whole of this test. `newFixture` hands out two
// distinct markers — one standing in for the pool and one for the transaction —
// precisely so that a write which went through the wrong seam is visible. A sweep
// that ran on `s.read` instead of on the transaction's `q` would still revoke the
// tokens in the happy path, on a pool with no transaction around it — which is a
// window whose length is not a number anybody chose.
func TestADisableSweepsTheAccessTokensInsideTheTransaction(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")

	if err := f.svc.Disable(context.Background(), disableFor(u.ID, f.clock.Now())); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	// THE CONTROL. Without this the assertions below are vacuous: a Disable that
	// swept nothing would produce an empty slice and pass a "no wrong querier"
	// check by having nothing to be wrong about.
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

	// The instant is the one the caller passed, not the service's own clock: the
	// row's revoked_at and the column's disabled_at are then the same fact, and
	// only one of the two is under test control.
	if !sweep.at.Equal(f.clock.Now()) {
		t.Errorf("the sweep stamped %v, want the instant Disable was given (%v)", sweep.at, f.clock.Now())
	}
}

// A SWEEP THAT FAILS TAKES THE SESSIONS AND THE COLUMN WITH IT.
//
// This is the unit half of the rollback; disabled_integration_test.go holds it
// against a real database, because a double cannot roll back. What this half can
// and does prove is the SEQUENCE and the CAUSE: a failure at the sweep is the error
// the caller sees, and the state change after it never ran.
//
// The order is the same argument `Disable`'s own header makes about the column
// write, applied to a third statement: the revocations come first and the state
// change last, so the state change is the thing that is either wholly there or
// wholly absent.
func TestAFailedAccessTokenSweepLeavesNothingAfterIt(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")
	f.access.err = errSweepInjected

	err := f.svc.Disable(context.Background(), disableFor(u.ID, f.clock.Now()))

	// THE INJECTED ERROR, and not "some error". A rollback caused by something else
	// — the session DELETE failing, say — would satisfy every assertion below and
	// prove nothing about the sweep.
	if !errors.Is(err, errSweepInjected) {
		t.Fatalf("Disable = %v, want the error the sweep raised (%v). A rollback caused by "+
			"something else would satisfy the assertions below and prove nothing about the "+
			"sweep being in the transaction", err, errSweepInjected)
	}

	if len(f.access.sweeps) != 1 {
		t.Fatalf("the sweep ran %d times, want 1", len(f.access.sweeps))
	}

	// The column write did NOT run. In production the transaction has rolled the
	// session DELETE back too; what a double can show is the sequence, and a
	// sequence that stamped the column before sweeping would be a disable whose
	// account reads as turned off while its tokens are still in third parties' hands.
	if read, ok := f.users.byID[u.ID]; !ok {
		t.Fatal("the registered user vanished from the double, which is not a state this test can reason about")
	} else if read.DisabledAt != nil {
		t.Errorf("DisabledAt = %v even though the sweep failed, want nothing: the state change "+
			"is the last statement, so a failure before it leaves it absent", read.DisabledAt)
	}
}

// AN UNWIRED SWEEPER IS A REFUSAL, AND IT REFUSES BEFORE IT WRITES ANYTHING.
//
// `ErrNoSecondFactor` is the precedent and the reason it is the precedent: a login
// that proceeded without being able to ask about a second factor IS the bypass MFA
// exists to prevent, so the missing dependency is an error rather than a degraded
// single-factor mode. The identical reasoning with the credential on the other side
// of it — "revoked the sessions, left the tokens" is a disable that says the
// opposite of what it did, and an operator who has already told somebody their
// access ended is the worst person to tell next.
//
// The direction that makes it an error rather than a log line is asserted below:
// nothing was written. A nil check that ran after the session revocation would have
// ended every session this user held and then reported failure, which is a
// signed-out user who is not disabled and cannot sign back in.
func TestADisableWithNoAccessTokenRevokerWiredRefusesAndWritesNothing(t *testing.T) {
	t.Parallel()

	f := newFixtureWithoutAccessRevoker()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")

	// A session to lose, so "nothing was written" is a claim about ROWS rather than
	// about a state this account happened to be in already.
	f.seedSession(u.ID)

	err := f.svc.Disable(context.Background(), disableFor(u.ID, f.clock.Now()))

	if !errors.Is(err, ErrNoAccessTokenRevoker) {
		t.Fatalf("Disable with no access token revoker = %v, want ErrNoAccessTokenRevoker. "+
			"A nil check that skipped the sweep would answer nil and leave fifteen-minute "+
			"access tokens live in every third party that holds one", err)
	}

	// THE CONTROL ON THE CLAIM ITSELF: "the sessions survive" is only a fact if
	// there was one to survive.
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

// The sweep is one call, not a loop over registrations and not a call per client.
//
// `oidc.Store.RevokeAccessTokensForUser`'s own header says it is a bulk UPDATE
// across every registration a user holds a token for, and a per-client loop in
// here would be a second implementation of that with a different failure mode.
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

// A DISABLE IS REPEATABLE, AND THE SECOND ONE IS NOT A SECOND REFRESH.
//
// `TestDisablingIsRepeatableAndNeitherDirectionInspectsTheAccountsState` in
// internal/httpapi proves the route may be called twice; this proves the store is
// asked once per call, with that call's own instant, and that the use case treats
// the second answer as the success it is. Zero tokens is not a failure — a user who
// never signed in through a product is already in the state the sweep is called
// for, and an error there would make a legitimate disable look like an outage.
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
