package auth

// PACKET identity-disabled-04: WHO TURNED THIS PERSON OFF, AND WHEN.
//
// # WHAT THIS FILE PROVES, AND WHY IT IS NOT A COMMENT ON Disable
//
// Three statements used to be a disable: two revocations and a column. None of them
// said who asked, so the first question of any incident review reaching this service
// had no answer in the database at all. This file is about the fourth statement — the
// row in `user_audit_log` — and about the three properties that make it worth
// having:
//
//	IT IS WRITTEN IN THE SAME TRANSACTION   the querier identity, proven here against
//	                                        a double, and the ROLLBACK proven against
//	                                        real Postgres in the integration file. A
//	                                        fakeUnitOfWork cannot roll anything back,
//	                                        so the rollback cannot be proven here at
//	                                        all and pretending otherwise is the trap
//	                                        disabled-01's own header names.
//	IT NAMES BOTH ACTOR IDS AND NOT A NIL   a disable that records nobody is a
//	                                        disable that cannot be reviewed, and
//	                                        ErrNoUserAuditRecorder is a refusal rather
//	                                        than a skip.
//	IT SAYS WHAT HAPPENED, IN A CLOSED SET  the action is named by the use case and
//	                                        validated in Go, so a row holding an
//	                                        action this build does not know is refused
//	                                        at the point of use.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/useraudit"
)

// errAuditInjected is the failure this file programs at the audit write.
//
// DISTINCT from every other error the fixture can produce, so that "the error came
// from the recorder" is a fact and not an inference from the fact that something
// failed. A rollback caused by anything else — a failed session DELETE, a failed
// sweep, a nil dereference — proves nothing about the recorder being inside the
// transaction, and a test that accepts any of those is a test that has never failed.
var errAuditInjected = errors.New("the user audit recorder refused, on purpose")

// auditCall is one recorded Append.
type auditCall struct {
	entry   useraudit.Entry
	querier db.Querier
}

// fakeAuditRecorder records what the disable and enable asked of user_audit_log.
//
// IT RECORDS THE QUERIER AND NOT JUST THE ENTRY, for the same reason
// fakeAccessRevoker does: the claim under test is that the write runs INSIDE the
// transaction, and a double that only counted calls could not tell a write on the
// transaction's `q` from one on the pool. `markerQuerier` is what makes the two
// distinguishable — a write that went through the wrong seam still SUCCEEDS in the
// happy path, with a pool and no transaction around it, which is a window whose
// length is not a number anybody chose.
//
// IT RECORDS THE CALL BEFORE IT RETURNS THE ERROR, and that order is the whole
// difference between a useful double and a green one. A double that appended only on
// success would leave `calls` EMPTY on the failure path, so every assertion about
// "the one write that failed" would be an assertion about a slice holding nothing —
// which passes. disabled-03 shipped that defect in its sibling double and the
// comment on it is the scar; this one is written the other way round on purpose.
type fakeAuditRecorder struct {
	calls []auditCall
	// err is returned instead of a successful write, so a test can program a failure
	// at the exact statement the atomicity claim is about.
	err error
}

func (f *fakeAuditRecorder) Append(_ context.Context, q db.Querier, e useraudit.Entry) (useraudit.Record, error) {
	f.calls = append(f.calls, auditCall{entry: e, querier: q})
	if f.err != nil {
		return useraudit.Record{}, f.err
	}
	return useraudit.Record{
		ID:          id.MustNew(),
		UserID:      e.UserID,
		Action:      e.Action,
		ActorUserID: e.Actor.UserID,
		ActorKeyID:  e.Actor.KeyID,
		TraceID:     e.Actor.TraceID,
		OccurredAt:  e.OccurredAt,
	}, nil
}

// The actor every fixture uses, built ONCE so that a test asserting "the row names
// this operator" is comparing against a value it did not invent per assertion.
//
// The trace id is a fixed string rather than a generated one for the same reason
// admin's test entries use one: a generated id would make the assertion "the trace id
// is the request's" impossible to state, because every value would differ.
var (
	auditActorUserID = id.MustNew()
	auditActorKeyID  = id.MustNew()
	auditTraceID     = "trace-disabled-04"
)

// disableFor builds the input every use-case test passes.
//
// IT EXISTS SO THE ACTOR AND THE SUBJECT CANNOT BE CONFUSED, which is the mistake the
// input struct was introduced to prevent: with `Disable(ctx, userID, at)` there was
// nowhere to put the actor, and a test — or a future handler — writing the subject's
// id where the actor's belongs produces a row blaming a person for turning themselves
// off. One builder, one place to get it right.
func disableFor(userID id.UUID, at time.Time) DisableInput {
	return DisableInput{
		UserID:      userID,
		ActorUserID: auditActorUserID,
		ActorKeyID:  auditActorKeyID,
		TraceID:     auditTraceID,
		At:          at,
	}
}

// enableFor is the same for Enable, and it is a separate function rather than a
// shared one so that a change to one use case's input cannot silently change the
// other's.
func enableFor(userID id.UUID, at time.Time) EnableInput {
	return EnableInput{
		UserID:      userID,
		ActorUserID: auditActorUserID,
		ActorKeyID:  auditActorKeyID,
		TraceID:     auditTraceID,
		At:          at,
	}
}

// TestADisableWritesItsRecordInsideTheTransaction is the first of the three
// properties, and the querier identity is the whole of it.
//
// The same property is proven against a real database in the integration file,
// because a double cannot prove a rollback. What this proves is the seam: a write on
// `s.read` instead of the transaction's `q` would still insert a row in the happy
// path, so counting rows proves nothing here and comparing markers proves everything.
func TestADisableWritesItsRecordInsideTheTransaction(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "disabled-04-tx@example.com", "correct horse battery staple")

	if err := f.svc.Disable(context.Background(), disableFor(u.ID, f.clock.Now())); err != nil {
		t.Fatalf("disabling: %v", err)
	}

	// THE CHECK OVER NOTHING IS GREEN, so the slice is proved non-empty before its
	// contents are reasoned about. A test that asserted `calls[0]` on an empty slice
	// would panic rather than mislead, but one asserting `len(calls) != 0` and then
	// describing "the record" has proved the recorder was asked — which is the
	// precondition for everything else in this file.
	if len(f.audit.calls) != 1 {
		t.Fatalf("the recorder was asked %d times, want exactly 1: %+v", len(f.audit.calls), f.audit.calls)
	}
	if got := f.audit.calls[0].querier; got != db.Querier(markerQuerier{name: "transaction"}) {
		t.Errorf("the record was written through %T(%v), want the TRANSACTION's querier. "+
			"A write on the pool would have committed its row in a second transaction, so a "+
			"disable could revoke every credential and stamp the column and still leave no "+
			"record — with both writes having succeeded.", got, got)
	}
}

// TestTheDisableRecordNamesTheOperatorAndTheSubjectAndWhen is the claim the packet
// exists for, asserted field by field rather than by a single "the row looks right".
//
// The actor and the subject are DIFFERENT uuids here on purpose. A single assertion
// that "the row was written" would pass against an implementation that swapped them,
// and a swapped row is the worst outcome available: an audit trail that indicts the
// person who was disabled.
func TestTheDisableRecordNamesTheOperatorAndTheSubjectAndWhen(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "disabled-04-fields@example.com", "correct horse battery staple")
	at := f.clock.Now()

	if err := f.svc.Disable(context.Background(), disableFor(u.ID, at)); err != nil {
		t.Fatalf("disabling: %v", err)
	}
	if len(f.audit.calls) != 1 {
		t.Fatalf("the recorder was asked %d times, want 1", len(f.audit.calls))
	}

	got := f.audit.calls[0].entry
	if got.UserID != u.ID {
		t.Errorf("the record's SUBJECT is %s, want the disabled user %s", got.UserID, u.ID)
	}
	if got.Actor.UserID != auditActorUserID {
		t.Errorf("the record's actor user is %s, want %s", got.Actor.UserID, auditActorUserID)
	}
	if got.Actor.KeyID != auditActorKeyID {
		t.Errorf("the record's actor KEY is %s, want %s — without the key id there is no "+
			"credential to revoke, and 'somebody' is not an answer an incident review can use",
			got.Actor.KeyID, auditActorKeyID)
	}
	if got.Actor.TraceID != auditTraceID {
		t.Errorf("the record's trace id is %q, want %q — the row has to join to the request's "+
			"log line without either carrying a timestamp comparison", got.Actor.TraceID, auditTraceID)
	}
	if !got.OccurredAt.Equal(at) {
		t.Errorf("the record happened at %s, want %s", got.OccurredAt, at)
	}
	if got.Action != useraudit.ActionUserDisabled {
		t.Errorf("the action is %q, want %q. The action is named by the USE CASE rather than "+
			"passed in, so there is no caller that can write a disable's record under another "+
			"action's name", got.Action, useraudit.ActionUserDisabled)
	}
}

// TestTheEnableRecordsToo is the second half of the pair, and it is here because the
// packet left it a decision. It is a decision: see `auth.Service.Enable`'s header for
// the argument. What this proves is the mechanism — the same transaction, the same
// actor, and a DIFFERENT action, because "was this one, or was this all of them" is
// not a question a repeated action name can answer.
func TestTheEnableRecordsToo(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "disabled-04-enable@example.com", "correct horse battery staple")

	if err := f.svc.Disable(context.Background(), disableFor(u.ID, f.clock.Now())); err != nil {
		t.Fatalf("disabling: %v", err)
	}
	if err := f.svc.Enable(context.Background(), enableFor(u.ID, f.clock.Now())); err != nil {
		t.Fatalf("enabling: %v", err)
	}

	if len(f.audit.calls) != 2 {
		t.Fatalf("the recorder was asked %d times across a disable and an enable, want 2: %+v",
			len(f.audit.calls), f.audit.calls)
	}
	if got := f.audit.calls[1].entry.Action; got != useraudit.ActionUserEnabled {
		t.Errorf("the re-enable was recorded as %q, want %q — a trail holding only the disable "+
			"answers 'who turned this off' while staying silent on whether the person is off "+
			"right now", got, useraudit.ActionUserEnabled)
	}
	if got := f.audit.calls[1].entry.UserID; got != u.ID {
		t.Errorf("the re-enable's subject is %s, want %s", got, u.ID)
	}
	if got := f.audit.calls[1].querier; got != db.Querier(markerQuerier{name: "transaction"}) {
		t.Errorf("the re-enable's record was written through %T(%v), want the transaction's querier",
			got, got)
	}
}

// TestADisableWithNoAuditRecorderIsRefusedAndNothingHappens is the unwired case, and
// it is the one the sentinel exists for.
//
// IT ASSERTS THE NEGATIVE DIRECTION, which is the half that matters: a refusal that
// only checked the returned error would pass against an implementation that revoked
// the sessions and the tokens, wrote the column, and THEN discovered it had nowhere
// to record it. That implementation answers the operator with an error while the
// person is signed out of everything and cannot sign back in — and the operator, told
// the disable failed, has no reason to go looking for it.
//
// It is a refusal and not a degraded "revoked everything, wrote nothing" because the
// trail is the WHOLE answer here. Unlike the token sweep, there is no second
// mechanism that would catch a missing record: an unattributable disable is not a
// degraded audit, it is no audit.
func TestADisableWithNoAuditRecorderIsRefusedAndNothingHappens(t *testing.T) {
	t.Parallel()

	f := newFixtureWithoutAuditRecorder()
	u := f.register(t, "disabled-04-unwired@example.com", "correct horse battery staple")

	// A session to lose, asserted BEFORE the call, so the negative assertions below
	// are against a person who had something and not against a vacuous state.
	//
	// The assertion is on `live`, not on `revoked`: a sign-in ADDS a session and
	// revokes nothing, so counting revocations here would be checking a slice that
	// is empty on the happy path and would fail for the wrong reason.
	if _, err := f.svc.Login(context.Background(), LoginInput{
		Email: "disabled-04-unwired@example.com", Password: "correct horse battery staple",
	}); err != nil {
		t.Fatalf("signing in, to have a session the refusal must not end: %v", err)
	}
	liveBefore := len(f.sessions.live)
	if liveBefore == 0 {
		t.Fatal("the sign-in left no live session, so the assertions below would prove nothing")
	}

	err := f.svc.Disable(context.Background(), disableFor(u.ID, f.clock.Now()))
	if !errors.Is(err, ErrNoUserAuditRecorder) {
		t.Fatalf("Disable with no recorder returned %v, want ErrNoUserAuditRecorder", err)
	}
	if got := len(f.sessions.live); got != liveBefore {
		t.Errorf("the refusal ended %d sessions anyway, want %d live. A nil check that ran after "+
			"the session DELETE would have signed the user out of everything and then reported "+
			"failure, which is a person who is signed out and NOT disabled.", liveBefore-got, liveBefore)
	}
	if got := len(f.sessions.revoked); got != 0 {
		t.Errorf("the refusal revoked %d sessions anyway, want 0", got)
	}
	if got := len(f.access.sweeps); got != 0 {
		t.Errorf("the refusal swept %d sets of access tokens anyway, want 0", got)
	}
	if stored := f.users.byID[u.ID]; stored.DisabledAt != nil {
		t.Errorf("the refusal wrote disabled_at (%s) anyway, want the user untouched", stored.DisabledAt)
	}
}

// TestAnEnableWithNoAuditRecorderIsRefusedAndTheColumnIsNotLifted is the mirror, and
// it exists because Enable's refusal is the one whose failure mode is least obvious.
//
// A re-enable that lifted the column and then failed to record leaves an operator
// believing a person is STILL disabled while the service has let them straight back
// in. Nothing looks wrong from either side: the person signs in, the operator's
// request errored. That is the half-applied state the whole ordering argument is
// about, and it is why the nil check sits before the transaction here too.
func TestAnEnableWithNoAuditRecorderIsRefusedAndTheColumnIsNotLifted(t *testing.T) {
	t.Parallel()

	f := newFixtureWithoutAuditRecorder()
	u := f.register(t, "disabled-04-unwired-enable@example.com", "correct horse battery staple")

	// The user is put into the disabled state THROUGH THE STORE DOUBLE rather than
	// through Disable, and the reason is that this fixture has no recorder — so calling
	// Disable would answer ErrNoUserAuditRecorder and disable nobody, and the assertion
	// below would then be about a column that was never written. Reaching past the use
	// case is the price of testing the refusal, and it is worth it: the alternative is
	// two fixtures where one fault is wired in each, and a test that cannot set up its
	// own precondition.
	disabledAt := f.clock.Now()
	f.users.Disable(context.Background(), markerQuerier{name: "transaction"}, u.ID, disabledAt)

	if got := f.users.byID[u.ID].DisabledAt; got == nil {
		t.Fatal("the user is not disabled before the enable runs, so a later assertion that " +
			"the column was not lifted would pass for the wrong reason")
	}

	err := f.svc.Enable(context.Background(), enableFor(u.ID, f.clock.Now()))
	if !errors.Is(err, ErrNoUserAuditRecorder) {
		t.Fatalf("Enable with no recorder returned %v, want ErrNoUserAuditRecorder", err)
	}
	// Asserted against the stored user rather than a flag the double maintains
	// separately: the claim is about the COLUMN, and the double's only record of it is
	// the field the real store writes.
	if got := f.users.byID[u.ID].DisabledAt; got == nil {
		t.Error("the refusal lifted disabled_at anyway, want the column still written")
	}
}

// TestADisableWhoseRecordFailsTellsTheCallerAboutTheRecorder is the plumbing half:
// the wrapped error has to NAME the recorder, or an operator staring at a 500 has
// nothing to search for.
//
// It asserts on the message rather than on a sentinel because there is no sentinel to
// assert on — the recorder's own error is a plain one — and "recording the disable" is
// the phrase a reader of a log line greps for.
func TestADisableWhoseRecordFailsTellsTheCallerAboutTheRecorder(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "disabled-04-recorder-err@example.com", "correct horse battery staple")
	f.audit.err = errAuditInjected

	err := f.svc.Disable(context.Background(), disableFor(u.ID, f.clock.Now()))
	if err == nil {
		t.Fatal("a disable whose audit write failed returned nil, so the caller was told their " +
			"disable succeeded while nothing recorded it")
	}
	if !errors.Is(err, errAuditInjected) {
		t.Errorf("the error does not wrap the recorder's own, so the cause is unreachable with "+
			"errors.Is: %v", err)
	}
	if !strings.Contains(err.Error(), "recording the disable") {
		t.Errorf("the error does not name the statement that failed: %v", err)
	}
}
