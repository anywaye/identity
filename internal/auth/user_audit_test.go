package auth


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

var errAuditInjected = errors.New("the user audit recorder refused, on purpose")

type auditCall struct {
	entry   useraudit.Entry
	querier db.Querier
}

type fakeAuditRecorder struct {
	calls []auditCall
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

var (
	auditActorUserID = id.MustNew()
	auditActorKeyID  = id.MustNew()
	auditTraceID     = "trace-disabled-04"
)

func disableFor(userID id.UUID, at time.Time) DisableInput {
	return DisableInput{
		UserID:      userID,
		ActorUserID: auditActorUserID,
		ActorKeyID:  auditActorKeyID,
		TraceID:     auditTraceID,
		At:          at,
	}
}

func enableFor(userID id.UUID, at time.Time) EnableInput {
	return EnableInput{
		UserID:      userID,
		ActorUserID: auditActorUserID,
		ActorKeyID:  auditActorKeyID,
		TraceID:     auditTraceID,
		At:          at,
	}
}

func TestADisableWritesItsRecordInsideTheTransaction(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "disabled-04-tx@example.com", "correct horse battery staple")

	if err := f.svc.Disable(context.Background(), disableFor(u.ID, f.clock.Now())); err != nil {
		t.Fatalf("disabling: %v", err)
	}

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

func TestADisableWithNoAuditRecorderIsRefusedAndNothingHappens(t *testing.T) {
	t.Parallel()

	f := newFixtureWithoutAuditRecorder()
	u := f.register(t, "disabled-04-unwired@example.com", "correct horse battery staple")

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

func TestAnEnableWithNoAuditRecorderIsRefusedAndTheColumnIsNotLifted(t *testing.T) {
	t.Parallel()

	f := newFixtureWithoutAuditRecorder()
	u := f.register(t, "disabled-04-unwired-enable@example.com", "correct horse battery staple")

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
	if got := f.users.byID[u.ID].DisabledAt; got == nil {
		t.Error("the refusal lifted disabled_at anyway, want the column still written")
	}
}

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
