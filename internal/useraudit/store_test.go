package useraudit

// THE STORE'S TESTS AGAINST A REAL POSTGRES.
//
// These are the claims only a database can settle, and each one is a property of the
// TABLE rather than of this Go code:
//
//	TestTheRecordCannotBeUpdated    the trigger, from the table's side
//	TestTheRecordCannotBeDeleted
//	TestTheTrailOutlivesTheUser    no foreign key, so deleting the person does not
//	                               delete the record of who turned them off
//	TestTheClosedSetIsARefusalNotASchemaCheck
//	TestTheActorIdsAreBothRequired
//
// A Go-level test could not establish any of them. A promise written in the service
// does not bind a psql session, a repair script, or a future packet — which is the
// whole reason 00022's trigger is in the database and not in Append.
//
// EVERY ASSERTION ABOUT A ROW GOES AROUND THE STORE, issuing its SQL directly against
// the pool. A test that read the row back through Append would be restating the
// method's own behaviour; the point of these is to prove what happens when something
// that is NOT this package touches the table.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// The database tier must actually run. Every test in this file needs a migrated
// schema, and a file that skips itself proves nothing — the rule AGENTS.md states
// for internal/mfa and internal/admin, and it applies here for the same reason.
func TestTheDatabaseTierActuallyRan(t *testing.T) {
	if testing.Short() {
		t.Fatal("this file is entirely database tests; -short would report them as skipped, " +
			"which is a green suite that proved nothing")
	}
}

func newTestStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()

	pool := dbtest.Schema(t)
	return NewStore(pool), pool
}

func testEntry(t *testing.T) Entry {
	t.Helper()
	return Entry{
		UserID:     id.MustNew(),
		Action:     ActionUserDisabled,
		Actor:      Actor{UserID: id.MustNew(), KeyID: id.MustNew(), TraceID: "trace-useraudit-store"},
		OccurredAt: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC),
	}
}

// tableExists is the guard against a check over nothing.
//
// EVERY assertion below counts rows in `user_audit_log`, and a count of zero is the
// answer both "nothing was recorded" and "there is no such table here" would produce
// if the query were allowed to fail quietly. This asserts the TABLE is there and is
// this table, before any test reasons about its contents — which is the second time
// this codebase has been bitten by a comparison of two empty things, and the reason
// the check is a named helper rather than something each test remembers to do.
func tableExists(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	var name string
	err := pool.QueryRow(t.Context(),
		`SELECT relname FROM pg_class WHERE oid = to_regclass('user_audit_log')`).Scan(&name)
	if err != nil {
		t.Fatalf("looking up user_audit_log: %v\n"+
			"Have the migrations been applied? `goose -dir migrations postgres \"$DATABASE_URL\" up`", err)
	}
	if name != "user_audit_log" {
		t.Fatalf("to_regclass('user_audit_log') resolved to %q, so every row count in this "+
			"file would be about a different relation", name)
	}
}

// TestTheRecordCannotBeUpdated is a red proof for the strongest claim in the
// migration: the record cannot be edited by the operator who performed it.
//
// It issues the UPDATE directly against the pool, which is what makes it a proof
// rather than a restatement — a test that called this package could only show that
// this package has no Update method, which is true, and irrelevant to somebody with
// psql.
func TestTheRecordCannotBeUpdated(t *testing.T) {
	store, pool := newTestStore(t)
	tableExists(t, pool)
	ctx := t.Context()

	rec, err := store.Append(ctx, pool, testEntry(t))
	if err != nil {
		t.Fatalf("appending a record: %v", err)
	}

	_, err = pool.Exec(ctx,
		`UPDATE user_audit_log SET action = 'user.enabled' WHERE id = $1`, rec.ID)
	if err == nil {
		t.Fatal("an UPDATE to the trail SUCCEEDED. The record is editable, and it is editable by " +
			"whoever can reach the database — which includes the operator whose action is in it, " +
			"through a repair script or a psql session that never goes near this service.")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("the UPDATE failed for a reason that is not the append-only rule: %v", err)
	}

	// And the row is genuinely unchanged, not merely reported as failing. This is the
	// direction that matters: a trigger that raised AFTER writing would satisfy the
	// check above.
	var action string
	if err := pool.QueryRow(ctx, `SELECT action FROM user_audit_log WHERE id = $1`, rec.ID).
		Scan(&action); err != nil {
		t.Fatalf("reading the record back: %v", err)
	}
	if action != string(rec.Action) {
		t.Errorf("action = %q, want the original %q — the failed UPDATE still changed the row",
			action, rec.Action)
	}
}

// TestTheRecordCannotBeDeleted is the other half, and DELETE is the one that matters
// more: a trail that cannot be edited can still be emptied, and an emptied trail is
// indistinguishable from one where nothing suspicious happened.
func TestTheRecordCannotBeDeleted(t *testing.T) {
	store, pool := newTestStore(t)
	tableExists(t, pool)
	ctx := t.Context()

	rec, err := store.Append(ctx, pool, testEntry(t))
	if err != nil {
		t.Fatalf("appending a record: %v", err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM user_audit_log WHERE id = $1`, rec.ID); err == nil {
		t.Fatal("a DELETE from the trail SUCCEEDED")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("the DELETE failed for a reason that is not the append-only rule: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_audit_log WHERE id = $1`, rec.ID).
		Scan(&count); err != nil {
		t.Fatalf("counting the record: %v", err)
	}
	if count != 1 {
		t.Errorf("the record is gone after a DELETE that reported failure")
	}
}

// TestTheTrailOutlivesTheUser is 00022's no-FOREIGN-KEY decision, proven.
//
// `DELETE /v1/users/{userID}` is not a route today, but the point is not today's
// routes: it is that the SHORTEST route from "an operator did something questionable"
// to "there is no record of it" must not be one statement. A CASCADE from users would
// make it one, and the trigger would be bypassed by it rather than enforcing against
// it — a cascading delete is a delete, and this table refuses deletes.
func TestTheTrailOutlivesTheUser(t *testing.T) {
	store, pool := newTestStore(t)
	tableExists(t, pool)
	ctx := t.Context()

	subject := id.MustNew()
	rec, err := store.Append(ctx, pool, Entry{
		UserID:     subject,
		Action:     ActionUserDisabled,
		Actor:      Actor{UserID: id.MustNew(), KeyID: id.MustNew(), TraceID: "trace-outlives"},
		OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("appending a record: %v", err)
	}

	// The user id is a bare uuid with no row behind it, which is the point: there is
	// nothing to delete. The assertion is that the RECORD is still there, and that the
	// table declares no foreign key that could have taken it.
	var fks int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_constraint c
		  JOIN pg_class t ON t.oid = c.conrelid
		 WHERE t.relname = 'user_audit_log' AND c.contype = 'f'`).Scan(&fks); err != nil {
		t.Fatalf("reading user_audit_log's foreign keys: %v", err)
	}
	if fks != 0 {
		t.Errorf("user_audit_log declares %d foreign keys, want 0. A CASCADE from users is a "+
			"DELETE, and this table refuses deletes — with one, deleting the person would "+
			"remove the record of who turned them off, which is one request away from there "+
			"being no record at all.", fks)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_audit_log WHERE id = $1`, rec.ID).
		Scan(&count); err != nil {
		t.Fatalf("counting the record: %v", err)
	}
	if count != 1 {
		t.Errorf("the record did not survive: %d rows, want 1", count)
	}
}

// TestTheTableCarriesNoAccountColumn is D14 as a database fact.
//
// The temptation this forecloses is the exact one the packet named: making a disable
// fit the account-scoped trail by adding an account_id. A nullable one would be worse
// than either extreme — a column that is supposed to be filled in and never is, so
// every reader handles two worlds and every writer decides what absence means.
func TestTheTableCarriesNoAccountColumn(t *testing.T) {
	_, pool := newTestStore(t)
	tableExists(t, pool)

	var cols int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*) FROM information_schema.columns
		 WHERE table_name = 'user_audit_log' AND column_name = 'account_id'`).
		Scan(&cols); err != nil {
		t.Fatalf("reading user_audit_log's columns: %v", err)
	}
	if cols != 0 {
		t.Error("user_audit_log HAS an account_id column. A disable names no account — that is " +
			"DECISIONS.md D14, and it is the reason `users:disable` is its own scope with no " +
			"account in its path. A user belongs to as many accounts as they like, so hanging a " +
			"record on \"the caller's own account\" grants one tenant that authority once per " +
			"membership, and puts a tenancy fiction into the one table whose value is being true.")
	}
}

// TestTheClosedSetIsARefusalNotASchemaCheck is the Go half of the decision 00012
// makes for its own action column.
//
// The property is TWO things at once and both are asserted: Append REFUSES an action
// this build does not know, and the DATABASE ACCEPTS one. The second is the half that
// distinguishes this design from a CHECK constraint — a closed set in the schema would
// make adding an action a migration, and 00011 gives that argument for api_keys.scopes
// and 00012 gives it for account_audit_log's action.
//
// The row is written with raw SQL on purpose. Going through Append could not produce
// the contrast: Append is the thing refusing.
func TestTheClosedSetIsARefusalNotASchemaCheck(t *testing.T) {
	store, pool := newTestStore(t)
	tableExists(t, pool)
	ctx := t.Context()

	// The refusal, first: no row, and a sentinel the caller can match on.
	unknown := testEntry(t)
	unknown.Action = Action("user.exploded")
	if _, err := store.Append(ctx, pool, unknown); !errors.Is(err, ErrUnknownAction) {
		t.Fatalf("Append accepted %q, want ErrUnknownAction", unknown.Action)
	}

	// THE DATABASE ACCEPTS IT, and that is the design rather than a hole in one. It is
	// also the fail-closed direction at the point of use: a row holding an action this
	// build does not know about is refused WHEN IT IS READ, which is what a future
	// reader of this trail has to do — and the alternative, treating an unknown action
	// as "and so anything goes", is the bug a CHECK constraint would introduce
	// silently the first time somebody wanted to add an action without a migration.
	const raw = `INSERT INTO user_audit_log
		(user_id, action, actor_user_id, actor_key_id, trace_id, occurred_at)
		VALUES ($1, 'user.exploded', $2, $3, 'trace-raw', now()) RETURNING id`
	var rawID id.UUID
	if err := pool.QueryRow(ctx, raw, id.MustNew(), id.MustNew(), id.MustNew()).
		Scan(&rawID); err != nil {
		t.Fatalf("the database refused an action this build does not know: %v\n"+
			"If a CHECK constraint has appeared on `action`, this design changed: the closed set "+
			"is a CODE fact and belongs in Go, or adding an action becomes a migration.", err)
	}

	// And the row is counted, so the insert above is proven to have inserted rather
	// than merely to have returned an id.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM user_audit_log WHERE id = $1`, rawID).Scan(&count); err != nil {
		t.Fatalf("counting the raw row: %v", err)
	}
	if count != 1 {
		t.Errorf("the raw INSERT returned an id but the row is not there: %d rows, want 1", count)
	}
}

// TestTheActorIdsAreBothRequired is the NOT NULL pair, and the reason is that there is
// no user to attribute this to on the other side: the caller is a machine credential.
//
// A zero actor means the row names nobody, and a record that names nobody is a record
// of an action with no responsible party — which for an audit trail is not a degraded
// row, it is a useless one. These refusals happen in Go before any statement runs, so
// this file proves the refusal AND that no row was left behind.
func TestTheActorIdsAreBothRequired(t *testing.T) {
	store, pool := newTestStore(t)
	tableExists(t, pool)
	ctx := t.Context()

	tests := []struct {
		name  string
		actor Actor
	}{
		{"no key id", Actor{UserID: id.MustNew(), TraceID: "trace-no-key"}},
		{"no user id", Actor{KeyID: id.MustNew(), TraceID: "trace-no-user"}},
		{"neither", Actor{TraceID: "trace-neither"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := testEntry(t)
			e.Actor = tt.actor
			if _, err := store.Append(ctx, pool, e); err == nil {
				t.Error("Append accepted an actor that names no credential, so the row would " +
					"record an action nobody can be held responsible for")
			}
		})
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_audit_log`).Scan(&count); err != nil {
		t.Fatalf("counting the table: %v", err)
	}
	if count != 0 {
		t.Errorf("the table holds %d rows after three refused appends, want 0 — a refusal that "+
			"leaves a row behind is not a refusal", count)
	}
}

// TestTheSubjectIsRequired, because a row naming no user is a record of nothing.
func TestTheSubjectIsRequired(t *testing.T) {
	store, pool := newTestStore(t)
	tableExists(t, pool)
	ctx := t.Context()

	e := testEntry(t)
	e.UserID = id.UUID{}
	if _, err := store.Append(ctx, pool, e); err == nil {
		t.Fatal("Append accepted a record with no subject")
	}
}

// TestATraceIdIsRequiredAndBounded, because the column carries a CHECK and this
// package carries the same bound — and two implementations of one bound is two things
// that can disagree.
func TestATraceIdIsRequiredAndBounded(t *testing.T) {
	store, pool := newTestStore(t)
	tableExists(t, pool)
	ctx := t.Context()

	empty := testEntry(t)
	empty.Actor.TraceID = ""
	if _, err := store.Append(ctx, pool, empty); err == nil {
		t.Error("Append accepted a record with no trace id, so the row cannot be joined to the " +
			"request's log line")
	}

	long := testEntry(t)
	long.Actor.TraceID = strings.Repeat("t", maxTraceIDLength+1)
	if _, err := store.Append(ctx, pool, long); err == nil {
		t.Errorf("Append accepted a %d character trace id, over the %d the column accepts. "+
			"A longer one means something is writing a paragraph into an id column.",
			len(long.Actor.TraceID), maxTraceIDLength)
	}

	// The boundary itself, which is the value a CHECK's off-by-one would hide.
	edge := testEntry(t)
	edge.Actor.TraceID = strings.Repeat("t", maxTraceIDLength)
	if _, err := store.Append(ctx, pool, edge); err != nil {
		t.Errorf("Append refused a trace id of exactly the accepted length %d: %v", maxTraceIDLength, err)
	}
}

// TestAppendNeedsAQuerier, because a nil one panics inside pgx rather than refusing,
// and a panic in the middle of a disable transaction is the worst place to discover
// the wiring is wrong.
func TestAppendNeedsAQuerier(t *testing.T) {
	store, _ := newTestStore(t)

	if _, err := store.Append(context.Background(), nil, testEntry(t)); err == nil {
		t.Fatal("Append accepted a nil querier")
	}
}

// TestTheRecordedRowComesBackAsWritten proves the RETURNING clause and the column
// list agree with each other.
//
// It is here because a drift between `auditColumns` and `scanRecord` is a RUNTIME
// error in one direction and a silent mis-mapping in the other: a column added to the
// list and not to the scan is a compile error, but a REORDERED pair is not, and the
// record would come back holding one field's value in another's. So every field is
// asserted against the entry it came from.
func TestTheRecordedRowComesBackAsWritten(t *testing.T) {
	store, pool := newTestStore(t)
	tableExists(t, pool)
	ctx := t.Context()

	in := testEntry(t)
	rec, err := store.Append(ctx, pool, in)
	if err != nil {
		t.Fatalf("appending: %v", err)
	}

	if rec.ID.IsZero() {
		t.Error("the returned record has no id, so the database generated nothing")
	}
	checks := []struct {
		name string
		got  any
		want any
	}{
		{"subject", rec.UserID, in.UserID},
		{"action", rec.Action, in.Action},
		{"actor user", rec.ActorUserID, in.Actor.UserID},
		{"actor key", rec.ActorKeyID, in.Actor.KeyID},
		{"trace id", rec.TraceID, in.Actor.TraceID},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	if !rec.OccurredAt.Equal(in.OccurredAt) {
		t.Errorf("occurred_at = %s, want %s", rec.OccurredAt, in.OccurredAt)
	}
}

// TestAllActionsIsTheClosedSetAndNothingMore holds the vocabulary in place from both
// sides, which is the shape admin.AllActions has.
//
// One direction catches an action added to the constant block and forgotten in the
// list — it would validate, and then never be reachable. The other catches a name in
// the list with no constant behind it, which would be an action this build promises
// and cannot produce.
func TestAllActionsIsTheClosedSetAndNothingMore(t *testing.T) {
	got := AllActions()

	known := map[Action]bool{
		ActionUserDisabled: true,
		ActionUserEnabled:  true,
	}
	if len(got) != len(known) {
		t.Errorf("AllActions() has %d entries, want %d: %v", len(got), len(known), got)
	}
	for _, a := range got {
		if !known[a] {
			t.Errorf("AllActions() names %q, which no constant declares — an action this build "+
				"promises and cannot produce", a)
		}
	}
	for a := range known {
		found := false
		for _, gotAction := range got {
			if gotAction == a {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is a declared action but AllActions() omits it, so validateAction would "+
				"accept a row this package's own list does not contain", a)
		}
	}
}
