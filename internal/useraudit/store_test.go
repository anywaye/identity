package useraudit


import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
)

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

func TestTheClosedSetIsARefusalNotASchemaCheck(t *testing.T) {
	store, pool := newTestStore(t)
	tableExists(t, pool)
	ctx := t.Context()

	unknown := testEntry(t)
	unknown.Action = Action("user.exploded")
	if _, err := store.Append(ctx, pool, unknown); !errors.Is(err, ErrUnknownAction) {
		t.Fatalf("Append accepted %q, want ErrUnknownAction", unknown.Action)
	}

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

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM user_audit_log WHERE id = $1`, rawID).Scan(&count); err != nil {
		t.Fatalf("counting the raw row: %v", err)
	}
	if count != 1 {
		t.Errorf("the raw INSERT returned an id but the row is not there: %d rows, want 1", count)
	}
}

func TestTheActorUserAndTraceAreRequired(t *testing.T) {
	store, pool := newTestStore(t)
	tableExists(t, pool)
	ctx := t.Context()

	tests := []struct {
		name  string
		actor Actor
	}{
		{"no user id", Actor{KeyID: id.MustNew(), TraceID: "trace-no-user"}},
		{"neither", Actor{TraceID: "trace-neither"}},
		{"no trace id", Actor{UserID: id.MustNew(), KeyID: id.MustNew()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := testEntry(t)
			e.Actor = tt.actor
			if _, err := store.Append(ctx, pool, e); err == nil {
				t.Error("Append accepted an actor that names nobody or carries no trace, so the row would " +
					"record an action nobody can be held responsible for or joined to a request")
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

func TestAZeroKeyIdIsAHumanSessionRow(t *testing.T) {
	store, pool := newTestStore(t)
	tableExists(t, pool)
	ctx := t.Context()

	staff := id.MustNew()
	e := testEntry(t)
	e.Actor = Actor{UserID: staff, TraceID: "trace-human-session"}

	rec, err := store.Append(ctx, pool, e)
	if err != nil {
		t.Fatalf("Append refused a human-session actor: %v", err)
	}
	if !rec.ActorKeyID.IsZero() {
		t.Errorf("the row's actor key id = %s, want the nil uuid: no token acted", rec.ActorKeyID)
	}
	if rec.ActorUserID != staff {
		t.Errorf("the row's actor user id = %s, want the staff user %s", rec.ActorUserID, staff)
	}
	if rec.TraceID != "trace-human-session" {
		t.Errorf("the row's trace id = %q, want the request's", rec.TraceID)
	}
}

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

	edge := testEntry(t)
	edge.Actor.TraceID = strings.Repeat("t", maxTraceIDLength)
	if _, err := store.Append(ctx, pool, edge); err != nil {
		t.Errorf("Append refused a trace id of exactly the accepted length %d: %v", maxTraceIDLength, err)
	}
}

func TestAppendNeedsAQuerier(t *testing.T) {
	store, _ := newTestStore(t)

	if _, err := store.Append(context.Background(), nil, testEntry(t)); err == nil {
		t.Fatal("Append accepted a nil querier")
	}
}

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
