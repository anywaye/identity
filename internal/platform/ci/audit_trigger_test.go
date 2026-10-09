package ci

// CHECKS ON THE AUDIT TRIGGERS, AND WHY THEY ARE NOT IN internal/admin
//
// `internal/admin/store_test.go` proves the account trail is append-only against a
// real database, by issuing an UPDATE and a DELETE and requiring both to fail. That is
// the strongest form of the proof and it is the one that matters — but it needs
// Postgres, so it runs only when TEST_DATABASE_URL is set, and a machine without one
// reports the two audit tables as having no append-only guarantee at all. Worse, the
// guarantee is a claim about MIGRATIONS, and the file that carries it
// (`migrations/00012`, `migrations/00022`) is not what that test opens.
//
// So this file holds the half that needs no database: that the trigger FUNCTION and
// the TRIGGER that installs it are actually written down in the migration, and that
// the Down removes both. It reads files, which is what lets it run in `bin/prime`.
//
// # WHAT IT IS NOT
//
// It is not a substitute for the database proof and does not pretend to be. A string
// check cannot establish that a trigger FIRES — a plpgsql body that parses and does
// nothing would satisfy every assertion here and fail every one in store_test.go. The
// two are complementary and neither is sufficient alone, which is why both exist: this
// one catches a trigger quietly deleted from a migration before it is applied
// anywhere, and the other catches one that exists but does not work.
//
// # WHY THE PAIR IS WALKED IN BOTH DIRECTIONS
//
// The Down half is not tidiness. `bin/rollback` measures a migration's Up, takes its
// Down, and compares the two CATALOG CENSUSES — so a Down that forgets
// `DROP TRIGGER` leaves the trigger in the census and the rollback check reports it as
// a leftover object. That check runs in CI on a database; this one names the omission
// at commit time, in a reviewer��s diff, which is where it is cheap to fix.

import (
	"regexp"
	"strings"
	"testing"
)

// auditTriggers is the set of append-only protections this repository's migrations
// declare, and it is NAMED rather than derived.
//
// Deriving it would mean scanning for `is_append_only` in the function name, and then
// a migration that renamed its function to `prevent_edits` would drop out of the check
// silently — a check whose coverage depends on a spelling it does not verify. Naming
// the pair means a THIRD audit table cannot be added without somebody deciding whether
// it belongs in this list, which is the moment to decide it.
var auditTriggers = []struct {
	// Table is the relation the trigger is installed on.
	Table string
	// Function is the trigger function, which is also what the Down must drop.
	Function string
	// Trigger is the trigger's own name.
	Trigger string
}{
	{"account_audit_log", "account_audit_log_is_append_only", "account_audit_log_append_only"},
	{"user_audit_log", "user_audit_log_is_append_only", "user_audit_log_append_only"},
	// 00031's agent trail, and it is in this list because a THIRD audit table
	// cannot be added without somebody deciding whether it belongs here — which
	// is the moment to decide it. An `agent_events` left out would be a table
	// whose append-only guarantee is installed in the migration and checked by
	// nothing, which is the direction this list exists to close.
	{"agent_events", "agent_events_is_append_only", "agent_events_append_only"},
}

var (
	createTriggerRE = regexp.MustCompile(`(?i)create\s+trigger\s+([a-z0-9_]+)`)
	dropTriggerRE   = regexp.MustCompile(`(?i)drop\s+trigger\s+(?:if\s+exists\s+|only\s+)*([a-z0-9_]+)`)
	createFuncRE    = regexp.MustCompile(`(?i)create\s+(?:or\s+replace\s+)?function\s+([a-z0-9_]+)`)
	dropFuncRE      = regexp.MustCompile(`(?i)drop\s+function\s+(?:if\s+exists\s+)*([a-z0-9_]+)`)
)

// section splits a migration into its Up and its Down bodies.
//
// The marker is the SAME one goose splits on, and it is split here rather than
// searching the whole file because that is what makes the two directions
// distinguishable: a trigger named in the Up is created, and the same trigger named in
// the Down is removed. A whole-file search would find each name exactly once in each
// file and could not tell a create from a drop.
func section(t *testing.T, name, half string) string {
	t.Helper()

	body := readMigration(t, name)
	var up, down string
	switch {
	case strings.Contains(body, "-- +goose Down"):
		parts := strings.SplitN(body, "-- +goose Down", 2)
		up = parts[0]
		down = parts[1]
	default:
		// TestEveryMigrationCarriesADownMarker already fails on a file with no Down,
		// so reaching here means the Up is the whole file.
		up = body
	}
	if half == "down" {
		return down
	}
	return up
}

// migrationNamed finds the migration that declares this table, so the check follows
// the table rather than a hardcoded file number.
//
// A check that hardcoded `00012` would keep passing after a `goose squash`, and would
// silently stop covering the table it was written for. Looking for the CREATE TABLE is
// one lookup and it fails loudly when the table's migration is renamed.
func migrationNamed(t *testing.T, table string) string {
	t.Helper()

	declares := regexp.MustCompile(`(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?` + table + `\b`)
	for _, name := range migrationsInTree(t) {
		if declares.MatchString(readMigration(t, name)) {
			return name
		}
	}
	t.Fatalf("no migration in migrations/ declares `create table %s`.\n"+
		"This audit table is in auditTriggers, so a table with no migration is a table whose\n"+
		"append-only guarantee is not written down anywhere. Either the migration is missing or\n"+
		"this list names a table that does not exist — both are the same defect: a list that has\n"+
		"drifted from the schema it describes.", table)
	return ""
}

// TestEveryAuditTablesAppendOnlyTriggerIsWrittenDown is the commit-time half of the
// account trail's guarantee and the user trail's.
//
// Each assertion is a separate failure rather than one combined check, because the
// three defects have three different fixes: a missing trigger is a missing trigger, a
// trigger on the wrong events is a trigger that permits exactly the edit it exists to
// refuse, and a missing drop is a rollback that leaves an object behind.
func TestEveryAuditTablesAppendOnlyTriggerIsWrittenDown(t *testing.T) {
	for _, tc := range auditTriggers {
		t.Run(tc.Table, func(t *testing.T) {
			file := migrationNamed(t, tc.Table)
			up := section(t, file, "up")

			// The function exists, or the trigger cannot reference it.
			if !createFuncRE.MatchString(up) || !strings.Contains(up, tc.Function) {
				t.Errorf("migrations/%s installs a trigger on %s but never creates the function "+
					"`%s`. The trigger is the GUARANTEE — a service that refuses to edit its own "+
					"audit rows has a bug-shaped hole in it — and it lives in the database because "+
					"a promise written in Go does not bind a psql session, a repair script, or the "+
					"next packet.", file, tc.Table, tc.Function)
			}

			// The trigger exists under its own name.
			created := createTriggerRE.FindStringSubmatch(up)
			if created == nil {
				t.Fatalf("migrations/%s creates table %s and no trigger.\n"+
					"The append-only guarantee is the BEFORE UPDATE OR DELETE trigger, not the "+
					"absence of an Update method in Go: without it, %s is editable by anybody who "+
					"can reach the database, which includes the operator whose action is in it.",
					file, tc.Table, tc.Table)
			}
			if created[1] != tc.Trigger {
				t.Errorf("migrations/%s creates the trigger as %q, want %q. This list is what the "+
					"check reasons about, so a renamed trigger would leave the check asserting a "+
					"name that is not there.", file, created[1], tc.Trigger)
			}

			// ON THE RIGHT EVENTS. This is the assertion that catches the subtle one: a
			// trigger written `BEFORE UPDATE` alone passes every existence check above
			// and still permits DELETE, which is the half that empties a trail rather than
			// editing it.
			if !strings.Contains(up, "BEFORE UPDATE OR DELETE") &&
				!strings.Contains(up, "BEFORE DELETE OR UPDATE") {
				t.Errorf("migrations/%s does not create %s `BEFORE UPDATE OR DELETE`.\n"+
					"Both halves are load-bearing. UPDATE is what lets an operator rewrite what they "+
					"did; DELETE is worse, because a trail that cannot be edited can still be "+
					"emptied, and an emptied trail is indistinguishable from one where nothing "+
					"suspicious happened.\n"+
					"Found instead: %s", file, tc.Table, triggerClause(up))
			}

			// NOT ON INSERT, and not on TRUNCATE. An INSERT trigger would make the
			// recording itself impossible; a TRUNCATE trigger would break dbtest.Reset.
			if strings.Contains(up, "BEFORE INSERT OR UPDATE OR DELETE") ||
				strings.Contains(up, "BEFORE INSERT OR DELETE OR UPDATE") ||
				strings.Contains(up, "BEFORE UPDATE OR INSERT OR DELETE") ||
				strings.Contains(up, "BEFORE DELETE OR INSERT OR UPDATE") ||
				strings.Contains(up, "BEFORE UPDATE OR DELETE OR INSERT") ||
				strings.Contains(up, "BEFORE DELETE OR UPDATE OR INSERT") {
				t.Errorf("migrations/%s fires %s on INSERT as well.\n"+
					"The trigger must fire on UPDATE and DELETE and NEVER on INSERT — it is what "+
					"refuses edits, not what permits writes, and firing on INSERT would make the "+
					"recording of an audit row impossible.", file, tc.Table)
			}
		})
	}
}

// triggerClause finds the trigger's event list, so the failure above can print what it
// found instead of only what it wanted.
//
// A check that says "not as expected" about a clause it cannot quote sends the next
// reader to the migration to work out what was written, which is the step this file
// exists to remove.
func triggerClause(up string) string {
	for _, line := range strings.Split(up, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "before ") && strings.Contains(lower, " on ") {
			return strings.TrimSpace(line)
		}
	}
	return "(no BEFORE ... ON line found)"
}

// TestEveryAuditTablesAppendOnlyTriggerIsDroppedByItsDown is the reverse direction,
// and it is the one that keeps bin/rollback honest.
//
// `bin/rollback` applies each Up, censuses the catalog, applies the Down, censuses
// again and compares — so a Down that leaves the trigger behind shows up there as a
// leftover object. That check runs in CI, against a database, on a schedule. This one
// runs in `bin/prime` on every commit and names the omission in a reviewer's diff,
// which is where it costs nothing to fix.
//
// A migration that cannot be reversed does not need a Down that does nothing — it
// needs a Down that says WHY, and `TestEveryMigrationCarriesADownMarker` is what holds
// the marker. These two hold the contents.
func TestEveryAuditTablesAppendOnlyTriggerIsDroppedByItsDown(t *testing.T) {
	for _, tc := range auditTriggers {
		t.Run(tc.Table, func(t *testing.T) {
			file := migrationNamed(t, tc.Table)
			down := section(t, file, "down")

			dropped := map[string]bool{}
			for _, m := range dropTriggerRE.FindAllStringSubmatch(down, -1) {
				dropped[m[1]] = true
			}
			if !dropped[tc.Trigger] {
				t.Errorf("migrations/%s drops table %s without dropping its trigger %s.\n"+
					"DROP TABLE does not fire a row-level trigger, so the trigger survives as an "+
					"orphan function bound to a relation that is gone. `bin/rollback` measures this "+
					"as a leftover object in the catalog — but it measures it in CI, on a database, "+
					"and this file measures it in a diff, where it is a one-line fix.",
					file, tc.Table, tc.Trigger)
			}

			droppedFuncs := map[string]bool{}
			for _, m := range dropFuncRE.FindAllStringSubmatch(down, -1) {
				droppedFuncs[m[1]] = true
			}
			if !droppedFuncs[tc.Function] {
				t.Errorf("migrations/%s drops the trigger but not the function %s.\n"+
					"The function is a schema object in its own right and it is in the census "+
					"`bin/rollback` compares, so leaving it behind makes a clean rollback read as "+
					"a dirty one.", file, tc.Function)
			}
		})
	}
}

// TestTheAuditTriggerListNamesRealObjects is the guard on the list itself.
//
// The list is NAMED rather than derived, and a named list is a promise about the
// schema rather than a description of it — which means it can drift in the direction
// that matters most, quietly. This asserts every entry names a table that a migration
// declares AND a trigger that migration installs, so an entry can only be added
// honestly. Without it, the check above is a loop over a list nobody has checked
// against the tree, and a list of intentions is not a check.
func TestTheAuditTriggerListNamesRealObjects(t *testing.T) {
	for _, tc := range auditTriggers {
		t.Run(tc.Table, func(t *testing.T) {
			// migrationNamed already fails when no migration declares the table, which
			// is half of it.
			file := migrationNamed(t, tc.Table)
			up := section(t, file, "up")

			var installed bool
			for _, m := range createTriggerRE.FindAllStringSubmatch(up, -1) {
				if m[1] == tc.Trigger {
					installed = true
				}
			}
			if !installed {
				t.Errorf("auditTriggers names %s on %s, but migrations/%s installs no trigger of "+
					"that name.\n"+
					"An entry naming a trigger that is not installed is a check asserting a "+
					"guarantee nothing provides: it reads as coverage and is decoration.",
					tc.Trigger, tc.Table, file)
			}
		})
	}
}
