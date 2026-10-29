package ci


import (
	"regexp"
	"strings"
	"testing"
)

var auditTriggers = []struct {
	Table string
	Function string
	Trigger string
}{
	{"account_audit_log", "account_audit_log_is_append_only", "account_audit_log_append_only"},
	{"user_audit_log", "user_audit_log_is_append_only", "user_audit_log_append_only"},
	{"agent_events", "agent_events_is_append_only", "agent_events_append_only"},
}

var (
	createTriggerRE = regexp.MustCompile(`(?i)create\s+trigger\s+([a-z0-9_]+)`)
	dropTriggerRE   = regexp.MustCompile(`(?i)drop\s+trigger\s+(?:if\s+exists\s+|only\s+)*([a-z0-9_]+)`)
	createFuncRE    = regexp.MustCompile(`(?i)create\s+(?:or\s+replace\s+)?function\s+([a-z0-9_]+)`)
	dropFuncRE      = regexp.MustCompile(`(?i)drop\s+function\s+(?:if\s+exists\s+)*([a-z0-9_]+)`)
)

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
		up = body
	}
	if half == "down" {
		return down
	}
	return up
}

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

func TestEveryAuditTablesAppendOnlyTriggerIsWrittenDown(t *testing.T) {
	for _, tc := range auditTriggers {
		t.Run(tc.Table, func(t *testing.T) {
			file := migrationNamed(t, tc.Table)
			up := section(t, file, "up")

			if !createFuncRE.MatchString(up) || !strings.Contains(up, tc.Function) {
				t.Errorf("migrations/%s installs a trigger on %s but never creates the function "+
					"`%s`. The trigger is the GUARANTEE — a service that refuses to edit its own "+
					"audit rows has a bug-shaped hole in it — and it lives in the database because "+
					"a promise written in Go does not bind a psql session, a repair script, or the "+
					"next packet.", file, tc.Table, tc.Function)
			}

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

			if !strings.Contains(up, "BEFORE UPDATE OR DELETE") &&
				!strings.Contains(up, "BEFORE DELETE OR UPDATE") {
				t.Errorf("migrations/%s does not create %s `BEFORE UPDATE OR DELETE`.\n"+
					"Both halves are load-bearing. UPDATE is what lets an operator rewrite what they "+
					"did; DELETE is worse, because a trail that cannot be edited can still be "+
					"emptied, and an emptied trail is indistinguishable from one where nothing "+
					"suspicious happened.\n"+
					"Found instead: %s", file, tc.Table, triggerClause(up))
			}

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

func triggerClause(up string) string {
	for _, line := range strings.Split(up, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "before ") && strings.Contains(lower, " on ") {
			return strings.TrimSpace(line)
		}
	}
	return "(no BEFORE ... ON line found)"
}

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

func TestTheAuditTriggerListNamesRealObjects(t *testing.T) {
	for _, tc := range auditTriggers {
		t.Run(tc.Table, func(t *testing.T) {
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
