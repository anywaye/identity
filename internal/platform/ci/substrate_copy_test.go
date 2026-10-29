package ci


import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	substrateMigration = "migrations/00016_account_isolation.sql"
	fixMigration       = "migrations/00017_credential_audit_dependencies.sql"
	userScopeMigration = "migrations/00018_membership_user_scope.sql"
)

func readMigration(t *testing.T, name string) string {
	t.Helper()
	if !strings.ContainsRune(name, filepath.Separator) {
		name = "migrations/" + name
	}
	b, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("%s: %v — a check that reads nothing reports agreement with nothing", name, err)
	}
	return string(b)
}

func sqlSection(t *testing.T, migration string, up bool) string {
	t.Helper()
	full := readMigration(t, migration)
	downAt := strings.Index(full, "\n-- +goose Down")
	if downAt < 0 {
		downAt = len(full)
	}
	head := full[:downAt]
	if !up {
		return full[downAt:]
	}
	upAt := strings.Index(head, "\n-- +goose Up")
	if upAt < 0 {
		return head
	}
	return head[upAt:]
}

func functionBodies(t *testing.T, migration, src, fn string) []string {
	t.Helper()
	needle := "create or replace function anywaye." + fn + "("
	var out []string
	for rest := src; ; {
		at := strings.Index(rest, needle)
		if at < 0 {
			return out
		}
		rest = rest[at:]
		end := strings.Index(rest, "\n$caf$;")
		if end < 0 {
			t.Fatalf("%s: anywaye.%s is opened and never closed with `$caf$;`", migration, fn)
		}
		out = append(out, rest[:end])
		rest = rest[end:]
	}
}

func functionBody(t *testing.T, migration, src, fn string) string {
	t.Helper()
	bodies := functionBodies(t, migration, src, fn)
	if len(bodies) != 1 {
		t.Fatalf("%s: expected exactly one `create or replace function anywaye.%s(`, found %d.\n"+
			"A check that picks one of several is reading a file nobody can reason about, and\n"+
			"the file is either malformed or carrying a definition this reader does not know "+
			"about.", migration, fn, len(bodies))
	}
	return bodies[0]
}

var migrationsThatPredateTheFix = map[string]string{
	"00016_account_isolation.sql": "the substrate copy, applied in deployed environments before " +
		"this was found; 00017 replaces its credential_tables() and rewriting 00016 is the " +
		"divergence the append-only rule exists to prevent",
}

func TestNoMigrationAfterTheFixInstallsAnAuditThatReadsASpelling(t *testing.T) {
	migrations, err := filepath.Glob(filepath.Join(repoRoot(t), "migrations", "*.sql"))
	if err != nil {
		t.Fatalf("glob migrations/*.sql: %v", err)
	}
	if len(migrations) < 2 {
		t.Fatalf("found %d migrations, which cannot include both the copy and its fix — "+
			"a glob that matched nothing would leave this test asserting agreement with no file at all",
			len(migrations))
	}

	audits := []string{"credential_tables", "membership_tables"}

	matched := map[string]bool{}
	for _, path := range migrations {
		name := filepath.Base(path)
		for _, audit := range audits {
			for i, body := range functionBodies(t, name, sqlSection(t, name, true), audit) {
				reads := ""
				for _, forbidden := range []string{"pg_get_expr", "regexp_match"} {
					if strings.Contains(body, forbidden) {
						reads = forbidden
						break
					}
				}
				if reads == "" {
					continue
				}
				matched[name] = true
				if _, excused := migrationsThatPredateTheFix[name]; excused {
					continue
				}
				t.Errorf("migrations/%s: the %d `%s()` in its Up section contains %q.\n"+
					"Reading a pretty-printed expression makes the answer depend on the session's\n"+
					"search_path, so the audit returns NOTHING as kit's cluster admin role\n"+
					"`anywaye` and the right answer as every other role — measured by\n"+
					"bin/credential-audit-drift. It reads as 'no table here can be resolved without\n"+
					"an account', which is the one answer an operator believes.\n"+
					"A migration is APPEND-ONLY: fix this with a new numbered file, and if the body\n"+
					"genuinely has to differ from kit's, record why in that migration.",
					name, i+1, audit, reads)
			}
		}
	}

	for name, reason := range migrationsThatPredateTheFix {
		if !matched[name] {
			t.Errorf("migrationsThatPredateTheFix lists %s (%s), but that migration no longer "+
				"installs an audit that reads a spelling.\n"+
				"The exception has stopped excepting anything and can now be deleted. A stale\n"+
				"allowlist entry is worse than a missing one: it teaches the next reader that "+
				"this shape is excusable here.", name, reason)
		}
	}
}

func TestTheCredentialAuditReadsDependenciesAndNotASpelling(t *testing.T) {
	body := functionBody(t, fixMigration, sqlSection(t, fixMigration, true), "credential_tables")

	for _, want := range []string{
		"pg_depend",
		"pg_proc",
		"pronargs = 0",
		"cd.refobjid = pol.polrelid",
		"'(unresolved)'",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("anywaye.credential_tables() does not contain %q.\n"+
				"Without it the audit is reading something the session can change. The argument is\n"+
				"kit's, at templates/database/tenancy/substrate.sql above that function.", want)
		}
	}

	for _, forbidden := range []string{
		"pg_get_expr",
		"regexp_match",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("anywaye.credential_tables() contains %q.\n"+
				"That is the reading the whole fix removed: it makes the answer depend on the\n"+
				"session's search_path, so the audit returns NOTHING as kit's cluster admin\n"+
				"role `anywaye` and the right answer as every other role. Measured by\n"+
				"bin/credential-audit-drift.", forbidden)
		}
	}
}

func TestTheMembershipAuditResolvesTheCallerAndNotASpelling(t *testing.T) {
	body := functionBody(t, userScopeMigration, sqlSection(t, userScopeMigration, true), "membership_tables")

	for _, want := range []string{
		"pg_depend",
		"pg_proc",
		"pronargs = 0",
		"proname = 'current_user_id'",
		"_anywaye!_members",
		"ud.refobjid = pol.polrelid",
		"'(unresolved)'",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("anywaye.membership_tables() does not contain %q.\n"+
				"Without it the audit is reading something the session can change, or answering\n"+
				"about a scope other than the caller's. The argument is kit's, at\n"+
				"templates/database/tenancy/substrate.sql above that function.", want)
		}
	}

	for _, forbidden := range []string{
		"pg_get_expr",
		"regexp_match",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("anywaye.membership_tables() contains %q.\n"+
				"That is the reading 00017 removed from the credential audit, and the reason it\n"+
				"matters twice over here: this audit answers 'which tables can be read with no\n"+
				"account because of WHO IS ASKING', so an admin told nothing reads as a service\n"+
				"with no caller-scoped path at all — which is the answer most likely to be\n"+
				"believed about the table that was silently unreadable to every caller.", forbidden)
		}
	}
}

func TestTheDriftCheckIsProvenAbleToFailOnTheBodyItRejects(t *testing.T) {
	old := functionBody(t, fixMigration, sqlSection(t, fixMigration, false), "credential_tables")

	if !strings.Contains(old, "pg_get_expr") || !strings.Contains(old, "regexp_match") {
		t.Fatalf("00017's Down section no longer carries the body it is meant to roll back.\n" +
			"Either the rollback was rewritten, which is a change nobody reviewed, or it was\n" +
			"dropped, and then this file's negative control is comparing against nothing.\n" +
			"bin/credential-audit-drift reads that section to install the 'before' column of\n" +
			"its table, so a silently rewritten Down makes a measurement lie.")
	}

	if !strings.Contains(old, "pg_get_expr") {
		t.Errorf("control: the pre-00017 body no longer reads pg_get_expr, so " +
			"TestTheCredentialAuditReadsDependenciesAndNotASpelling's forbidden-list is not " +
			"the thing that would have caught this drift")
	}
	if strings.Contains(old, "pg_depend") {
		t.Errorf("control: the pre-00017 body already reads pg_depend, so it would have " +
			"passed the required-substring list and the check above never bit")
	}
}

func TestEverySubstrateFunctionThisRepositoryInstallsIsKitsBytes(t *testing.T) {
	kitPath := findKitSubstrate(t)
	kitBytes, err := os.ReadFile(kitPath)
	if err != nil {
		t.Skipf("SKIP: no kit substrate within three levels above this repository (%s), so the copy "+
			"could not be compared against the template. Not checked: that the six functions 00016 "+
			"installed and the four 00018 added are still byte-identical to kit's. Re-run this "+
			"beside a kit checkout to close it; the audit checks above need no kit and are not "+
			"gated on this.",
			filepath.Join(repoRoot(t), ".."))
	}
	kitSrc := string(kitBytes)
	here := sqlSection(t, substrateMigration, true)

	for _, fn := range []string{
		"current_account_id",
		"begin_account",
		"current_credential_digest",
		"begin_credential",
		"protect_table",
		"protect_credential_table",
	} {
		if a, b := kitFunctionBody(t, kitSrc, fn), functionBody(t, substrateMigration, here, fn); a != b {
			t.Errorf("anywaye.%s differs from kit's.\n"+
				"00016 claims to embed kit's substrate verbatim, and one function differing\n"+
				"means the copy has drifted again. Either re-copy it in a NEW migration or\n"+
				"record why this one is deliberately different.", fn)
		}
	}

	membershipSrc := sqlSection(t, userScopeMigration, true)
	for _, fn := range []string{
		"current_user_id",
		"begin_user",
		"protect_membership_table",
		"membership_tables",
	} {
		if a, b := kitFunctionBody(t, kitSrc, fn), functionBody(t, userScopeMigration, membershipSrc, fn); a != b {
			t.Errorf("anywaye.%s differs from kit's.\n"+
				"%s claims to embed kit's substrate verbatim, and one function differing\n"+
				"means the copy has drifted again — the failure 00017 exists because it\n"+
				"happened once and nothing noticed. Either re-copy it in a NEW migration\n"+
				"or record why this one is deliberately different.",
				fn, userScopeMigration)
		}
	}

	if kitFunctionBody(t, kitSrc, "credential_tables") != functionBody(t, fixMigration, sqlSection(t, fixMigration, true), "credential_tables") {
		t.Errorf("anywaye.credential_tables() in %s is NOT kit's current body.\n"+
			"The fix and the template have drifted apart, which is this file's own defect\n"+
			"one layer up.", fixMigration)
	}
}

func kitFunctionBody(t *testing.T, src, fn string) string {
	t.Helper()
	return functionBody(t, "kit/templates/database/tenancy/substrate.sql", src, fn)
}

func findKitSubstrate(t *testing.T) string {
	t.Helper()
	dir := repoRoot(t)
	rel := []string{"kit", "templates", "database", "tenancy", "substrate.sql"}
	for range 3 {
		dir = filepath.Dir(dir)
		candidate := filepath.Join(append([]string{dir}, rel...)...)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}
