package tenancy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type result struct{ expected, actual, verdict, why string }

const oneMinute = time.Minute

var identityTables = []string{
	"account_users",
	"account_invitations",
	"oidc_clients",
	"api_keys",
	"account_audit_log",
}

func dsnOrSkip(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRED_DB") == "1" {
			t.Fatal("REQUIRED_DB=1 and TEST_DATABASE_URL is unset: the account-isolation " +
				"proof cannot run, and a skipped proof is a green run that proved nothing. " +
				"Start the database, or unset REQUIRED_DB to skip this tier on purpose.")
		}
		t.Skip("TEST_DATABASE_URL is unset, so NOTHING WAS CHECKED HERE. The account " +
			"boundary - that no request without an account reads another account's rows - " +
			"was not proven by this run. Apply the migrations and set the variable: " +
			"`goose -dir migrations postgres \"$DATABASE_URL\" up` then re-run. To make this " +
			"tier non-optional, set REQUIRED_DB=1 and it fails instead of skipping.")
	}
	return dsn
}

func connect(t *testing.T) (ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), oneMinute)
	t.Cleanup(cancel)

	conn, err := pgx.Connect(ctx, dsnOrSkip(t))
	if err != nil {
		t.Fatalf("connect to TEST_DATABASE_URL: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return ctx, conn
}

func TestTenancyAccountIsolation(t *testing.T) {
	ctx, conn := connect(t)

	script, err := os.ReadFile(here("isolation.sql"))
	if err != nil {
		t.Fatalf("read isolation.sql: %v", err)
	}
	if _, err := conn.Exec(ctx, string(script)); err != nil {
		t.Fatalf("isolation.sql did not complete: %v", err)
	}

	rows, err := conn.Query(ctx, `
		select assertion, expected, actual, verdict, why
		  from pg_temp.anywaye_probe_result
		 order by assertion`)
	if err != nil {
		t.Fatalf("read the assertion results: %v", err)
	}

	got := map[string]result{}
	for rows.Next() {
		var name string
		var r result
		if err := rows.Scan(&name, &r.expected, &r.actual, &r.verdict, &r.why); err != nil {
			t.Fatalf("scan an assertion result: %v", err)
		}
		got[name] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate the assertion results: %v", err)
	}

	if _, err := conn.Exec(ctx, "rollback"); err != nil {
		t.Fatalf("roll back the proof's transaction: %v", err)
	}

	t.Logf("kit's assertion set returned %d assertions", len(got))
	assertComplete(t, got)
	assertAllPass(t, got)
}

func TestTenancyIdentityOwnsItsFiveTables(t *testing.T) {
	ctx, conn := connect(t)

	t.Run("the owner and app roles are not superuser or BYPASSRLS", func(t *testing.T) {
		for _, role := range []string{"identity", "identity_app"} {
			var super, bypass bool
			if err := conn.QueryRow(ctx, `select rolsuper, rolbypassrls from pg_roles where rolname = $1`, role).Scan(&super, &bypass); err != nil {
				t.Fatalf("reading pg_roles for %s: %v", role, err)
			}
			if super {
				t.Errorf("role %s is superuser, which bypasses row-level security even with FORCE. Recreate the cluster without POSTGRES_USER=%s (use kit's kit-postgres image, or plain postgres without that variable)", role, role)
			}
			if bypass {
				t.Errorf("role %s has BYPASSRLS, which bypasses row-level security even with FORCE. Recreate it as NOBYPASSRLS", role)
			}
		}
	})

	t.Run("every declared table is enabled and FORCED", func(t *testing.T) {
		for _, table := range identityTables {
			enabled, forced, acctIndex, policies := protectedCatalogRow(ctx, t, conn, table)
			why := rlsDiagnosis(enabled, policies)

			if !enabled {
				t.Errorf("%s: row level security is NOT enabled, so no policy on it is ever evaluated.%s", table, why)
			}
			if !forced {
				t.Errorf("%s: NOT set FORCE ROW LEVEL SECURITY. Postgres exempts a table's owner "+
					"from its own policies, and this service runs its migrations as the role that "+
					"owns every table here - so the role that matters reads every account's rows "+
					"while every policy on it sits in the catalog looking like a boundary%s", table, why)
			}
			if !acctIndex {
				t.Errorf("%s: no index leads with account_id. A policy is a filter on every row, so "+
					"an unindexed one is a sequential scan behind a primary-key lookup%s", table, why)
			}
			if !policies {
				t.Errorf("%s: row level security is enabled with no policy, which hides every row "+
					"from every role including this service%s", table, why)
			}
		}
	})

	t.Run("the sweep finds nothing unprotected", func(t *testing.T) {
		rows, err := conn.Query(ctx, `
			select table_schema, table_name, why
			  from anywaye.unprotected_tables()
			 where table_schema = 'public'`)
		if err != nil {
			t.Fatalf("running the sweep: %v", err)
		}
		defer rows.Close()
		var unprotected []string
		for rows.Next() {
			var schema, table, why string
			if err := rows.Scan(&schema, &table, &why); err != nil {
				t.Fatalf("scan a sweep row: %v", err)
			}
			unprotected = append(unprotected, fmt.Sprintf("%s.%s (%s)", schema, table, why))
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate the sweep: %v", err)
		}
		if len(unprotected) > 0 {
			t.Errorf("anywaye.unprotected_tables() found %d account-scoped table(s) in public with "+
				"no boundary - an account-scoped table that no policy covers:\n  %s",
				len(unprotected), strings.Join(unprotected, "\n  "))
		}
	})

	for _, role := range []string{"identity_app", "identity"} {
		t.Run("three-way denial as "+role, func(t *testing.T) {
			ctx, conn := connect(t)

			if _, err := conn.Exec(ctx, "begin"); err != nil {
				t.Fatalf("begin: %v", err)
			}
			t.Cleanup(func() {
				if _, err := conn.Exec(context.Background(), "rollback"); err != nil {
					t.Logf("rollback: %v", err)
				}
			})

			if _, err := conn.Exec(ctx, "set local role "+role); err != nil {
				t.Fatalf("set local role %s: %v", role, err)
			}

			tenantA, tenantB := seedAuditRows(ctx, t, conn, role)

			if _, err := conn.Exec(ctx, `select anywaye.begin_account(NULL)`); err != nil {
				t.Fatalf("clearing the account identity: %v", err)
			}
			if got := countAuditRows(ctx, t, conn); got != 0 {
				t.Errorf("as %s with NO identity: read %d rows, want 0. A request that never "+
					"authenticated is reading account data", role, got)
			}

			if _, err := conn.Exec(ctx, `select anywaye.begin_account($1)`, tenantB); err != nil {
				t.Fatalf("setting the other tenant's identity: %v", err)
			}
			if got := countAuditRows(ctx, t, conn); got != 1 {
				t.Errorf("as %s carrying ANOTHER tenant's valid identity: read %d rows, want 1 "+
					"(its own). Anything more is a cross-account read", role, got)
			}
			if got := countAuditRowsIn(ctx, t, conn, tenantA); got != 0 {
				t.Errorf("as %s carrying ANOTHER tenant's valid identity: read %d of THAT "+
					"tenant's rows, want 0", role, got)
			}

			if _, err := conn.Exec(ctx, `select anywaye.begin_account($1)`, tenantA); err != nil {
				t.Fatalf("setting the account's own identity: %v", err)
			}
			if got := countAuditRowsIn(ctx, t, conn, tenantA); got != 1 {
				t.Errorf("as %s with its OWN identity: read %d of its own rows, want 1. A table "+
					"that denies everybody also passes the two arms above, which is why this one "+
					"exists", role, got)
			}
			if got := countAuditRows(ctx, t, conn); got != 1 {
				t.Errorf("as %s with its OWN identity: an unqualified read returned %d rows, want 1 "+
					"(its own only)", role, got)
			}

			if _, err := conn.Exec(ctx, `select anywaye.begin_account($1)`, tenantB); err != nil {
				t.Fatalf("setting the other tenant's identity: %v", err)
			}
			tag, err := conn.Exec(ctx,
				`update account_audit_log set target = 'rewritten' where account_id = $1`, tenantA)
			if err != nil {
				t.Fatalf("the cross-account UPDATE raised %v, which is a different failure from "+
					"the one being asserted: a `using` denial matches zero rows and raises "+
					"nothing, so this statement is expected to SUCCEED and change nothing", err)
			}
			if tag.RowsAffected() != 0 {
				t.Errorf("as %s: a cross-account UPDATE matched %d rows, want 0",
					role, tag.RowsAffected())
			}
		})
	}
}

const catalogProof = `
	select c.relrowsecurity, c.relforcerowsecurity,
	       (select count(*) > 0 from pg_index i
	         where i.indrelid = c.oid
	           and i.indkey[0] = (select attnum from pg_attribute a
	                               where a.attrelid = c.oid and a.attname = 'account_id')) as acct_index,
	       (select count(*) > 0 from pg_policy p where p.polrelid = c.oid) as policies
	  from pg_class c
	 where c.relnamespace = 'public'::regnamespace
	   and c.relkind = 'r'
	   and c.relname = $1`

func protectedCatalogRow(ctx context.Context, t *testing.T, conn *pgx.Conn, table string) (enabled, forced, acctIndex, policies bool) {
	t.Helper()

	rows, err := conn.Query(ctx, catalogProof, table)
	if err != nil {
		t.Fatalf("reading the catalog for %s: %v", table, err)
	}
	defer rows.Close()

	if !rows.Next() {
		t.Fatalf("%s is not in the public schema at all, so 00016 protected nothing. "+
			"Have the migrations been applied?", table)
	}
	if err := rows.Scan(&enabled, &forced, &acctIndex, &policies); err != nil {
		t.Fatalf("scan the catalog row for %s: %v", table, err)
	}
	if rows.Next() {
		t.Fatalf("%s answered the proof's query with more than one row, which cannot happen "+
			"within a single schema — the scope is broken and the proof is reading an arbitrary "+
			"row again", table)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating the catalog rows for %s: %v", table, err)
	}
	return enabled, forced, acctIndex, policies
}

func rlsDiagnosis(enabled, policies bool) string {
	if enabled && policies {
		return ""
	}
	if policies {
		return "\n\n  Its policies are all still installed, which is the signature of 00016's Down " +
			"section stopping between its `alter table … disable row level security` statements and the " +
			"`drop policy` statements after them (migrations/00016_account_isolation.sql:1025-1056): " +
			"a boundary that looks complete and enforces nothing.\n" +
			"  A migration replay ran against this database and was interrupted part-way. psql commits " +
			"each statement of a Down section separately, so there is no transaction to roll back, and a " +
			"concurrent suite makes the interruption likely: `ALTER TABLE` needs ACCESS EXCLUSIVE and a " +
			"test holding a lock on the next table blocks the replay there.\n" +
			"  Check who is replaying migrations against TEST_DATABASE_URL — `goose down`, `goose redo`, " +
			"`bin/migrate`, or `bin/migration-down-section | psql` — and whether one ran while this suite " +
			"was running. Then re-apply the migrations for the branch you are testing."
	}
	return "\n\n  Its policies are gone as well as its row-level security, so this is not an interrupted " +
		"undo: it is a database that does not have identity's migrations applied to it (or has had them " +
		"rolled all the way back). Rebuild it:\n" +
		"    goose -dir migrations postgres \"$TEST_DATABASE_URL\" up"
}

func TestTenancyCatalogProofReadsThePublicRowNotAClone(t *testing.T) {
	ctx, conn := connect(t)

	var noise [6]byte
	if _, err := rand.Read(noise[:]); err != nil {
		t.Fatalf("generating a schema name: %v", err)
	}
	schema := "test_" + hex.EncodeToString(noise[:])

	if _, err := conn.Exec(ctx, `create schema `+schema); err != nil {
		t.Fatalf("creating the %s schema: %v", schema, err)
	}
	t.Cleanup(func() {
		if _, err := conn.Exec(context.Background(), `drop schema if exists `+schema+` cascade`); err != nil {
			t.Logf("dropping the %s schema: %v", schema, err)
		}
	})
	if _, err := conn.Exec(ctx,
		`create table `+schema+`.account_users (like public.account_users including all)`); err != nil {
		t.Fatalf("cloning account_users into the %s schema: %v", schema, err)
	}

	var sameName int
	if err := conn.QueryRow(ctx,
		`select count(*) from pg_class where relname = $1`, "account_users").Scan(&sameName); err != nil {
		t.Fatalf("counting the relations named account_users: %v", err)
	}
	if sameName < 2 {
		t.Fatalf("this database holds %d relation(s) named account_users, so the clone above was not "+
			"created and the unscoped query cannot be shown to be ambiguous here. A test in that state "+
			"proves nothing.", sameName)
	}

	rows, err := conn.Query(ctx, catalogProof, "account_users")
	if err != nil {
		t.Fatalf("reading the catalog for account_users: %v", err)
	}
	defer rows.Close()

	if !rows.Next() {
		t.Fatal("the proof's query returned no row for account_users, so it proved nothing " +
			"about the public table")
	}
	var enabled, forced, acctIndex, policies bool
	if err := rows.Scan(&enabled, &forced, &acctIndex, &policies); err != nil {
		t.Fatalf("scan the catalog row for account_users: %v", err)
	}
	if rows.Next() {
		t.Fatal("the proof's query returned more than one row for account_users even " +
			"scoped to public, which should be impossible — a name is unique within a " +
			"schema. The scope is broken and the proof is reading an arbitrary row again")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating the catalog rows for account_users: %v", err)
	}

	if !enabled || !forced {
		t.Errorf("the proof read a catalog row for account_users with enabled=%v, forced=%v — "+
			"that is a clone's answer (or a real regression in 00016), and the proof is "+
			"supposed to read the public table's", enabled, forced)
	}
}

func seedAuditRows(ctx context.Context, t *testing.T, conn *pgx.Conn, role string) (tenantA, tenantB string) {
	t.Helper()

	var ids [2]string
	for i := range ids {
		if err := conn.QueryRow(ctx, `select gen_random_uuid()::text`).Scan(&ids[i]); err != nil {
			t.Fatalf("minting a tenant account id: %v", err)
		}
	}

	for _, id := range ids {
		if _, err := conn.Exec(ctx, `select anywaye.begin_account($1)`, id); err != nil {
			t.Fatalf("setting the identity for the seeded row: %v", err)
		}
		if _, err := conn.Exec(ctx, `
			insert into account_audit_log
				(account_id, action, actor_user_id, actor_key_id, target, affected, trace_id, occurred_at)
			values ($1, 'account.created', gen_random_uuid(), gen_random_uuid(),
			        'seed', 0, 'tenancy-test', now())`, id); err != nil {
			t.Fatalf("seeding account_audit_log for %s: %v", id, err)
		}
	}

	if _, err := conn.Exec(ctx, "set local role "+role); err != nil {
		t.Fatalf("restoring the role under test: %v", err)
	}
	return ids[0], ids[1]
}

func countAuditRows(ctx context.Context, t *testing.T, conn *pgx.Conn) int {
	t.Helper()
	return countAuditRowsIn(ctx, t, conn, "")
}

func countAuditRowsIn(ctx context.Context, t *testing.T, conn *pgx.Conn, accountID string) int {
	t.Helper()
	var n int
	var err error
	if accountID == "" {
		err = conn.QueryRow(ctx,
			`select count(*) from account_audit_log where target = 'seed'`).Scan(&n)
	} else {
		err = conn.QueryRow(ctx,
			`select count(*) from account_audit_log where target = 'seed' and account_id = $1`,
			accountID).Scan(&n)
	}
	if err != nil {
		t.Fatalf("counting account_audit_log rows: %v", err)
	}
	return n
}

func assertComplete(t *testing.T, got map[string]result) {
	t.Helper()
	want := readManifest(t)

	var missing, unexpected []string
	for _, name := range want {
		if _, ok := got[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range got {
		if !contains(want, name) {
			unexpected = append(unexpected, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)

	if len(missing) > 0 {
		t.Errorf("the proof did not return %d of the %d assertions it is supposed to make: %s",
			len(missing), len(want), strings.Join(missing, ", "))
		t.Error("  A missing assertion is a green suite proving less than it says. isolation.sql and")
		t.Error("  assertions.txt have drifted apart; isolation.sql is the one that moved.")
	}
	if len(unexpected) > 0 {
		t.Errorf("the proof returned %d assertion(s) assertions.txt does not name: %s",
			len(unexpected), strings.Join(unexpected, ", "))
		t.Error("  A new assertion has to be listed in assertions.txt before it counts, or it is")
		t.Error("  invisible to every service that adopted this.")
	}
}

func assertAllPass(t *testing.T, got map[string]result) {
	t.Helper()
	var failed []string
	for name, r := range got {
		if r.verdict != "pass" {
			failed = append(failed, fmt.Sprintf(
				"\n  %s\n    expected %q\n    actual   %q\n    because   %s",
				name, r.expected, r.actual, r.why))
		}
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		t.Errorf("%d of %d account-isolation assertions failed:%s",
			len(failed), len(got), strings.Join(failed, ""))
	}
}

func readManifest(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(here("assertions.txt"))
	if err != nil {
		t.Fatalf("read assertions.txt: %v", err)
	}
	var names []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		names = append(names, line)
	}
	if len(names) == 0 {
		t.Fatal("assertions.txt lists no assertions, so completeness is satisfied by a proof that returns nothing")
	}
	return names
}

func here(name string) string {
	_, self, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(self), name)
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
