// Package tenancy proves that identity's account boundary is enforced by Postgres.
//
// Two tests, and they prove two different things, which is why both are here.
//
//	TestTenancyAccountIsolation          kit's assertion set, run whole. Its fixture is
//	                                    its OWN TEMPORARY tables, so it proves the
//	                                    SUBSTRATE 00016 installed and that the
//	                                    assertion set can still fail - including the
//	                                    FORCE-RLS control, which is the only half that
//	                                    proves the owner is subject to its own policies.
//
// TestTenancyIdentityOwnsItsFiveTables  the other half. The first test's tables are
//
//	kit's, not identity's, so on its own it proves a
//	service can call protect_table and nothing about
//	whether identity's FIVE tables are protected.
//	This one names them, reads pg_catalog, and runs
//	the three-way denial against real rows.
//
// THE DSN IS THE OWNER. TEST_DATABASE_URL must be a role that may `set role` to
// `identity_app`, because the proof has to run as BOTH roles and impersonating a
// strictly weaker one cannot widen anything. On the dev cluster the owner is
// `identity` and kit's initdb grants `identity_app` TO `identity` for exactly this.
// In CI the same DSN is `identity:identity@localhost:5432/identity`.
//
// NO BUILD TAG, and that is a decision rather than an omission. kit's template is
// tagged `tier_db`, and this repository has no tier_db convention: `go test ./...` in
// .github/workflows/ci.yml is the whole suite and it passes no tags, so a tagged test
// would never be COMPILED there and the account boundary would ship with a proof that
// cannot run. What replaces the tag is the repository's own pair: a loud skip when
// TEST_DATABASE_URL is unset (so `go test ./...` stays green with no database, which
// this suite is built to do), and REQUIRED_DB=1 to turn that skip into a FAILURE for
// anyone who needs the tier to be non-optional - which is the same contract kit's
// driver states, carried over so the driver is still recognisably kit's.
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

// result is one row of the proof's answer: what was asserted, what was expected,
// what happened, and why the assertion exists at all.
type result struct{ expected, actual, verdict, why string }

// oneMinute is the whole budget for the proof. Bounded rather than defaulted because
// a hang here is a hang in the service's gate.
const oneMinute = time.Minute

// identityTables is the set 00016 protects. Named here as well as in the migration
// because the migration is the decision and this is the check on the decision: a
// table added to one and not the other is exactly what the sweep below reports.
var identityTables = []string{
	"account_users",
	"account_invitations",
	"oidc_clients",
	"api_keys",
	"account_audit_log",
}

// dsnOrSkip is the loud one.
//
// The message names the variable, says what was NOT proven, and says what to do -
// a skip whose text is only "skipping" is indistinguishable at a glance from a test
// that passed, which is the whole failure mode a database tier has.
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

// TestTenancyAccountIsolation runs kit's assertion set and checks the names it got
// back against the manifest, in BOTH directions.
//
// Named with a `Tenancy` prefix rather than kit's `TestAccountIsolation` so that
// `-run Tenancy` selects it; the shape of the file is otherwise kit's, because the
// file's own argument is that a thin driver is safe precisely when it compares names
// rather than counts.
func TestTenancyAccountIsolation(t *testing.T) {
	ctx, conn := connect(t)

	// The proof, run whole and unexamined. It opens a transaction and leaves it open,
	// because two of the things it does refuse to do outside one; every object it
	// creates is TEMPORARY, so nothing survives the session either way.
	//
	// pgx sends a statement with no bind parameters over the simple protocol, which
	// is the one that accepts a multi-statement batch.
	script, err := os.ReadFile(here("isolation.sql"))
	if err != nil {
		t.Fatalf("read isolation.sql: %v", err)
	}
	if _, err := conn.Exec(ctx, string(script)); err != nil {
		t.Fatalf("isolation.sql did not complete: %v", err)
	}

	rows, err := conn.Query(ctx, `
		select assertion, expected, actual, verdict, why
		  from pg_temp.cafaye_probe_result
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

	// Roll the proof's transaction back rather than leaving it open: everything it
	// created is temporary, but a test that leaves a transaction open makes every test
	// after it run inside it.
	if _, err := conn.Exec(ctx, "rollback"); err != nil {
		t.Fatalf("roll back the proof's transaction: %v", err)
	}

	t.Logf("kit's assertion set returned %d assertions", len(got))
	assertComplete(t, got)
	assertAllPass(t, got)
}

// TestTenancyIdentityOwnsItsFiveTables is the half kit's assertion set cannot be.
//
// isolation.sql protects its own temporary fixture table and proves the substrate
// works. It never names account_users, account_invitations, oidc_clients, api_keys or
// account_audit_log, so a migration that installed a perfect substrate and protected
// NO tables would pass it. This test is the one that closes that gap, in the two ways
// that are available from outside:
//
//  1. the CATALOG. For each of the five: row-level security enabled, and FORCED - the
//     bit without which the owner reads every account's rows while the policies look
//     like they are in place - plus the four named policies protect_table wrote.
//  2. THE THREE-WAY DENIAL, on real rows, as BOTH roles. no identity reads zero; the
//     other tenant's VALID identity reads zero of that tenant's rows; the account's
//     own identity reads its own rows. The third arm is the one with the information
//     in it: a suite that only asserts the first two is satisfied by a table nobody
//     can read.
//
// IT USES account_audit_log FOR THE DATA-BEARING HALF, and the reason is in 00012's
// header: this table has NO foreign keys, so the fixture needs no users and no
// accounts and cannot collide with any other package's rows. The four tables that do
// have foreign keys are covered by the catalog half above rather than by fixture
// rows, because seeding them correctly means seeding users and accounts in tables
// this repository's other packages also write to - and a shared database plus a
// global TRUNCATE is precisely the non-deterministic failure dbtest's package comment
// warns about.
func TestTenancyIdentityOwnsItsFiveTables(t *testing.T) {
	ctx, conn := connect(t)

	t.Run("the owner and app roles are not superuser or BYPASSRLS", func(t *testing.T) {
		// A role with rolsuper or rolbypassrls bypasses row-level security even
		// when FORCE is set, so the catalog can read t/t while the owner still
		// reads every row. The gate postgres that used POSTGRES_USER=identity on
		// postgres:17-alpine made identity the bootstrap superuser; fresh volume,
		// migrations green, tenancy red with extra owner rows and the append-only
		// trigger instead of the RLS denial — m156. kit's cluster and brew postgres
		// provision identity as NOSUPERUSER NOBYPASSRLS.
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
			enabled, forced, acctIndex, policies := protectedCatalogRow(t, ctx, conn, table)
			// One sentence for every finding below, decided once. Four failure
			// messages that each restate "the catalog disagrees" is how a
			// two-line catalog diff ends up costing a worker an hour: the
			// messages name the disagreement and not the two things that can
			// cause it, and both of those are things the reader can go and check.
			why := rlsDiagnosis(enabled, policies)

			if !enabled {
				t.Errorf("%s: row level security is NOT enabled, so no policy on it is ever evaluated.%s", table, why)
			}
			if !forced {
				// The one finding no lint in this fleet checks for, and the one this
				// whole migration exists to get right.
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
		// The sweep is the question "is this service isolated?", and it answers for
		// every table rather than the first, because a caller that gets rows can
		// print them all.
		//
		// SCOPED TO public, and this is not a narrowing to make the assertion pass.
		// `go test ./...` runs packages in parallel and internal/platform/dbtest
		// gives every package that needs an empty database a PRIVATE schema named
		// test_<hex>, built with LIKE ... INCLUDING ALL. LIKE does not copy
		// row-level security, so every one of those clones carries an account_id
		// column and no policies — and the sweep reports them, which is correct and
		// is exactly what kit's README says it is for ("temporary tables are NOT
		// excluded, and that is deliberate... a temp table with an account_id
		// column and no policies is genuinely unprotected, it is exactly the shape
		// a service's test fixture has").
		//
		// Measured before this was scoped, running the whole suite: 21 rows, every
		// one of them another package's fixture schema. identity's own five tables
		// are in `public`, and that is the schema this assertion is about.
		rows, err := conn.Query(ctx, `
			select table_schema, table_name, why
			  from cafaye.unprotected_tables()
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
			t.Errorf("cafaye.unprotected_tables() found %d account-scoped table(s) in public with "+
				"no boundary - an account-scoped table that no policy covers:\n  %s",
				len(unprotected), strings.Join(unprotected, "\n  "))
		}
	})

	// THE THREE-WAY DENIAL, on real rows, as each role in turn.
	//
	// `role` is a parameter rather than an identifier, so it cannot be interpolated
	// into SQL - it is passed to `set role`, which takes a string, and both values
	// are literals in this file.
	for _, role := range []string{"identity_app", "identity"} {
		role := role
		t.Run("three-way denial as "+role, func(t *testing.T) {
			ctx, conn := connect(t)

			// The transaction is explicit because begin_account/1 is
			// transaction-local: outside one it expires at the end of the statement
			// that set it, and this would read zero rows everywhere and look like
			// perfect isolation.
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

			// Two tenants, one row each, written by the OWNER before the identity is
			// set and before the role is dropped - because the insert policy is
			// `with check (account_id = (select cafaye.current_account_id()))`, so a
			// writer with no identity is refused, which is the write-side twin of the
			// read denial and is itself correct.
			tenantA, tenantB := seedAuditRows(t, ctx, conn, role)

			// ARM ONE. No identity. `begin_account(NULL)` clears, which is the state a
			// request that never authenticated is in.
			if _, err := conn.Exec(ctx, `select cafaye.begin_account(NULL)`); err != nil {
				t.Fatalf("clearing the account identity: %v", err)
			}
			if got := countAuditRows(t, ctx, conn); got != 0 {
				t.Errorf("as %s with NO identity: read %d rows, want 0. A request that never "+
					"authenticated is reading account data", role, got)
			}

			// ARM TWO. The other tenant's VALID identity. This is the arm that carries
			// the information: the credential is real, it belongs to another account,
			// and it must be indistinguishable from one that does not exist.
			if _, err := conn.Exec(ctx, `select cafaye.begin_account($1)`, tenantB); err != nil {
				t.Fatalf("setting the other tenant's identity: %v", err)
			}
			if got := countAuditRows(t, ctx, conn); got != 1 {
				t.Errorf("as %s carrying ANOTHER tenant's valid identity: read %d rows, want 1 "+
					"(its own). Anything more is a cross-account read", role, got)
			}
			if got := countAuditRowsIn(t, ctx, conn, tenantA); got != 0 {
				t.Errorf("as %s carrying ANOTHER tenant's valid identity: read %d of THAT "+
					"tenant's rows, want 0", role, got)
			}

			// ARM THREE. Its own identity. The positive control, and the only arm a
			// deny-everything table can pass.
			if _, err := conn.Exec(ctx, `select cafaye.begin_account($1)`, tenantA); err != nil {
				t.Fatalf("setting the account's own identity: %v", err)
			}
			if got := countAuditRowsIn(t, ctx, conn, tenantA); got != 1 {
				t.Errorf("as %s with its OWN identity: read %d of its own rows, want 1. A table "+
					"that denies everybody also passes the two arms above, which is why this one "+
					"exists", role, got)
			}
			if got := countAuditRows(t, ctx, conn); got != 1 {
				t.Errorf("as %s with its OWN identity: an unqualified read returned %d rows, want 1 "+
					"(its own only)", role, got)
			}

			// AND THE WRITE SIDE, because a read denial with no write assertion is
			// half a boundary: `using` denies an UPDATE by matching zero rows and
			// raising nothing, so "the other tenant's row came back unchanged" is the
			// only proof that the denial happened rather than the write being a no-op.
			if _, err := conn.Exec(ctx, `select cafaye.begin_account($1)`, tenantB); err != nil {
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

// catalogProof is the proof's one question about one of identity's tables,
// answered from the catalog: is the table in `public` protected — row-level
// security enabled, FORCED, the account_id index in place, at least one
// policy.
//
// SCOPED TO public, AND THE SCOPE IS THE FIX FOR THE FLAKE OF 2026-10-06.
// dbtest.Schema clones these same table names into test_<hex> schemas with
// LIKE ... INCLUDING ALL — which copies the indexes and NOT the row-level
// security — so an unscoped `where c.relname = $1` returns one row per clone
// as well, in whatever order the heap happens to walk. A proof that reads the
// first row of that can read a CLONE's answer — relrowsecurity false, no
// policies — and report the public table broken, which is exactly the
// signature the damaged days produced. The public tables were never damaged;
// rebuilding the database "fixed" it only because a fresh database has no
// clones to be confused with. The scope narrows nothing the proof claims:
// identity's tables live in public, and a table that migrates elsewhere is a
// fact the proof should report, not a row to quietly skip.
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

// protectedCatalogRow asks catalogProof about one table and returns the
// answer.
//
// IT FAILS THE TEST UNLESS THE ANSWER IS EXACTLY ONE ROW. "Exactly one" is
// the property the schema scope exists to guarantee — a relation name is
// unique within a schema — and a proof that accepted two rows and read
// either one would be the flake again with extra steps.
func protectedCatalogRow(t *testing.T, ctx context.Context, conn *pgx.Conn, table string) (enabled, forced, acctIndex, policies bool) {
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

// rlsDiagnosis is the sentence every finding in
// "every declared table is enabled and FORCED" carries, and it is one function
// because the two causes have to be told apart by SOMETHING and the only
// something available is the rest of the row.
//
// THE TWO CAUSES, AND WHICH IS WHICH.
//
//   - POLICIES PRESENT, RLS OFF. This is migrations/00016's Down section, cut in
//     half. That section disables row-level security on the five tables in five
//     separate statements and only THEN drops their policies
//     (migrations/00016_account_isolation.sql:1025-1056), so a replay that stops
//     between the two groups leaves a table with all of its policies still
//     installed and no RLS evaluating them — a boundary that looks complete and
//     enforces nothing. psql runs a Down section one statement per transaction,
//     so a replay is only ever atomic per statement, and a replay running
//     against a database another suite is using is interrupted more easily than
//     it looks: `ALTER TABLE` needs ACCESS EXCLUSIVE, and the third table is as
//     likely to be the one a concurrent test holds a lock on as the first.
//
//   - POLICIES ABSENT. Not a half-finished undo: a table with no policies on it
//     is what the migrations never produced, so this is the database not being
//     the one these tests were written against.
//
// WHY THE MESSAGE SAYS SO INSTEAD OF NAMING THE SYMPTOM. The two produce the
// same two lines of diff in a log — "NOT enabled", "NOT FORCE" — and they have
// opposite remedies: one is somebody's interrupted migration replay and the other
// is a database to rebuild. A reader who is handed only the first has to go and
// work out which one they are looking at.
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

// TestTheCatalogProofReadsThePublicRowNotAClone is the regression test for
// the flake of 2026-10-06, and it is a test of the PROOF rather than of the
// database: it builds the thing that fooled the proof — a same-named clone
// in a test_ schema, with the indexes and without the row-level security,
// which is what dbtest.Schema's LIKE ... INCLUDING ALL produces — and asserts
// the proof's query still answers with the public table's row and nothing
// else.
//
// WHAT IT WOULD HAVE CAUGHT. The proof's catalog query was
// `where c.relname = $1` with no schema filter and no ORDER BY, and it read one
// row of what could be many. Which row came first was not the query's business:
// with enough same-named relations in the catalog, Postgres answers that shape
// with a Bitmap Heap Scan, which returns rows in physical heap order — and the
// public table's physical position is NOT stable. `ANALYZE`, `TRUNCATE` and
// `ALTER TABLE` all write a new pg_class tuple under MVCC, and a new tuple
// version lands AFTER every clone created since the last move. `dbtest.Schema`
// clones every one of the five tables in identityTables and drops the clone at
// test cleanup, so a clone outlives its test whenever the suite is killed
// mid-run — and a clone that predates the public table's current tuple is a
// row the proof reads first: RLS off, no FORCE, no policies, and the
// account_id index present because LIKE copies indexes. Reproduced
// deterministically on a scratch database for this packet: with the public
// tuple moved and 1200 clones present, the old query returns the clone's
// (enabled=false, forced=false) for a public table that reads (true, true).
//
// THE COUNT IS THE DETERMINISTIC HALF, and it is the half asserted first.
// Against the old query a clone makes it match two rows — every time, no
// ordering luck involved — so removing the scope fails this test even on a heap
// where the public row would have won. The unscoped query is run here on
// purpose rather than described in a comment: a comment saying "the old query
// was ambiguous" is a claim, and the query matching two rows is the proof of
// it. The enabled/forced assertions are the other half: the one row read must be
// the public table's answer, not merely A row.
func TestTenancyCatalogProofReadsThePublicRowNotAClone(t *testing.T) {
	ctx, conn := connect(t)

	// The clone, built the way dbtest.Schema builds them. The name is random
	// for the reason dbtest.Schema's is: two proofs running at once, or a
	// killed run's debris, must not collide with this one.
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

	// THE FAILURE DIRECTION, asserted before the fix is asserted. This is the
	// query that was there before, verbatim apart from the columns: it matched
	// every relation of that name in the whole cluster and read whichever row
	// the plan produced first. With one clone beside the public table it matches
	// two rows — every time, no ordering luck involved — so the assertion is
	// about a COUNT and not about an ordering. A check that only asked which row
	// came first would pass on a heap where the public row happened to win, and
	// that heap is the one the flake was hiding in.
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

	// The proof's query, with a clone of the same name sitting in the catalog.
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

	// And the one row it did read is the PUBLIC table's answer: protected.
	// A clone's row reads enabled=false, forced=false — the flake's signature —
	// so this is the assertion that the scope is pointed at the right schema
	// and not merely at one row.
	if !enabled || !forced {
		t.Errorf("the proof read a catalog row for account_users with enabled=%v, forced=%v — "+
			"that is a clone's answer (or a real regression in 00016), and the proof is "+
			"supposed to read the public table's", enabled, forced)
	}
}

// seedAuditRows writes one account_audit_log row per tenant and returns the two
// account ids.
//
// IT SETS AN IDENTITY FOR EACH ROW, AND THAT IS NOT A WORKAROUND — it is the write
// side of the same boundary, arriving in the fixture. `protect_table` names the OWNER
// in every policy (FORCE removed the owner's exemption, so an owner with no identity
// would read nothing at all), which means the owner's INSERT is subject to
// `with check (account_id = (select cafaye.current_account_id()))` too. Seeding
// without an identity fails with:
//
//	ERROR: new row violates row-level security policy for table "account_audit_log"
//	(SQLSTATE 42501)
//
// which is the correct behaviour and the first evidence in this repository that the
// boundary is live: before 00016 that INSERT succeeded. Each row therefore gets its
// own `begin_account` inside the same transaction — `is_local = true` means the value
// is transaction-scoped rather than connection-scoped, so overwriting it per row is
// exactly what it is for and a pooled connection cannot carry it to the next request.
//
// account_audit_log is the table used because 00012 gives it NO foreign keys, so the
// fixture needs no users and no accounts and cannot collide with another package's
// rows in the shared TEST_DATABASE_URL.
func seedAuditRows(t *testing.T, ctx context.Context, conn *pgx.Conn, role string) (tenantA, tenantB string) {
	t.Helper()

	// `gen_random_uuid()` is executable by PUBLIC and reads no table, so this works
	// under either role.
	var ids [2]string
	for i := range ids {
		if err := conn.QueryRow(ctx, `select gen_random_uuid()::text`).Scan(&ids[i]); err != nil {
			t.Fatalf("minting a tenant account id: %v", err)
		}
	}

	for _, id := range ids {
		if _, err := conn.Exec(ctx, `select cafaye.begin_account($1)`, id); err != nil {
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

	// `set local role` again, because seeding ran under whichever role the caller had
	// already selected and this makes the choice explicit rather than inherited.
	if _, err := conn.Exec(ctx, "set local role "+role); err != nil {
		t.Fatalf("restoring the role under test: %v", err)
	}
	return ids[0], ids[1]
}

func countAuditRows(t *testing.T, ctx context.Context, conn *pgx.Conn) int {
	t.Helper()
	return countAuditRowsIn(t, ctx, conn, "")
}

func countAuditRowsIn(t *testing.T, ctx context.Context, conn *pgx.Conn, accountID string) int {
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

// assertComplete — the assertion set is EXACTLY the one assertions.txt names.
//
// Both directions, and both are needed. A missing name means the proof stopped
// asserting something, which a "no failures" assertion would report as a pass. An
// extra name means the proof grew something the driver does not know about, which
// means the driver and the proof have separated and the next edit to either is made
// against a stale idea of the other. A count would not do: a count of 24 is
// compatible with 24 of the wrong 24.
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

// assertAllPass — every assertion that came back, and its reason when it did not.
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

// readManifest — the names assertions.txt lists, comments and blanks dropped.
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

// here — the directory this source file is in.
//
// `runtime.Caller` rather than the working directory, because a test's working
// directory is the package directory only for `go test` in the module root: run from
// elsewhere, and a relative path silently finds nothing.
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
