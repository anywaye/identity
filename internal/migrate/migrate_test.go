package migrate

// THE TESTS HERE RUN AGAINST A REAL POSTGRES, IN A DATABASE OF THEIR OWN.
//
// Not against TEST_DATABASE_URL's database: the two things this file asserts —
// that the migrations apply to an EMPTY database, and that a failure stops the
// run — are properties of a database that starts with no schema and no
// `goose_db_version` table. TEST_DATABASE_URL's database has both (bin/prime
// provisions and migrates it before the suite runs), so a test there would be
// asserting on a replay rather than on an apply, and would be green whatever the
// embed did.
//
// The scratch database is created and dropped by the test through the same DSN's
// credentials, which is what bin/rollback does for the same reason. It has to
// hold CREATEDB: locally the `identity` role does, and CI's job runs as a
// superuser. Without TEST_DATABASE_URL every test here skips and
// TestTheDatabaseTierActuallyRan fails, which is the same pair internal/mfa keeps.

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/migrations"
)

// TestRunRefusesWithNoDSN is the contract with the substrate's step, which sets
// DATABASE_URL: a Job launched without one must fail with a sentence, not start a
// connection to nowhere or report success by doing nothing.
func TestRunRefusesWithNoDSN(t *testing.T) {
	for _, dsn := range []string{"", "   ", "\t"} {
		if _, err := Run(context.Background(), dsn, migrations.FS, testLogger(t)); !errors.Is(err, ErrNoDSN) {
			t.Errorf("Run(%q) returned %v; want ErrNoDSN", dsn, err)
		}
	}
}

// TestASecondRunAppliesNothingAndALaterFileIsTheOnlyThingItApplies is the
// idempotency the substrate's re-run depends on, with the control that makes it
// mean something.
//
// The substrate re-runs its migrate step whenever the image changes
// (`migration_guard_applied` only skips it for the image already recorded), so
// "applies nothing the second time" is a contract and not a nicety.
//
// THE CONTROL IS THE THIRD RUN, and it is the reason this is one test rather
// than two. `len(second) == 0` is also true of a Run that never looks at the
// filesystem, of one that fails to see new files, and of one that was never
// called again — so the same Run, against the same database, is told about one
// more file and must apply exactly that one.
func TestASecondRunAppliesNothingAndALaterFileIsTheOnlyThingItApplies(t *testing.T) {
	dsn := newScratchDatabase(t)
	ctx := context.Background()
	logger := testLogger(t)

	first, err := Run(ctx, dsn, migrations.FS, logger)
	if err != nil {
		t.Fatalf("applying the embedded migrations to an empty database: %v", err)
	}
	// The control in the other direction: a first run that applied NOTHING would
	// make the assertion below true for the worst possible reason.
	if len(first) == 0 {
		t.Fatal("the first run against an empty database applied nothing, so the " +
			"`second run applies nothing` assertion below is vacuous")
	}
	t.Logf("the first run applied %d migrations, %s … %s", len(first), first[0], first[len(first)-1])

	second, err := Run(ctx, dsn, migrations.FS, logger)
	if err != nil {
		t.Fatalf("the second run failed: %v", err)
	}
	if len(second) != 0 {
		t.Errorf("a second run against the same database applied %v; the substrate's "+
			"re-run of the migrate step depends on this being empty", second)
	}

	const later = "99999_a_later_migration.sql"
	withLater := extend(t, migrations.FS, map[string]string{
		later: "-- +goose Up\nCREATE TABLE migrate_test_later (id int);\n" +
			"\n-- +goose Down\nDROP TABLE migrate_test_later;\n",
	})

	third, err := Run(ctx, dsn, withLater, logger)
	if err != nil {
		t.Fatalf("a run with one new file failed: %v", err)
	}
	if len(third) != 1 || third[0] != later {
		t.Errorf("a run with one new file applied %v; want exactly [%s]. "+
			"`nothing was pending` and `the new file was not seen` are indistinguishable "+
			"unless this holds", third, later)
	}
}

// TestAMigrationThatFailsIsNamedAndTheRunStopsThere is the third done-means: a
// bad migration exits non-zero NAMING THE FILE, and nothing after it runs.
//
// IT RUNS TWICE WITH TWO DIFFERENT NAMES, and that is the control: an assertion
// that the error contains a filename would also pass against a hardcoded string
// in the implementation, and a single case cannot tell the two apart.
func TestAMigrationThatFailsIsNamedAndTheRunStopsThere(t *testing.T) {
	ctx := context.Background()

	// THE CONTROL THAT THE HARNESS IS NOT THE PROBLEM. Same engine, same
	// migrations, same Postgres, a database of its own, no injected file: no
	// error. Without this, a red below could be the suite's database, a missing
	// role or a broken embed rather than the injected statement.
	control := newScratchDatabase(t)
	applied, err := Run(ctx, control, migrations.FS, testLogger(t))
	if err != nil {
		t.Fatalf("the embedded migrations do not apply cleanly to a fresh database, "+
			"so a failure below would not be about the injected file: %v", err)
	}
	if len(applied) == 0 {
		t.Fatal("the control run applied nothing, so it is not evidence that a failure below comes from the injected file")
	}
	if tableExists(t, control, "migrate_test_never_reached") {
		t.Fatal("the control database already has the marker table, so `nothing after the failure ran` below would be vacuous")
	}

	for _, broken := range []string{
		"00036_deliberately_broken.sql",
		"00036_a_different_broken_name.sql",
	} {
		t.Run(broken, func(t *testing.T) {
			dsn := newScratchDatabase(t)
			files := extend(t, migrations.FS, map[string]string{
				// After the last embedded migration (00035) and before the marker,
				// so `the run stopped` is a statement about the middle of the run
				// rather than about the last file.
				broken: "-- +goose Up\nCREATE TABLE this is not sql;\n\n-- +goose Down\n",
				// A valid migration AFTER the broken one. If the run continued past
				// the failure this table would exist; it must not.
				"00037_never_reached.sql": "-- +goose Up\nCREATE TABLE migrate_test_never_reached (id int);\n" +
					"\n-- +goose Down\nDROP TABLE migrate_test_never_reached;\n",
			})

			applied, err := Run(ctx, dsn, files, testLogger(t))
			if err == nil {
				t.Fatal("a migration whose SQL is not SQL was applied without an error, " +
					"so a box would report a finished install over a schema the migrator never got past")
			}
			t.Logf("the failure, as the substrate's `kubectl logs` would show it: %v", err)

			if !strings.Contains(err.Error(), broken) {
				t.Errorf("the failure does not name %s, so a deployed failure is a bisect "+
					"rather than a filename: %v", broken, err)
			}
			// goose returns the applied set only on success. The substrate reads the
			// exit status, but a caller that reported `applied: nil` as a partial
			// success would be the defect this asserts against.
			if applied != nil {
				t.Errorf("a failed run reported an applied set %v; a caller cannot tell that from a completed run", applied)
			}

			// "STOPS AT THE FIRST FAILURE" IS A FACT ABOUT THE DATABASE, not about
			// the error: the file after the broken one must not have run, and the
			// file before it must have.
			if tableExists(t, dsn, "migrate_test_never_reached") {
				t.Error("00037 applied after 00036 failed: the run did not stop at the failure, " +
					"so a schema could be half this image and half the next one")
			}
			if !tableExists(t, dsn, "users") {
				t.Error("the migrations before the failure did not apply either, so the " +
					"run failed at something other than the injected file")
			}
		})
	}
}

// TestTheDatabaseTierActuallyRan is the last line of defense against a green gate
// that verified nothing.
//
// It FAILS rather than skips when TEST_DATABASE_URL is unset, because every test
// above is a database test that skips without it: this file would report `ok`
// having proven nothing about the image's ability to migrate.
//
// IT IS A READ, deliberately. The tests above migrate databases of their own;
// this one points at the SHARED suite database, which bin/prime has already
// provisioned and migrated, and it asks it for its recorded version. Applying
// anything there would be this file mutating a database other packages are
// testing against at the same moment.
func TestTheDatabaseTierActuallyRan(t *testing.T) {
	dsn := os.Getenv(dbtest.EnvVar)
	if dsn == "" {
		t.Fatalf("%s is not set, so every migrate test above skipped and a green run "+
			"has verified nothing about the image's ability to migrate its own schema. "+
			"Start Postgres (`docker compose up -d --wait postgres`) and re-run with %s set.",
			dbtest.EnvVar, dbtest.EnvVar)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("opening %s: %v", dbtest.EnvVar, err)
	}
	defer func() { _ = db.Close() }()

	var version int64
	if err := db.QueryRowContext(context.Background(),
		`select coalesce(max(version_id), 0) from goose_db_version`).Scan(&version); err != nil {
		t.Fatalf("%s is set but has no readable goose_db_version (%v), so the suite is "+
			"running against a database no migration has touched. bin/prime provisions it "+
			"with bin/provision-testdb before the suite; a scan that reaches a server without it "+
			"reads like a code failure rather than a pipeline that is wired wrong.", dbtest.EnvVar, err)
	}
	if version < 1 {
		t.Fatalf("%s records no applied migration (max version %d)", dbtest.EnvVar, version)
	}
	t.Logf("the shared suite database is at migration version %d", version)
}

// newScratchDatabase creates a database for one test and returns a DSN for it.
//
// A DATABASE AND NOT A SCHEMA. The migrations qualify objects (`public.users`,
// `anywaye.protect_table`) and carry their own version table, so a private
// `search_path` would be a second, quieter schema model that production does not
// have. The database is dropped on the way out.
func newScratchDatabase(t *testing.T) string {
	t.Helper()

	base := os.Getenv(dbtest.EnvVar)
	if base == "" {
		t.Skipf("%s is not set, so there is no server to migrate against", dbtest.EnvVar)
	}

	ctx := context.Background()
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatalf("opening an admin connection to %s: %v", dbtest.EnvVar, err)
	}
	// Registered first, so it runs LAST: cleanups are LIFO and the DROP below
	// still needs this connection.
	t.Cleanup(func() { _ = admin.Close() })
	if err := admin.PingContext(ctx); err != nil {
		t.Fatalf("%s is set but not reachable (%v). Is the server up?", dbtest.EnvVar, err)
	}

	name := "identity_migrate_" + randomSuffix(t)

	if _, err := admin.ExecContext(ctx, `create database "`+name+`"`); err != nil {
		t.Fatalf("creating the scratch database %s (does %s's user hold CREATEDB?): %v",
			name, dbtest.EnvVar, err)
	}
	t.Cleanup(func() {
		// An `if exists` because a failed CREATE below would otherwise turn the
		// cleanup into a second, more confusing failure.
		if _, err := admin.ExecContext(context.Background(), `drop database if exists "`+name+`"`); err != nil {
			t.Errorf("dropping the scratch database %s: %v", name, err)
		}
	})

	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parsing %s: %v", dbtest.EnvVar, err)
	}
	parsed.Path = "/" + name
	return parsed.String()
}

func randomSuffix(t *testing.T) string {
	t.Helper()

	var noise [6]byte
	if _, err := rand.Read(noise[:]); err != nil {
		t.Fatalf("generating a database name: %v", err)
	}
	return hex.EncodeToString(noise[:])
}

// tableExists asks the database, not the error, whether a migration ran.
func tableExists(t *testing.T, dsn, name string) bool {
	t.Helper()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("opening the scratch database: %v", err)
	}
	defer func() { _ = db.Close() }()

	var exists bool
	if err := db.QueryRowContext(context.Background(),
		`select exists (select 1 from information_schema.tables
		                where table_schema = 'public' and table_name = $1)`, name).Scan(&exists); err != nil {
		t.Fatalf("asking the database about %s: %v", name, err)
	}
	return exists
}

// extend copies base and adds files, so a test can inject a migration into the
// real set without touching the tree. The copy is what makes the injection the
// ONLY difference between the control and the case.
func extend(t *testing.T, base fs.FS, extra map[string]string) fstest.MapFS {
	t.Helper()

	out := fstest.MapFS{}
	err := fs.WalkDir(base, ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		body, err := fs.ReadFile(base, p)
		if err != nil {
			return err
		}
		out[p] = &fstest.MapFile{Data: body}
		return nil
	})
	if err != nil {
		t.Fatalf("copying the embedded migrations: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("the embedded set is empty, so every case below would be testing an empty directory")
	}

	for name, body := range extra {
		out[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return out
}

// testLogger routes goose's own progress lines into the test's output (visible
// under -v), which is where the substrate's `kubectl logs` would show them.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(&testWriter{t: t}, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

type testWriter struct{ t *testing.T }

func (w *testWriter) Write(p []byte) (int, error) {
	if line := bytes.TrimRight(p, "\n"); len(line) > 0 {
		w.t.Logf("%s", line)
	}
	return len(p), nil
}
