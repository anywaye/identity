package migrate


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

func TestRunRefusesWithNoDSN(t *testing.T) {
	for _, dsn := range []string{"", "   ", "\t"} {
		if _, err := Run(context.Background(), dsn, migrations.FS, testLogger(t)); !errors.Is(err, ErrNoDSN) {
			t.Errorf("Run(%q) returned %v; want ErrNoDSN", dsn, err)
		}
	}
}

func TestASecondRunAppliesNothingAndALaterFileIsTheOnlyThingItApplies(t *testing.T) {
	dsn := newScratchDatabase(t)
	ctx := context.Background()
	logger := testLogger(t)

	first, err := Run(ctx, dsn, migrations.FS, logger)
	if err != nil {
		t.Fatalf("applying the embedded migrations to an empty database: %v", err)
	}
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

func TestAMigrationThatFailsIsNamedAndTheRunStopsThere(t *testing.T) {
	ctx := context.Background()

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
				broken: "-- +goose Up\nCREATE TABLE this is not sql;\n\n-- +goose Down\n",
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
			if applied != nil {
				t.Errorf("a failed run reported an applied set %v; a caller cannot tell that from a completed run", applied)
			}

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
