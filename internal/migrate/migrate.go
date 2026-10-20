// Package migrate applies this repository's goose migrations from an embedded
// copy of `migrations/`, inside the `identity` binary, with no shell and no
// `psql`.
//
// # WHY THE BINARY MIGRATES ITSELF, AND WHY THAT IS NOT "MIGRATE AT BOOT"
//
// A box that finishes the substrate used to boot this service against an empty
// schema: `relation "outbox_events" does not exist (SQLSTATE 42P01)` forever.
// The substrate now runs one one-shot migrate Job per schema-owning service, in
// that service's own image, as its OWNER role (kit's
// `templates/substrate/install.sh`, `install_migrations`) — and identity's image
// had nothing to run: the runtime stage is
// `gcr.io/distroless/static-debian12:nonroot`, which has no shell, no `psql` and
// no `migrations/`, while `bin/migrate` is a `psql` loop over those files.
//
// This package is the other half. It is NOT "the service migrates at boot":
// nothing here is called from `run()`. Migrating stays a deploy step
// (migrations/README.md), performed by a process that starts, applies, and
// exits — which is exactly what `identity migrate` is, and why the entrypoint
// below dispatches on a subcommand rather than migrating on the way to serving.
//
// # WHY THE goose LIBRARY AND NOT A SECOND APPLIER
//
// `goose` is pinned at v3.28.0, the version `bin/provision-testdb`,
// `ci/ci.yml` and the README's own commands use. Linking the
// library in at that same version means ONE migration engine describes the
// schema on a developer's machine, in CI and on the box, and one version table
// (`goose_db_version`) records where each database is.
//
// The alternative — embedding the files and writing a second applier over pgx —
// was refused, and this repository has the receipt: `bin/migrate` was the
// second implementation, it fed psql both goose sections, and it applied every
// migration and then reverted it, exiting zero (identity-31, and
// `internal/platform/ci/migrate_test.go` is the guard). A third implementation
// would inherit that class of bug and add the version table to it. What this
// package owns is the wiring — which DSN, which files, which log, which exit
// status — and nothing about the annotations, the transaction per migration,
// the checksums or the version table.
//
// # WHAT IT DOES NOT NEED
//
// The DSN comes from `DATABASE_URL` and nothing else, which is the variable the
// substrate's step sets and the one `bin/migrate` reads. This package never
// loads the service's configuration: a migrate Job is handed a database and
// nothing else, so requiring OIDC_LOGIN_UI_URL or SIGNUP_SIGNING_KEY to apply a
// migration would make the Job fail for a reason that has nothing to do with the
// schema.
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"strings"
	"time"

	"github.com/pressly/goose/v3"

	// The `database/sql` driver goose needs, and it is pgx — the Postgres
	// library this service already depends on — rather than a second connection
	// stack in the image. Imported for its side effect: it registers the "pgx"
	// driver name `sql.Open` below asks for.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// ErrNoDSN is returned when there is no database to migrate.
//
// It is a named error rather than a message so a caller can tell "the Job was
// started without a DSN" from "the DSN was refused", which are different
// conversations with different people.
var ErrNoDSN = errors.New("DATABASE_URL is not set; there is no database to migrate")

// RunTimeout bounds the whole apply, and the number comes from the substrate's
// own patience rather than from taste: `install_migrations` polls the Job's pod
// phase 36 times with a 5 second sleep — 180 seconds — before it declares the
// migration failed. A process that is still connected at 180 seconds produces
// "last pod phase: 'Running'" and a red install that names nobody's mistake, so
// this is deliberately shorter: the run gives up first, with an error that says
// which database it could not reach.
//
// A fresh box applies all migrations in seconds; the headroom is for an
// `ALTER TABLE` waiting on a lock, which is the slow case that is real.
const RunTimeout = 2 * time.Minute

// Run applies every pending migration in fsys to the database named by dsn and
// returns the file names it applied, in order.
//
// A SECOND CALL RETURNS AN EMPTY SLICE, and that is the idempotency the
// substrate's re-run depends on: goose records every applied file in
// `goose_db_version` (as the CLI does, because this is the same engine at the
// same version), so "pending" is a question about that table and not about
// whether the files look applied. A file that fails is rolled back with its own
// transaction, and the error names it.
func Run(ctx context.Context, dsn string, fsys fs.FS, logger *slog.Logger) ([]string, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, ErrNoDSN
	}
	if fsys == nil {
		return nil, errors.New("no migrations to apply: the filesystem is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithTimeout(ctx, RunTimeout)
	defer cancel()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening the database: %w", err)
	}
	defer func() { _ = db.Close() }()

	// sql.Open is lazy, which is the same shape the service's own pool has
	// (AGENTS.md): connecting here means an unreachable database reports as a
	// connect failure with this error, rather than as a nil dereference or a
	// timeout inside goose's first query.
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("connecting to the database: %w", err)
	}

	// The provider rather than the package-level goose functions: goose's global
	// API is process-wide mutable state, and this package has no reason to have
	// any. One provider, built from the call's own arguments.
	provider, err := goose.NewProvider(goose.DialectPostgres, db, fsys, goose.WithSlog(logger))
	if err != nil {
		return nil, fmt.Errorf("reading the migrations: %w", err)
	}

	results, err := provider.Up(ctx)
	if err != nil {
		// `results` is nil on failure, deliberately: the applied set is what
		// goose's own version table already records, and the useful sentence is
		// which file stopped the run.
		return nil, nameTheFailure(err)
	}

	applied := make([]string, 0, len(results))
	for _, result := range results {
		if result.Source != nil {
			applied = append(applied, path.Base(result.Source.Path))
		}
	}
	return applied, nil
}

// nameTheFailure makes sure the error a caller prints NAMES THE FILE that
// failed, because that is the one fact a failed deploy needs and the one
// goose's own message does not carry.
//
// goose's `PartialError.Error` is
//
//	partial migration error (type:go,sql,version:3): <driver error>
//
// — a version number, not a filename. "version 3 failed" is a bisect; "00003_sessions.sql
// failed" is the file to open, and it is the same sentence the substrate's step
// prints under `error:`. `Source.Path` is the only place the name lives, so it
// is read off the structured error rather than parsed back out of a string.
//
// A failure that is not a PartialError — the version table could not be read,
// the database went away mid-run — is returned unchanged: it has no file to
// name, and inventing one would be worse than saying nothing.
func nameTheFailure(err error) error {
	var partial *goose.PartialError
	if !errors.As(err, &partial) || partial.Failed == nil || partial.Failed.Source == nil {
		return err
	}
	return fmt.Errorf("%s failed: %w", path.Base(partial.Failed.Source.Path), err)
}
