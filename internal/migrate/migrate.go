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

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("connecting to the database: %w", err)
	}

	provider, err := goose.NewProvider(goose.DialectPostgres, db, fsys, goose.WithSlog(logger))
	if err != nil {
		return nil, fmt.Errorf("reading the migrations: %w", err)
	}

	results, err := provider.Up(ctx)
	if err != nil {
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

func nameTheFailure(err error) error {
	var partial *goose.PartialError
	if !errors.As(err, &partial) || partial.Failed == nil || partial.Failed.Source == nil {
		return err
	}
	return fmt.Errorf("%s failed: %w", path.Base(partial.Failed.Source.Path), err)
}
