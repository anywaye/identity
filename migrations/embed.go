// Package migrations carries this directory's goose SQL files into the
// `identity` binary, so the image can migrate its own database without a shell,
// without `psql` and without the goose command line tool.
//
// # WHY A GO PACKAGE LIVES IN A DIRECTORY OF SQL
//
// `go:embed` can only reach files at or below the directory of the importing
// package, so the embed has to be declared here. The alternative — a Go file at
// the repository root holding `//go:embed migrations/*.sql` — would create a
// root package whose only reason to exist is to work around that rule, and the
// embedded path would then be `migrations/00001_init.sql` rather than
// `00001_init.sql`, which the migrator would have to strip back off.
//
// It is not a migration. `goose` loads `*.sql` from this directory, `bin/migrate`
// loops over `migrations/*.sql`, `bin/rollback` globs `migrations/[0-9]*.sql`
// and `bin/provision-testdb` hands the directory to the goose CLI; none of them
// see a `.go` file, and all of them keep working unchanged.
//
// See `internal/migrate` for what reads this, and why the image needs it at all.
package migrations

import "embed"

// FS is the schema, as it ships in the image.
//
// THE PATTERN IS `*.sql` AND NOT `migrations/*.sql`, because this package's
// directory IS `migrations/`. It is also deliberately not `.` — embedding the
// whole directory would pull `README.md` in, and the set the binary applies
// should be exactly the set a `*.sql` glob names, which is the set goose and
// `bin/migrate` apply on a developer's machine.
//
// `TestTheEmbeddedSetIsTheSetOnDisk` is the check that the pattern has not
// narrowed: a rename or a pattern edit that drops a file from the binary is
// invisible until a deployed box migrates to the wrong version.
//
//go:embed *.sql
var FS embed.FS
