package ci

// WHAT THE IMAGE DOES NOT CARRY.
//
// `github.com/pressly/goose/v3` is now a direct dependency (see README.md,
// "Dependencies"), and its own `go.mod` requires a driver for every dialect it
// speaks: ClickHouse, MySQL, MSSQL, SQLite, libSQL, Vertica, YDB. That looks
// alarming in a service image and it is not, because Go builds the packages a
// program IMPORTS and the goose root package imports no driver at all — the
// dialect it is asked for is chosen at run time through `database/sql`.
//
// The claim is load-bearing rather than cosmetic. This is a distroless image in
// a security service, and "the schemas are in the binary" would be a very
// different sentence if the binary also carried four CGO-adjacent database
// clients and their TLS stacks. A claim like that rots the moment somebody
// imports goose's CLI package (`github.com/pressly/goose/v3/cmd/goose`, which
// does pull them) or a helper that happens to live beside a driver.
//
// So it is a check rather than a sentence in the README, and the check is on the
// BINARY'S dependency closure — `go list -deps ./cmd/identity`, which is what
// compiles into /app/service — not on go.mod.

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

// gooseDialectDeps are the modules goose's other dialects are built from. The
// list is deliberately of MODULE PREFIXES rather than of import paths: a driver
// can be reached through a helper package this file has never heard of, and the
// question being asked is "is any of this in the image", not "which package
// imported it".
var gooseDialectDeps = []string{
	"github.com/ClickHouse/",
	"github.com/go-sql-driver/mysql",
	"github.com/microsoft/go-mssqldb",
	"github.com/tursodatabase/",
	"github.com/vertica/",
	"github.com/ydb-platform/",
	"github.com/ziutek/mymysql",
	"modernc.org/sqlite",
}

// TestTheServiceBinaryCarriesNoDatabaseDriverButPgx is the check.
//
// It fails in both directions, which is the only arrangement that makes it a
// check: the modules above must be absent, AND the closure must be non-empty and
// must contain pgx — a `go list` that printed nothing, or a path typo, would
// satisfy "no dialect drivers" vacuously.
func TestTheServiceBinaryCarriesNoDatabaseDriverButPgx(t *testing.T) {
	command := exec.CommandContext(context.Background(), "go", "list", "-deps", "./cmd/identity")
	// A test's working directory is its own package directory, and the path
	// above is relative to the repository root — so the command runs there, the
	// same way bin/prime's own `go list` lines do.
	command.Dir = repoRoot(t)
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ./cmd/identity failed: %v\n%s", err, out)
	}
	deps := strings.Fields(string(out))

	if len(deps) == 0 {
		t.Fatal("go list -deps printed nothing, so every assertion below would pass vacuously")
	}
	if !hasModulePrefix(deps, "github.com/jackc/pgx/v5/pgxpool") {
		t.Fatalf("the service's dependency closure does not contain pgx's pool, so this list is not " +
			"the binary's closure and the absences below prove nothing")
	}
	if !hasModulePrefix(deps, "github.com/pressly/goose/v3") {
		t.Fatal("the service's dependency closure does not contain goose, so the migrator is not in " +
			"the binary and this check is about nothing")
	}

	for _, module := range gooseDialectDeps {
		if hasModulePrefix(deps, module) {
			t.Errorf("the service binary reaches %s, a goose dialect driver it has no dialect for. "+
				"The image is distroless and this is a security service: an extra database client in "+
				"it is a supply chain this repository did not ask for. Something imported goose's CLI.", module)
		}
	}
}

// hasModulePrefix reports whether the closure includes a package from the named
// module, so a module prefix matches its packages.
func hasModulePrefix(deps []string, module string) bool {
	for _, dep := range deps {
		if dep == module || strings.HasPrefix(dep, module) {
			return true
		}
	}
	return false
}
