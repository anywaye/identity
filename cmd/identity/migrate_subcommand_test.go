package main

// THE MIGRATE SUBCOMMAND, AND THE ONE ASSET THAT MAKES IT REACHABLE.
//
// This file holds the two facts a substrate depends on and neither of which is
// visible from the service's own tests:
//
//  1. WHICH INVOCATION MEANS `migrate`. kit's `install_migrations` runs a
//     service's migrate entrypoint by a path it already knows, with no
//     override — `/app/bin/migrate` for identity — so the path is not a
//     preference this repository can change unilaterally. The binary has to
//     recognise it, and the only thing that differs between the two
//     invocations is the name the process was started under.
//  2. THAT THE IMAGE SHIPS IT. The runtime stage is distroless with no shell,
//     so `/app/bin/migrate` cannot be a script, and building the image to prove
//     the Dockerfile's text is Docker, which this suite does not run — the same
//     argument cmd/identity-staff's packaging test makes for the staff binary.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/migrate"
)

// TestTheMigrateSubcommandIsSelectedByArgumentAndByArgvZero covers every way a
// caller reaches the migrator, and the one way it must not be reached by
// accident.
func TestTheMigrateSubcommandIsSelectedByArgumentAndByArgvZero(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no arguments is the server", []string{"/app/service"}, commandServe},
		{"the serve subcommand", []string{"/app/service", "serve"}, commandServe},
		{"the migrate subcommand", []string{"/app/service", "migrate"}, commandMigrate},
		{
			// THE LINE THE SUBSTRATE ACTUALLY RUNS. `kubectl run … --command --
			// /app/bin/migrate` hands the process exactly this argv, and argv[0]
			// survives a symlink, which is what lets one binary answer to two
			// names without a script and without a second copy.
			"the path kit invokes, under the name it invokes it by",
			[]string{"/app/bin/migrate"},
			commandMigrate,
		},
		{
			// The same name reached through PATH rather than an absolute path.
			"a bare migrate argv[0]",
			[]string{"migrate"},
			commandMigrate,
		},
		{
			// A flag must not become a usage error: `-healthcheck` is handled
			// before this, and a container started with a future flag should
			// still serve.
			"a flag falls through to serve",
			[]string{"/app/service", "-something"},
			commandServe,
		},
		{
			// The name is read from argv[0] and nowhere else: a server at a path
			// that happens to contain "migrate" is still a server.
			"a path that merely mentions migrate is not the migrator",
			[]string{"/app/migrate/service"},
			commandServe,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := subcommand(test.args)
			if err != nil {
				t.Fatalf("subcommand(%q) returned an error: %v", test.args, err)
			}
			if got != test.want {
				t.Errorf("subcommand(%q) = %q; want %q", test.args, got, test.want)
			}
		})
	}
}

// TestAnUnknownCommandIsRefusedRatherThanServed is the control on the table
// above: the default is `serve`, and a default is exactly the thing that turns a
// typo into a silently working server. A box whose install ran
// `identity migration` would come up, answer /healthz, and boot against an empty
// schema — the defect this packet exists to remove.
func TestAnUnknownCommandIsRefusedRatherThanServed(t *testing.T) {
	command, err := subcommand([]string{"/app/service", "migration"})
	if err == nil {
		t.Fatalf("an unknown command was accepted as %q; a typo that starts a server reads as success", command)
	}
	if !strings.Contains(err.Error(), "migration") {
		t.Errorf("the error does not name what was typed: %v", err)
	}
}

// TestRunMigrateRefusesWithoutADSN is the fail-loud direction for the Job: the
// substrate passes DATABASE_URL, and a Job started without it must exit non-zero
// with a sentence rather than reporting a schema it never touched.
func TestRunMigrateRefusesWithoutADSN(t *testing.T) {
	var out bytes.Buffer
	err := runMigrate(context.Background(), "", &out)
	if !errors.Is(err, migrate.ErrNoDSN) {
		t.Fatalf("runMigrate with no DSN returned %v; want migrate.ErrNoDSN", err)
	}
}

// TestTheImageShipsTheMigrateEntrypointTheSubstrateInvokes holds the Dockerfile
// to the path and the name, because the failure mode is silent: an image that
// cannot migrate is an install that stops at the migrate step, and nothing in Go
// would notice.
func TestTheImageShipsTheMigrateEntrypointTheSubstrateInvokes(t *testing.T) {
	dockerfile := dockerfileText(t)

	// ONE `go build`, TWO NAMES, and the COPY is the only thing that makes them
	// the same bytes: the runtime stage has no shell, so `/app/bin/migrate`
	// cannot be a script, and `COPY --from=<stage>` DEREFERENCES a symlink
	// (measured — see the Dockerfile's comment), so a link made in the builder
	// would arrive as this same second copy anyway.
	if !strings.Contains(dockerfile, "COPY --from=build /out/service /app/bin/migrate") {
		t.Error("the Dockerfile does not copy the service binary to /app/bin/migrate, so the " +
			"image has no migrate entrypoint at the path kit's substrate invokes and the " +
			"migrations step can only fail loudly.")
	}
	if !strings.Contains(dockerfile, "/app/bin/migrate") {
		t.Error("the Dockerfile never mentions /app/bin/migrate, which is the path " +
			"`migration_command_for identity` in kit's substrate invokes with no override")
	}

	// And the entrypoint is still the server: the migrator is a second name for
	// the same binary, never what a replica boots into.
	if !strings.Contains(dockerfile, `ENTRYPOINT ["/app/service"]`) {
		t.Error("the Dockerfile's ENTRYPOINT is not /app/service: every replica would boot " +
			"into the migrator")
	}
}

// TestTheEmbeddedSchemaIsInTheBinary is the reason the Dockerfile does not need
// to copy `migrations/`: the files are in the executable. The assertion is on
// the embed pattern because that is the one line that decides it.
func TestTheEmbeddedSchemaIsInTheBinary(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "migrations", "embed.go"))
	if err != nil {
		t.Fatalf("reading migrations/embed.go: %v", err)
	}
	if !strings.Contains(string(raw), "//go:embed *.sql") {
		t.Error("migrations/embed.go no longer embeds *.sql, so the binary carries no schema " +
			"and the migrate subcommand has nothing to apply")
	}
}

// dockerfileText reads the repository's Dockerfile. Building the image is
// Docker and this suite does not run it, so the text is the check — the same
// one cmd/identity-staff's packaging test makes.
func dockerfileText(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "Dockerfile"))
	if err != nil {
		t.Fatalf("reading the Dockerfile: %v", err)
	}
	return string(raw)
}

// repoRoot finds the repository root from this file's own path, so the test does
// not depend on the working directory.
func repoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed, so the repository root cannot be found")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}
