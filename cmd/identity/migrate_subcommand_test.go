package main


import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/migrate"
)

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
			"the path kit invokes, under the name it invokes it by",
			[]string{"/app/bin/migrate"},
			commandMigrate,
		},
		{
			"a bare migrate argv[0]",
			[]string{"migrate"},
			commandMigrate,
		},
		{
			"a flag falls through to serve",
			[]string{"/app/service", "-something"},
			commandServe,
		},
		{
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

func TestAnUnknownCommandIsRefusedRatherThanServed(t *testing.T) {
	command, err := subcommand([]string{"/app/service", "migration"})
	if err == nil {
		t.Fatalf("an unknown command was accepted as %q; a typo that starts a server reads as success", command)
	}
	if !strings.Contains(err.Error(), "migration") {
		t.Errorf("the error does not name what was typed: %v", err)
	}
}

func TestRunMigrateRefusesWithoutADSN(t *testing.T) {
	var out bytes.Buffer
	err := runMigrate(context.Background(), "", &out)
	if !errors.Is(err, migrate.ErrNoDSN) {
		t.Fatalf("runMigrate with no DSN returned %v; want migrate.ErrNoDSN", err)
	}
}

func TestTheImageShipsTheMigrateEntrypointTheSubstrateInvokes(t *testing.T) {
	dockerfile := dockerfileText(t)

	if !strings.Contains(dockerfile, "COPY --from=build /out/service /app/bin/migrate") {
		t.Error("the Dockerfile does not copy the service binary to /app/bin/migrate, so the " +
			"image has no migrate entrypoint at the path kit's substrate invokes and the " +
			"migrations step can only fail loudly.")
	}
	if !strings.Contains(dockerfile, "/app/bin/migrate") {
		t.Error("the Dockerfile never mentions /app/bin/migrate, which is the path " +
			"`migration_command_for identity` in kit's substrate invokes with no override")
	}

	if !strings.Contains(dockerfile, `ENTRYPOINT ["/app/service"]`) {
		t.Error("the Dockerfile's ENTRYPOINT is not /app/service: every replica would boot " +
			"into the migrator")
	}
}

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

func dockerfileText(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "Dockerfile"))
	if err != nil {
		t.Fatalf("reading the Dockerfile: %v", err)
	}
	return string(raw)
}

func repoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed, so the repository root cannot be found")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}
