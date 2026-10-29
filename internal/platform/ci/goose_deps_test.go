package ci


import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

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

func TestTheServiceBinaryCarriesNoDatabaseDriverButPgx(t *testing.T) {
	command := exec.CommandContext(context.Background(), "go", "list", "-deps", "./cmd/identity")
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

func hasModulePrefix(deps []string, module string) bool {
	for _, dep := range deps {
		if dep == module || strings.HasPrefix(dep, module) {
			return true
		}
	}
	return false
}
