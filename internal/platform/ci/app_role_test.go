package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const appRole = "identity_app"

var composeDSN = regexp.MustCompile(`(?m)^\s*DATABASE_URL:\s*(\S+)\s*$`)

func dsnUser(t *testing.T, dsn string) string {
	t.Helper()

	scheme, rest, found := strings.Cut(dsn, "://")
	if !found {
		t.Fatalf("DATABASE_URL %q is not a URL, so this check cannot say which role it names", dsn)
	}
	_ = scheme

	userinfo, _, _ := strings.Cut(rest, "@")
	user, _, _ := strings.Cut(userinfo, ":")
	return user
}

func composeFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join("..", "..", "..", "docker-compose.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(raw)
}

func TestTheComposeServiceConnectsAsTheAppRole(t *testing.T) {
	body := composeFile(t)

	var found []string
	for _, m := range composeDSN.FindAllStringSubmatch(body, -1) {
		found = append(found, m[1])
	}
	if len(found) != 1 {
		t.Fatalf("docker-compose.yml carries %d DATABASE_URL assignments, want exactly 1: %v. "+
			"A second one is a second runtime role, and nothing here can say which one serves.", len(found), found)
	}

	if got := dsnUser(t, found[0]); got != appRole {
		t.Errorf("the runtime DSN names the role %q, want %q.\n"+
			"Postgres exempts a table's OWNER from its own row-level-security policies, so a\n"+
			"pool on %q bypasses every policy migrations/00016 installed: every account-scoped\n"+
			"query answers with the whole table and nothing fails.", got, appRole, got)
	}

	if body := composeFile(t); strings.Contains(body, "POSTGRES_USER:") {
		t.Errorf("docker-compose.yml assigns POSTGRES_USER, which is the cluster superuser the\n" +
			"official image creates. Its absence is what keeps this service's credentials\n" +
			"off that role, and it is the one override kit's own fleet_check.py recommends.")
	}

	for _, tc := range []struct{ name, dsn, want string }{
		{"the app role itself", "postgres://identity_app:anywaye@postgres:5432/identity", appRole},
		{"the owner, which is the regression", "postgres://identity:anywaye@postgres:5432/identity", "identity"},
		{"no user at all", "postgres://postgres:5432/identity", "postgres"},
	} {
		t.Run("reads the role out of "+tc.name, func(t *testing.T) {
			if got := dsnUser(t, tc.dsn); got != tc.want {
				t.Errorf("dsnUser(%q) = %q, want %q", tc.dsn, got, tc.want)
			}
		})
	}
}

func TestTheDeployConfigNamesTheAppRoleToo(t *testing.T) {
	path := filepath.Join("..", "..", "..", "config", "deploy.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	body := string(raw)

	if !strings.Contains(body, appRole) {
		t.Errorf("config/deploy.yml never names %s. The deployed runtime DSN has to name the\n"+
			"role migrations/00016's policies were written for, and the file has to say so\n"+
			"where an operator reads it — a bare postgres:17-alpine accessory creates no app\n"+
			"role, so the DSN fails with 'role does not exist' until somebody provisions one.", appRole)
	}

	if strings.Contains(body, "POSTGRES_USER:") {
		t.Error("config/deploy.yml's postgres accessory sets POSTGRES_USER. That variable is " +
			"the cluster superuser, and its absence in this block is deliberate — see the " +
			"paragraph above the accessory.")
	}
}
