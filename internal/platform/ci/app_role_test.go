// The runtime role is a claim three files make, so it is checked in all three.
//
// `docker-compose.yml` says the dev service logs in as `identity_app`,
// `config/deploy.yml` says the deployed one does, and migrations/00016's
// `protect_table` wrote four row-level-security policies per account-scoped
// table naming that role and the owner. Two of those three are prose. This file
// is what stops them disagreeing, or stopping at the owner, in the way that
// cannot be noticed from inside the service: a pool on the owner answers every
// account-scoped query, so nothing fails, no test goes red, and the boundary is
// simply not there.
package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const appRole = "identity_app"

// The DSN the compose stack gives the running service.
var composeDSN = regexp.MustCompile(`(?m)^\s*DATABASE_URL:\s*(\S+)\s*$`)

// The DATABASE_URL's user, read from the URL rather than by splitting on `://`.
//
// A DSN is a URL with a userinfo section, and the user is the part before the
// first `:` in it. Splitting the whole string on `:` would also work by accident
// on the scheme and the host port, which is the kind of accident that survives
// until someone writes a DSN with no port.
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

// TestTheComposeServiceConnectsAsTheAppRole is the check that a deploy file
// cannot make for itself: the DSN in the compose stack names the role the
// account policies were written for.
//
// NEGATIVE CONTROL, because a comparison that cannot fail is not a check. The
// table carries the two DSNs this repository used to have — the owner, which is
// the regression, and a DSN with no user at all — and the assertion has to hold
// for the second and fail for the first and the third. Without it, a regexp that
// matched nothing would report the same result as one that matched the right
// thing, which is the failure mode this file exists to prevent.
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

	// The absence is load-bearing and is asserted as its own property rather than
	// as part of the DSN check, because it is a different mistake with a different
	// blast radius: POSTGRES_USER is the cluster's SUPERUSER, and naming it after
	// this service makes the auth service a superuser of whatever host it lands on.
	//
	// Matched WITH its colon, and this file says why rather than leaving it to the
	// next reader: docker-compose.yml spends eighty lines explaining at length why
	// the variable is absent, and every one of those lines contains the word. A
	// substring check over the file therefore fails on the explanation of the
	// absence, which is a check that cannot be made green by writing the comment
	// that says the thing is right — and a check like that gets deleted rather than
	// fixed. `POSTGRES_USER:` is an assignment; the prose is not one.
	if body := composeFile(t); strings.Contains(body, "POSTGRES_USER:") {
		t.Errorf("docker-compose.yml assigns POSTGRES_USER, which is the cluster superuser the\n" +
			"official image creates. Its absence is what keeps this service's credentials\n" +
			"off that role, and it is the one override kit's own fleet_check.py recommends.")
	}

	for _, tc := range []struct{ name, dsn, want string }{
		{"the app role itself", "postgres://identity_app:cafaye@postgres:5432/identity", appRole},
		{"the owner, which is the regression", "postgres://identity:cafaye@postgres:5432/identity", "identity"},
		{"no user at all", "postgres://postgres:5432/identity", "postgres"},
	} {
		t.Run("reads the role out of "+tc.name, func(t *testing.T) {
			if got := dsnUser(t, tc.dsn); got != tc.want {
				t.Errorf("dsnUser(%q) = %q, want %q", tc.dsn, got, tc.want)
			}
		})
	}
}

// TestTheDeployConfigNamesTheAppRoleToo holds the second of the two prose files to
// the same statement.
//
// It reads the deployed DSN out of `config/deploy.yml` rather than out of
// `.kamal/secrets`, because the secret store is not in this repository and the
// variable NAME is what the file declares. The assertion is that the file says
// which role the operator has to provision: a deployed DSN naming a role nothing
// creates is a boot failure named after a role, which is the least informative
// failure this stack can produce.
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

	// The same absence, in the same file, for the same reason. Asserted here as
	// well as in the compose check because they are two files somebody can edit
	// independently, and this is the one that reaches a real host.
	if strings.Contains(body, "POSTGRES_USER:") {
		t.Error("config/deploy.yml's postgres accessory sets POSTGRES_USER. That variable is " +
			"the cluster superuser, and its absence in this block is deliberate — see the " +
			"paragraph above the accessory.")
	}
}
