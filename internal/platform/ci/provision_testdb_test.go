package ci

// bin/provision-testdb creates the owner and app login roles with a password
// that travels as a psql variable (:'pw'), never interpolated into SQL.
//
// THE DEFECT THIS HOLDS (m151). The role creation passed :'pw' through
// `psql -c`. psql performs :'var' interpolation on the input it scans
// (interactive, -f, stdin) and sends `-c` straight to the server, so the
// server received a literal `:'pw'` and answered
// `ERROR: syntax error at or near ":"` — a clean test database could not be
// provisioned and the gate was blocked before tests started.
//
// THE FIX. The CREATE ROLE statement reaches psql on standard input (a
// printf pipe), where its scanner interpolates :'pw' from `-v pw=...`, while
// role names stay shell-interpolated and therefore stay validated against the
// safe-identifier pattern. The tests below hold both halves: the corrected
// form is present, and the old `-c` form is shown to fail.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// provisionTestDBSource reads bin/provision-testdb as text.
func provisionTestDBSource(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "bin", "provision-testdb"))
	if err != nil {
		t.Fatalf("reading bin/provision-testdb: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("bin/provision-testdb is empty, so every assertion below would pass vacuously")
	}
	return string(raw)
}

// TestProvisionTestDBRoleCreationUsesAStdinVariable holds the fix to the
// script: no CREATE ROLE carrying :'pw' may travel via `psql -c`, and each
// role creation must pipe a statement carrying the literal :'pw' into a psql
// invocation that sets the password with `-v pw=`.
func TestProvisionTestDBRoleCreationUsesAStdinVariable(t *testing.T) {
	source := provisionTestDBSource(t)

	if strings.Contains(source, "-c \"CREATE ROLE") || strings.Contains(source, "-c 'CREATE ROLE") {
		t.Error("bin/provision-testdb passes CREATE ROLE via `psql -c`.\n" +
			"psql does not interpolate :'pw' in a -c string, so the server receives a literal " +
			"`:'pw'` and answers `ERROR: syntax error at or near \":\"`. Feed the statement on stdin instead.")
	}

	// Both roles are created, and both creations must carry the password as a
	// psql variable rather than a hand-built SQL literal.
	for _, role := range []string{"CREATE ROLE $owner", "CREATE ROLE $app_role"} {
		if !strings.Contains(source, role) {
			t.Errorf("bin/provision-testdb no longer creates %q; a fix that deletes a role is not a fix", role)
		}
	}
	if got := strings.Count(source, "PASSWORD :'pw'"); got != 2 {
		t.Errorf("want exactly 2 role creations carrying the literal PASSWORD :'pw' (owner and app role), got %d.\n"+
			"The password must travel as the psql variable :'pw', fed on stdin — not interpolated into SQL.", got)
	}
	if got := strings.Count(source, "-v pw=\"$password\""); got != 2 {
		t.Errorf("want exactly 2 psql invocations setting the password with `-v pw=\"$password\"`, got %d.\n"+
			"The variable has to be set where the statement can consume it.", got)
	}

	// The statements must reach psql on stdin: a printf pipe into the psql
	// binary. Either side of the pipe alone proves nothing — a printf whose
	// output goes nowhere provisions nothing, and a psql reading stdin with
	// no statement creates nothing.
	if !strings.Contains(source, "printf '%s\\n'") {
		t.Error("bin/provision-testdb carries no printf feeding a statement on stdin; the CREATE ROLE text reaches psql no other way")
	}
	piped := strings.Count(source, "\"$psql_bin\" \"$admin_dsn\" -X -q -w --set ON_ERROR_STOP=1 -v pw=\"$password\"")
	if piped != 2 {
		t.Errorf("want exactly 2 psql invocations bound with `-v pw=\"$password\"` and no -c (owner and app role), got %d", piped)
	}
	if !strings.Contains(source, "| \\") {
		t.Error("no pipe feeds a statement into psql; the CREATE ROLE text reaches psql on stdin or not at all")
	}

	// The script's promise, kept: the raw password is never interpolated into
	// SQL or logs. It appears only as `-v pw="$password"` (the variable
	// binding) and inside the DSN parsing above it.
	for i, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(line, "$password") && !strings.Contains(line, "-v pw=\"$password\"") &&
			!strings.Contains(line, "password=\"") && !strings.Contains(line, "password:-") &&
			!strings.Contains(line, "${userinfo") && !strings.Contains(line, "userinfo") {
			t.Errorf("line %d interpolates the raw password outside the `-v pw=` binding: %q.\n"+
				"A password in SQL text breaks on a quote and leaks into logs; it travels as a psql variable or not at all.",
				i+1, strings.TrimSpace(line))
		}
	}
}

// TestProvisionTestDBOldFormIsRejectedAndTheNewFormDeliversAVariable is the
// tripwire's own tripwire: it executes the two CALL SHAPES against a fake
// psql that models the real one's contract — `-c` bypasses :'var'
// interpolation (so the server sees a literal `:'pw'` and rejects it), stdin
// does not — and asserts the old shape fails while the new shape delivers a
// statement carrying the variable with the secret nowhere in it.
//
// The fake models psql's argument handling, not a server: the real server's
// rejection (`ERROR: syntax error at or near ":"`) is quoted in the failure
// text the fake prints, and the assertion is on the exit code and on what the
// fake received, not on the wording.
func TestProvisionTestDBOldFormIsRejectedAndTheNewFormDeliversAVariable(t *testing.T) {
	dir := t.TempDir()

	fake := filepath.Join(dir, "psql")
	script := "#!/usr/bin/env bash\n" +
		"# Fake psql: models the one contract this test needs. A -c string is\n" +
		"# sent straight through (no :'var' interpolation); stdin is scanned\n" +
		"# (:'var' interpolation applies). Like the real server, reject a\n" +
		"# literal :'pw' in SQL text.\n" +
		"has_v_pw=0\n" +
		"for arg in \"$@\"; do\n" +
		"  case \"$arg\" in\n" +
		"    pw=*) has_v_pw=1 ;;\n" +
		"  esac\n" +
		"  case \"$arg\" in\n" +
		"    *\"CREATE ROLE\"*)\n" +
		"      if [[ \"$arg\" == *\":'pw'\"* ]]; then\n" +
		"        echo \"ERROR: syntax error at or near \\\":\\\"\" >&2\n" +
		"        echo \"LINE 1: $arg\" >&2\n" +
		"        exit 1\n" +
		"      fi\n" +
		"      if [[ \"$arg\" == *\"s3cret' OR '1'='1\"* ]]; then\n" +
		"        echo 'fake-psql: raw password interpolated into SQL' >&2\n" +
		"        exit 2\n" +
		"      fi\n" +
		"      ;;\n" +
		"  esac\n" +
		"done\n" +
		"body=\"$(cat)\"\n" +
		"printf '%s' \"$body\" > \"$FAKE_PSQL_OUT\"\n" +
		"if [[ \"$body\" == *\":'pw'\"* ]]; then\n" +
		"  if [ \"$has_v_pw\" != 1 ]; then\n" +
		"    echo 'fake-psql: stdin carries :'\"'\"'pw'\"'\"' with no -v pw= binding' >&2\n" +
		"    exit 1\n" +
		"  fi\n" +
		"  exit 0\n" +
		"fi\n" +
		"if [[ \"$body\" == *\"s3cret' OR '1'='1\"* ]]; then\n" +
		"  echo 'fake-psql: raw password interpolated into SQL on stdin' >&2\n" +
		"  exit 2\n" +
		"fi\n" +
		"echo 'fake-psql: stdin carried neither the variable nor the password' >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatalf("writing the fake psql: %v", err)
	}

	// The OLD shape: the defect. psql receives the variable reference in -c,
	// interpolation does not apply, and the server rejects it.
	old := exec.Command("bash", "-c", `"$0" "$1" -X -q -w --set ON_ERROR_STOP=1 -v pw="$2" -c "CREATE ROLE $3 LOGIN PASSWORD :'pw'"`,
		fake, "postgres://x/x", "p@ss", "identity")
	if out, err := old.CombinedOutput(); err == nil {
		t.Errorf("the old `-c \"CREATE ROLE ... PASSWORD :'pw'\"` shape succeeded against the fake psql; it must be rejected.\n"+
			"Without this failure the static check above could go green on a form the server refuses.\noutput: %s", out)
	} else if !strings.Contains(string(out), `syntax error at or near`) {
		t.Errorf("the old shape failed, but not with the server's rejection; the fake models the wrong fault.\noutput: %s", out)
	}

	// The NEW shape, quoted exactly as bin/provision-testdb now writes it: a
	// printf pipe into psql with `-v pw=` bound and :'pw' literal in SQL.
	outFile := filepath.Join(dir, "stdin.sql")
	runNew := func(role string) (string, error) {
		cmd := exec.Command("bash", "-c", `printf '%s\n' "CREATE ROLE $0 LOGIN PASSWORD :'pw'" | "$1" "$2" -X -q -w --set ON_ERROR_STOP=1 -v pw="$3"`,
			role, fake, "postgres://x/x", "s3cret' OR '1'='1")
		cmd.Env = append(os.Environ(), "FAKE_PSQL_OUT="+outFile)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, role := range []string{"identity", "identity_app"} {
		os.Remove(outFile)
		out, err := runNew(role)
		if err != nil {
			t.Errorf("the corrected stdin shape for role %s failed: %v\n%s", role, err, out)
			continue
		}
		raw, rerr := os.ReadFile(outFile)
		if rerr != nil {
			t.Errorf("the fake psql received nothing for role %s: %v", role, rerr)
			continue
		}
		got := string(raw)
		if !strings.Contains(got, "PASSWORD :'pw'") {
			t.Errorf("role %s: psql received %q, which carries no :'pw' variable.\n"+
				"The statement must reference the variable rather than a hand-built literal.", role, got)
		}
		if strings.Contains(got, "s3cret") {
			t.Errorf("role %s: the raw password reached the SQL text %q; it travels as `-v pw=` or not at all.", role, got)
		}
	}
}

// TestProvisionTestDBIsValidBash parses the script without executing it, so a
// quoting slip in the corrected pipe fails here rather than at 3am in the gate.
func TestProvisionTestDBIsValidBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is not on PATH, so neither this check nor bin/provision-testdb can run: %v", err)
	}
	path := filepath.Join(repoRoot(t), "bin", "provision-testdb")
	if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
		t.Errorf("bin/provision-testdb is not valid bash: %v\n%s", err, out)
	}
}
