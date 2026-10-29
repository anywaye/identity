package ci


import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestProvisionTestDBRoleCreationUsesAStdinVariable(t *testing.T) {
	source := provisionTestDBSource(t)

	if strings.Contains(source, "-c \"CREATE ROLE") || strings.Contains(source, "-c 'CREATE ROLE") {
		t.Error("bin/provision-testdb passes CREATE ROLE via `psql -c`.\n" +
			"psql does not interpolate :'pw' in a -c string, so the server receives a literal " +
			"`:'pw'` and answers `ERROR: syntax error at or near \":\"`. Feed the statement on stdin instead.")
	}

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

	old := exec.CommandContext(t.Context(), "bash", "-c", `"$0" "$1" -X -q -w --set ON_ERROR_STOP=1 -v pw="$2" -c "CREATE ROLE $3 LOGIN PASSWORD :'pw'"`,
		fake, "postgres://x/x", "p@ss", "identity")
	if out, err := old.CombinedOutput(); err == nil {
		t.Errorf("the old `-c \"CREATE ROLE ... PASSWORD :'pw'\"` shape succeeded against the fake psql; it must be rejected.\n"+
			"Without this failure the static check above could go green on a form the server refuses.\noutput: %s", out)
	} else if !strings.Contains(string(out), `syntax error at or near`) {
		t.Errorf("the old shape failed, but not with the server's rejection; the fake models the wrong fault.\noutput: %s", out)
	}

	outFile := filepath.Join(dir, "stdin.sql")
	runNew := func(role string) (string, error) {
		cmd := exec.CommandContext(t.Context(), "bash", "-c", `printf '%s\n' "CREATE ROLE $0 LOGIN PASSWORD :'pw'" | "$1" "$2" -X -q -w --set ON_ERROR_STOP=1 -v pw="$3"`,
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

func TestProvisionTestDBUnsafeRoleRefusalIsBeforeAnySideEffect(t *testing.T) {
	source := provisionTestDBSource(t)

	ownerRefusal := "select rolsuper from pg_roles where rolname = '$owner'"
	appRefusal := "select rolsuper from pg_roles where rolname = '$app_role'"

	ownerIdx := strings.Index(source, ownerRefusal)
	appIdx := strings.Index(source, appRefusal)
	if ownerIdx == -1 {
		t.Fatalf("bin/provision-testdb has no owner superuser/BYPASSRLS refusal query %q", ownerRefusal)
	}
	if appIdx == -1 {
		t.Fatalf("bin/provision-testdb has no app-role superuser/BYPASSRLS refusal query %q", appRefusal)
	}
	firstRefusal := ownerIdx
	if appIdx < firstRefusal {
		firstRefusal = appIdx
	}
	lastRefusal := ownerIdx
	if appIdx > lastRefusal {
		lastRefusal = appIdx
	}

	sideEffects := []string{
		"CREATE ROLE $owner",
		"CREATE ROLE $app_role",
		"CREATE DATABASE $dbname",
		`"$goose_bin" -dir "$ROOT/migrations" postgres "$dsn" up`,
		"GRANT $app_role TO $owner",
	}
	firstSideEffect := -1
	var firstSideEffectName string
	for _, needle := range sideEffects {
		idx := strings.Index(source, needle)
		if idx == -1 {
			t.Fatalf("bin/provision-testdb no longer contains side effect %q; expected provisioning steps are missing", needle)
		}
		if firstSideEffect == -1 || idx < firstSideEffect {
			firstSideEffect = idx
			firstSideEffectName = needle
		}
	}

	if firstRefusal > firstSideEffect {
		t.Errorf("unsafe-role refusal appears AFTER the first side effect.\n"+
			"First refusal at byte %d (%q at %d, %q at %d), first side effect %q at byte %d.\n"+
			"The refusal must be the earliest check after the admin connection is verified, before any CREATE ROLE / CREATE DATABASE / migration / GRANT — otherwise a run against an unsafe cluster provisions a disposable DB before failing.",
			firstRefusal, ownerRefusal, ownerIdx, appRefusal, appIdx, firstSideEffectName, firstSideEffect)
	}

	if lastRefusal > firstSideEffect {
		t.Errorf("one unsafe-role refusal appears after the first side effect (last refusal at %d, first side effect %q at %d).\n"+
			"Both owner and app-role checks must precede every mutation.", lastRefusal, firstSideEffectName, firstSideEffect)
	}

	grantNeedle := "GRANT $app_role TO $owner"
	grantIdx := strings.Index(source, grantNeedle)
	if grantIdx == -1 {
		t.Fatalf("cannot locate %q to bound the late-check region", grantNeedle)
	}
	afterGrant := source[grantIdx:]
	if strings.Contains(afterGrant, "rolsuper") || strings.Contains(afterGrant, "rolbypassrls") {
		t.Error("bin/provision-testdb still checks rolsuper/rolbypassrls after GRANT. " +
			"The refusal was moved to before any side effect; a trailing check is the post-mutation cost m158 removes.")
	}

	for _, want := range []string{
		"is superuser or BYPASSRLS, which bypasses row-level security even with FORCE",
		"Recreate the cluster without POSTGRES_USER=",
		"bootstrap superuser cannot be demoted",
		"is superuser or BYPASSRLS, which bypasses row-level security",
		"Recreate it as NOSUPERUSER NOBYPASSRLS",
	} {
		if !strings.Contains(source, want) {
			t.Errorf("bin/provision-testdb no longer contains actionable error text %q — the early refusal must preserve m156's message", want)
		}
	}

	verifiedProbe := "rolsuper or (rolcreaterole and rolcreatedb)"
	verifiedIdx := strings.Index(source, verifiedProbe)
	if verifiedIdx == -1 {
		t.Fatalf("cannot locate admin verification probe %q; the script's structure has changed", verifiedProbe)
	}
	if firstRefusal < verifiedIdx {
		t.Error("unsafe-role refusal appears BEFORE the admin connection is verified; it must be after the admin DSN is resolved/verified and before any mutation")
	}
}

func TestProvisionTestDBIsValidBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is not on PATH, so neither this check nor bin/provision-testdb can run: %v", err)
	}
	path := filepath.Join(repoRoot(t), "bin", "provision-testdb")
	if out, err := exec.CommandContext(t.Context(), bash, "-n", path).CombinedOutput(); err != nil {
		t.Errorf("bin/provision-testdb is not valid bash: %v\n%s", err, out)
	}
}
