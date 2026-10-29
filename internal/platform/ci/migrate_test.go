package ci


import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestMigrateFeedsPsqlTheUpSectionAndNotTheDownOne(t *testing.T) {
	captured, run := stubPsql(t)

	if _, err := run("postgres://stub/identity"); err != nil {
		t.Fatalf("bin/migrate: %v\n\nwhat the stub psql received:\n%s", err, readAll(t, captured))
	}

	fed := readAll(t, captured)
	if fed == "" {
		t.Fatal("the stub psql received nothing at all on stdin, so bin/migrate " +
			"is still passing files with `--file` and psql is running their Down sections")
	}

	for _, name := range []string{
		"DROP TABLE users",
		"DROP TABLE account_invitations",
		"DROP INDEX users_email_key",
	} {
		if strings.Contains(fed, name) {
			t.Errorf("the Down section reached psql — the stub received %q, so applying this migration would undo it\n\nwhat the stub psql received:\n%s",
				name, fed)
		}
	}

	for _, name := range []string{
		"CREATE TABLE users",
		"CREATE UNIQUE INDEX users_email_key",
		"CREATE TABLE account_invitations",
	} {
		if !strings.Contains(fed, name) {
			t.Errorf("the Up section is missing from what psql was sent: no %q\n\nwhat the stub psql received:\n%s", name, fed)
		}
	}

	if strings.Contains(fed, "+goose Down") {
		t.Error("the `-- +goose Down` marker was fed to psql rather than used as the cut point")
	}
}

func TestEveryMigrationForwardsItsUpSectionIntact(t *testing.T) {
	root := repoRoot(t)
	extractor := filepath.Join(root, "bin", "migration-up-section")

	migrations, err := filepath.Glob(filepath.Join(root, "migrations", "*.sql"))
	if err != nil {
		t.Fatalf("globbing migrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatalf("no migrations found in %s — a glob that matches nothing is the shape of a test that proves nothing", filepath.Join(root, "migrations"))
	}

	dropsTheSubject := regexp.MustCompile(`(?im)^\s*DROP\s+TABLE\s`)

	for _, migration := range migrations {
		t.Run(filepath.Base(migration), func(t *testing.T) {
			out, err := exec.CommandContext(t.Context(), extractor, migration).Output()
			if err != nil {
				t.Fatalf("bin/migration-up-section %s: %v", filepath.Base(migration), err)
			}
			if len(out) == 0 {
				t.Fatal("the extracted Up section is empty, so this migration would apply nothing and say nothing")
			}
			if dropsTheSubject.Match(out) {
				t.Errorf("the extracted Up section drops a table, which means the Down section leaked into it:\n%s", out)
			}
		})
	}
}

func TestTheExtractorRefusesWhatItCannotRead(t *testing.T) {
	root := repoRoot(t)
	extractor := filepath.Join(root, "bin", "migration-up-section")

	for _, args := range [][]string{
		{},
		{filepath.Join(root, "migrations", "00001_nonexistent.sql")},
		{"a.sql", "b.sql"},
	} {
		cmd := exec.CommandContext(t.Context(), extractor, args...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		err := cmd.Run()

		if err == nil {
			t.Errorf("bin/migration-up-section %v exited 0 and printed to stdout; "+
				"an empty stream into psql is a run that migrated nothing and reported success", args)
			continue
		}
		if stderr.Len() == 0 {
			t.Errorf("bin/migration-up-section %v failed with no message on stderr, so the caller is told nothing about which file was wrong", args)
		}
	}
}

func stubPsql(t *testing.T) (string, func(dsn string) (string, error)) {
	t.Helper()
	root := repoRoot(t)

	dir := t.TempDir()
	capture := filepath.Join(dir, "fed-to-psql.sql")
	stub := filepath.Join(dir, "psql")

	script := "#!/usr/bin/env bash\n" +
		"{\n" +
		"  echo \"### psql called with: $*\"\n" +
		"  echo '### stdin follows'\n" +
		"  cat\n" +
		"} >> " + capture + "\n" +
		"exit 0\n"

	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatalf("writing the stub psql: %v", err)
	}

	run := func(dsn string) (string, error) {
		cmd := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "bin", "migrate"))
		cmd.Dir = root
		cmd.Env = append(os.Environ(),
			"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
			"DATABASE_URL="+dsn,
		)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	return capture, run
}

func readAll(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

func TestTheDownSectionExtractorHandsPsqlTheUndoAndNotTheForwardApply(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()
	migration := filepath.Join(dir, "00099_scratch.sql")
	body := "-- +goose Up\n" +
		"-- +goose StatementBegin\n" +
		"CREATE TABLE scratch (id int);\n" +
		"-- +goose StatementEnd\n" +
		"-- a comment that MENTIONS +goose Down in prose, and must survive\n" +
		"--+goose   Down\n" +
		"-- +goose StatementBegin\n" +
		"DROP TABLE scratch;\n" +
		"-- +goose StatementEnd\n"
	if err := os.WriteFile(migration, []byte(body), 0o644); err != nil {
		t.Fatalf("writing the scratch migration: %v", err)
	}

	out, err := exec.CommandContext(t.Context(), filepath.Join(root, "bin", "migration-down-section"), migration).Output()
	if err != nil {
		t.Fatalf("bin/migration-down-section: %v", err)
	}
	got := string(out)

	for _, want := range []string{"DROP TABLE scratch;"} {
		if !strings.Contains(got, want) {
			t.Errorf("the Down section is missing %q; the extractor produced:\n%s", want, got)
		}
	}
	for _, absent := range []string{
		"CREATE TABLE scratch",
		"MENTIONS",
	} {
		if strings.Contains(got, absent) {
			t.Errorf("the extractor produced %q, which belongs to the Up half:\n%s", absent, got)
		}
	}
	if !strings.Contains(got, "DROP TABLE") || strings.Contains(got, "+goose Statement") {
		t.Errorf("the goose Statement markers are SQL noise psql would have to skip; "+
			"the extractor strips them on the Up side and must here too:\n%s", got)
	}

	noDown := filepath.Join(dir, "00098_scratch_nodown.sql")
	if err := os.WriteFile(noDown, []byte("-- +goose Up\nCREATE TABLE scratch2 (id int);\n"), 0o644); err != nil {
		t.Fatalf("writing the Down-less migration: %v", err)
	}
	out, err = exec.CommandContext(t.Context(), filepath.Join(root, "bin", "migration-down-section"), noDown).Output()
	if err != nil {
		t.Fatalf("bin/migration-down-section on a Down-less file: %v", err)
	}
	if len(strings.TrimSpace(string(out))) != 0 {
		t.Errorf("a migration with no Down section produced output:\n%s\n"+
			"an empty stream is the fact the rollback check acts on", out)
	}
}
