package migrations

// WHAT THESE TESTS HOLD, AND WHY THEY ARE ABOUT THE SET RATHER THAN THE SQL.
//
// `//go:embed *.sql` is a pattern, and a pattern is a thing that can quietly
// match less. Nothing else in the repository reads the embedded FS, so a file
// left out of it is a migration a deployed box never gets — and the migrator
// reports success, because the set it was given applied cleanly.
//
// The second test holds a sharper edge: goose's own file collection is
// NON-STRICT (goose v3.28.0, provider.go:122 passes strict=false), so a `.sql`
// file whose name does not start `NNNNN_` is SKIPPED without an error. A
// migration renamed by hand would simply not run, on a box, with a green exit
// status.

import (
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var migrationName = regexp.MustCompile(`^([0-9]+)_([a-z0-9_]+)\.sql$`)

func TestTheEmbeddedSetIsTheSetOnDisk(t *testing.T) {
	embedded := fileNames(t, FS, ".")
	if len(embedded) == 0 {
		t.Fatal("the embedded filesystem is empty, so the image can migrate nothing and " +
			"every assertion below would pass vacuously")
	}

	onDisk := sqlFilesOnDisk(t)
	if !equal(embedded, onDisk) {
		t.Errorf("the binary's migrations are not the directory's.\n  embedded: %v\n  on disk:  %v\n"+
			"A file the embed pattern drops is a migration a deployed box never applies, "+
			"and the migrator reports success when it does.", embedded, onDisk)
	}
}

func TestEveryEmbeddedMigrationWillActuallyRun(t *testing.T) {
	names := fileNames(t, FS, ".")
	if len(names) == 0 {
		t.Fatal("the embedded filesystem is empty")
	}

	seen := make(map[int64]string, len(names))
	previous := int64(-1)
	for _, name := range names {
		match := migrationName.FindStringSubmatch(name)
		if match == nil {
			t.Errorf("migrations/%s is not NNNNN_snake_case_description.sql. goose collects "+
				"migrations NON-STRICTLY, so this file is skipped without an error and the "+
				"migration it holds never runs on any box.", name)
			continue
		}

		version, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil {
			t.Errorf("migrations/%s: the numeric component %q does not parse: %v", name, match[1], err)
			continue
		}
		if other, ok := seen[version]; ok {
			t.Errorf("migrations/%s and migrations/%s are both version %d; goose refuses a "+
				"duplicate version outright, so this is a deploy that stops at the migrate step.", other, name, version)
			continue
		}
		seen[version] = name

		if version <= previous {
			t.Errorf("migrations/%s (version %d) sorts after version %d, so the apply order is "+
				"not the version order", name, version, previous)
		}
		previous = version

		body, err := fs.ReadFile(FS, name)
		if err != nil {
			t.Errorf("reading the embedded %s: %v", name, err)
			continue
		}
		if len(strings.TrimSpace(string(body))) == 0 {
			t.Errorf("migrations/%s is empty, so it is a version with nothing behind it", name)
		}
	}
}

func fileNames(t *testing.T, fsys fs.FS, dir string) []string {
	t.Helper()

	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		t.Fatalf("reading %q from the filesystem: %v", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func sqlFilesOnDisk(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the migrations directory: %v", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
