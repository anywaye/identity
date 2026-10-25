package ci

// Helpers that read the repository's own tree. They used to live in the
// ci.yml-reading test files; GitHub Actions is retired (publishing is
// bin/publish from the box, deploys are Argo), those files went with it, and
// these stay because the migration tree is worth checking whatever runs the
// gate.

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// repoRoot is the repository root, resolved: an unresolved root makes a walk
// visit exactly one entry and stop, so every helper that walks the tree reads
// an empty one.
func repoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed, so the repository root cannot be found")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolving symlinks in repository root %s: %v", root, err)
	}
	return resolved
}

// migrationsInTree is every migration file, parsed from the directory rather
// than from a list, so a new migration is covered the day it is written and a
// deleted one is visible.
func migrationsInTree(t *testing.T) []string {
	t.Helper()

	dir := filepath.Join(repoRoot(t), "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations/: %v", err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		if !migrationOrderRE.MatchString(entry.Name()) {
			t.Errorf("migrations/%s is not named NNNNN_name.sql, so goose will not order it.\n"+
				"Every migration in this directory has followed that shape since 00001 and "+
				"a file that does not is applied last regardless of what its name says.", entry.Name())
			continue
		}
		names = append(names, entry.Name())
	}
	return names
}

var migrationOrderRE = regexp.MustCompile(`^[0-9]{5}_[a-z0-9_]+\.sql$`)

// sortedKeys is a map[string]string's keys, ordered, so a test that walks a
// map is deterministic in both directions.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
