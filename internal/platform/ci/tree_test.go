package ci


import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

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

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
