package courier

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/recovery"
)


func sprint(t *testing.T, thing any, verb string) (out string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("formatting under %s panicked: %v", verb, r)
		}
	}()
	return fmt.Sprintf(verb, thing)
}

func reflectMessageFields() string {
	typ := reflect.TypeOf(recovery.Message{})
	names := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		names = append(names, typ.Field(i).Name)
	}
	return strings.Join(names, " ")
}

var subjectLine = regexp.MustCompile(`Subject:\s*"([^"]+)"`)

func subjectsInRecoverySource(t *testing.T) map[string]struct{} {
	t.Helper()
	path := filepath.Join("..", "recovery", "message.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	found := map[string]struct{}{}
	for _, match := range subjectLine.FindAllStringSubmatch(string(raw), -1) {
		found[match[1]] = struct{}{}
	}
	if len(found) == 0 {
		t.Fatalf("no subjects found in %s; the pattern this test reads has drifted "+
			"from the file and the check is now agreeing with nothing", path)
	}
	return found
}
