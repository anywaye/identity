package mfa

import (
	"testing"

	"github.com/anywaye/identity/internal/platform/id"
)

func mustUUID(t *testing.T, raw string) id.UUID {
	t.Helper()
	parsed, err := id.Parse(raw)
	if err != nil {
		t.Fatalf("parsing the fixture id %q: %v", raw, err)
	}
	return parsed
}
