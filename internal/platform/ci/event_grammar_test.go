package ci


import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var publishedEventConstant = regexp.MustCompile(`(?m)^\s*(Event[A-Za-z0-9_]*)\s*=\s*"([^"]+)"`)

const outboxDir = "internal/outbox"

func emittedEventTypes(t *testing.T) map[string]string {
	t.Helper()

	dir := filepath.Join(repoRoot(t), outboxDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v\nThe published event types are defined there, and a check that cannot find them is a check that agrees with a reader that cannot find them.", outboxDir, err)
	}
	if len(entries) == 0 {
		t.Fatalf("%s holds no files, so this service publishes no event types.\nThat is a change to the service, not to a test, and it is not something a reader of a green suite should have to guess at.", outboxDir)
	}

	got := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", filepath.Join(outboxDir, name), err)
		}
		for _, match := range publishedEventConstant.FindAllStringSubmatch(string(source), -1) {
			constant, typ := match[1], match[2]
			if previous, clash := got[constant]; clash && previous != typ {
				t.Errorf("%s is %q and also %q — one name publishing two types is a fact stated twice", constant, previous, typ)
			}
			got[constant] = typ
		}
	}

	if len(got) == 0 {
		t.Fatalf("no published event constant matched in %s.\nEither the constants moved or the expression %s is wrong; both are this test's problem and neither is a reason to read zero events as correct.", outboxDir, publishedEventConstant)
	}
	return got
}

var knownUndeclaredEvents = map[string]string{
	"identity.account.created":               "core has the catalog row but no payload schema; declaring it fails event.payload-schema-missing",
	"identity.member.invited":                "core has the catalog row but no payload schema",
	"identity.member.accepted":               "core has NO catalog row — its row is identity.member.joined, and the divergence is a recorded manager decision (see internal/outbox/tenancy.go)",
	"identity.member.role_changed":           "core has the catalog row but no payload schema",
	"identity.member.removed":                "core has the catalog row but no payload schema",
	"identity.account.ownership_transferred": "core has NO catalog row — nothing in core 0.2 describes an account changing hands. The reason it is one event and not two role_changed events is on the constant itself",

	"identity.user.deleted": "core has NO catalog row and no payload schema for a user deletion — declaring it fails event.payload-schema-missing. Emitted so the outbox has the whole history when core ships one",
}

func TestEveryEmittedEventTypeIsThreeSegmentAndOwnPrefixed(t *testing.T) {
	const service = "identity"

	emitted := emittedEventTypes(t)
	for _, constant := range sortedKeys(emitted) {
		typ := emitted[constant]
		t.Run(typ, func(t *testing.T) {
			segments := strings.Split(typ, ".")
			if len(segments) != 3 {
				t.Errorf("%s = %q has %d segments, want exactly 3 (`<service>.<entity>.<action>`).\ncore froze the two-segment form away in 0.2.0 — CHANGELOG.md maps every one of them — and a type in that form is refused by core's eventType pattern.", constant, typ, len(segments))
			}
			for i, segment := range segments {
				if segment == "" {
					t.Errorf("%s = %q has an empty segment at position %d", constant, typ, i)
				}
			}
			if !strings.HasPrefix(typ, service+".") {
				t.Errorf("%s = %q does not start with the publishing service's own name (%s.…).\nThis is core's event.own-prefix rule, applied to the emitted side: a type without the prefix is one no consumer can route by service.", constant, typ, service)
			}
		})
	}
}

func TestTheManifestDeclaresEveryEmittedEvent(t *testing.T) {
	emitted := emittedEventTypes(t)
	declared := manifestEventTypes(t)

	emittedTypes := map[string]bool{}
	for _, typ := range emitted {
		emittedTypes[typ] = true
	}

	var undeclared []string
	for _, constant := range sortedKeys(emitted) {
		if typ := emitted[constant]; !contains(declared, typ) {
			undeclared = append(undeclared, typ)
		}
	}
	sort.Strings(undeclared)

	for _, typ := range undeclared {
		reason, known := knownUndeclaredEvents[typ]
		if !known {
			t.Errorf("%q is emitted by internal/outbox and is not in anywaye.yml's exposes.events, and it is not in knownUndeclaredEvents.\nThat is the defect this file exists to catch: every core rule reads the manifest, so an event nobody declared is invisible to all of them. Declare it, or pin it here with the reason it cannot be declared yet.", typ)
			continue
		}
		t.Logf("KNOWN GAP: %q is emitted and undeclared — %s", typ, reason)
	}

	for _, typ := range declared {
		if !emittedTypes[typ] {
			t.Errorf("%q is declared in exposes.events and emitted nowhere in internal/outbox.\ncore's event.unknown-published only fires for a type core's catalog knows, so a declared-but-unemitted type outside the catalog is this file's to catch.", typ)
		}
	}

	for _, typ := range sortedKeys(knownUndeclaredEvents) {
		if contains(declared, typ) {
			t.Errorf("knownUndeclaredEvents still lists %q, but it IS declared in exposes.events now.\nDelete the line — that is the only legal way this map shrinks, and it shrinks by a packet declaring the event.", typ)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
