package ci


import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func manifestEventTypes(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "anywaye.yml")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading anywaye.yml: %v", err)
	}
	got, err := eventTypesFromManifest(string(source))
	if err != nil {
		t.Fatalf("reading anywaye.yml: %v", err)
	}
	return got
}

func eventTypesFromManifest(source string) ([]string, error) {
	lines := strings.Split(source, "\n")

	exposesAt := -1
	for i, line := range lines {
		if line == "exposes:" {
			if exposesAt >= 0 {
				return nil, fmt.Errorf("a second top-level `exposes:` at line %d, so which block is the contract is ambiguous", i+1)
			}
			exposesAt = i
		}
	}
	if exposesAt < 0 {
		return nil, fmt.Errorf("no top-level `exposes:`, so the event list could not be located")
	}

	eventsAt := -1
	for i := exposesAt + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line == "  events:" {
			eventsAt = i
			break
		}
		if !strings.HasPrefix(line, "  ") {
			break
		}
	}
	if eventsAt < 0 {
		return nil, fmt.Errorf("no `events:` list under `exposes:`, so the declaration could not be located")
	}

	var got []string
	for i := eventsAt + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, "    - ") {
			if !strings.HasPrefix(line, "    ") {
				break
			}
			return nil, fmt.Errorf("line %d is inside `exposes.events` and is not a list entry, a comment, or blank: %q", i+1, line)
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		if value == "" {
			return nil, fmt.Errorf("line %d is an `exposes.events` entry with no value", i+1)
		}
		got = append(got, value)
	}

	if len(got) == 0 {
		return nil, fmt.Errorf("`exposes.events` yielded no entries, so a comparison against it would report every published event as undeclared")
	}
	return got, nil
}


func TestTheManifestReaderReadsTheRealShape(t *testing.T) {
	const document = `name: identity
exposes:
  api: openapi/v1.yaml

  events:
    # A comment at the entry indentation.
    - identity.user.created

    - identity.api_key.created
repository:
  url: git@github.com:anywaye/identity.git
`

	got, err := eventTypesFromManifest(document)
	if err != nil {
		t.Fatalf("reading a well-formed document: %v\nIf the reader refuses this, the refusals below prove nothing about the real manifest.", err)
	}
	want := []string{"identity.user.created", "identity.api_key.created"}
	if len(got) != len(want) {
		t.Fatalf("read %v, want %v", got, want)
	}
	for i, typ := range want {
		if got[i] != typ {
			t.Errorf("entry %d = %q, want %q", i, got[i], typ)
		}
	}
}

func TestTheManifestReaderRefusesWhatItDidNotRead(t *testing.T) {
	const wellFormed = `exposes:
  events:
    - identity.user.created
`

	for name, document := range map[string]string{
		"no exposes block":                         "name: identity\nconsumes: []\n",
		"no events list under exposes":             "exposes:\n  api: openapi/v1.yaml\nrepository:\n  url: git@github.com:anywaye/identity.git\n",
		"an events list that yields nothing":       "exposes:\n  events:\n    # every line here is a comment\nrepository:\n  url: git@github.com:anywaye/identity.git\n",
		"an entry with no value":                   "exposes:\n  events:\n    - \n    - identity.user.created\n",
		"a line in the block that is not an entry": "exposes:\n  events:\n    - identity.user.created\n    identity.member.invited\n",
		"a second top-level exposes":               wellFormed + "exposes:\n  events:\n    - identity.user.created\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := eventTypesFromManifest(document); err == nil {
				t.Errorf("the reader returned a list for this document instead of refusing it.\nA reader that under-reads a document it did not understand is worse than no reader: the checks built on it go green, and they are green about a list nobody read.")
			}
		})
	}
}

func TestTheManifestReaderAcceptsWhatItUnderstands(t *testing.T) {
	const document = `exposes:
  events:
    - identity.user.created
`
	if _, err := eventTypesFromManifest(document); err != nil {
		t.Fatalf("the reader refused a document it is supposed to read: %v", err)
	}
}
