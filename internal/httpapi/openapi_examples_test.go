package httpapi


import (
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"
)

var uuidShaped = regexp.MustCompile(`[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}`)

func TestEveryIdentifierInAnExampleIsAUuid(t *testing.T) {
	checked := 0
	for _, path := range []string{v1Document, openidDocument} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}

		found := 0
		for i, line := range strings.Split(string(raw), "\n") {
			for _, candidate := range uuidShaped.FindAllString(line, -1) {
				found++
				digits := strings.ReplaceAll(candidate, "-", "")
				if _, err := hex.DecodeString(digits); err != nil {
					t.Errorf("%s:%d: %q is not a uuid: %v\n"+
						"Every id in this document is declared `format: uuid`, and an example that "+
						"cannot be one is a false claim a reader discovers by trying it. Use hex "+
						"digits — the mnemonic suffixes in use are a1 (api key), b1 (user), c1 "+
						"(account), d1 (invitation).",
						path, i+1, candidate, err)
				}
			}
		}
		checked += found
		t.Logf("%s: %d identifiers, all of them hex", path, found)
	}

	if checked == 0 {
		t.Errorf("neither document carries an identifier in the canonical 8-4-4-4-12 grouping, " +
			"so this test proved nothing about either. Either the examples were removed or they " +
			"were spelled some other way, and a check that cannot see them cannot hold them.")
	}
}
