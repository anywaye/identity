package oauth

// DERIVING THE PROVIDER CLOSED SET OUT OF THE MIGRATION, for
// TestKnownProvidersMatchesTheNamesTheEnumAccepts.
//
// # WHY A TEST READS A .sql FILE
//
// `knownProviders` in provider.go is a Go list of two strings. The column it has
// to agree with is a PostgreSQL enum declared in
// migrations/00008_connected_accounts.sql. Nothing in Go connects them: add a
// provider to one and the other is stale, and the two failures are asymmetric and
// both bad.
//
//   - In the Go list but not the enum: the store's INSERT is refused by a CHECK
//     constraint, so the FIRST real sign-in for that provider fails at the
//     database with a constraint violation.
//   - In the enum but not the Go list: `Settings.Providers` never offers it, so a
//     deployment that configured it serves a 404 for a provider its own database
//     schema says is legitimate — and nothing reports the mismatch.
//
// A test that restated the enum as a Go slice would have the same staleness
// problem as the list it checks. Reading the file is what makes the check hold on
// the day a provider is added, which is the only day it is worth anything.
//
// # WHY IT FAILS LOUDLY WHEN THE FILE IS GONE
//
// `ok` is false rather than "the enum is empty", because an empty enum would
// make the caller's length comparison pass vacuously — a check that reports
// agreement because it read nothing is worse than no check. A caller that gets
// ok=false is told to re-point the check, and told not to delete it.

import (
	"os"
	"regexp"
)

// connectedAccountProviderEnum is the migration holding the `oauth_provider`
// enum.
//
// A CONSTANT AND NOT A SEARCH, because a search would make the test's subject
// depend on which migration happens to be present. Applied migrations are never
// edited in this repository — an applied migration is not edited — so this path
// does not go stale when a LATER migration adds a provider; that is a limitation
// of this check and it is stated rather than papered over.
//
// The path is relative to THIS PACKAGE's directory (internal/oauth), so it walks
// up two levels to the repository root. A test that opened the migration by
// walking up from the working directory would resolve differently under `go test`
// than under `go test ./...` from a subpackage, and would read nothing at all.
const connectedAccountProviderFile = "../../migrations/00008_connected_accounts.sql"

// enumPattern captures the quoted values of a `CREATE TYPE <name> AS ENUM (...)`
// statement. It is anchored on the type name so a different enum in the same file
// cannot be mistaken for this one.
var enumPattern = regexp.MustCompile(`(?i)CREATE\s+TYPE\s+oauth_provider\s+AS\s+ENUM\s*\(([^)]*)\)`)

// quotedPattern captures one single-quoted SQL string literal.
var quotedPattern = regexp.MustCompile(`'([^']*)'`)

// connectedAccountProviderEnum reads the `oauth_provider` enum out of the
// migration, or reports ok=false when it cannot.
func connectedAccountProviderEnum() (names []string, ok bool) {
	raw, err := os.ReadFile(connectedAccountProviderFile)
	if err != nil {
		return nil, false
	}

	match := enumPattern.FindSubmatch(raw)
	if match == nil {
		return nil, false
	}

	for _, quoted := range quotedPattern.FindAllSubmatch(match[1], -1) {
		names = append(names, string(quoted[1]))
	}
	// An `AS ENUM ()` with no values parses to an empty slice and a nil ok=false
	// distinction would be lost, so an empty read is treated as a failed read.
	if len(names) == 0 {
		return nil, false
	}
	return names, true
}

// contains reports whether names holds want.
func contains(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}
