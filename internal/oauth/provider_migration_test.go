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

// connectedAccountProviderFile is the migration that CREATED the `oauth_provider`
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

// connectedAccountProviderAdditions is the list of migrations that ADD VALUE to
// the enum after the fact.
//
// IT IS A LIST AND NOT A SECOND CONSTANT because the whole point of the shape is
// that a provider added after 00008 lands in a NEW migration — the rule this tree
// writes down — and the check has to see every one of them or it is checking
// against an enum the database no longer has. The list is walked in order and
// each file's values are appended, so the union is what a migrated database
// ends up with.
//
// A provider added to knownProviders and not to this list is the failure this
// check exists to catch, in the direction that is silent: the Go side offers a
// provider whose name the database refuses, and nothing reports the mismatch
// until the first real sign-in fails at the constraint.
var connectedAccountProviderAdditions = []string{
	"../../migrations/00025_oauth_provider_microsoft.sql",
	"../../migrations/00026_oauth_provider_apple.sql",
}

// enumPattern captures the quoted values of a `CREATE TYPE <name> AS ENUM (...)`
// statement. It is anchored on the type name so a different enum in the same file
// cannot be mistaken for this one.
var enumPattern = regexp.MustCompile(`(?i)CREATE\s+TYPE\s+oauth_provider\s+AS\s+ENUM\s*\(([^)]*)\)`)

// addValuePattern captures the quoted value of an `ALTER TYPE <name> ADD VALUE`
// statement. Anchored on the type name for the same reason as enumPattern.
var addValuePattern = regexp.MustCompile(`(?i)ALTER\s+TYPE\s+oauth_provider\s+ADD\s+VALUE\s+'([^']*)'`)

// quotedPattern captures one single-quoted SQL string literal.
var quotedPattern = regexp.MustCompile(`'([^']*)'`)

// connectedAccountProviderEnum reads the `oauth_provider` enum out of the
// migrations, or reports ok=false when it cannot.
//
// THE SUBJECT IS THE UNION: the values 00008 created plus every value a later
// migration added. A check that read only the CREATE TYPE would report agreement
// on the day a provider is added — the one day it is worth anything — because the
// new name would be missing from both sides of its comparison.
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

	for _, file := range connectedAccountProviderAdditions {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, false
		}
		for _, m := range addValuePattern.FindAllSubmatch(raw, -1) {
			names = append(names, string(m[1]))
		}
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
