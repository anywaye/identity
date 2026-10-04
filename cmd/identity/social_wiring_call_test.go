package main

// THE TRIPWIRE THAT WOULD HAVE CAUGHT c1fc199.
//
// # WHAT IT HOLDS AND WHY A SOURCE-READING CHECK IS THE RIGHT INSTRUMENT HERE
//
// `oauth_absent_test.go` was deleted with the message "the surface is mounted, so
// the file's rule is satisfied by its deletion." It was not mounted. `WithSocial`
// had no call site anywhere outside its own definition, so `options.social` was nil
// in every process, `registerSocialRoutes` returned before registering anything,
// and a deployment that set six OAUTH_* variables served 404s for a feature it had
// been given credentials for.
//
// Every other check in the repository missed it, and each missed it for a
// legible reason:
//
//   - The router walks set `options.social` to a double, so they saw a router
//     nobody deploys.
//   - The mount tests build `options` by hand, so they stay green if the CALLER
//     stops calling.
//
// The gap is the last link in the chain, and that link is a single call in a
// `main` package. `package main` cannot be imported, so nothing outside it can
// construct `newApp` and observe what it assembled — which leaves reading the
// source as the only instrument available.
//
// # WHY THAT IS NOT A COP-OUT
//
// A source-reading check is weak, and it is weak in a specific way worth stating:
// it holds the SHAPE of the wiring and not its behaviour. It cannot tell a correct
// `buildSocial` from a stub returning a non-nil value. What it does hold is that
// the mount is WIRED AT ALL, which is the entire content of the defect — a claim
// that was deleted on the strength of a statement about a call site that did not
// exist.
//
// The behaviour is covered elsewhere and this file says where: the adapter is
// exercised against a real registry and a real use case in
// internal/httpapi/social_wiring_test.go, the router's two states are held in
// social_mount_test.go, and the use case's five outcomes are held in
// internal/auth/social_test.go. Between them the chain is covered end to end
// EXCEPT this call, and this file is what covers it.
//
// # WHY IT READS ALL THREE PLACES RATHER THAN ONE
//
// Because "is the surface wired" is three facts and each one alone is satisfied by
// a broken deployment:
//
//   1. `httpapi.WithSocial(` is called — the option exists.
//   2. the result is appended to `opts` — so the router is actually handed it.
//      Appending to a local and returning it is how an option gets dropped, and it
//      is invisible in a check that only greps for the call.
//   3. the call is INSIDE the `if authSvc != nil` branch, or beside it with its
//      own guard. A social sign-in creates a user row through auth.Service, so a
//      mount reached on a process with no database would send a browser to a
//      provider and answer 404 on the way back — and `registerRoutes` gates on the
//      same thing at auth.go:125, so the two must agree.

import (
	"os"
	"regexp"
	"testing"
)

// mainSource is this file's own package source, which is the subject under test.
const mainSource = "main.go"

// The three facts, each derived from main.go rather than from a list written down
// here.
//
// They are PATTERNS and not line numbers, because a line number goes stale on
// every unrelated edit above it and then fails for the wrong reason — which is the
// same failure mode as a check that stops matching.
var (
	// withSocialCall matches `httpapi.WithSocial(`.
	withSocialCall = regexp.MustCompile(`httpapi\.WithSocial\(`)

	// appendsToOpts matches a line that appends to the slice the handler is built
	// from. It requires the `opts = append(` shape specifically rather than the
	// bare identifier, because `opts` appears in a dozen places in newApp and only
	// the append is the wiring.
	appendsToOpts = regexp.MustCompile(`opts\s*=\s*append\(\s*opts\s*,`)

	// buildSocialCall matches the call to the builder this packet adds.
	buildSocialCall = regexp.MustCompile(`\bbuildSocial\(`)
)

// TestNewAppWiresTheSocialLoginSurface is the check.
//
// It reads main.go and requires all three facts. Each failure message names what
// the deployment would look like, because a red line here has to be actionable by
// whoever sees it in CI without reading this file.
func TestNewAppWiresTheSocialLoginSurface(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile(mainSource)
	if err != nil {
		t.Fatalf("reading %s: %v", mainSource, err)
	}
	text := string(source)

	// 1. The option is called.
	if !withSocialCall.MatchString(text) {
		t.Error("main.go never calls httpapi.WithSocial. That is the defect this file exists to " +
			"hold: the two social routes were written, registerSocialRoutes is called from " +
			"registerRoutes, and options.social was nil in every process, so a deployment with " +
			"OAUTH_* configured served 404s for a feature it had been given credentials for.")
	}

	// 2. Something is appended to opts at all — the slice newApp hands to
	// httpapi.New. Without this the previous assertion could be satisfied by a call
	// whose result was discarded.
	if !appendsToOpts.MatchString(text) {
		t.Fatal("main.go builds no options slice at all (`opts = append(opts,` is absent), so the " +
			"wiring this file is looking for cannot be in a list that is never extended.")
	}

	// 3. The builder exists and is called, so the option's argument is derived from
	// the configuration rather than being a hand-made value.
	if !buildSocialCall.MatchString(text) {
		t.Error("main.go never calls buildSocial. Whatever is handed to WithSocial is then a " +
			"literal, and a deployment cannot turn social login on or off by configuration — " +
			"which is the whole of how every other optional surface in this process is mounted.")
	}

	// The adjacency of 1 and 2, which is the part neither fact holds alone.
	//
	// `opts = append(opts, ...)` and `httpapi.WithSocial(` both appear in main.go,
	// and it is entirely possible for both to be true while the social option is
	// appended to a local slice that is thrown away. So the call has to appear
	// inside a WithSocial-bearing append. The window is generous — 400 characters —
	// because gofmt's line breaking puts the option on its own line inside a
	// multi-line append, and a tighter window would fail on formatting rather than
	// on wiring.
	if !withinWindow(text, withSocialCall, appendsToOpts, 400) {
		t.Error("httpapi.WithSocial( appears in main.go but not inside an `opts = append(opts, …)` " +
			"expression. An option appended to anything else never reaches httpapi.New, so the " +
			"routes stay unmounted and every check that builds options by hand stays green — " +
			"which is the shape of the original defect.")
	}
}

// TestTheSocialWiringSitsBehindAnAuthService is fact 3: the call is not reachable
// on a process that cannot complete a social sign-in.
//
// It is a separate test rather than part of the one above because it needs to
// reason about a REGION rather than about the whole file, and because its failure
// mode is different: mounting outside the guard does not produce a missing feature,
// it produces a broken one.
//
// The assertion is deliberately loose — "some guard mentions authSvc before the
// call" — because the alternatives are worse. Pinning an exact brace depth would
// make this fail when somebody adds an unrelated `if` above it, and a check that
// fails on refactoring is a check people learn to delete.
func TestTheSocialWiringSitsBehindAnAuthService(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile(mainSource)
	if err != nil {
		t.Fatalf("reading %s: %v", mainSource, err)
	}
	text := string(source)

	at := withSocialCall.FindStringIndex(text)
	if at == nil {
		t.Fatal("main.go never calls httpapi.WithSocial; see " +
			"TestNewAppWiresTheSocialLoginSurface for what that means")
	}

	// The nearest preceding guard that mentions the auth service.
	guard := regexp.MustCompile(`if\s+authSvc\s*!=\s*nil\s*\{`)
	guards := guard.FindAllStringIndex(text[:at[0]], -1)
	if len(guards) == 0 {
		t.Fatal("httpapi.WithSocial is called with no `if authSvc != nil` guard anywhere above it. " +
			"A social sign-in creates a user row, provisions a personal account and mints a session, " +
			"all through auth.Service — so on a process with no database the start route would send a " +
			"browser to a provider and the callback would answer 500. registerRoutes gates the same " +
			"way at auth.go:125, so a mount outside that guard and a router that expects it are a " +
			"half-mounted flow.")
	}

	// The nearest guard's span must REACH the call, not merely precede it. A guard
	// that closes above the call is a guard of something else, and matching on
	// position alone would accept it — which is the failure a loose test invites.
	opened := guards[len(guards)-1]
	if !braceRegionCovers(text, opened[1], at[0]) {
		t.Errorf("httpapi.WithSocial is called at offset %d but the nearest `if authSvc != nil` at "+
			"offset %d closes before it, so the option is appended outside the guard. Either it "+
			"needs its own guard or it needs to move inside this one.", at[0], opened[0])
	}
}

// withinWindow reports whether two matches are close enough together to be part of
// the same expression.
//
// It scans BACKWARDS from the first match to the nearest occurrence of the second,
// which is the direction that matters: the append is what wraps the option, so it
// precedes it. A forward scan would find the next append in the file and report
// agreement between two unrelated statements.
func withinWindow(text string, first, second *regexp.Regexp, window int) bool {
	at := first.FindStringIndex(text)
	if at == nil {
		return false
	}

	// `window` is a DISTANCE, not a slice bound, so there is no `from` to clamp: the
	// search is over `text[:at[0]]` and the distance is checked against the nearest
	// match at the end. An earlier version clamped an offset and then never read it,
	// which golangci-lint's ineffassign caught — a real finding about dead code in
	// a test whose whole job is to not contain any.
	all := second.FindAllStringIndex(text[:at[0]], -1)
	if len(all) == 0 {
		return false
	}

	nearest := all[len(all)-1]
	return at[0]-nearest[0] <= window
}

// braceRegionCovers reports whether the block opened just before `from` is still
// open at `at`.
//
// It counts braces rather than trusting indentation, because gofmt's indentation
// is a convention and this is a security-relevant claim. Strings and comments can
// contain braces, so a brace inside one is counted wrong — which is acceptable and
// stated rather than handled: main.go has no brace inside a string literal in the
// region this is asked about, and adding one would make this test fail loudly
// rather than quietly conclude the wrong thing.
func braceRegionCovers(text string, from, at int) bool {
	depth := 1 // the guard's own opening brace

	for i := from; i < at; i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				// The guard closed above the call, so this is not inside it.
				return false
			}
		}
	}
	return depth > 0
}
