package main

// THE TRIPWIRE THAT WOULD HAVE CAUGHT THE MISSING SIGNUP WIRING.
//
// # WHAT IT HOLDS AND WHY A SOURCE-READING CHECK IS THE RIGHT INSTRUMENT HERE
//
// The signup timestamp surface once had this exact defect: the option existed,
// the handler existed, every test built its router by hand with the option set,
// and `main.go` never called `httpapi.WithSignup` — so in a running process the
// mint route was never mounted and the verify never ran, while the whole suite
// was green against hand-built routers. The gap is the last link in the chain,
// and that link is a single call in a `main` package. `package main` cannot be
// imported, so nothing outside it can construct `newApp` and observe what it
// assembled — which leaves reading the source as the only instrument available.
// This file is the signup instance of the tripwire social_wiring_call_test.go
// wrote for the same defect class on the social surface.
//
// # WHY IT READS THREE PLACES RATHER THAN ONE
//
// Because "is the surface wired" is three facts and each one alone is satisfied
// by a broken deployment:
//
//   1. `httpapi.WithSignup(` is called — the option exists.
//   2. the result is appended to `opts` — so the router is actually handed it.
//      Appending to a local and returning it is how an option gets dropped, and
//      it is invisible in a check that only greps for the call.
//   3. the service is built from the configuration (`signup.New(`), so the key
//      is the one the deployment configured rather than a literal.
//
// The helpers `appendsToOpts`, `withinWindow` and `braceRegionCovers` are
// social_wiring_call_test.go's, reused rather than restated: two copies of a
// window check are two copies to drift, and the shape of the wiring they read
// is the same shape.
//
// # AND THE FACT THAT IS THE OPPOSITE OF SOCIAL'S
//
// Social's tripwire asserts the call sits BEHIND the `if authSvc != nil` guard,
// because a social sign-in creates a user row through auth.Service. Signup's
// is the reverse: the mint needs no database — only SIGNUP_SIGNING_KEY, which
// every boot has — so the wiring must be reachable on a process with no
// DATABASE_URL. A pair such a process hands out is refused by a POST /v1/users
// that is not mounted there, and the endpoint's answer is the same on every
// process. The second test below holds that line.

import (
	"os"
	"regexp"
	"testing"
)

// The facts, derived from main.go rather than from a list written down here.
//
// They are PATTERNS and not line numbers, because a line number goes stale on
// every unrelated edit above it and then fails for the wrong reason — which is
// the same failure mode as a check that stops matching.
var (
	// withSignupCall matches `httpapi.WithSignup(`.
	withSignupCall = regexp.MustCompile(`httpapi\.WithSignup\(`)

	// signupNewCall matches the call to the service's constructor, so the
	// option's argument is derived from the configuration rather than being a
	// hand-made value.
	signupNewCall = regexp.MustCompile(`\bsignup\.New\(`)
)

// TestNewAppWiresTheSignupTimestampSurface is the check.
//
// It reads main.go and requires the three facts. Each failure message names
// what the deployment would look like, because a red line here has to be
// actionable by whoever sees it in CI without reading this file.
func TestNewAppWiresTheSignupTimestampSurface(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile(mainSource)
	if err != nil {
		t.Fatalf("reading %s: %v", mainSource, err)
	}
	text := string(source)

	// 1. The option is called.
	if !withSignupCall.MatchString(text) {
		t.Error("main.go never calls httpapi.WithSignup. The mint route and the " +
			"verify were written and every test passes against a hand-built router, " +
			"but options.signup is nil in every process, so a deployment serves no " +
			"mint route and verifies no pair — the whole surface is absent where it " +
			"is actually deployed.")
	}

	// 2. Something is appended to opts at all — the slice newApp hands to
	// httpapi.New. Without this the previous assertion could be satisfied by a
	// call whose result was discarded.
	if !appendsToOpts.MatchString(text) {
		t.Fatal("main.go builds no options slice at all (`opts = append(opts,` is absent), so the " +
			"wiring this file is looking for cannot be in a list that is never extended.")
	}

	// 3. The service is built from the configuration, so the key is the one the
	// deployment configured.
	if !signupNewCall.MatchString(text) {
		t.Error("main.go never calls signup.New. Whatever is handed to WithSignup is then a " +
			"literal, and a deployment's SIGNUP_SIGNING_KEY would sign nothing — the mint " +
			"would hand out pairs its own verify refuses.")
	}

	// The adjacency of 1 and 2, which is the part neither fact holds alone.
	//
	// `opts = append(opts, ...)` and `httpapi.WithSignup(` both appear in
	// main.go, and it is entirely possible for both to be true while the signup
	// option is appended to a local slice that is thrown away. So the call has
	// to appear inside a WithSignup-bearing append. The window is generous —
	// 400 characters — because gofmt's line breaking puts the option on its own
	// line inside a multi-line append, and a tighter window would fail on
	// formatting rather than on wiring.
	if !withinWindow(text, withSignupCall, appendsToOpts, 400) {
		t.Error("httpapi.WithSignup( appears in main.go but not inside an `opts = append(opts, …)` " +
			"expression. An option appended to anything else never reaches httpapi.New, so the " +
			"routes stay unmounted and every check that builds options by hand stays green — " +
			"which is the shape of the original defect.")
	}
}

// TestTheSignupWiringIsNotBehindAnAuthService is the fact that is the opposite
// of social's: the call must be reachable on a process with no database.
//
// It is a separate test rather than part of the one above because it needs to
// reason about a REGION rather than about the whole file, and because its
// failure mode is different: wiring the mint behind the auth guard does not
// produce a missing feature, it produces an inconsistent one — a process with
// no DATABASE_URL would serve no mint, while the same deployment with a
// database would, and nothing but this test could see the difference.
func TestTheSignupWiringIsNotBehindAnAuthService(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile(mainSource)
	if err != nil {
		t.Fatalf("reading %s: %v", mainSource, err)
	}
	text := string(source)

	at := withSignupCall.FindStringIndex(text)
	if at == nil {
		t.Fatal("main.go never calls httpapi.WithSignup; see " +
			"TestNewAppWiresTheSignupTimestampSurface for what that means")
	}

	// Every `if authSvc != nil {` guard in the file must NOT cover the call. A
	// guard that opens after the call cannot cover it and is skipped — the
	// region scan in braceRegionCovers would run backwards and report a hit.
	guard := regexp.MustCompile(`if\s+authSvc\s*!=\s*nil\s*\{`)
	for _, opened := range guard.FindAllStringIndex(text, -1) {
		if opened[1] >= at[0] {
			continue
		}
		if braceRegionCovers(text, opened[1], at[0]) {
			t.Errorf("httpapi.WithSignup is called at offset %d inside the `if authSvc != nil` "+
				"guard at offset %d. The mint needs no database — only SIGNUP_SIGNING_KEY, which "+
				"every boot has — so a process with no DATABASE_URL must mount it too: the pair it "+
				"hands out is refused by a POST /v1/users that is not mounted there, and the "+
				"endpoint's answer is the same on every process.", at[0], opened[0])
		}
	}
}
