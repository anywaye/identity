package main


import (
	"os"
	"regexp"
	"testing"
)

var (
	withSignupCall = regexp.MustCompile(`httpapi\.WithSignup\(`)

	signupNewCall = regexp.MustCompile(`\bsignup\.New\(`)
)

func TestNewAppWiresTheSignupTimestampSurface(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile(mainSource)
	if err != nil {
		t.Fatalf("reading %s: %v", mainSource, err)
	}
	text := string(source)

	if !withSignupCall.MatchString(text) {
		t.Error("main.go never calls httpapi.WithSignup. The mint route and the " +
			"verify were written and every test passes against a hand-built router, " +
			"but options.signup is nil in every process, so a deployment serves no " +
			"mint route and verifies no pair — the whole surface is absent where it " +
			"is actually deployed.")
	}

	if !appendsToOpts.MatchString(text) {
		t.Fatal("main.go builds no options slice at all (`opts = append(opts,` is absent), so the " +
			"wiring this file is looking for cannot be in a list that is never extended.")
	}

	if !signupNewCall.MatchString(text) {
		t.Error("main.go never calls signup.New. Whatever is handed to WithSignup is then a " +
			"literal, and a deployment's SIGNUP_SIGNING_KEY would sign nothing — the mint " +
			"would hand out pairs its own verify refuses.")
	}

	if !withinWindow(text, withSignupCall, appendsToOpts, 400) {
		t.Error("httpapi.WithSignup( appears in main.go but not inside an `opts = append(opts, …)` " +
			"expression. An option appended to anything else never reaches httpapi.New, so the " +
			"routes stay unmounted and every check that builds options by hand stays green — " +
			"which is the shape of the original defect.")
	}
}

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
