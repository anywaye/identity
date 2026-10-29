package main


import (
	"os"
	"regexp"
	"testing"
)

const mainSource = "main.go"

var (
	withSocialCall = regexp.MustCompile(`httpapi\.WithSocial\(`)

	appendsToOpts = regexp.MustCompile(`opts\s*=\s*append\(\s*opts\s*,`)

	buildSocialCall = regexp.MustCompile(`\bbuildSocial\(`)
)

func TestNewAppWiresTheSocialLoginSurface(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile(mainSource)
	if err != nil {
		t.Fatalf("reading %s: %v", mainSource, err)
	}
	text := string(source)

	if !withSocialCall.MatchString(text) {
		t.Error("main.go never calls httpapi.WithSocial. That is the defect this file exists to " +
			"hold: the two social routes were written, registerSocialRoutes is called from " +
			"registerRoutes, and options.social was nil in every process, so a deployment with " +
			"OAUTH_* configured served 404s for a feature it had been given credentials for.")
	}

	if !appendsToOpts.MatchString(text) {
		t.Fatal("main.go builds no options slice at all (`opts = append(opts,` is absent), so the " +
			"wiring this file is looking for cannot be in a list that is never extended.")
	}

	if !buildSocialCall.MatchString(text) {
		t.Error("main.go never calls buildSocial. Whatever is handed to WithSocial is then a " +
			"literal, and a deployment cannot turn social login on or off by configuration — " +
			"which is the whole of how every other optional surface in this process is mounted.")
	}

	if !withinWindow(text, withSocialCall, appendsToOpts, 400) {
		t.Error("httpapi.WithSocial( appears in main.go but not inside an `opts = append(opts, …)` " +
			"expression. An option appended to anything else never reaches httpapi.New, so the " +
			"routes stay unmounted and every check that builds options by hand stays green — " +
			"which is the shape of the original defect.")
	}
}

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

	opened := guards[len(guards)-1]
	if !braceRegionCovers(text, opened[1], at[0]) {
		t.Errorf("httpapi.WithSocial is called at offset %d but the nearest `if authSvc != nil` at "+
			"offset %d closes before it, so the option is appended outside the guard. Either it "+
			"needs its own guard or it needs to move inside this one.", at[0], opened[0])
	}
}

func withinWindow(text string, first, second *regexp.Regexp, window int) bool {
	at := first.FindStringIndex(text)
	if at == nil {
		return false
	}

	all := second.FindAllStringIndex(text[:at[0]], -1)
	if len(all) == 0 {
		return false
	}

	nearest := all[len(all)-1]
	return at[0]-nearest[0] <= window
}

func braceRegionCovers(text string, from, at int) bool {
	depth := 1

	for i := from; i < at; i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return false
			}
		}
	}
	return depth > 0
}
