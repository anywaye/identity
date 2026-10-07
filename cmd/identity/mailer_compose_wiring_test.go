package main

// # THE AGREEMENT TEST: identity's manifest, read by identity's own suite
//
// `mailer_wiring_test.go` proves that a given ENVIRONMENT produces the right
// mailer. It cannot prove the one thing that matters for a bring-up: that the
// environment the stack actually hands this process is one that wires the mail
// path. That is a claim about `docker-compose.yml`, and until this file it was
// made by nobody — the compose block carried no courier variables at all, so a
// composed stack booted with no mail path and every recovery route answered 503
// with a sentence naming a problem the developer had been told to configure.
//
// So this file reads the identity service's `environment:` block out of
// `docker-compose.yml`, resolves `${VAR}` / `${VAR:-default}` / `${VAR:?message}`
// the way compose does, sets that environment, and boots the REAL wiring path —
// `config.Load` and `buildMailer` — asserting the mailer is courier's and not
// the refusing one.
//
// # WHY THE TEST SUPPLIES TWO VALUES ITSELF
//
// The block requires two things from outside the repository, and the test
// provides them the way a developer's `.env` would:
//
//   - COURIER_TOKEN, the one secret the manifest requires. This test proves the
//     MANIFEST carries the variable into the wiring, not that a particular
//     secret exists, so the value is a fixture. The static test below is what
//     holds the shape: a literal here is a value that has to equal a literal in
//     another repository, and a default is a shared secret committed to this one.
//   - SIGNUP_SIGNING_KEY, the one secret a boot cannot go without. The compose
//     file does not carry it (that is m63's packet); every other wiring test in
//     this package supplies it the same way, and a deployment that cannot boot
//     produces no mailer to inspect.
//
// # WHAT IS DELIBERATELY NOT ASSERTED
//
// Nothing here reads courier's repository. The equality between identity's
// COURIER_TOKEN and courier's COURIER_IDENTITY_TOKEN is a fact about a running
// stack, and a test in this tree that reached into another tree to check it
// would be a test that goes long and stale — the fleet's standing rule. The
// install script (m68) owns that check; this file owns identity's side of it,
// which is that the variable is declared, required, and never a literal.

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/config"
	"github.com/cafaye/identity/internal/courier"
	"github.com/cafaye/identity/internal/recovery"
)

// composeVar matches the three interpolation forms this repository uses.
//
// THE SUBSET IS STATED rather than implied: `${VAR}`, `${VAR:-default}` and
// `${VAR:?message}`, and nothing else. Compose also accepts `$VAR` without
// braces and `$$` as an escape; this file uses neither, and a half-implemented
// escape is worse than a stated omission — the reader of the compose file can
// see every form in use by grepping for `${`.
var composeVar = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?::([+-?])([^}]*))?\}`)

// composeInterpolate resolves the three forms against the host environment,
// which is what compose reads (the shell plus `.env`).
//
// `${VAR}` is the host's value, empty when unset. `${VAR:-default}` is the
// host's value when it is set and non-empty, otherwise the default. `${VAR:?message}`
// is the host's value when it is set and non-empty, otherwise an ERROR naming
// the variable and the message — compose refuses to start the stack, and this
// resolver refuses to pretend otherwise.
func composeInterpolate(raw string) (string, error) {
	var resolveErr error
	out := composeVar.ReplaceAllStringFunc(raw, func(match string) string {
		if resolveErr != nil {
			return ""
		}
		g := composeVar.FindStringSubmatch(match)
		name, op, arg := g[1], g[2], g[3]
		value, set := os.LookupEnv(name)
		switch op {
		case "": // ${VAR}
			return value
		case "-": // ${VAR:-default}
			if set && value != "" {
				return value
			}
			return arg
		case "?": // ${VAR:?message}
			if set && value != "" {
				return value
			}
			resolveErr = fmt.Errorf("%s is not set: %s", name, arg)
			return ""
		default:
			// Compose also has `:+`; this file does not use it, and resolving it
			// to the literal text would be a silent wrong answer.
			resolveErr = fmt.Errorf("%s uses %q, which this resolver does not implement", name, op)
			return ""
		}
	})
	return out, resolveErr
}

// composeIdentityEnv reads the identity service's `environment:` block out of
// docker-compose.yml and returns it unresolved.
//
// THE PARSER IS INDENTATION-BASED, like `openapi_reader_test.go`'s: this
// repository has no YAML dependency behind go.mod and adding one for forty
// lines of structure is the trade that file refuses. The subset is stated: a
// service key at two spaces, an `environment:` key at four, entries at six,
// comments and blank lines skipped, values unquoted when double-quoted.
//
// IT FAILS LOUDLY RATHER THAN RETURNING LESS THAN IT SHOULD. A parser that
// finds no block agrees with another parser that finds no block, and that is
// how a check over nothing goes green: no `identity:` service, no
// `environment:` key, or a block with no entries is a hard error naming what
// was missing, never an empty map that a later assertion would read as "the
// deployment configures nothing".
func composeIdentityEnv(t *testing.T) map[string]string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("reading docker-compose.yml: %v", err)
	}
	lines := strings.Split(string(raw), "\n")

	env := map[string]string{}
	inService, inEnv := false, false
	for _, line := range lines {
		if !inService {
			if line == "  identity:" {
				inService = true
			}
			continue
		}
		// Inside the identity service. A key at two spaces is the next service,
		// and identity is the last one in the file — but the check is what makes
		// that a fact rather than an assumption.
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			break
		}
		if !inEnv {
			if line == "    environment:" {
				inEnv = true
			}
			continue
		}
		// Inside the environment block. Blank lines separate entries; a line
		// with no six-space indent is the next key of the service.
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, "      ") {
			break
		}
		if strings.HasPrefix(line, "      #") {
			continue
		}
		m := regexp.MustCompile(`^      ([A-Za-z0-9_]+): ?(.*)$`).FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("docker-compose.yml's identity environment block carries a line this "+
				"parser does not understand: %q. The subset is stated in composeIdentityEnv — "+
				"either the line fits it or the parser was not updated with the file.", line)
		}
		env[m[1]] = unquoteComposeValue(m[2])
	}

	if !inService {
		t.Fatal("docker-compose.yml carries no `identity:` service at two-space indent, so this " +
			"check is reading a file that is not the one it was written for")
	}
	if !inEnv {
		t.Fatal("docker-compose.yml's identity service carries no `environment:` block, so a " +
			"composed stack boots with no configuration at all and every recovery route answers 503")
	}
	if len(env) == 0 {
		t.Fatal("docker-compose.yml's identity environment block parsed as empty — a parser " +
			"that finds nothing agrees with another parser that finds nothing")
	}
	return env
}

// unquoteComposeValue strips one layer of double quotes, the way compose does
// for a quoted scalar. An unquoted value is returned unchanged.
func unquoteComposeValue(raw string) string {
	if len(raw) >= 2 && strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) {
		return raw[1 : len(raw)-1]
	}
	return raw
}

// TestTheComposeServiceDeclaresTheCourierClientConfig is the static half of the
// agreement, and the one that was RED on arrival: the block carried no courier
// variables, so the first assertion failed and the proof was that the mail path
// did not exist in the only bring-up this repository ships.
//
// IT HOLDS THE SHAPE OF THE CONTRACT, which is the part a deployment can get
// wrong without noticing:
//
//   - COURIER_BASE_URL is courier's compose-network name and its own port. A
//     wrong port here is a mail path that dials nothing, and the failure is a
//     send that times out in front of a user who cannot sign in.
//   - COURIER_TOKEN is a REQUIRED interpolation, never a literal and never a
//     default. A literal is a value that has to equal a literal in another
//     repository and cannot be kept equal; a default is a shared secret
//     committed to this one. The failure message names COURIER_IDENTITY_TOKEN
//     because the message IS the contract — an operator who hits it is told the
//     rule at the moment they break it.
//   - both link templates are outside-supplied interpolations carrying
//     `{token}`. The hostname is a deployment fact identity does not own, and a
//     template without the placeholder is refused by config.Load because a link
//     with no token reaches a screen with nothing to redeem.
func TestTheComposeServiceDeclaresTheCourierClientConfig(t *testing.T) {
	env := composeIdentityEnv(t)

	rawBase, ok := env["COURIER_BASE_URL"]
	if !ok {
		t.Fatal("docker-compose.yml's identity service does not set COURIER_BASE_URL, so a " +
			"composed stack boots with no courier address and every recovery route answers 503")
	}
	base, err := composeInterpolate(rawBase)
	if err != nil {
		t.Fatalf("resolving COURIER_BASE_URL: %v", err)
	}
	if base != "http://courier:4000" {
		t.Errorf("COURIER_BASE_URL resolves to %q, want %q — courier's compose-network name "+
			"and its own port (courier's compose PORT is 4000). A wrong port here is a mail "+
			"path that dials nothing, and the failure is a send timing out in front of a user "+
			"who cannot sign in.", base, "http://courier:4000")
	}

	rawToken, ok := env["COURIER_TOKEN"]
	if !ok {
		t.Fatal("docker-compose.yml's identity service does not set COURIER_TOKEN, so a " +
			"composed stack boots with no service credential and every recovery route answers 503")
	}
	if !strings.HasPrefix(rawToken, "${COURIER_TOKEN:?") {
		t.Errorf("COURIER_TOKEN is %q, want a ${COURIER_TOKEN:?...} interpolation. The "+
			"credential comes from outside the repository: a literal is a value that has to "+
			"equal a literal in courier's compose file and cannot be kept equal, and a "+
			"`:-` default is a shared secret committed to this one.", rawToken)
	}
	if !strings.Contains(rawToken, "COURIER_IDENTITY_TOKEN") {
		t.Errorf("COURIER_TOKEN's failure message does not name COURIER_IDENTITY_TOKEN, so an "+
			"operator who hits it is not told the contract: %q", rawToken)
	}

	for _, variable := range []string{
		"PASSWORD_RESET_LINK_TEMPLATE",
		"EMAIL_VERIFICATION_LINK_TEMPLATE",
	} {
		raw, ok := env[variable]
		if !ok {
			t.Fatalf("docker-compose.yml's identity service does not set %s, so the sellable "+
				"loop's %s link points wherever the shared default says — which for the "+
				"configuration this shape was introduced to replace is the wrong screen",
				variable, variable)
		}
		if !strings.Contains(raw, "{token}") {
			t.Errorf("%s is %q, which has no {token} — config.Load refuses such a template "+
				"because a link would carry no token and the reader would reach a screen with "+
				"nothing to redeem", variable, raw)
		}
		if !strings.Contains(raw, "${") {
			t.Errorf("%s is the literal %q — the hostname is a deployment fact this service "+
				"does not own, so it must be supplied from outside and overridable per deployment",
				variable, raw)
		}
		resolved, err := composeInterpolate(raw)
		if err != nil {
			t.Fatalf("resolving %s: %v", variable, err)
		}
		if !strings.HasPrefix(resolved, "http") || !strings.Contains(resolved, "{token}") {
			t.Errorf("%s resolves to %q, which is not an http(s) URL carrying {token}",
				variable, resolved)
		}
	}
}

// TestTheComposeServiceEnvWiresTheMailer is the dynamic half: the block,
// resolved the way compose resolves it, fed to the real wiring path.
//
// IT IS THE ASSERTION THAT MATTERS MOST. The static test can be satisfied by a
// block that declares the right shapes and still produces a mailer that cannot
// send; this one boots `config.Load` and `buildMailer` on the resolved
// environment and refuses `recovery.Unavailable{}`, which is the type that
// answers 503 to a user who believes their reset is on its way.
func TestTheComposeServiceEnvWiresTheMailer(t *testing.T) {
	const token = "svc-7f3a9c1e4b8d2056-the-credential"

	env := composeIdentityEnv(t)

	// The two values a developer's `.env` carries, supplied here the way the
	// shell would supply them to compose — see the file header for why the test
	// proves the manifest carries them and not that the secrets exist.
	env["COURIER_TOKEN"] = token
	env["SIGNUP_SIGNING_KEY"] = signupKey

	resolved := make(map[string]string, len(env))
	for key, raw := range env {
		value, err := composeInterpolate(raw)
		if err != nil {
			// This is the error docker compose would print, and it is a failure
			// rather than a skip: a stack that cannot resolve does not boot, so
			// there is no mailer to inspect.
			t.Fatalf("resolving %s: %v — this is the error docker compose would print", key, err)
		}
		resolved[key] = value
		t.Setenv(key, value)
	}

	cfg, err := config.Load(lookupFrom(resolved))
	if err != nil {
		t.Fatalf("config.Load: %v — the compose stack's environment is not a bootable "+
			"configuration, so the stack does not come up and there is no mail path", err)
	}

	var log strings.Builder
	mailer, err := buildMailer(cfg, slog.New(slog.NewTextHandler(&log, nil)))
	if err != nil {
		t.Fatalf("buildMailer: %v", err)
	}
	if mailer == nil {
		t.Fatal("buildMailer returned nil, which is not a Mailer and would panic the " +
			"recovery flows on their first send")
	}

	_, isCourier := mailer.(*courier.RecoveryMailer)
	_, isUnavailable := mailer.(recovery.Unavailable)

	if !isCourier {
		t.Errorf("the compose stack's environment produced %T, want *courier.RecoveryMailer — "+
			"every recovery route would answer 503", mailer)
	}
	if isUnavailable {
		t.Error("the compose stack's environment produced recovery.Unavailable{}, which " +
			"answers 503 to a user who configured a mail path")
	}

	// The manifest's value reached the wiring, not merely some environment: a
	// block that declared the right shapes and wired them to nothing would pass
	// the type assertions above only by accident, and this is the assertion
	// that pins the value the container actually dials.
	if cfg.CourierBaseURL != "http://courier:4000" {
		t.Errorf("cfg.CourierBaseURL is %q, want %q from the compose file",
			cfg.CourierBaseURL, "http://courier:4000")
	}

	// The credential never reaches the log, even when it came out of the
	// compose file rather than a hand-built map — the sweep in
	// mailer_wiring_test.go covers the hand-built case, and this is the same
	// boundary reached from the other side.
	if strings.Contains(log.String(), token) {
		t.Errorf("the startup log carries the service credential:\n%s", log.String())
	}
}

// TestComposeResolutionFollowsTheThreeForms holds the resolver to compose's
// semantics, because a resolver that silently resolves nothing is how a check
// over nothing goes green.
//
// THE UNSET CASES ARE THE POINT. `${VAR}` and `${VAR:-default}` both have a
// defined answer for an unset variable (empty, and the default); `${VAR:?message}`
// has none, and the error is the contract — it is what makes `docker compose up`
// fail before a container starts rather than booting a stack with no mail path.
func TestComposeResolutionFollowsTheThreeForms(t *testing.T) {
	const setVar = "COMPOSE_TEST_SET"
	const unsetVar = "COMPOSE_TEST_UNSET"
	t.Setenv(setVar, "from-the-host")
	os.Unsetenv(unsetVar)

	for _, tc := range []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{"a variable that is set", "${" + setVar + "}", "from-the-host", false},
		{"a variable that is unset", "${" + unsetVar + "}", "", false},
		{"a default when the variable is set", "${" + setVar + ":-fallback}", "from-the-host", false},
		{"a default when the variable is unset", "${" + unsetVar + ":-fallback}", "fallback", false},
		{"a required variable that is set", "${" + setVar + ":?set it}", "from-the-host", false},
		{"a required variable that is unset", "${" + unsetVar + ":?set it}", "", true},
		{"a literal with no interpolation", "http://courier:4000", "http://courier:4000", false},
		{
			"two interpolations in one value",
			"${" + setVar + ":-a}/${" + unsetVar + ":-b}",
			"from-the-host/b",
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := composeInterpolate(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("composeInterpolate(%q) = %q, want an error — compose refuses "+
						"to start the stack, and this resolver refuses to pretend otherwise",
						tc.raw, got)
				}
				if !strings.Contains(err.Error(), unsetVar) {
					t.Errorf("the error does not name the missing variable: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("composeInterpolate(%q): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("composeInterpolate(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
