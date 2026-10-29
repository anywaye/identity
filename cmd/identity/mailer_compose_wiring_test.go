package main


import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/config"
	"github.com/anywaye/identity/internal/courier"
	"github.com/anywaye/identity/internal/recovery"
)

var composeVar = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?::([+-?])([^}]*))?\}`)

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
		case "":
			return value
		case "-":
			if set && value != "" {
				return value
			}
			return arg
		case "?":
			if set && value != "" {
				return value
			}
			resolveErr = fmt.Errorf("%s is not set: %s", name, arg)
			return ""
		default:
			resolveErr = fmt.Errorf("%s uses %q, which this resolver does not implement", name, op)
			return ""
		}
	})
	return out, resolveErr
}

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
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			break
		}
		if !inEnv {
			if line == "    environment:" {
				inEnv = true
			}
			continue
		}
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

func unquoteComposeValue(raw string) string {
	if len(raw) >= 2 && strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) {
		return raw[1 : len(raw)-1]
	}
	return raw
}

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
		"INVITATION_LINK_TEMPLATE",
		"EMAIL_CHANGE_LINK_TEMPLATE",
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

func TestTheComposeServiceEnvWiresTheMailer(t *testing.T) {
	const token = "svc-7f3a9c1e4b8d2056-the-credential"

	env := composeIdentityEnv(t)

	env["COURIER_TOKEN"] = token
	env["SIGNUP_SIGNING_KEY"] = signupKey

	resolved := make(map[string]string, len(env))
	for key, raw := range env {
		value, err := composeInterpolate(raw)
		if err != nil {
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

	if cfg.CourierBaseURL != "http://courier:4000" {
		t.Errorf("cfg.CourierBaseURL is %q, want %q from the compose file",
			cfg.CourierBaseURL, "http://courier:4000")
	}

	if strings.Contains(log.String(), token) {
		t.Errorf("the startup log carries the service credential:\n%s", log.String())
	}
}

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
