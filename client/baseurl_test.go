package client


import (
	"errors"
	"strings"
	"testing"
)

func env(pairs map[string]string) LookupEnv {
	return func(name string) string { return pairs[name] }
}

func TestResolveBaseURLPrefersTheExplicitOptionOverEverything(t *testing.T) {
	got, err := ResolveBaseURL(BaseURLOptions{
		BaseURL:   "https://explicit.example.com",
		LookupEnv: env(map[string]string{ServiceBaseURLEnvVar: "https://service.example.com", BaseURLEnvVar: "https://fleet.example.com"}),
	})
	if err != nil {
		t.Fatalf("resolution failed: %v", err)
	}
	if got != "https://explicit.example.com" {
		t.Errorf("the explicit option lost to the environment: got %q.\n"+
			"Explicit beats ambient: somebody wrote this URL in code, which is the "+
			"strongest statement of intent available.", got)
	}
}

func TestResolveBaseURLPrefersTheServiceVariableOverTheFleetVariable(t *testing.T) {
	got, err := ResolveBaseURL(BaseURLOptions{
		LookupEnv: env(map[string]string{
			ServiceBaseURLEnvVar: "https://identity.example.com",
			BaseURLEnvVar:        "https://fleet.example.com",
		}),
	})
	if err != nil {
		t.Fatalf("resolution failed: %v", err)
	}
	if got != "https://identity.example.com" {
		t.Errorf("got %q, want the per-service variable to win.\n"+
			"Within one source the more specific beats the less. A self-hoster running "+
			"two deployments sets $ANYWAYE_BASE_URL for the fleet and "+
			"$ANYWAYE_IDENTITY_BASE_URL for this one; if the fleet-wide value won, the "+
			"per-service variable would be a setting that does nothing.",
			got)
	}
}

func TestResolveBaseURLUsesTheFleetVariableWhenNoServiceVariableIsSet(t *testing.T) {
	got, err := ResolveBaseURL(BaseURLOptions{
		LookupEnv: env(map[string]string{BaseURLEnvVar: "https://fleet.example.com"}),
	})
	if err != nil {
		t.Fatalf("resolution failed: %v", err)
	}
	if got != "https://fleet.example.com" {
		t.Errorf("got %q, want the fleet-wide variable.\n"+
			"A self-hoster with one deployment of everything should not have to spell "+
			"out six variable names.", got)
	}
}

func TestResolveBaseURLRefusesToGuess(t *testing.T) {
	_, err := ResolveBaseURL(BaseURLOptions{LookupEnv: env(nil)})
	if err == nil {
		t.Fatal("resolution succeeded with nothing configured.\n" +
			"A default would be a guess about which deployment to send a customer's " +
			"credentials to, and that is the one guess this package refuses to make. If " +
			"you want identity.anywaye.com, set it.")
	}

	if !errors.Is(err, ErrNoBaseURL) {
		t.Errorf("the error does not match ErrNoBaseURL, so a caller cannot branch on "+
			"it: %v", err)
	}

	message := err.Error()
	for _, want := range []string{ServiceBaseURLEnvVar, BaseURLEnvVar} {
		if !strings.Contains(message, want) {
			t.Errorf("the error does not name $%s, so a caller reading it does not know "+
				"what to set:\n%s", want, message)
		}
	}
}

func TestResolveBaseURLRefusesABareHost(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"a bare host", "identity.example.com"},
		{"a scheme with no host", "https://"},
		{"a non-http scheme", "ftp://identity.example.com"},
		{"a javascript scheme", "javascript:alert(1)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ResolveBaseURL(BaseURLOptions{BaseURL: tc.value}); err == nil {
				t.Errorf("%q was accepted as a base URL.\n"+
					"anywaye's generated clients concatenate rather than resolve, so a bare "+
					"host produces something that is not a URL and an error naming neither "+
					"the value nor the cause.", tc.value)
			}
		})
	}
}

func TestResolveBaseURLStripsTrailingSlashesAndKeepsAPathPrefix(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"a trailing slash", "https://identity.example.com/", "https://identity.example.com"},
		{"several trailing slashes", "https://identity.example.com///", "https://identity.example.com"},
		{"surrounding whitespace", "  https://identity.example.com  ", "https://identity.example.com"},
		{"a path prefix", "https://example.com/anywaye/", "https://example.com/anywaye"},
		{"a path prefix without a trailing slash", "https://example.com/anywaye", "https://example.com/anywaye"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveBaseURL(BaseURLOptions{BaseURL: tc.in})
			if err != nil {
				t.Fatalf("resolution failed: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q.\n"+
					"The generated client concatenates the base URL with the operation's "+
					"path, so a trailing slash becomes a doubled separator.", got, tc.want)
			}
		})
	}
}

func TestResolveBaseURLPrefersTheExplicitOptionEvenWhenItIsBlank(t *testing.T) {
	got, err := ResolveBaseURL(BaseURLOptions{
		BaseURL:   "   ",
		LookupEnv: env(map[string]string{BaseURLEnvVar: "https://fleet.example.com"}),
	})
	if err != nil {
		t.Fatalf("resolution failed: %v", err)
	}
	if got != "https://fleet.example.com" {
		t.Errorf("a blank explicit value resolved to %q.\n"+
			"Blank is treated as absent so `Options{BaseURL: someVariable}` does not "+
			"silently override an operator's environment with nothing. A value that is "+
			"present and empty is a mistake worth reporting, not a silent redirect.",
			got)
	}
}

func TestBaseURLEnvVarForDerivesRatherThanLists(t *testing.T) {
	for _, tc := range []struct{ service, want string }{
		{"identity", "ANYWAYE_IDENTITY_BASE_URL"},
		{"billing", "ANYWAYE_BILLING_BASE_URL"},
		{"courier", "ANYWAYE_COURIER_BASE_URL"},
	} {
		t.Run(tc.service, func(t *testing.T) {
			if got := BaseURLEnvVarFor(tc.service); got != tc.want {
				t.Errorf("BaseURLEnvVarFor(%q) = %q, want %q", tc.service, got, tc.want)
			}
		})
	}

	for _, bad := range []string{"Identity", "identity-api", "identity2", "", "id entity"} {
		if got := BaseURLEnvVarFor(bad); got != "" {
			t.Errorf("BaseURLEnvVarFor(%q) = %q, want the empty string.\n"+
				"A name that cannot identify a anywaye service should not have an "+
				"environment variable derived from it: a typo would resolve to a "+
				"variable nobody sets, and the mistake would surface as a connection "+
				"refused rather than as a name.", bad, got)
		}
	}
}

func TestNewResolvesTheBaseURLEagerly(t *testing.T) {
	_, err := New(Options{LookupEnv: env(nil)})
	if err == nil {
		t.Fatal("New succeeded with no base URL configured.\n" +
			"Resolution belongs in the constructor: a per-request resolution reports a " +
			"configuration mistake as a transport failure, in a call site that has " +
			"nothing to do with configuration.")
	}
	if !errors.Is(err, ErrNoBaseURL) {
		t.Errorf("New returned %v, which does not match ErrNoBaseURL", err)
	}
}
