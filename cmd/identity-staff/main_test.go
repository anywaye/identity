package main

// THE OPERATOR COMMAND'S TESTS, in two halves.
//
// parse is pure: the table below drives every usage error without a database,
// so a typo in the argument handling is red here rather than in an operator's
// terminal. apply needs a database and is in staff_integration_test.go, which
// runs wherever TEST_DATABASE_URL points — the same split the service's own
// suites use.

import (
	"testing"
)

func TestParseAcceptsTheThreeActionsWithANormalizedAddress(t *testing.T) {
	for _, verb := range []string{"grant", "revoke", "status"} {
		t.Run(verb, func(t *testing.T) {
			act, email, err := parse([]string{verb, "  KAKA@Example.com "})
			if err != nil {
				t.Fatalf("parse(%s) = %v, want success", verb, err)
			}
			if string(act) != verb {
				t.Errorf("action = %q, want %q", act, verb)
			}
			// Normalized exactly as registration normalizes: the lookup below
			// must find the row the registration stored.
			if email != "kaka@example.com" {
				t.Errorf("email = %q, want the normalized kaka@example.com", email)
			}
		})
	}
}

func TestParseRefusesEveryUsageError(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"an action and nothing else", []string{"grant"}},
		{"an address and nothing else", []string{"kaka@example.com"}},
		{"three arguments", []string{"grant", "kaka@example.com", "extra"}},
		{"an unknown action", []string{"promote", "kaka@example.com"}},
		{"an empty address", []string{"grant", ""}},
		{"a blank address", []string{"grant", "   "}},
		{"not an address", []string{"grant", "kaka"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parse(tc.args); err == nil {
				t.Errorf("parse(%q) succeeded, want a usage error", tc.args)
			}
		})
	}
}
