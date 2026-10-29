package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheCourierBlockIsAllOrNothing(t *testing.T) {
	const validURL = "https://courier.example.com"
	const validLink = "https://app.example.com/reset?token=" + recoveryTokenPlaceholder

	cases := []struct {
		name    string
		env     map[string]string
		wantErr error
		wantEnabled bool
		wantNoToken bool
	}{
		{
			name: "all four set is the working configuration",
			env: map[string]string{
				"COURIER_BASE_URL":         validURL,
				"COURIER_TOKEN":            "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE":   validLink,
				"INVITATION_LINK_TEMPLATE": validLink,
			},
			wantEnabled: true,
		},
		{
			name:    "all three absent is a deployment with no mail path, and is supported",
			env:     map[string]string{},
			wantErr: nil,
		},
		{
			name:    "a base URL with no credential would send as an anonymous caller",
			env:     map[string]string{"COURIER_BASE_URL": validURL},
			wantErr: ErrInvalidCourier,
		},
		{
			name:    "a credential with no base URL is a secret with nowhere to go",
			env:     map[string]string{"COURIER_TOKEN": "svc-3f9a1c7e5b2d8046"},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a link template with no base URL",
			env: map[string]string{
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a base URL and a token with no link template",
			env: map[string]string{
				"COURIER_BASE_URL": validURL,
				"COURIER_TOKEN":    "svc-3f9a1c7e5b2d8046",
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a base URL and a token with the recovery templates but no invitation template",
			env: map[string]string{
				"COURIER_BASE_URL":       validURL,
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "an invitation template with no base URL",
			env: map[string]string{
				"INVITATION_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a link template and a token with no base URL",
			env: map[string]string{
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a base URL and a link template with no token",
			env: map[string]string{
				"COURIER_BASE_URL":       validURL,
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a base URL that is not a URL at all",
			env: map[string]string{
				"COURIER_BASE_URL":       "://nope",
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a base URL that is not http",
			env: map[string]string{
				"COURIER_BASE_URL":       "courier.example.com",
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a base URL with a query, which a path would be appended to",
			env: map[string]string{
				"COURIER_BASE_URL":       "https://courier.example.com?debug=1",
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a link template with no placeholder, so a reset link has no token",
			env: map[string]string{
				"COURIER_BASE_URL":       validURL,
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": "https://app.example.com/reset",
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a relative link template, which cannot be rendered in a mail",
			env: map[string]string{
				"COURIER_BASE_URL":       validURL,
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": "/reset?token=" + recoveryTokenPlaceholder,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a link template whose fragment a mail client would not send",
			env: map[string]string{
				"COURIER_BASE_URL":       validURL,
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": "https://app.example.com/reset#/" + recoveryTokenPlaceholder,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a link template with a userinfo section, which is a credential in a URL",
			env: map[string]string{
				"COURIER_BASE_URL":       validURL,
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": "https://kaka:pw@app.example.com/reset?token=" + recoveryTokenPlaceholder,
			},
			wantErr: ErrInvalidCourier,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.env
			if tc.wantErr == nil {
				env = withSignupKey(env)
			}
			cfg, err := Load(lookupFrom(env))

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Load error = %v, want one matching %v", err, tc.wantErr)
				}
				if cfg.CourierEnabled() {
					t.Error("Load returned a Config that reports a mail path alongside an error")
				}
				if !strings.Contains(err.Error(), "COURIER_") &&
					!strings.Contains(err.Error(), "RECOVERY_LINK_TEMPLATE") &&
					!strings.Contains(err.Error(), "INVITATION_LINK_TEMPLATE") {
					t.Errorf("the error names no variable: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.CourierEnabled(); got != tc.wantEnabled {
				t.Errorf("CourierEnabled = %t, want %t", got, tc.wantEnabled)
			}
			if tc.wantEnabled {
				token, err := cfg.CourierToken()
				if err != nil {
					t.Fatalf("CourierToken: %v", err)
				}
				if token != tc.env["COURIER_TOKEN"] {
					t.Error("CourierToken did not return the configured value")
				}
			}
		})
	}
}

func TestAnAbsentCourierBlockIsDistinguishableFromABrokenOne(t *testing.T) {
	absent, err := Load(lookupFrom(withSignupKey(map[string]string{})))
	if err != nil {
		t.Fatalf("an absent courier block must not be an error: %v", err)
	}
	if _, err := absent.CourierToken(); !errors.Is(err, ErrNoCourierToken) {
		t.Errorf("an absent token = %v, want ErrNoCourierToken", err)
	}
	if errors.Is(ErrNoCourierToken, ErrInvalidCourier) || errors.Is(ErrInvalidCourier, ErrNoCourierToken) {
		t.Error("the absent and invalid sentinels are the same value, so no caller can tell them apart")
	}

	broken, err := Load(lookupFrom(map[string]string{"COURIER_BASE_URL": "https://courier.example.com"}))
	if !errors.Is(err, ErrInvalidCourier) {
		t.Fatalf("a partial block = %v, want ErrInvalidCourier", err)
	}
	if errors.Is(err, ErrNoCourierToken) {
		t.Error("a partial block reported itself as an absent token, so a deployment with a typo would mount Unavailable instead of failing to start")
	}
	_ = broken
}

func TestTheBootRulesAndTheClientRulesAgree(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		wantBoot bool
	}{
		{name: "https", raw: "https://courier.example.com", wantBoot: true},
		{name: "http for a local stack", raw: "http://localhost:4003", wantBoot: true},
		{name: "http over a hostname", raw: "http://courier.example.com", wantBoot: true},
		{name: "a path on the base URL", raw: "https://courier.example.com/v1", wantBoot: true},
		{name: "a trailing slash", raw: "https://courier.example.com/", wantBoot: true},
		{name: "no scheme", raw: "courier.example.com", wantBoot: false},
		{name: "a non-http scheme", raw: "ftp://courier.example.com", wantBoot: false},
		{name: "no host", raw: "https://", wantBoot: false},
		{name: "a query", raw: "https://courier.example.com?a=1", wantBoot: false},
		{name: "a fragment", raw: "https://courier.example.com#x", wantBoot: false},
		{name: "empty", raw: "", wantBoot: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bootAccepted := validateMailBaseURL(tc.raw) == nil
			if bootAccepted != tc.wantBoot {
				t.Errorf("boot accepted %q = %t, want %t", tc.raw, bootAccepted, tc.wantBoot)
			}
		})
	}
}

func TestTheBootPlaceholderIsCouriersPlaceholder(t *testing.T) {
	source := readSource(t, "courier")
	if !strings.Contains(source, `TokenPlaceholder = "`+recoveryTokenPlaceholder+`"`) {
		t.Errorf("internal/courier no longer declares TokenPlaceholder as %q; a link "+
			"template validated here would be rejected there", recoveryTokenPlaceholder)
	}
}

func readSource(t *testing.T, pkg string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", pkg, "mailer.go"))
	if err != nil {
		t.Fatalf("reading internal/%s: %v", pkg, err)
	}
	return string(raw)
}
