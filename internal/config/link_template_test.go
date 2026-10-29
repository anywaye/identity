package config

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/recovery"
)


const defaultTemplate = "https://app.example.com/reset?token=" + recoveryTokenPlaceholder

const invitationLink = "https://app.example.com/invitations/accept?token=" + recoveryTokenPlaceholder

func TestTheDefaultLinkTemplateIsTheDefaultForEveryPurpose(t *testing.T) {
	const resetLink = "https://app.example.com/reset?token=" + recoveryTokenPlaceholder
	const verifyLink = "https://app.example.com/verify-email?token=" + recoveryTokenPlaceholder
	const changeLink = "https://app.example.com/confirm-change?token=" + recoveryTokenPlaceholder

	credentials := map[string]string{
		"COURIER_BASE_URL": "https://courier.example.com",
		"COURIER_TOKEN":    "svc-3f9a1c7e5b2d8046",
		"SIGNUP_SIGNING_KEY": base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	}

	cases := []struct {
		name string
		env  map[string]string
		want map[recovery.Purpose]string
	}{
		{
			name: "the single template an existing deployment has",
			env:  map[string]string{"RECOVERY_LINK_TEMPLATE": resetLink},
			want: map[recovery.Purpose]string{
				recovery.PurposePasswordReset: resetLink,
				recovery.PurposeVerifyEmail:   resetLink,
				recovery.PurposeEmailChange:   resetLink,
			},
		},
		{
			name: "the default plus a verification link of its own",
			env: map[string]string{
				"RECOVERY_LINK_TEMPLATE":           resetLink,
				"EMAIL_VERIFICATION_LINK_TEMPLATE": verifyLink,
			},
			want: map[recovery.Purpose]string{
				recovery.PurposePasswordReset: resetLink,
				recovery.PurposeVerifyEmail:   verifyLink,
				recovery.PurposeEmailChange:   resetLink,
			},
		},
		{
			name: "the default plus a reset link of its own",
			env: map[string]string{
				"RECOVERY_LINK_TEMPLATE":           resetLink,
				"PASSWORD_RESET_LINK_TEMPLATE":     "https://app.example.com/forgot?token=" + recoveryTokenPlaceholder,
				"EMAIL_VERIFICATION_LINK_TEMPLATE": verifyLink,
			},
			want: map[recovery.Purpose]string{
				recovery.PurposePasswordReset: "https://app.example.com/forgot?token=" + recoveryTokenPlaceholder,
				recovery.PurposeVerifyEmail:   verifyLink,
				recovery.PurposeEmailChange:   resetLink,
			},
		},
		{
			name: "the default plus an email-change link of its own",
			env: map[string]string{
				"RECOVERY_LINK_TEMPLATE":           resetLink,
				"EMAIL_VERIFICATION_LINK_TEMPLATE": verifyLink,
				"EMAIL_CHANGE_LINK_TEMPLATE":       changeLink,
			},
			want: map[recovery.Purpose]string{
				recovery.PurposePasswordReset: resetLink,
				recovery.PurposeVerifyEmail:   verifyLink,
				recovery.PurposeEmailChange:   changeLink,
			},
		},
		{
			name: "per purpose only, with the legacy variable removed",
			env: map[string]string{
				"PASSWORD_RESET_LINK_TEMPLATE":     resetLink,
				"EMAIL_VERIFICATION_LINK_TEMPLATE": verifyLink,
				"EMAIL_CHANGE_LINK_TEMPLATE":       changeLink,
			},
			want: map[recovery.Purpose]string{
				recovery.PurposePasswordReset: resetLink,
				recovery.PurposeVerifyEmail:   verifyLink,
				recovery.PurposeEmailChange:   changeLink,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			for key, value := range credentials {
				env[key] = value
			}
			for key, value := range tc.env {
				env[key] = value
			}
			env["INVITATION_LINK_TEMPLATE"] = invitationLink

			cfg, err := Load(lookupFrom(env))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !cfg.CourierEnabled() {
				t.Fatal("CourierEnabled = false for a fully configured deployment")
			}
			if cfg.InvitationLinkTemplate != invitationLink {
				t.Errorf("InvitationLinkTemplate = %q, want the variable's value %q",
					cfg.InvitationLinkTemplate, invitationLink)
			}
			if len(cfg.LinkTemplates) != len(tc.want) {
				t.Fatalf("LinkTemplates has %d purposes (%v), want %d",
					len(cfg.LinkTemplates), cfg.LinkTemplates, len(tc.want))
			}
			for purpose, want := range tc.want {
				if got := cfg.LinkTemplates[purpose]; got != want {
					t.Errorf("the %s link is %q, want %q", purpose, got, want)
				}
			}
			if cfg.LinkTemplateFor(recovery.PurposeVerifyEmail) != tc.want[recovery.PurposeVerifyEmail] {
				t.Error("LinkTemplateFor disagrees with LinkTemplates")
			}
		})
	}
}

func TestAPurposeWithNeitherItsOwnVariableNorTheDefaultRefusesToBoot(t *testing.T) {
	cases := []struct {
		name        string
		env         map[string]string
		wantNamed   string
		wantMissing bool
	}{
		{
			name:      "a reset link configured and nothing to fall back to",
			env:       map[string]string{"PASSWORD_RESET_LINK_TEMPLATE": defaultTemplate},
			wantNamed: "EMAIL_CHANGE_LINK_TEMPLATE",
		},
		{
			name:      "a verification link configured and nothing to fall back to",
			env:       map[string]string{"EMAIL_VERIFICATION_LINK_TEMPLATE": defaultTemplate},
			wantNamed: "EMAIL_CHANGE_LINK_TEMPLATE",
		},
		{
			name:      "an email-change link configured and nothing to fall back to",
			env:       map[string]string{"EMAIL_CHANGE_LINK_TEMPLATE": defaultTemplate},
			wantNamed: "PASSWORD_RESET_LINK_TEMPLATE",
		},
		{
			name: "every purpose but the verification configured",
			env: map[string]string{
				"PASSWORD_RESET_LINK_TEMPLATE": defaultTemplate,
				"EMAIL_CHANGE_LINK_TEMPLATE":   defaultTemplate,
			},
			wantNamed: "EMAIL_VERIFICATION_LINK_TEMPLATE",
		},
		{
			name:      "no link template at all, so no mail has anything to click",
			env:       map[string]string{},
			wantNamed: "EMAIL_CHANGE_LINK_TEMPLATE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{
				"COURIER_BASE_URL": "https://courier.example.com",
				"COURIER_TOKEN":    "svc-3f9a1c7e5b2d8046",
			}
			for key, value := range tc.env {
				env[key] = value
			}

			cfg, err := Load(lookupFrom(env))
			if !errors.Is(err, ErrInvalidCourier) {
				t.Fatalf("Load = %v, want one matching ErrInvalidCourier; a deployment that "+
					"can send mail and cannot say where one of its links points must not boot", err)
			}
			if !strings.Contains(err.Error(), tc.wantNamed) {
				t.Errorf("the refusal names %s rather than %s, so an operator reading the "+
					"startup log cannot act on it: %v", err, tc.wantNamed, err)
			}
			if cfg.CourierEnabled() {
				t.Error("Load returned a Config that reports a mail path alongside an error")
			}
		})
	}
}

func TestALinkTemplateIsSetWithoutCredentialsIsRefused(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "the legacy template with no credentials",
			env:  map[string]string{"RECOVERY_LINK_TEMPLATE": defaultTemplate},
		},
		{
			name: "a per-purpose template with no credentials",
			env:  map[string]string{"EMAIL_VERIFICATION_LINK_TEMPLATE": defaultTemplate},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(lookupFrom(tc.env))
			if !errors.Is(err, ErrInvalidCourier) {
				t.Fatalf("Load = %v, want one matching ErrInvalidCourier", err)
			}
			if !strings.Contains(err.Error(), "COURIER_BASE_URL") ||
				!strings.Contains(err.Error(), "COURIER_TOKEN") {
				t.Errorf("the refusal does not name the credentials it is about: %v", err)
			}
		})
	}
}

func TestEveryLinkTemplateIsHeldToTheSameRefusalsAndNamesItsOwnVariable(t *testing.T) {
	refusals := []struct {
		name     string
		template string
	}{
		{name: "no placeholder", template: "https://app.example.com/reset"},
		{name: "relative", template: "/reset?token=" + recoveryTokenPlaceholder},
		{name: "a fragment a mail client would not send", template: "https://app.example.com/reset#/" + recoveryTokenPlaceholder},
		{name: "a userinfo section", template: "https://kaka:pw@app.example.com/reset?token=" + recoveryTokenPlaceholder},
		{name: "a scheme courier's schema rejects", template: "javascript:alert(" + recoveryTokenPlaceholder + ")"},
		{name: "not a URL", template: "://nope?token=" + recoveryTokenPlaceholder},
		{name: "no host", template: "https://?token=" + recoveryTokenPlaceholder},
	}

	variables := []string{
		"RECOVERY_LINK_TEMPLATE",
		"PASSWORD_RESET_LINK_TEMPLATE",
		"EMAIL_VERIFICATION_LINK_TEMPLATE",
		"EMAIL_CHANGE_LINK_TEMPLATE",
	}

	for _, variable := range variables {
		t.Run(variable, func(t *testing.T) {
			for _, tc := range refusals {
				t.Run(tc.name, func(t *testing.T) {
					env := map[string]string{
						"COURIER_BASE_URL": "https://courier.example.com",
						"COURIER_TOKEN":    "svc-3f9a1c7e5b2d8046",
						variable:           tc.template,
					}
					if variable != "RECOVERY_LINK_TEMPLATE" {
						env["RECOVERY_LINK_TEMPLATE"] = defaultTemplate
					} else {
						env["PASSWORD_RESET_LINK_TEMPLATE"] = defaultTemplate
						env["EMAIL_VERIFICATION_LINK_TEMPLATE"] =
							"https://app.example.com/verify-email?token=" + recoveryTokenPlaceholder
						env["EMAIL_CHANGE_LINK_TEMPLATE"] =
							"https://app.example.com/confirm-change?token=" + recoveryTokenPlaceholder
					}
					_, err := Load(lookupFrom(env))
					if !errors.Is(err, ErrInvalidCourier) {
						t.Fatalf("Load accepted %s=%q, want one matching ErrInvalidCourier", variable, tc.template)
					}
					if !strings.Contains(err.Error(), variable) {
						t.Errorf("the refusal does not name %s: %v", variable, err)
					}
				})
			}
		})
	}
}

func TestAnInsecureLinkTemplateIsDescribedAsThoughHTTPSWereTheOnlyOneAccepted(t *testing.T) {
	t.Run("the courier base URL", func(t *testing.T) {
		_, err := Load(lookupFrom(map[string]string{
			"COURIER_BASE_URL":       "ftp://courier.example.com",
			"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
			"RECOVERY_LINK_TEMPLATE": defaultTemplate,
		}))
		if !errors.Is(err, ErrInvalidCourier) {
			t.Fatalf("Load = %v, want one matching ErrInvalidCourier", err)
		}
		if !strings.Contains(err.Error(), "http or https") {
			t.Errorf("the refusal does not say which schemes are accepted, while http is "+
				"one this service boots with: %v", err)
		}
	})

	t.Run("a link template", func(t *testing.T) {
		_, err := Load(lookupFrom(map[string]string{
			"COURIER_BASE_URL":       "https://courier.example.com",
			"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
			"RECOVERY_LINK_TEMPLATE": "ftp://app.example.com/reset?token=" + recoveryTokenPlaceholder,
		}))
		if !errors.Is(err, ErrInvalidCourier) {
			t.Fatalf("Load = %v, want one matching ErrInvalidCourier", err)
		}
		if !strings.Contains(err.Error(), "http or https") {
			t.Errorf("the refusal does not say which schemes are accepted, while http is "+
				"one this service boots with: %v", err)
		}
	})
}

func TestLinkTemplateVariableNamesEveryPurposeThatCanHaveALink(t *testing.T) {
	want := map[recovery.Purpose]string{
		recovery.PurposePasswordReset: "PASSWORD_RESET_LINK_TEMPLATE",
		recovery.PurposeVerifyEmail:   "EMAIL_VERIFICATION_LINK_TEMPLATE",
		recovery.PurposeEmailChange:   "EMAIL_CHANGE_LINK_TEMPLATE",
	}

	got := map[recovery.Purpose]string{}
	for _, purpose := range []recovery.Purpose{
		recovery.PurposePasswordReset,
		recovery.PurposeVerifyEmail,
		recovery.PurposeEmailChange,
	} {
		if variable, ok := LinkTemplateVariable(purpose); ok {
			got[purpose] = variable
		}
	}

	if len(got) != len(want) {
		t.Errorf("LinkTemplateVariable names %d purposes (%v), want %d (%v)",
			len(got), got, len(want), want)
	}
	for purpose, variable := range want {
		if got[purpose] != variable {
			t.Errorf("the %s link is configured by %q, want %q", purpose, got[purpose], variable)
		}
	}
}

func TestABlankLinkTemplateIsAbsentRatherThanBroken(t *testing.T) {
	cfg, err := Load(lookupFrom(map[string]string{
		"COURIER_BASE_URL":                 "https://courier.example.com",
		"COURIER_TOKEN":                    "svc-3f9a1c7e5b2d8046",
		"RECOVERY_LINK_TEMPLATE":           defaultTemplate,
		"EMAIL_VERIFICATION_LINK_TEMPLATE": "   ",
		"INVITATION_LINK_TEMPLATE":         invitationLink,
		"SIGNUP_SIGNING_KEY": base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	}))
	if err != nil {
		t.Fatalf("a blank variable must be absent, not a startup failure: %v", err)
	}
	if got := cfg.LinkTemplateFor(recovery.PurposeVerifyEmail); got != defaultTemplate {
		t.Errorf("the %s link is %q, want the default %q; a blank value is absent and "+
			"absent means the default, not an empty link",
			recovery.PurposeVerifyEmail, got, defaultTemplate)
	}
	shared := cfg.LinkPurposesUsingTheDefault()
	found := false
	for _, purpose := range shared {
		if purpose == recovery.PurposeVerifyEmail {
			found = true
		}
	}
	if !found {
		t.Errorf("LinkPurposesUsingTheDefault = %v, which omits the %s purpose a blank "+
			"variable resolved; the startup warning would not name it",
			shared, recovery.PurposeVerifyEmail)
	}

	if _, err := Load(lookupFrom(map[string]string{
		"COURIER_BASE_URL":                 "https://courier.example.com",
		"COURIER_TOKEN":                    "svc-3f9a1c7e5b2d8046",
		"PASSWORD_RESET_LINK_TEMPLATE":     defaultTemplate,
		"EMAIL_VERIFICATION_LINK_TEMPLATE": "   ",
		"INVITATION_LINK_TEMPLATE":         invitationLink,
	})); !errors.Is(err, ErrInvalidCourier) {
		t.Errorf("Load = %v, want one matching ErrInvalidCourier; a blank variable with no "+
			"default leaves the purpose with nothing", err)
	}
}
