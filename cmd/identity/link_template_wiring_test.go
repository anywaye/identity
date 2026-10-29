package main

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/config"
	"github.com/anywaye/identity/internal/recovery"
)

const signupKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"


func courierEnv(links map[string]string) map[string]string {
	env := map[string]string{
		"COURIER_BASE_URL":         "https://courier.example.com",
		"COURIER_TOKEN":            "svc-7f3a9c1e4b8d2056-the-credential",
		"INVITATION_LINK_TEMPLATE": "https://app.example.com/invitations/accept?token={token}",
		"SIGNUP_SIGNING_KEY":       signupKey,
	}
	for key, value := range links {
		env[key] = value
	}
	return env
}

func buildWithEnv(t *testing.T, env map[string]string) string {
	t.Helper()
	cfg, err := config.Load(lookupFrom(env))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	var log strings.Builder
	if _, err := buildMailer(cfg, slog.New(slog.NewTextHandler(&log, nil))); err != nil {
		t.Fatalf("buildMailer: %v", err)
	}
	return log.String()
}

func TestADeploymentConfiguredBeforePerPurposeTemplatesStillBootsAndIsToldAboutIt(t *testing.T) {
	const legacy = "https://app.example.com/reset?token={token}"
	env := courierEnv(map[string]string{"RECOVERY_LINK_TEMPLATE": legacy})

	written := buildWithEnv(t, env)

	cfg, err := config.Load(lookupFrom(env))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if !cfg.CourierEnabled() {
		t.Fatal("a deployment with the single legacy template reports no mail path, so " +
			"every install that exists breaks at this change")
	}
	for _, purpose := range []recovery.Purpose{
		recovery.PurposePasswordReset,
		recovery.PurposeVerifyEmail,
	} {
		if got := cfg.LinkTemplateFor(purpose); got != legacy {
			t.Errorf("the %s link is %q, want the configured %q", purpose, got, legacy)
		}
	}

	for _, want := range []string{
		"link_template.password_reset",
		"link_template.verify_email",
		legacy,
	} {
		if !strings.Contains(written, want) {
			t.Errorf("the startup log does not carry %q:\n%s", want, written)
		}
	}

	for _, want := range []string{
		"RECOVERY_LINK_TEMPLATE",
		"PASSWORD_RESET_LINK_TEMPLATE",
		"EMAIL_VERIFICATION_LINK_TEMPLATE",
		string(recovery.PurposePasswordReset),
		string(recovery.PurposeVerifyEmail),
	} {
		if !strings.Contains(written, want) {
			t.Errorf("the shared-default warning does not mention %q:\n%s", want, written)
		}
	}
	if !strings.Contains(written, "404") {
		t.Errorf("the warning does not say what happens to a reader who follows the "+
			"link:\n%s", written)
	}
}

func TestADeploymentThatHasConfiguredEachPurposeIsNotWarned(t *testing.T) {
	const reset = "https://app.example.com/reset?token={token}"
	const verify = "https://app.example.com/verify-email?token={token}"
	const change = "https://app.example.com/email-change?token={token}"

	written := buildWithEnv(t, courierEnv(map[string]string{
		"PASSWORD_RESET_LINK_TEMPLATE":     reset,
		"EMAIL_VERIFICATION_LINK_TEMPLATE": verify,
		"EMAIL_CHANGE_LINK_TEMPLATE":       change,
	}))

	if strings.Contains(written, "RECOVERY_LINK_TEMPLATE") {
		t.Errorf("the startup log warns about the shared default for a deployment that "+
			"never set it:\n%s", written)
	}
	for _, want := range []string{
		"link_template.password_reset",
		"link_template.verify_email",
		"link_template.email_change",
	} {
		if !strings.Contains(written, want) {
			t.Errorf("the startup log does not carry %q:\n%s", want, written)
		}
	}
	if !strings.Contains(written, reset) || !strings.Contains(written, verify) ||
		!strings.Contains(written, change) {
		t.Errorf("the startup log does not carry all three configured links:\n%s", written)
	}
}

func TestAMigrationInProgressStillGetsWorkingLinks(t *testing.T) {
	const reset = "https://app.example.com/reset?token={token}"
	const verify = "https://app.example.com/verify-email?token={token}"
	env := courierEnv(map[string]string{
		"RECOVERY_LINK_TEMPLATE":           reset,
		"EMAIL_VERIFICATION_LINK_TEMPLATE": verify,
	})

	cfg, err := config.Load(lookupFrom(env))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if got := cfg.LinkTemplateFor(recovery.PurposePasswordReset); got != reset {
		t.Errorf("the reset link is %q, want the unchanged default %q", got, reset)
	}
	if got := cfg.LinkTemplateFor(recovery.PurposeVerifyEmail); got != verify {
		t.Errorf("the verification link is %q, want the new %q", got, verify)
	}

	written := buildWithEnv(t, env)
	if !strings.Contains(written, "RECOVERY_LINK_TEMPLATE") {
		t.Errorf("the warning does not fire for the purpose that still falls back:\n%s", written)
	}
	shared := strings.Index(written, "RECOVERY_LINK_TEMPLATE is the link")
	if shared < 0 {
		t.Fatalf("the shared-default warning is not in the startup log:\n%s", written)
	}
	rest := written[shared:]
	if !strings.Contains(rest, "PASSWORD_RESET_LINK_TEMPLATE") {
		t.Errorf("the warning does not name the variable for the purpose that needs it:\n%s", rest)
	}
	if strings.Contains(rest, "EMAIL_VERIFICATION_LINK_TEMPLATE") {
		t.Errorf("the warning asks for EMAIL_VERIFICATION_LINK_TEMPLATE, which this "+
			"deployment has already set:\n%s", rest)
	}
}
