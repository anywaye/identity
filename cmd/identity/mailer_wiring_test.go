package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/config"
	"github.com/anywaye/identity/internal/courier"
	"github.com/anywaye/identity/internal/recovery"
)


func envWithSignupKey(env map[string]string) map[string]string {
	out := make(map[string]string, len(env)+1)
	for k, v := range env {
		out[k] = v
	}
	out["SIGNUP_SIGNING_KEY"] = signupKey
	return out
}

func TestAMailerIsCouriersOrUnavailableAndNothingElse(t *testing.T) {
	const token = "svc-7f3a9c1e4b8d2056-the-credential"

	cases := []struct {
		name string
		env  map[string]string
		wantCourier bool
	}{
		{
			name: "a fully configured deployment gets courier",
			env: map[string]string{
				"COURIER_BASE_URL":         "https://courier.example.com",
				"COURIER_TOKEN":            token,
				"RECOVERY_LINK_TEMPLATE":   "https://app.example.com/reset?token={token}",
				"INVITATION_LINK_TEMPLATE": "https://app.example.com/invitations/accept?token={token}",
			},
			wantCourier: true,
		},
		{
			name:        "an unconfigured deployment refuses loudly",
			env:         map[string]string{},
			wantCourier: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.Load(lookupFrom(envWithSignupKey(tc.env)))
			if err != nil {
				t.Fatalf("config.Load: %v", err)
			}
			var log strings.Builder
			mailer, err := buildMailer(cfg, slog.New(slog.NewTextHandler(&log, nil)))
			if err != nil {
				t.Fatalf("buildMailer: %v", err)
			}
			if mailer == nil {
				t.Fatal("buildMailer returned nil, which is not a Mailer and would panic " +
					"the recovery flows on their first send")
			}

			_, isCourier := mailer.(*courier.RecoveryMailer)
			_, isUnavailable := mailer.(recovery.Unavailable)

			if tc.wantCourier {
				if !isCourier {
					t.Errorf("got %T, want *courier.RecoveryMailer", mailer)
				}
				if isUnavailable {
					t.Error("a configured deployment got recovery.Unavailable{}, which would " +
						"answer 503 to a user who configured a mail path")
				}
			} else {
				if !isUnavailable {
					t.Errorf("got %T, want recovery.Unavailable{}", mailer)
				}
			}

			if strings.Contains(log.String(), token) {
				t.Errorf("the startup log carries the service credential:\n%s", log.String())
			}
		})
	}
}

func TestAnUnconfiguredDeploymentIsLoudAtStartup(t *testing.T) {
	cfg, err := config.Load(lookupFrom(envWithSignupKey(map[string]string{})))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	var log strings.Builder
	if _, err := buildMailer(cfg, slog.New(slog.NewTextHandler(&log, nil))); err != nil {
		t.Fatalf("buildMailer: %v", err)
	}

	written := log.String()
	for _, want := range []string{"COURIER_BASE_URL", "COURIER_TOKEN", "RECOVERY_LINK_TEMPLATE"} {
		if !strings.Contains(written, want) {
			t.Errorf("the startup warning does not name %s:\n%s", want, written)
		}
	}
	if !strings.Contains(written, "503") {
		t.Errorf("the startup warning does not say what the routes will answer:\n%s", written)
	}
}

func TestAConfiguredDeploymentSaysWhatItCanAndCannotSend(t *testing.T) {
	cfg, err := config.Load(lookupFrom(envWithSignupKey(map[string]string{
		"COURIER_BASE_URL":         "https://courier.example.com",
		"COURIER_TOKEN":            "svc-7f3a9c1e4b8d2056-the-credential",
		"RECOVERY_LINK_TEMPLATE":   "https://app.example.com/reset?token={token}",
		"INVITATION_LINK_TEMPLATE": "https://app.example.com/invitations/accept?token={token}",
	})))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	var log strings.Builder
	if _, err := buildMailer(cfg, slog.New(slog.NewTextHandler(&log, nil))); err != nil {
		t.Fatalf("buildMailer: %v", err)
	}

	written := log.String()
	if !strings.Contains(written, "https://courier.example.com") {
		t.Errorf("the startup line does not say which courier this is pointed at:\n%s", written)
	}
	if strings.Contains(written, "svc-7f3a9c1e4b8d2056-the-credential") {
		t.Error("the startup line carries the credential")
	}
	for _, want := range []string{"email change"} {
		if !strings.Contains(written, want) {
			t.Errorf("the startup line does not mention that %s cannot be delivered:\n%s", want, written)
		}
	}
	for _, overclaim := range []string{"mail will be sent", "delivery is working", "ready"} {
		if strings.Contains(written, overclaim) {
			t.Errorf("the startup line claims %q, which a readiness probe cannot establish:\n%s",
				overclaim, written)
		}
	}
}

func TestTheRefusingMailerStillRefuses(t *testing.T) {
	cfg, err := config.Load(lookupFrom(envWithSignupKey(map[string]string{})))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	mailer, err := buildMailer(cfg, slog.New(slog.NewTextHandler(&strings.Builder{}, nil)))
	if err != nil {
		t.Fatalf("buildMailer: %v", err)
	}

	ctx := context.Background()
	if err := mailer.Ready(ctx); err == nil {
		t.Error("Ready returned nil for a deployment that cannot send mail, which would " +
			"let a reset request mint a token for a message nobody can deliver")
	}
	if err := mailer.Send(ctx, recovery.Message{To: "kaka@example.com"}); err == nil {
		t.Error("Send returned nil for a deployment that cannot send mail")
	}
}

func lookupFrom(env map[string]string) config.Lookup {
	return func(key string) (string, bool) {
		value, present := env[key]
		return value, present
	}
}
