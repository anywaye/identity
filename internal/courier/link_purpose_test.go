package courier

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/config"
	"github.com/anywaye/identity/internal/recovery"
)


var allPurposes = []recovery.Purpose{
	recovery.PurposePasswordReset,
	recovery.PurposeVerifyEmail,
	recovery.PurposeEmailChange,
	recovery.PurposeSessionLink,
}

func deploymentEnv(overrides map[string]string) map[string]string {
	env := map[string]string{
		"COURIER_BASE_URL":                 "https://courier.example.com",
		"COURIER_TOKEN":                    "svc-4b1d7e0a3c95f28",
		"PASSWORD_RESET_LINK_TEMPLATE":     "https://app.example.com/reset?token={token}",
		"EMAIL_VERIFICATION_LINK_TEMPLATE": "https://app.example.com/verify-email?token={token}",
		"INVITATION_LINK_TEMPLATE":         "https://app.example.com/invitations/accept?token={token}",
		"EMAIL_CHANGE_LINK_TEMPLATE":       "https://app.example.com/confirm-change?token={token}",
		"SIGNUP_SIGNING_KEY": base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	}
	for key, value := range overrides {
		if value == "" {
			delete(env, key)
			continue
		}
		env[key] = value
	}
	return env
}

func configLookup(env map[string]string) config.Lookup {
	return func(key string) (string, bool) {
		value, present := env[key]
		return value, present
	}
}

func mailerFromEnv(t *testing.T, env map[string]string, baseURL string) *RecoveryMailer {
	t.Helper()

	cfg, err := config.Load(configLookup(env))
	if err != nil {
		t.Fatalf("config.Load on a deployment that says where each link goes: %v", err)
	}
	if !cfg.CourierEnabled() {
		t.Fatal("the deployment reported no mail path, so nothing below could be proven")
	}

	mailer, err := NewRecoveryMailer(RecoveryMailerConfig{
		Client:        newTestClient(t, baseURL, cfg.CourierTokenValue),
		LinkTemplates: cfg.LinkTemplates,
	})
	if err != nil {
		t.Fatalf("NewRecoveryMailer: %v", err)
	}
	return mailer
}

func TestAVerificationLinkIsNotThePasswordResetLinkAndEachRedeemsAtItsOwnEndpoint(t *testing.T) {
	stub := newCourierStub(t)
	mailer := mailerFromEnv(t, deploymentEnv(nil), stub.server.URL)
	flow := newRecoveryFlow(t, mailer)

	ctx := context.Background()
	if err := flow.svc.RequestPasswordReset(ctx, flow.who.email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := flow.svc.RequestVerification(ctx, flow.who.email); err != nil {
		t.Fatalf("RequestVerification: %v", err)
	}

	if len(stub.sent) != 2 {
		t.Fatalf("courier saw %d requests, want 2 (one reset, one verification)", len(stub.sent))
	}
	resetLink := stringOf(stub.sent[0].Body["url"])
	verifyLink := stringOf(stub.sent[1].Body["url"])

	resetPath := pathOf(t, resetLink)
	verifyPath := pathOf(t, verifyLink)
	if resetPath == verifyPath {
		t.Fatalf("both messages carried a link to %s. The deployment configured a "+
			"verification link separately and it was not used, so a verification mail "+
			"lands the reader on the reset screen, where a verification token answers 404.",
			resetPath)
	}
	if verifyPath != "/verify-email" {
		t.Errorf("the verification link is %q, want the configured %q", verifyPath, "/verify-email")
	}
	if resetPath != "/reset" {
		t.Errorf("the reset link is %q, want the configured %q", resetPath, "/reset")
	}

	resetToken := tokenIn(t, resetLink)
	verifyToken := tokenIn(t, verifyLink)
	if resetToken == verifyToken {
		t.Fatal("the reset and the verification link carry the same token")
	}
	if strings.Contains(resetLink, verifyToken) || strings.Contains(verifyLink, resetToken) {
		t.Error("one purpose's link carries the other purpose's token")
	}

	if _, err := flow.svc.RedeemPasswordReset(ctx, recovery.RedeemPasswordResetInput{
		Token: verifyToken, Password: "correct-horse-battery-staple",
	}); !isError(err, recovery.ErrTokenNotFound) {
		t.Errorf("the reset endpoint on a VERIFICATION token = %v, want ErrTokenNotFound; a "+
			"verification link that could change a password is a takeover", err)
	}
	if err := flow.svc.RedeemVerification(ctx,
		recovery.RedeemVerificationInput{Token: resetToken}); !isError(err, recovery.ErrTokenNotFound) {
		t.Errorf("the verification endpoint on a RESET token = %v, want ErrTokenNotFound", err)
	}

	if err := flow.svc.RedeemVerification(ctx,
		recovery.RedeemVerificationInput{Token: verifyToken}); err != nil {
		t.Errorf("the verification token from the verification link was refused: %v", err)
	}
	if _, err := flow.svc.RedeemPasswordReset(ctx, recovery.RedeemPasswordResetInput{
		Token: resetToken, Password: "correct-horse-battery-staple-2",
	}); err != nil {
		t.Errorf("the reset token from the reset link was refused: %v", err)
	}
}

func TestOneTemplateForBothPurposesRendersOneLinkForBothMessages(t *testing.T) {
	const legacy = "https://app.example.com/reset?token={token}"

	env := deploymentEnv(map[string]string{
		"PASSWORD_RESET_LINK_TEMPLATE":     "",
		"EMAIL_VERIFICATION_LINK_TEMPLATE": "",
		"RECOVERY_LINK_TEMPLATE":           legacy,
	})

	stub := newCourierStub(t)
	flow := newRecoveryFlow(t, mailerFromEnv(t, env, stub.server.URL))

	ctx := context.Background()
	if err := flow.svc.RequestPasswordReset(ctx, flow.who.email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := flow.svc.RequestVerification(ctx, flow.who.email); err != nil {
		t.Fatalf("RequestVerification: %v", err)
	}
	if len(stub.sent) != 2 {
		t.Fatalf("courier saw %d requests, want 2", len(stub.sent))
	}

	resetLink := stringOf(stub.sent[0].Body["url"])
	verifyLink := stringOf(stub.sent[1].Body["url"])
	if got, want := withoutToken(resetLink), withoutToken(verifyLink); got != want {
		t.Errorf("with one RECOVERY_LINK_TEMPLATE the two purposes rendered from different "+
			"templates (%q and %q), so the default is not the default", got, want)
	}
	if pathOf(t, resetLink) != pathOf(t, verifyLink) {
		t.Errorf("with one RECOVERY_LINK_TEMPLATE the two purposes rendered links to %q and "+
			"%q, so the default is not the default", pathOf(t, resetLink), pathOf(t, verifyLink))
	}

	resetToken := tokenIn(t, resetLink)
	verifyToken := tokenIn(t, verifyLink)
	if resetToken == verifyToken {
		t.Error("the two links carry the same token, so the flows minted one credential between them")
	}
	if err := flow.svc.RedeemVerification(ctx,
		recovery.RedeemVerificationInput{Token: verifyToken}); err != nil {
		t.Errorf("the verification token from the legacy link was refused: %v", err)
	}
	if _, err := flow.svc.RedeemPasswordReset(ctx, recovery.RedeemPasswordResetInput{
		Token: resetToken, Password: "correct-horse-battery-staple-3",
	}); err != nil {
		t.Errorf("the reset token from the legacy link was refused: %v", err)
	}
}

func TestEveryPurposeThisAdapterCanDeliverHasAVariableToConfigureItsLink(t *testing.T) {
	for subject, purpose := range linkPurposeFor {
		if _, ok := config.LinkTemplateVariable(purpose); !ok {
			t.Errorf("%q is deliverable and needs a %s link, but no environment variable "+
				"configures one; a deployment would have no way to say where that link "+
				"points", subject, purpose)
		}
	}

	for _, purpose := range allPurposes {
		deliverable := false
		for _, deliverablePurpose := range linkPurposeFor {
			if deliverablePurpose == purpose {
				deliverable = true
			}
		}
		if deliverable {
			continue
		}
		if variable, ok := config.LinkTemplateVariable(purpose); ok {
			t.Errorf("config declares %s for the %q purpose, which this adapter cannot "+
				"deliver; a variable an operator sets and nothing honors is a promise "+
				"this service does not keep", variable, purpose)
		}
	}

	_, err := NewRecoveryMailer(RecoveryMailerConfig{
		Client: newTestClient(t, "https://courier.example.com", "svc-4b1d7e0a3c95f28"),
		LinkTemplates: map[recovery.Purpose]string{
			recovery.PurposePasswordReset: "https://app.example.com/reset?token={token}",
			recovery.PurposeVerifyEmail:   "https://app.example.com/verify-email?token={token}",
			recovery.PurposeEmailChange:   "https://app.example.com/confirm-change?token={token}",
			recovery.PurposeSessionLink:   "https://app.example.com/relay?token={token}",
		},
	})
	if err == nil {
		t.Fatal("a link template for the session link was accepted, and no message this " +
			"adapter can deliver carries it; the setting would be honored nowhere")
	}
	if !strings.Contains(err.Error(), string(recovery.PurposeSessionLink)) {
		t.Errorf("the refusal does not name the purpose it is about: %v", err)
	}
}

func TestTheConstructorRefusesAPurposeWithNoLinkTemplate(t *testing.T) {
	cases := []struct {
		name string
		templates map[recovery.Purpose]string
		wantNamed recovery.Purpose
	}{
		{
			name: "no template for the password reset",
			templates: map[recovery.Purpose]string{
				recovery.PurposeVerifyEmail: "https://app.example.com/verify-email?token={token}",
				recovery.PurposeEmailChange: "https://app.example.com/confirm-change?token={token}",
			},
			wantNamed: recovery.PurposePasswordReset,
		},
		{
			name: "no template for the verification",
			templates: map[recovery.Purpose]string{
				recovery.PurposePasswordReset: "https://app.example.com/reset?token={token}",
				recovery.PurposeEmailChange:   "https://app.example.com/confirm-change?token={token}",
			},
			wantNamed: recovery.PurposeVerifyEmail,
		},
		{
			name: "no template for the email change",
			templates: map[recovery.Purpose]string{
				recovery.PurposePasswordReset: "https://app.example.com/reset?token={token}",
				recovery.PurposeVerifyEmail:   "https://app.example.com/verify-email?token={token}",
			},
			wantNamed: recovery.PurposeEmailChange,
		},
		{
			name:      "no template for any of them",
			templates: map[recovery.Purpose]string{},
			wantNamed: recovery.PurposeEmailChange,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRecoveryMailer(RecoveryMailerConfig{
				Client:        newTestClient(t, "https://courier.example.com", "svc-4b1d7e0a3c95f28"),
				LinkTemplates: tc.templates,
			})
			if err == nil {
				t.Fatal("a mailer was built with a purpose that has no link; every message " +
					"of that purpose would carry a link to nowhere")
			}
			if !strings.Contains(err.Error(), string(tc.wantNamed)) {
				t.Errorf("the refusal does not name the %s purpose: %v", tc.wantNamed, err)
			}
		})
	}
}

func TestEachPurposesLinkTemplateIsHeldToTheSameThreeRefusals(t *testing.T) {
	refusals := []struct {
		name     string
		template string
	}{
		{name: "no placeholder", template: "https://app.example.com/reset"},
		{name: "relative", template: "/reset?token={token}"},
		{name: "a fragment a mail client would not send", template: "https://app.example.com/reset#/{token}"},
		{name: "a userinfo section", template: "https://kaka:pw@app.example.com/reset?token={token}"},
		{name: "a scheme courier's schema rejects", template: "javascript:alert({token})"},
		{name: "empty", template: ""},
	}

	accepted := map[recovery.Purpose]string{
		recovery.PurposePasswordReset: "https://app.example.com/reset?token={token}",
		recovery.PurposeVerifyEmail:   "https://app.example.com/verify-email?token={token}",
		recovery.PurposeEmailChange:   "https://app.example.com/confirm-change?token={token}",
	}

	purposes := make([]recovery.Purpose, 0, len(linkPurposeFor))
	for _, purpose := range linkPurposeFor {
		purposes = append(purposes, purpose)
	}
	if len(purposes) != 3 {
		t.Fatalf("%d purposes have a link, want 3 (password reset, address verification "+
			"and the current-address half of an email change); the new-address half is "+
			"courier's one message with no link and must not grow a template here",
			len(purposes))
	}

	for _, purpose := range purposes {
		t.Run(string(purpose), func(t *testing.T) {
			if _, err := NewRecoveryMailer(RecoveryMailerConfig{
				Client: newTestClient(t, "https://courier.example.com", "svc-4b1d7e0a3c95f28"),
				LinkTemplates: map[recovery.Purpose]string{
					recovery.PurposePasswordReset: accepted[recovery.PurposePasswordReset],
					recovery.PurposeVerifyEmail:   accepted[recovery.PurposeVerifyEmail],
					recovery.PurposeEmailChange:   accepted[recovery.PurposeEmailChange],
				},
			}); err != nil {
				t.Fatalf("a working configuration was refused: %v", err)
			}

			for _, tc := range refusals {
				t.Run(tc.name, func(t *testing.T) {
					templates := map[recovery.Purpose]string{purpose: tc.template}
					for _, other := range allPurposes {
						if other == purpose {
							continue
						}
						if working, ok := accepted[other]; ok {
							templates[other] = working
						}
					}
					_, err := NewRecoveryMailer(RecoveryMailerConfig{
						Client:        newTestClient(t, "https://courier.example.com", "svc-4b1d7e0a3c95f28"),
						LinkTemplates: templates,
					})
					if err == nil {
						t.Fatalf("the %s link template %q was accepted", purpose, tc.template)
					}
					if !strings.Contains(err.Error(), string(purpose)) {
						t.Errorf("the refusal does not name the %s purpose: %v", purpose, err)
					}
				})
			}
		})
	}
}

func TestEveryRecoverableMessageHasALinkPurposeAndOneDoesNot(t *testing.T) {
	noLinkPurpose := ""
	for subject := range courierTypeFor {
		if _, present := linkPurposeFor[subject]; !present {
			if noLinkPurpose != "" {
				t.Errorf("%q and %q are both deliverable with no link purpose; the "+
					"new-address half is the only message courier's template renders "+
					"no link for", noLinkPurpose, subject)
			}
			noLinkPurpose = subject
		}
	}
	if noLinkPurpose != kindChangeNew {
		t.Errorf("the one deliverable message with no link purpose is %q, want %q — "+
			"courier's email_change_new template renders the previous address and "+
			"nothing else, so any other message delivered without a link would be a "+
			"mail nobody can use", noLinkPurpose, kindChangeNew)
	}
	for subject := range linkPurposeFor {
		if _, deliverable := courierTypeFor[subject]; !deliverable {
			t.Errorf("%q has a link purpose but no courier type, so a deployment "+
				"configuring a template for it would be refused at boot for a message "+
				"that is never sent", subject)
		}
	}
	if len(courierTypeFor)-len(linkPurposeFor) != 1 {
		t.Errorf("courierTypeFor has %d entries and linkPurposeFor has %d; the "+
			"difference must be exactly the new-address half",
			len(courierTypeFor), len(linkPurposeFor))
	}
}

func pathOf(t *testing.T, link string) string {
	t.Helper()
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("the rendered link %q is not a URL: %v", link, err)
	}
	if parsed.Path == "" {
		t.Errorf("the rendered link %q has no path, so it has no screen to point at", link)
	}
	return parsed.Path
}

func withoutToken(link string) string {
	parsed, err := url.Parse(link)
	if err != nil {
		return link
	}
	query := parsed.Query()
	if query.Has("token") {
		query.Set("token", TokenPlaceholder)
		parsed.RawQuery = query.Encode()
	}
	return parsed.String()
}

func tokenIn(t *testing.T, link string) string {
	t.Helper()
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("the rendered link %q is not a URL: %v", link, err)
	}
	token := parsed.Query().Get("token")
	if token == "" {
		t.Fatalf("the rendered link %q carries no token; a link with nothing in it is a "+
			"mail a user can follow and cannot use", link)
	}
	return token
}
