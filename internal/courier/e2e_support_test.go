package courier

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/recovery"
)


const (
	courierURLVariable = "TEST_COURIER_URL"

	courierTokenVariable = "TEST_COURIER_TOKEN"
)

func TestAPasswordResetGoesOutThroughARealCourier(t *testing.T) {
	live := requireLiveCourier(t)

	const recipient = "identity-e2e@example.com"
	token := liveToken(t)

	message := resetMessageFor(recipient, token)
	message.UserID = testUserID

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := live.mailer.client.SendMessage(ctx, MessageRequest{
		Type:   TypePasswordReset,
		UserID: message.UserID.String(),
		To:     recipient,
		URL:    renderTestLink(t, recovery.PurposePasswordReset, token),
	})
	if err != nil {
		t.Fatalf("a real courier refused a password reset identity can compose: %v", err)
	}

	if result.Status != StatusAccepted {
		t.Errorf("Status = %q, want %q", result.Status, StatusAccepted)
	}
	if result.Type != TypePasswordReset {
		t.Errorf("Type = %q, want %q", result.Type, TypePasswordReset)
	}
	if result.MessageID == "" {
		t.Error("MessageID is empty; a bounce quoting it would tie back to nothing")
	}
	if result.EventID == "" {
		t.Error("EventID is empty; it is the outbox row every bus subscriber sees")
	}
	if result.UserID != message.UserID.String() {
		t.Errorf("UserID = %q, want the one sent (%q)", result.UserID, message.UserID)
	}
	if !strings.HasPrefix(result.MessageID, "courier-") {
		t.Errorf("MessageID = %q, want courier's own id shape", result.MessageID)
	}

	if err := live.mailer.Send(ctx, message); err != nil {
		t.Fatalf("RecoveryMailer.Send against a real courier: %v", err)
	}
}

func TestAVerificationLinkReachesCouriersWelcomeTemplate(t *testing.T) {
	live := requireLiveCourier(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := live.mailer.client.SendMessage(ctx, MessageRequest{
		Type:   TypeWelcome,
		UserID: "7e8f9a0b-1c2d-4e3f-9a4b-5c6d7e8f9a0b",
		To:     "identity-e2e-welcome@example.com",
		URL:    renderTestLink(t, recovery.PurposeVerifyEmail, liveToken(t)),
	})
	if err != nil {
		t.Fatalf("a real courier refused a verification welcome: %v", err)
	}
	if result.Type != TypeWelcome {
		t.Errorf("notification_type = %q, want %q", result.Type, TypeWelcome)
	}
	if result.Status != StatusAccepted {
		t.Errorf("Status = %q, want %q", result.Status, StatusAccepted)
	}
	if result.MessageID == "" {
		t.Error("MessageID is empty")
	}
}

func TestTheTwoEmailChangeMessagesReachARealCourier(t *testing.T) {
	live := requireLiveCourier(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cases := []struct {
		name    string
		message recovery.Message
	}{
		{name: "the current-address half of an email change", message: changeCurrentMessage(liveToken(t))},
		{name: "the new-address half of an email change", message: changeNewMessage(liveToken(t))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.message.UserID = testUserID
			if err := live.mailer.Send(ctx, tc.message); err != nil {
				t.Fatalf("a real courier refused an email-change message identity can "+
					"compose: %v", err)
			}
		})
	}
}

func TestAnInvitationGoesOutThroughARealCourier(t *testing.T) {
	live := requireLiveCourier(t)

	const recipient = "identity-invite-e2e@example.com"
	token := liveToken(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := live.invitationMailer.client.SendMessage(ctx, MessageRequest{
		Type:        TypeTeamInvitation,
		UserID:      testUserID.String(),
		To:          recipient,
		URL:         renderInvitationTestLink(t, token),
		AccountName: "Acme Corporation",
		InvitedBy:   "Kaka",
		Role:        "member",
	})
	if err != nil {
		t.Fatalf("a real courier refused a team_invitation identity can compose: %v", err)
	}
	if result.Status != StatusAccepted {
		t.Errorf("Status = %q, want %q", result.Status, StatusAccepted)
	}
	if result.Type != TypeTeamInvitation {
		t.Errorf("Type = %q, want %q", result.Type, TypeTeamInvitation)
	}
	if result.MessageID == "" {
		t.Error("MessageID is empty; a bounce quoting it would tie back to nothing")
	}
	if result.EventID == "" {
		t.Error("EventID is empty; it is the outbox row every bus subscriber sees")
	}
	if result.UserID != testUserID.String() {
		t.Errorf("UserID = %q, want the invitation's id %q — an invitee has no user, "+
			"and the invitation's id is what the send's idempotency is derived from",
			result.UserID, testUserID)
	}

	invitation := accounts.OutgoingInvitation{
		ID:          id.MustNew(),
		Email:       recipient,
		Token:       token,
		AccountName: "Acme Corporation",
		InvitedBy:   "Kaka",
		Role:        "member",
	}
	if err := live.invitationMailer.SendInvitation(ctx, invitation); err != nil {
		t.Fatalf("InvitationMailer.Send against a real courier: %v", err)
	}
}

func renderInvitationTestLink(t *testing.T, token string) string {
	t.Helper()
	rendered, err := LinkTemplate(invitationLinkTemplate).render(token)
	if err != nil {
		t.Fatalf("rendering the invitation link: %v", err)
	}
	return rendered
}


type liveCourier struct {
	mailer *RecoveryMailer

	invitationMailer *InvitationMailer
}

func requireLiveCourier(t *testing.T) *liveCourier {
	t.Helper()

	raw, present := os.LookupEnv(courierURLVariable)
	if !present || strings.TrimSpace(raw) == "" {
		skipWithoutCourier(t)
	}
	token, present := os.LookupEnv(courierTokenVariable)
	if !present || token == "" {
		t.Fatalf("%s is not set while %s is, so the courier is pointed at and cannot be "+
			"authenticated to. The value is never printed; set it to the service "+
			"credential your courier accepts.", courierTokenVariable, courierURLVariable)
	}

	client, err := New(Config{
		BaseURL: raw,
		Token:   token,
		Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatalf("building a client for %s: %v", courierURLVariable, err)
	}
	mailer, err := NewRecoveryMailer(RecoveryMailerConfig{
		Client:        client,
		LinkTemplates: testLinkTemplates(),
	})
	if err != nil {
		t.Fatalf("NewRecoveryMailer: %v", err)
	}
	invitationMailer, err := NewInvitationMailer(InvitationMailerConfig{
		Client:       client,
		LinkTemplate: invitationLinkTemplate,
	})
	if err != nil {
		t.Fatalf("NewInvitationMailer: %v", err)
	}

	probe, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.Ready(probe); err != nil {
		t.Fatalf("the courier at %s is not ready: %v", courierURLVariable, err)
	}

	return &liveCourier{mailer: mailer, invitationMailer: invitationMailer}
}

func skipWithoutCourier(t *testing.T) {
	t.Helper()

	t.Skipf("SKIPPED A LIVE-PROOF, NOT A BEHAVIOR: %s is not set, so this test could not "+
		"prove that a message identity rendered by internal/recovery traverses courier's own "+
		"validation and comes back accepted.\n"+
		"  Every other property of this integration IS asserted offline: the request identity "+
		"and its stable Idempotency-Key in wiring_test.go, courier's request contract in "+
		"client_test.go, and courier's byte-for-byte recorded answers in recorded_test.go. "+
		"What is left for this file is the one claim a fixture cannot make about itself.\n"+
		"  TO RUN IT: start a courier with its own principal resolver and provider — the "+
		"script is at the bottom of %s — then:\n"+
		"    TEST_COURIER_URL=http://127.0.0.1:4014 TEST_COURIER_TOKEN=\"$(openssl rand -hex 16)\" "+
		"go test ./internal/courier/ -v\n"+
		"  (%s is the service credential that courier accepts. Both are needed: a URL with no "+
		"token is a skip above and a token with no URL is nothing at all.)",
		courierURLVariable, "internal/courier/e2e_support_test.go", courierTokenVariable)
}

func TestTheDatabaseTierActuallyRan(t *testing.T) {
	if os.Getenv(dbtest.EnvVar) == "" {
		t.Fatalf("%s is not set, so every database test in this package skipped. The courier "+
			"tier in this file skipping for want of a courier is a different case and has its "+
			"own reason above; this one is not it. Run `goose -dir migrations postgres "+
			"\"$DATABASE_URL\" up` and then `TEST_DATABASE_URL=\"$DATABASE_URL\" go test ./...`; "+
			"see README.md, Testing.", dbtest.EnvVar)
	}
}

func liveToken(t *testing.T) string {
	t.Helper()
	token, err := newUUIDv4()
	if err != nil {
		t.Fatalf("minting a token: %v", err)
	}
	return strings.ReplaceAll(token, "-", "")
}

func renderTestLink(t *testing.T, purpose recovery.Purpose, token string) string {
	t.Helper()
	template, present := testLinkTemplates()[purpose]
	if !present {
		t.Fatalf("the fixtures configure no link template for the %s purpose", purpose)
	}
	rendered, err := LinkTemplate(template).render(token)
	if err != nil {
		t.Fatalf("rendering the %s link: %v", purpose, err)
	}
	return rendered
}

