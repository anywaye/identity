package courier


import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/platform/id"
)

func invitationFixture() accounts.OutgoingInvitation {
	return accounts.OutgoingInvitation{
		ID:          id.MustNew(),
		Email:       "teammate@example.com",
		Token:       "the-one-time-token",
		AccountName: "Acme Corporation",
		InvitedBy:   "Kaka",
		Role:        "member",
	}
}

func newInvitationMailer(t *testing.T, server *httptest.Server) *InvitationMailer {
	t.Helper()

	client := newTestClient(t, server.URL, "service-token-value")
	mailer, err := NewInvitationMailer(InvitationMailerConfig{
		Client:       client,
		LinkTemplate: "https://app.example.com/invitations/accept?token={token}",
	})
	if err != nil {
		t.Fatalf("NewInvitationMailer: %v", err)
	}
	return mailer
}

func TestInvitationMailerPutsCouriersRequestOnTheWire(t *testing.T) {
	server, seen := recordingCourier(t)
	mailer := newInvitationMailer(t, server)

	invitation := invitationFixture()
	if err := mailer.SendInvitation(context.Background(), invitation); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}

	if len(*seen) != 1 {
		t.Fatalf("courier saw %d requests, want 1", len(*seen))
	}
	sent := (*seen)[0]

	if sent.method != http.MethodPost {
		t.Errorf("method = %q, want POST", sent.method)
	}
	if sent.path != "/v1/messages" {
		t.Errorf("path = %q, want /v1/messages", sent.path)
	}

	body := sent.body
	if got := body["type"]; got != TypeTeamInvitation {
		t.Errorf("type = %v, want %q", got, TypeTeamInvitation)
	}
	if got := body["to"]; got != invitation.Email {
		t.Errorf("to = %v, want the invitee %q", got, invitation.Email)
	}
	if got := body["user_id"]; got != invitation.ID.String() {
		t.Errorf("user_id = %v, want the invitation's id %q — an invitee has no "+
			"user, because the invitation exists precisely because they have "+
			"not signed up", got, invitation.ID)
	}
	if got := body["account_name"]; got != invitation.AccountName {
		t.Errorf("account_name = %v, want %q", got, invitation.AccountName)
	}
	if got := body["invited_by"]; got != invitation.InvitedBy {
		t.Errorf("invited_by = %v, want %q", got, invitation.InvitedBy)
	}
	if got := body["role"]; got != invitation.Role {
		t.Errorf("role = %v, want %q", got, invitation.Role)
	}

	wantURL := "https://app.example.com/invitations/accept?token=" + invitation.Token
	if got := body["url"]; got != wantURL {
		t.Errorf("url = %v, want the rendered link %q", got, wantURL)
	}

	key := sent.header.Get("Idempotency-Key")
	if key == "" {
		t.Fatal("no Idempotency-Key on the wire; courier's :idempotent pipeline " +
			"scopes the key to the principal, so a keyless send cannot be deduplicated")
	}
	if !isUUID(key) {
		t.Errorf("Idempotency-Key = %q, which is not a uuid; courier answers 422 for one", key)
	}
	if strings.Contains(key, invitation.Token) {
		t.Error("the Idempotency-Key carries the invitation token, and a live " +
			"credential in somebody else's store is a credential the next reader can redeem")
	}
}

func TestOneInvitationSendCarriesOneStableKey(t *testing.T) {
	server, seen := recordingCourier(t)
	mailer := newInvitationMailer(t, server)

	invitation := invitationFixture()
	for range 2 {
		if err := mailer.SendInvitation(context.Background(), invitation); err != nil {
			t.Fatalf("SendInvitation: %v", err)
		}
	}

	if len(*seen) != 2 {
		t.Fatalf("courier saw %d requests, want 2 — the sends that reach courier "+
			"are what the key is for", len(*seen))
	}

	first, second := (*seen)[0], (*seen)[1]
	if first.header.Get("Idempotency-Key") != second.header.Get("Idempotency-Key") {
		t.Errorf("two sends of ONE invitation carried different keys, so a retried " +
			"send would be a second email in the invitee's inbox")
	}
	if !reflect.DeepEqual(first.body, second.body) {
		t.Errorf("the two sends of one invitation carried different bodies:\n%v\n%v",
			first.body, second.body)
	}
}

func TestInvitationMailerRefusesAnInvitationWithNoToken(t *testing.T) {
	server, seen := recordingCourier(t)
	mailer := newInvitationMailer(t, server)

	invitation := invitationFixture()
	invitation.Token = ""
	if err := mailer.SendInvitation(context.Background(), invitation); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("SendInvitation error = %v, want one matching ErrInvalidRequest", err)
	}
	if len(*seen) != 0 {
		t.Errorf("courier saw %d requests for an invitation with no token, want 0", len(*seen))
	}
}

func TestNewInvitationMailerRefusesATemplateThatCannotRenderALink(t *testing.T) {
	client := newTestClient(t, "https://courier.example.com", "service-token-value")

	for _, tc := range []struct {
		name     string
		template string
	}{
		{"no placeholder", "https://app.example.com/invitations/accept"},
		{"not a URL", "invitations/accept?token={token}"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewInvitationMailer(InvitationMailerConfig{
				Client:       client,
				LinkTemplate: tc.template,
			}); err == nil {
				t.Errorf("NewInvitationMailer accepted the template %q, which cannot "+
					"render a link a person can follow", tc.template)
			}
		})
	}
}
