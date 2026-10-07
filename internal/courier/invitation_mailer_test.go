package courier

// # THE INVITATION MAILER'S CONTRACT, PROVABLE WITHOUT A COURIER
//
// The same claim `wiring_test.go` makes for the recovery mailer, for the
// adapter identity's accounts.Service now calls: an invitation this service
// composes traverses THIS adapter and lands on the wire as a request
// courier's own validation accepts.
//
// # WHAT IS REAL AND WHAT IS NOT
//
//	REAL     the rendered link, the four required fields, the derived
//	         idempotency key, and the refusal of an invitation with no
//	         token — the parts under test.
//	STAND-IN courier is `recordingCourier`, the same refusing-nothing
//	         `httptest` server `wiring_test.go` uses, and it is the right way
//	         round: a stand-in that ENFORCED could falsify the request, which
//	         is a real risk here, and no stand-in can answer for courier.
//	         `e2e_support_test.go` covers the other direction — a live
//	         courier's answer to bytes this composes.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/platform/id"
)

// invitationFixture is one invitation waiting to be mailed.
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

// newInvitationMailer builds the mailer over a recording courier, the way
// `testMailer` builds the recovery one.
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

// TestInvitationMailerPutsCouriersRequestOnTheWire is the request IDENTITY:
// the fields courier reads before it does anything, and the link the invitee
// actually follows.
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

	// method and path: the one door into courier's send path.
	if sent.method != http.MethodPost {
		t.Errorf("method = %q, want POST", sent.method)
	}
	if sent.path != "/v1/messages" {
		t.Errorf("path = %q, want /v1/messages", sent.path)
	}

	// THE FOUR REQUIRED FIELDS, each filled from the invitation. courier's
	// team_invitation refuses a request missing any of them, and each is a
	// fact only this service holds: the account's name and the inviter's
	// name are not in courier's world at all.
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

	// THE LINK, rendered from the template with the one-time token in it —
	// the whole of what the mail is for.
	wantURL := "https://app.example.com/invitations/accept?token=" + invitation.Token
	if got := body["url"]; got != wantURL {
		t.Errorf("url = %v, want the rendered link %q", got, wantURL)
	}

	// THE IDEMPOTENCY KEY: derived, on the header, and carrying no token.
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

// TestOneInvitationSendCarriesOneStableKey is the property a retried send
// depends on, and it is a COMPOSITION rather than a unit for the reason
// `TestOneSendCarriesOneStableKey` gives: the derivation is asserted
// elsewhere, and this asserts the adapter DERIVES it AND SENDS it.
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
	// And the bodies must be identical too, or courier answers 409
	// `idempotency_key_reused` on the retry instead of replaying the first
	// response — which would turn the stable key into a second failure rather
	// than a second send.
	if !reflect.DeepEqual(first.body, second.body) {
		t.Errorf("the two sends of one invitation carried different bodies:\n%v\n%v",
			first.body, second.body)
	}
}

// TestInvitationMailerRefusesAnInvitationWithNoToken is the refusal that
// keeps a tokenless link from reaching a real inbox.
//
// IT IS UNREACHABLE through accounts, which mints the token — checked because
// the alternative is a mail whose button goes nowhere, and the reader has just
// been told it works.
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

// TestNewInvitationMailerRefusesATemplateThatCannotRenderALink holds the
// construction-time validation, for the reason NewRecoveryMailer's exists: a
// deployment with a template courier would reject is broken at boot rather
// than at a user's first invitation.
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
