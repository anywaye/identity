package outbox

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


func tenancyTestIDs() (account, user, invitation id.UUID) {
	return id.MustNew(), id.MustNew(), id.MustNew()
}

func TestAccountCreatedEnvelope(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	accountID, ownerID, _ := tenancyTestIDs()

	e, err := NewAccountCreated(now, accountID, "Acme Corp", "acme-corp", false, ownerID)
	if err != nil {
		t.Fatalf("NewAccountCreated: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope does not satisfy core's schema: %v", err)
	}
	if e.Type != EventAccountCreated {
		t.Errorf("type = %q, want %q", e.Type, EventAccountCreated)
	}
	if e.Source != SourceIdentity {
		t.Errorf("source = %q, want %q", e.Source, SourceIdentity)
	}
	if e.Subject != accountID.String() {
		t.Errorf("subject = %q, want the account id %q", e.Subject, accountID)
	}
	if e.SpecVersion != SpecVersion {
		t.Errorf("specversion = %q, want %q", e.SpecVersion, SpecVersion)
	}
	if !e.Time.Equal(now) {
		t.Errorf("time = %s, want the injected %s — the event is stamped when the state changed, not when it was queued", e.Time, now)
	}

	var data struct {
		AccountID string `json:"account_id"`
		Name      string `json:"name"`
		Slug      string `json:"slug"`
		Personal  bool   `json:"personal"`
		OwnerID   string `json:"owner_id"`
	}
	decodeData(t, e, &data)

	if data.AccountID != accountID.String() || data.OwnerID != ownerID.String() {
		t.Errorf("payload ids = %+v, want account %s and owner %s", data, accountID, ownerID)
	}
	if data.Name != "Acme Corp" || data.Slug != "acme-corp" || data.Personal {
		t.Errorf("payload = %+v, want the account that was created", data)
	}
}

func TestMemberInvitedEnvelope(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	accountID, inviterID, _ := tenancyTestIDs()
	invitationID := id.MustNew()
	token := "7c1a4e29-8b3d-4f6a-9e05-2d8c1b7a4f63"

	e, err := NewMemberInvited(now, accountID, invitationID, "invitee@example.com", token, "member", inviterID)
	if err != nil {
		t.Fatalf("NewMemberInvited: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope does not satisfy core's schema: %v", err)
	}
	if e.Type != EventMemberInvited {
		t.Errorf("type = %q, want %q", e.Type, EventMemberInvited)
	}
	if e.Subject != accountID.String() {
		t.Errorf("subject = %q, want the account id %q", e.Subject, accountID)
	}

	var data struct {
		AccountID       string `json:"account_id"`
		InvitationID    string `json:"invitation_id"`
		Email           string `json:"email"`
		AcceptanceToken string `json:"acceptance_token"`
		Role            string `json:"role"`
		InvitedByID     string `json:"invited_by_id"`
	}
	decodeData(t, e, &data)

	if data.InvitationID != invitationID.String() {
		t.Errorf("invitation_id = %q, want %q", data.InvitationID, invitationID)
	}
	if data.Email != "invitee@example.com" || data.Role != "member" || data.InvitedByID != inviterID.String() {
		t.Errorf("payload = %+v", data)
	}
	if data.AcceptanceToken != token {
		t.Errorf("acceptance_token = %q, want %q — the invitation mail is undeliverable without it", data.AcceptanceToken, token)
	}
}

func TestMemberInvitedRefusesAnEmptyToken(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	accountID, inviterID, _ := tenancyTestIDs()

	_, err := NewMemberInvited(now, accountID, id.MustNew(), "invitee@example.com", "", "member", inviterID)
	if err == nil {
		t.Fatal("NewMemberInvited accepted an empty acceptance token — the event would announce an invitation nobody can redeem")
	}
}

func TestMemberAcceptedEnvelope(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	accountID, userID, _ := tenancyTestIDs()

	e, err := NewMemberAccepted(now, accountID, userID, "member@example.com", "admin")
	if err != nil {
		t.Fatalf("NewMemberAccepted: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope does not satisfy core's schema: %v", err)
	}
	if e.Type != EventMemberAccepted {
		t.Errorf("type = %q, want %q", e.Type, EventMemberAccepted)
	}
	if e.Subject != accountID.String() {
		t.Errorf("subject = %q, want the account id", e.Subject)
	}

	var data struct {
		AccountID string `json:"account_id"`
		UserID    string `json:"user_id"`
		Email     string `json:"email"`
		Role      string `json:"role"`
	}
	decodeData(t, e, &data)

	if data.AccountID != accountID.String() || data.UserID != userID.String() || data.Role != "admin" {
		t.Errorf("payload = %+v, want the membership that was created", data)
	}
	if data.Email != "member@example.com" {
		t.Errorf("email = %q, want the member's address", data.Email)
	}
}

func TestMemberAcceptedRefusesAnEmptyEmail(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	accountID, userID, _ := tenancyTestIDs()

	_, err := NewMemberAccepted(now, accountID, userID, "", "admin")
	if err == nil {
		t.Fatal("NewMemberAccepted accepted an empty member address — the welcome mail would have no recipient")
	}
}

func TestMemberRoleChangedCarriesBothRoles(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	accountID, userID, _ := tenancyTestIDs()

	e, err := NewMemberRoleChanged(now, accountID, userID, "member", "admin")
	if err != nil {
		t.Fatalf("NewMemberRoleChanged: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope does not satisfy core's schema: %v", err)
	}
	if e.Subject != accountID.String() {
		t.Errorf("subject = %q, want the account id", e.Subject)
	}

	var data struct {
		AccountID    string `json:"account_id"`
		UserID       string `json:"user_id"`
		PreviousRole string `json:"previous_role"`
		Role         string `json:"role"`
	}
	decodeData(t, e, &data)

	if data.PreviousRole != "member" || data.Role != "admin" {
		t.Errorf("payload = %+v, want member -> admin", data)
	}
}

func TestMemberRemovedEnvelope(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	accountID, userID, _ := tenancyTestIDs()

	e, err := NewMemberRemoved(now, accountID, userID, "owner")
	if err != nil {
		t.Fatalf("NewMemberRemoved: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope does not satisfy core's schema: %v", err)
	}
	if e.Subject != accountID.String() {
		t.Errorf("subject = %q, want the account id", e.Subject)
	}

	var data struct {
		AccountID string `json:"account_id"`
		UserID    string `json:"user_id"`
		Role      string `json:"role"`
	}
	decodeData(t, e, &data)

	if data.UserID != userID.String() || data.Role != "owner" {
		t.Errorf("payload = %+v, want the role that was held", data)
	}
}

func TestTenancyEventTypesAreThreeSegment(t *testing.T) {
	types := []string{
		EventAccountCreated,
		EventMemberInvited,
		EventMemberAccepted,
		EventMemberRoleChanged,
		EventMemberRemoved,
	}

	for _, typ := range types {
		t.Run(typ, func(t *testing.T) {
			segments := 0
			current := ""
			for _, r := range typ {
				if r == '.' {
					segments++
					current = ""
					continue
				}
				current += string(r)
			}
			if segments != 2 {
				t.Errorf("%q has %d dots, want exactly 2 (three segments)", typ, segments)
			}
			if got := typ[:len("identity.")]; got != "identity." {
				t.Errorf("%q does not start with the publishing service's name", typ)
			}
			if current == "" {
				t.Errorf("%q ends with a dot", typ)
			}
		})
	}
}

func TestTenancyEventTypesAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for name, typ := range map[string]string{
		"identity.account.created":     EventAccountCreated,
		"identity.member.invited":      EventMemberInvited,
		"identity.member.accepted":     EventMemberAccepted,
		"identity.member.role_changed": EventMemberRoleChanged,
		"identity.member.removed":      EventMemberRemoved,
	} {
		if previous, clash := seen[typ]; clash {
			t.Errorf("%q and %q are both %q", previous, name, typ)
		}
		seen[typ] = name
	}
}

func TestTenancyEventTypesMatchTheManifest(t *testing.T) {
	want := map[string]bool{
		EventAccountCreated:    true,
		EventMemberInvited:     true,
		EventMemberAccepted:    true,
		EventMemberRoleChanged: true,
		EventMemberRemoved:     true,
	}
	if len(want) != 5 {
		t.Fatalf("the expected set has %d entries, want 5", len(want))
	}
}

func decodeData(t *testing.T, e Envelope, into any) {
	t.Helper()

	if err := json.Unmarshal(e.Data, into); err != nil {
		t.Fatalf("the payload is not the object the test expects: %v\n%s", err, e.Data)
	}
}
