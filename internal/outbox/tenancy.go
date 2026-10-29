package outbox

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


const (
	EventAccountCreated = "identity.account.created"

	EventMemberInvited = "identity.member.invited"

	EventMemberAccepted = "identity.member.accepted"

	EventMemberRoleChanged = "identity.member.role_changed"

	EventAccountOwnershipTransferred = "identity.account.ownership_transferred"

	EventMemberRemoved = "identity.member.removed"
)

// NewAccountCreated builds the event emitted when an account is provisioned.
//
// It fires twice in the life of a user who signs up: once for the personal
// account the registration creates, and once for every team account they make
// afterwards. Both are the same fact — an account now exists and this user owns
// it — and a consumer that wants to tell them apart reads data.personal.
func NewAccountCreated(now time.Time, accountID id.UUID, name, slug string, personal bool, ownerID id.UUID) (Envelope, error) {
	return newTenancyEvent(now, EventAccountCreated, accountID, struct {
		AccountID string `json:"account_id"`
		Name      string `json:"name"`
		Slug      string `json:"slug"`
		Personal  bool   `json:"personal"`
		OwnerID   string `json:"owner_id"`
	}{
		AccountID: accountID.String(),
		Name:      name,
		Slug:      slug,
		Personal:  personal,
		OwnerID:   ownerID.String(),
	})
}

// NewMemberInvited builds the event emitted when an invitation is created.
//
// The email and the acceptance token are in the payload because a consumer that
// mails the invitation needs both and there is no other way to get them: this
// service does not send mail, and the fleet's consumer is cross-service —
// courier has no identity client, no identity credentials and no identity
// tables, so neither field is a fact it can read from the user row or re-read
// from a store (REPORT-courier-consumer-invite-01 §2.6, where the two
// lookups and the token re-read were each refused, and the refusals recorded as
// decisions rather than worked around).
//
// WHAT TRAVELS IS THE TOKEN AND NOT A URL, and that is the manager decision
// recorded in REPORT-courier-consumer-invite-01 §2.4: the token-in-a-mail is
// the same credential class as the reset links identity already mails, courier
// re-reading the token was refused three times and stays refused, and a
// redeem-by-id route is a bigger design than the packet that asked for this.
// Composing the accept URL is the consumer's job: no base configuration for the
// acceptance screen exists in this service (identity renders no HTML, and the
// recovery flow's per-purpose link templates have no invitation purpose), so
// the platform's accept route is not courier's to know.
func NewMemberInvited(now time.Time, accountID, invitationID id.UUID, email, token, role string, inviterID id.UUID) (Envelope, error) {
	if token == "" {
		return Envelope{}, fmt.Errorf("outbox: refusing to build an %s payload with no acceptance token", EventMemberInvited)
	}
	return newTenancyEvent(now, EventMemberInvited, accountID, struct {
		AccountID       string `json:"account_id"`
		InvitationID    string `json:"invitation_id"`
		Email           string `json:"email"`
		AcceptanceToken string `json:"acceptance_token"`
		Role            string `json:"role"`
		InvitedByID     string `json:"invited_by_id"`
	}{
		AccountID:       accountID.String(),
		InvitationID:    invitationID.String(),
		Email:           email,
		AcceptanceToken: token,
		Role:            role,
		InvitedByID:     inviterID.String(),
	})
}

// NewMemberAccepted builds the event emitted when an invitation is redeemed.
//
// It is emitted in the same transaction as the membership it describes. An
// event without a membership announces somebody joined who did not, and a
// membership without the event leaves a consumer's member list permanently one
// short with no way to notice.
//
// THE MEMBER'S ADDRESS TRAVELS because the "welcome to the account" mail goes to
// them and the consumer is cross-service: courier has no identity client and no
// identity tables, so the address is not a fact it can read from the user row
// (REPORT-courier-consumer-invite-01 §2.6). It is the MEMBER's address — the
// registered user who redeemed the token — and not the address the invitation
// was sent to: the token is not bound to an address, so the two are different
// facts and only one of them is the person who joined.
func NewMemberAccepted(now time.Time, accountID, userID id.UUID, email, role string) (Envelope, error) {
	if email == "" {
		return Envelope{}, fmt.Errorf("outbox: refusing to build an %s payload with no member address", EventMemberAccepted)
	}
	return newTenancyEvent(now, EventMemberAccepted, accountID, struct {
		AccountID string `json:"account_id"`
		UserID    string `json:"user_id"`
		Email     string `json:"email"`
		Role      string `json:"role"`
	}{
		AccountID: accountID.String(),
		UserID:    userID.String(),
		Email:     email,
		Role:      role,
	})
}

// NewMemberRoleChanged builds the event emitted when a role is granted or
// revoked.
//
// Both roles are in the payload. One of them is not enough in either direction:
// the old role is what a consumer needs to revoke what it previously granted,
// and the new role is what it needs to grant. A consumer that only receives the
// new role has to remember the old one, and a consumer that forgot is the bug
// this is here to prevent.
func NewMemberRoleChanged(now time.Time, accountID, userID id.UUID, previous, current string) (Envelope, error) {
	return newTenancyEvent(now, EventMemberRoleChanged, accountID, struct {
		AccountID    string `json:"account_id"`
		UserID       string `json:"user_id"`
		PreviousRole string `json:"previous_role"`
		Role         string `json:"role"`
	}{
		AccountID:    accountID.String(),
		UserID:       userID.String(),
		PreviousRole: previous,
		Role:         current,
	})
}

// NewMemberRemoved builds the event emitted when a member is removed.
//
// The role they held travels with it. "user X was removed from account Y" tells
// a downstream service very little; "user X, who was an owner, is no longer an
// owner of account Y" tells it whether to re-check its own authorization cache.
func NewMemberRemoved(now time.Time, accountID, userID id.UUID, role string) (Envelope, error) {
	return newTenancyEvent(now, EventMemberRemoved, accountID, struct {
		AccountID string `json:"account_id"`
		UserID    string `json:"user_id"`
		Role      string `json:"role"`
	}{
		AccountID: accountID.String(),
		UserID:    userID.String(),
		Role:      role,
	})
}

// NewAccountOwnershipTransferred builds the event emitted when an account
// changes hands.
//
// BOTH sides are in the payload and neither is derivable from the other, which
// is the property that makes this one event rather than two: `new_owner_id` is
// the heir and `previous_owner_id` is the account's owner before this, and a
// consumer keeping its own member list up to date needs both — it has to promote
// one and demote the other, and which is which is not a thing it can work out
// from the current list alone.
//
// Actor is the authenticated caller rather than the previous owner, and the two
// are separate fields for the same reason: every transfer an operator investigates
// is either "the owner did this" or "somebody with a stolen session did this",
// and an event that cannot tell them apart answers neither question.
func NewAccountOwnershipTransferred(now time.Time, accountID, previousOwnerID, newOwnerID, actorID id.UUID) (Envelope, error) {
	return newTenancyEvent(now, EventAccountOwnershipTransferred, accountID, struct {
		AccountID       string `json:"account_id"`
		PreviousOwnerID string `json:"previous_owner_id"`
		NewOwnerID      string `json:"new_owner_id"`
		TransferredByID string `json:"transferred_by_id"`
	}{
		AccountID:       accountID.String(),
		PreviousOwnerID: previousOwnerID.String(),
		NewOwnerID:      newOwnerID.String(),
		TransferredByID: actorID.String(),
	})
}

func newTenancyEvent(now time.Time, eventType string, accountID id.UUID, payload any) (Envelope, error) {
	return newSubjectEvent(now, eventType, accountID.String(), payload)
}

func newSubjectEvent(now time.Time, eventType, subject string, payload any) (Envelope, error) {
	eventID, err := id.New()
	if err != nil {
		return Envelope{}, fmt.Errorf("outbox: minting an envelope id: %w", err)
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("outbox: building the %s payload: %w", eventType, err)
	}

	return Envelope{
		SpecVersion: SpecVersion,
		ID:          eventID,
		Type:        eventType,
		Source:      SourceIdentity,
		Subject:     subject,
		Time:        now.UTC(),
		Data:        data,
	}, nil
}
