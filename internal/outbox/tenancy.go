package outbox

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The tenancy events: an account came into being, somebody was invited, the
// invitation was accepted, a role moved, a member left.
//
// Every one of them has its subject set to the *account*, including the three
// that are obviously about a person. That is the decision core's "Why subject is
// required" section is about: subject is the entity the event is about and the
// value a consumer correlates per-entity ordering on. A membership change is
// about the account's member list — five members accepting five invitations is
// five events in one ordered stream, and a consumer that cared about the order
// of one person's memberships across accounts would correlate on the user id
// instead, which is a different question and gets a different event.
//
// The time is the moment of the state change, taken from the injected clock for
// the same reason NewUserCreated takes it: the event and the row it describes
// have to agree, and only one of the two is under test control.
//
// ROLES ARE STRINGS HERE, NOT accounts.Role.
//
// This package is transport: it knows the envelope and the payload schemas and
// nothing about the domain those payloads describe. Taking accounts.Role would
// make outbox import accounts, and accounts import outbox to append its events —
// a cycle that exists only because a role happens to be a string on the wire.
// The caller writes string(role), which is what goes into the JSON anyway, and
// the two packages stay independent: outbox is reusable by a service with no
// accounts in it, and accounts can change its role type without touching a
// published event's shape.

// The event types this service publishes for tenancy.
//
// The three-segment form is core's since v0.2 and the packet specifies it. Each
// is in core's catalog under these exact names except identity.member.accepted
// — see the note on that constant.
const (
	// EventAccountCreated is emitted when an account is provisioned — by
	// POST /v1/accounts, and by a registration creating its personal account.
	EventAccountCreated = "identity.account.created"

	// EventMemberInvited is emitted when an invitation is created. Its
	// data.invitation_id is the thing to act on (core's catalog).
	EventMemberInvited = "identity.member.invited"

	// EventMemberAccepted is emitted when an invitation is redeemed and the
	// membership is created.
	//
	// CORE DISAGREES WITH THIS NAME, AND THE MANAGER HAS TO RULE ON IT.
	//
	// core's docs/event-naming.md catalog has a row for this fact and calls it
	// `identity.member.joined` ("An invitation is accepted"), and `accepted` is
	// not in core's action vocabulary — the document says "Stick to this list for
	// v0; anything else is a manager decision".
	//
	// This service follows the packet for identity-04, which specifies
	// `identity.member.accepted` in its event list, for the same reason
	// identity-02 followed the packet for `identity.user.created`: the packet is
	// the manager's decision and the divergence is recorded rather than silently
	// resolved. The cost is that identity's cafaye.yml now advertises a type core's
	// catalog does not have, while core's catalog row has no publisher.
	//
	// Flipping it is this constant and the matching line in cafaye.yml. Nothing
	// else moves: the payload schema, the subject, and every consumer keyed on the
	// account id are unaffected.
	EventMemberAccepted = "identity.member.accepted"

	// EventMemberRoleChanged is emitted when a role is granted or revoked. The
	// payload carries the old and the new role, per core's catalog.
	EventMemberRoleChanged = "identity.member.role_changed"

	// EventAccountOwnershipTransferred is emitted when an account changes hands.
	//
	// IT IS ONE EVENT AND NOT TWO role_changed EVENTS, and that is the whole
	// reason this constant exists. A transfer changes two memberships at once —
	// the heir is promoted, the previous owner is demoted — and emitting those as
	// two `identity.member.role_changed` events would publish two independently
	// ordered facts about a single atomic change. A consumer that received them
	// could interleave either with any other event in the account's stream and
	// reconstruct a state that never existed: an account with two owners, or with
	// none. Both of those are exactly the states the transfer exists to prevent.
	//
	// So the event names BOTH sides — data.previous_owner_id and
	// data.new_owner_id — and a consumer applies it as the one thing it is.
	EventAccountOwnershipTransferred = "identity.account.ownership_transferred"

	// EventMemberRemoved is emitted when a member is removed. The payload carries
	// the role they held, because "who was removed" is not the question a
	// downstream service asks; "what could they do until now" is.
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

// newTenancyEvent is newSubjectEvent with the account as the subject, which is
// the rule for every event in this file: see the package comment's note on why a
// membership change is an event about the account.
func newTenancyEvent(now time.Time, eventType string, accountID id.UUID, payload any) (Envelope, error) {
	return newSubjectEvent(now, eventType, accountID.String(), payload)
}

// newSubjectEvent is the shared construction for every event this service
// publishes: a fresh envelope id, a subject, the injected time, and a payload
// marshaled from a struct.
//
// The struct-and-marshal is not ceremony. Concatenating these fields into a JSON
// string by hand is how a name containing a quote produces a payload that is not
// a JSON object, and Validate would then reject the event at the one place that
// could have caught it with a useful message.
//
// The subject is a parameter rather than derived, because the entity an event is
// about is not always the entity whose id the caller happens to have in hand:
// tenancy events are about the account, the OIDC events are about the client.
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
