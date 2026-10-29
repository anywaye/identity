package outbox

import (
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


const (
	EventOIDCClientCreated = "identity.oidc_client.created"

	EventOIDCClientRevoked = "identity.oidc_client.revoked"
)

// NewOIDCClientCreated builds the event emitted when a client is registered.
//
// The redirect URIs, the grant types and the scopes are all in the payload
// because the registration's whole content is "this credential may now be
// delivered to these origins, for these capabilities". A consumer auditing who
// holds a credential into a product cannot answer that from the bare fact that
// a client exists.
//
// There is no secret here, and no digest of one. The raw client secret exists
// exactly once, in the 201 response to whoever registered it; the row holds a
// SHA-256 digest, and a digest of a 256-bit random value is of no use to anyone.
// Every event on the platform reaches every subscriber, which is exactly the
// wrong place for a credential.
//
// rowID is the row's own uuid and the event's subject; clientID is the
// `client_id` string the relying party will present at the token endpoint. They
// are different values and conflating them is how a consumer ends up correlating
// on something it cannot look up.
func NewOIDCClientCreated(
	now time.Time,
	rowID, accountID id.UUID,
	clientID string,
	redirectURIs, grantTypes, scopes []string,
	registeredBy id.UUID,
) (Envelope, error) {
	return newSubjectEvent(now, EventOIDCClientCreated, rowID.String(), struct {
		ClientID     string   `json:"client_id"`
		AccountID    string   `json:"account_id"`
		RedirectURIs []string `json:"redirect_uris"`
		GrantTypes   []string `json:"grant_types"`
		Scopes       []string `json:"scopes"`
		RegisteredBy string   `json:"registered_by"`
	}{
		ClientID:     clientID,
		AccountID:    accountID.String(),
		RedirectURIs: redirectURIs,
		GrantTypes:   grantTypes,
		Scopes:       scopes,
		RegisteredBy: registeredBy.String(),
	})
}

// NewOIDCClientRevoked builds the event emitted when a registration is revoked.
//
// It carries no reason. A reason is operator-facing context typed by a human at
// a call site, it is not a fact about the credential, and a field whose values
// vary per operator is a field every consumer learns to ignore.
func NewOIDCClientRevoked(now time.Time, rowID, accountID id.UUID, clientID string, revokedBy id.UUID) (Envelope, error) {
	return newSubjectEvent(now, EventOIDCClientRevoked, rowID.String(), struct {
		ClientID  string `json:"client_id"`
		AccountID string `json:"account_id"`
		RevokedBy string `json:"revoked_by"`
	}{
		ClientID:  clientID,
		AccountID: accountID.String(),
		RevokedBy: revokedBy.String(),
	})
}
