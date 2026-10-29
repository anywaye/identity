package outbox

import (
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


const (
	EventMFAEnabled = "identity.mfa.enabled"

	EventMFADisabled = "identity.mfa.disabled"
)

// NewMFAEnabled builds the event emitted when a second factor goes live.
//
// THERE IS NO SECRET IN THIS PAYLOAD, and the omissions are the interesting part:
//
//   - no TOTP secret, and no `otpauth://` URI, which contains the secret and would
//     carry it to every subscriber on the platform
//   - no recovery code, and no digest of one
//   - no code, presented or expected
//
// Every event on the platform reaches every subscriber, which is exactly the wrong
// place for a credential. The same reasoning is in NewOIDCClientCreated, and it
// is the rule rather than a coincidence: the raw values exist once, in the
// response to whoever asked, and the rows hold digests.
func NewMFAEnabled(now time.Time, userID, credentialID id.UUID, method string) (Envelope, error) {
	return newSubjectEvent(now, EventMFAEnabled, userID.String(), struct {
		UserID       string `json:"user_id"`
		CredentialID string `json:"credential_id"`
		Method       string `json:"method"`
	}{
		UserID:       userID.String(),
		CredentialID: credentialID.String(),
		Method:       method,
	})
}

// NewMFADisabled builds the event emitted when a second factor goes off.
//
// It carries the method and the credential that is gone, and nothing about WHY.
// "Why" is operator-facing context typed by a human at a call site — a lost
// phone, a support ticket, somebody else telling them to — and a field whose
// values vary per operator is a field every consumer learns to ignore. The
// credential id is in the payload rather than only in the subject so a consumer
// can tell a rotation-then-disable from a disable of a long-standing factor,
// which is the difference between a lost phone and an account being cleaned up.
func NewMFADisabled(now time.Time, userID id.UUID, method string) (Envelope, error) {
	return newSubjectEvent(now, EventMFADisabled, userID.String(), struct {
		UserID string `json:"user_id"`
		Method string `json:"method"`
	}{
		UserID: userID.String(),
		Method: method,
	})
}
