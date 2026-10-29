package courier

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/anywaye/identity/internal/platform/id"
)


var (
	errNotOK = errors.New("the response was not 200")
)

func newUUIDv4() (string, error) {
	value, err := id.New()
	if err != nil {
		return "", fmt.Errorf("minting a uuid: %w", err)
	}
	return value.String(), nil
}

func idempotencyKeyFor(purpose, userID, token string) (string, error) {
	if token == "" {
		return "", errors.New("courier: refusing to derive an idempotency key from nothing")
	}
	return deriveIdempotencyKey(idempotencyKeyDomain,
		purpose+"\x00"+userID+"\x00"+token)
}

func isUUID(value string) bool {
	if _, err := id.Parse(value); err != nil {
		return false
	}
	return true
}

const idempotencyKeyDomain = "anywaye/identity/recovery/idempotency/v1"

const invitationIdempotencyKeyDomain = "anywaye/identity/invitation/idempotency/v1"

func invitationIdempotencyKeyFor(invitationID, token string) (string, error) {
	if token == "" {
		return "", errors.New("courier: refusing to derive an idempotency key from nothing")
	}
	return deriveIdempotencyKey(invitationIdempotencyKeyDomain, invitationID+"\x00"+token)
}

func deriveIdempotencyKey(domain, input string) (string, error) {
	digest := sha256.Sum256([]byte(domain + "\x00" + input))

	var value id.UUID
	copy(value[:], digest[:16])
	value[6] = (value[6] & 0x0f) | 0x80
	value[8] = (value[8] & 0x3f) | 0x80

	return value.String(), nil
}
