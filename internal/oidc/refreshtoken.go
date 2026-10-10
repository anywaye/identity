package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// The refresh token: a long-lived credential, stored the way every other
// credential in this service is stored.
//
// THREE PROPERTIES, each of which is a check rather than a comment:
//
//   - THE VALUE IS NEVER STORED. The column holds the lower-case hex SHA-256 of
//     32 bytes from crypto/rand, which is the same construction as
//     sessions.token_digest, api_keys.token_digest and
//     oidc_clients.secret_digest. The digest is 64 characters and the CHECK
//     constraint in the migration says so, so a row that somehow holds a value
//     fails at the database rather than in review.
//   - IT ROTATES ON USE. A refresh consumes its row and mints a replacement,
//     linked by replaced_by. A stolen token is therefore useful for exactly one
//     request, after which it is a token that has already been used.
//   - A REUSE REVOKES THE FAMILY. Presenting a token that has already been used
//     is the one thing that cannot happen by accident — a client that rotates
//     correctly never does it — so it is treated as theft rather than as a
//     retry, and every token descended from the same login is revoked. Rotation
//     without reuse detection is a delay, not a defence: it makes the thief work
//     twice and then lets them keep the fruit.

// RefreshToken is one issued refresh token.
type RefreshToken struct {
	ID          id.UUID
	ClientRowID id.UUID
	Subject     id.UUID
	Scopes      []string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
	UsedAt      *time.Time
	ReplacedBy  *id.UUID
}

// NewRefreshToken is a token to record.
type NewRefreshToken struct {
	ID          id.UUID
	ClientRowID id.UUID
	Subject     id.UUID
	Scopes      []string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// The four refusals a presented refresh token can get, and why there are four
// rather than one.
//
// The library collapses them all into an `invalid_grant` at the token endpoint,
// so none of them reaches a caller as a distinct fact. They are kept apart here
// because the log has to say which happened: "this token is old" is a client
// that has not signed in for a month, "this token was already used" is theft,
// and one error for both makes the second invisible in an incident.
var (
	// ErrNoRefreshToken means the digest is not one this service issued.
	ErrNoRefreshToken = errors.New("refresh token is not valid")
	// ErrRefreshTokenExpired means the row is past its expiry.
	ErrRefreshTokenExpired = errors.New("refresh token has expired")
	// ErrRefreshTokenRevoked means the row, or its family, was revoked.
	ErrRefreshTokenRevoked = errors.New("refresh token has been revoked")
	// ErrRefreshTokenReused means a token that was already spent was presented
	// again. The family is revoked before this is returned, so a caller that
	// receives it has nothing left to clean up.
	ErrRefreshTokenReused = errors.New("refresh token has already been used")
)

// RefreshTokenTTL is how long one of these lives, and it is the one number a
// deployment can trade for the other two it cares about: longer means fewer
// sign-ins, shorter means less of a window a stolen token is useful in.
//
// Thirty days, and the alternative considered was ninety. Fifteen minutes — the
// access token's lifetime — is what a product sees between silent refreshes, so
// the counter only moves when a client stops refreshing, which a client that is
// unused for a month has done. A TTL is not the security boundary: rotation and
// reuse detection are, and a window that only opens while a token is being
// rotated through correctly is a window that never opens at all.
const RefreshTokenTTL = 30 * 24 * time.Hour

// NewRefreshTokenValue mints the presented value and its digest.
//
// 32 bytes from crypto/rand, base64url, no padding: the same shape and the same
// rationale as the authorization code in client.go. The digest is what the store
// keeps and the value is what the response carries, and the two never meet after
// this function returns.
func NewRefreshTokenValue() (value, digest string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		// Not a swallowed failure: a degraded entropy source is not something to
		// discover when a credential turns out to be guessable.
		return "", "", fmt.Errorf("reading random bytes for a refresh token: %w", err)
	}
	value = base64.RawURLEncoding.EncodeToString(raw)
	return value, SecretDigest(value), nil
}

const refreshTokenColumns = `id, client_row_id, subject, scopes, issued_at, expires_at, revoked_at, used_at, replaced_by`

// CreateRefreshToken records a freshly minted refresh token.
func (s *Store) CreateRefreshToken(ctx context.Context, q db.Querier, n NewRefreshToken) error {
	const query = `
		INSERT INTO oidc_refresh_tokens
			(id, client_row_id, subject, scopes, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	if _, err := q.Exec(ctx, query, n.ID, n.ClientRowID, n.Subject, n.Scopes, n.IssuedAt, n.ExpiresAt); err != nil {
		return fmt.Errorf("oidc: recording a refresh token: %w", err)
	}
	return nil
}

// ReplaceRefreshToken links a spent token to the one that succeeded it.
//
// It is a separate statement rather than part of the claim because the claim has
// already happened by the time the new row's id exists, and because a failure
// here is not a failure to refresh: the client has a working access token
// either way, and a missing link costs a family walk rather than a refused user.
func (s *Store) ReplaceRefreshToken(ctx context.Context, q db.Querier, spentID, replacementID id.UUID) error {
	const query = `
		UPDATE oidc_refresh_tokens
		SET replaced_by = $2
		WHERE id = $1 AND replaced_by IS NULL`

	if _, err := q.Exec(ctx, query, spentID, replacementID); err != nil {
		return fmt.Errorf("oidc: linking a rotated refresh token: %w", err)
	}
	return nil
}

// RotateRefreshToken claims a refresh token for one use and returns the row.
//
// THIS IS THE SINGLE-USE GATE, and it is one conditional UPDATE for the reason
// ConsumeAuthCode's is: a read-then-update would let two concurrent requests
// both pass the read, and the second UPDATE matches zero rows so only one of
// them can win. The losing racer then classifies itself below, and its answer is
// the same one it would have got had it lost by a month.
//
// THE FOUR REFUSALS ARE CLASSIFIED AFTER THE FACT, and that is not a TOCTOU.
// The claim is the mutating statement and it is done by the time anything is
// read; the SELECT that follows changes nothing, and what it reads is a row
// whose used_at, revoked_at and expires_at were all fixed before the claim ran.
// Winning the race is what decides whether a token may be used, and losing it
// decides only which of three refusals is named in the log.
func (s *Store) RotateRefreshToken(ctx context.Context, q db.Querier, digest string, now time.Time) (RefreshToken, error) {
	const claim = `
		UPDATE oidc_refresh_tokens
		SET used_at = $2
		WHERE token_digest = $1
		  AND revoked_at IS NULL
		  AND used_at IS NULL
		  AND expires_at > $2
		RETURNING ` + refreshTokenColumns

	var t RefreshToken
	err := q.QueryRow(ctx, claim, digest, now).Scan(
		&t.ID, &t.ClientRowID, &t.Subject, &t.Scopes, &t.IssuedAt, &t.ExpiresAt, &t.RevokedAt, &t.UsedAt, &t.ReplacedBy,
	)
	if err == nil {
		return t, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return RefreshToken{}, fmt.Errorf("oidc: claiming a refresh token: %w", err)
	}

	claimed, classifyErr := s.classifyUnusedRefreshToken(ctx, q, digest)
	if classifyErr != nil {
		return RefreshToken{}, classifyErr
	}

	// A token that was already spent is the one state that is never an accident.
	// Everything else — expired, revoked, never issued — is something a client
	// can do by being slow, by being logged out, or by being wrong.
	if claimed.UsedAt != nil {
		if err := s.RevokeRefreshTokenFamily(ctx, q, claimed.ID, now); err != nil {
			// The refusal is returned either way. A client must not be able to
			// keep using a reused token because a cleanup UPDATE failed.
			return RefreshToken{}, fmt.Errorf("%w (and the family could not be revoked: %v)", ErrRefreshTokenReused, err)
		}
		return RefreshToken{}, ErrRefreshTokenReused
	}
	if claimed.RevokedAt != nil {
		return RefreshToken{}, ErrRefreshTokenRevoked
	}
	if !claimed.ExpiresAt.After(now) {
		return RefreshToken{}, ErrRefreshTokenExpired
	}
	return RefreshToken{}, ErrNoRefreshToken
}

// classifyUnusedRefreshToken reads a row the claim did not take, without
// changing anything. See RotateRefreshToken for why the read is safe.
func (s *Store) classifyUnusedRefreshToken(ctx context.Context, q db.Querier, digest string) (RefreshToken, error) {
	const query = `SELECT ` + refreshTokenColumns + `
		FROM oidc_refresh_tokens
		WHERE token_digest = $1`

	var t RefreshToken
	err := q.QueryRow(ctx, query, digest).Scan(
		&t.ID, &t.ClientRowID, &t.Subject, &t.Scopes, &t.IssuedAt, &t.ExpiresAt, &t.RevokedAt, &t.UsedAt, &t.ReplacedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshToken{}, ErrNoRefreshToken
	}
	if err != nil {
		return RefreshToken{}, fmt.Errorf("oidc: reading a refresh token: %w", err)
	}
	return t, nil
}

// RevokeRefreshTokenFamily revokes every token descended from one row.
//
// THE WALK IS THE POINT. Rotating leaves the spent row behind on purpose — that
// is what makes a reuse detectable — so a family is a linked list and this
// follows replaced_by until it stops. A thief holding token 4 of a chain is
// refused, the walk finds that 4 was replaced by 5, and 5 and every token after
// it is dead too, which is the only way the legitimate client can be told to
// sign in again rather than silently continuing.
//
// The whole chain is revoked in ONE statement, so there is no half-revoked
// family for a failure to leave behind. Termination is replaced_by having no
// successor, which is exactly the state a client's last successful refresh left
// behind — and the chain is finite because every link in it was written by a
// successful rotation, one per refresh, and a refresh only happens while the
// root is alive.
func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, q db.Querier, rootID id.UUID, at time.Time) error {
	const query = `
		WITH RECURSIVE chain AS (
			SELECT id FROM oidc_refresh_tokens WHERE id = $1
			UNION ALL
			SELECT r.id
			FROM oidc_refresh_tokens r
			JOIN chain c ON r.replaced_by = c.id
		)
		UPDATE oidc_refresh_tokens t
		SET revoked_at = $2
		FROM chain
		WHERE t.id = chain.id AND t.revoked_at IS NULL`

	if _, err := q.Exec(ctx, query, rootID, at); err != nil {
		return fmt.Errorf("oidc: revoking a refresh token's family: %w", err)
	}
	return nil
}

// RevokeRefreshTokensForClient stops every refresh token issued to a
// registration.
//
// Bulk and idempotent for the reason Storage.RevokeAccessTokensForClient is: a
// revoked registration whose refresh tokens keep working for a month is a
// revoked registration that is not revoked, and a second sweep that changes no
// rows is a successful sweep.
func (s *Store) RevokeRefreshTokensForClient(ctx context.Context, q db.Querier, clientRowID id.UUID, at time.Time) error {
	const query = `
		UPDATE oidc_refresh_tokens
		SET revoked_at = $2
		WHERE client_row_id = $1 AND revoked_at IS NULL`

	if _, err := q.Exec(ctx, query, clientRowID, at); err != nil {
		return fmt.Errorf("oidc: revoking a client's refresh tokens: %w", err)
	}
	return nil
}
