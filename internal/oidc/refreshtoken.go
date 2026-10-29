package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)


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
	TokenDigest string
	Scopes      []string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

var (
	ErrNoRefreshToken = errors.New("refresh token is not valid")
	ErrRefreshTokenExpired = errors.New("refresh token has expired")
	ErrRefreshTokenRevoked = errors.New("refresh token has been revoked")
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
			(id, client_row_id, subject, token_digest, scopes, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	if _, err := q.Exec(ctx, query, n.ID, n.ClientRowID, n.Subject, n.TokenDigest, n.Scopes, n.IssuedAt, n.ExpiresAt); err != nil {
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

	claimed, classifyErr := s.RefreshToken(ctx, q, digest)
	if classifyErr != nil {
		return RefreshToken{}, classifyErr
	}

	if !claimed.ExpiresAt.After(now) {
		return RefreshToken{}, ErrRefreshTokenExpired
	}
	if claimed.UsedAt != nil {
		if _, err := s.RevokeRefreshTokenFamily(ctx, q, claimed.ID, now); err != nil {
			return RefreshToken{}, fmt.Errorf("%w (and the family could not be revoked: %w)", ErrRefreshTokenReused, err)
		}
		return RefreshToken{}, ErrRefreshTokenReused
	}
	if claimed.RevokedAt != nil {
		return RefreshToken{}, ErrRefreshTokenRevoked
	}
	return RefreshToken{}, ErrNoRefreshToken
}



// The join condition that reads the other way round — `s.replaced_by =
// c.id`, joining on CHAIN's id — is the mistake, and it is a mistake that
// survives review because it looks like the ordinary parent/child idiom. A
// chain is a singly-linked list with the pointer on the PARENT, so joining on
// `replaced_by = c.id` walks toward the root. On a linear chain that terminates
// after the anchor: nothing points at a root, so the recursive term matches
// nothing and `UNION ALL` has one row in it. One UPDATE, one row revoked, no
// error anywhere. The assertion in the tests is the count, not the error.
//
// THE COUNT IS THE CHAIN'S LENGTH, and each test says so with a number it
// derived from the rows it just wrote rather than one it remembered.
//
// Termination is `replaced_by` being NULL, which is exactly the state a client's
// last successful refresh left behind; the chain is finite because every link
// in it was written by a successful rotation, one per refresh.
func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, q db.Querier, rootID id.UUID, at time.Time) (int64, error) {
	const query = `
		WITH RECURSIVE chain AS (
			SELECT id, replaced_by FROM oidc_refresh_tokens WHERE id = $1
			UNION ALL
			SELECT successor.id, successor.replaced_by
			FROM oidc_refresh_tokens successor
			JOIN chain ON successor.id = chain.replaced_by
		)
		UPDATE oidc_refresh_tokens t
		SET revoked_at = $2
		FROM chain
		WHERE t.id = chain.id AND t.revoked_at IS NULL`

	tag, err := q.Exec(ctx, query, rootID, at)
	if err != nil {
		return 0, fmt.Errorf("oidc: revoking a refresh token's family: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RefreshToken loads a row by its digest, WITHOUT claiming it.
//
// This is the read the optional CanRefreshTokenInfo path uses, and the difference
// from RotateRefreshToken is the whole of its reason to exist: claiming mutates,
// so an endpoint that reads a token to decide what to do with it would burn the
// credential it was asked about. Nothing on the token endpoint goes through
// here.
func (s *Store) RefreshToken(ctx context.Context, q db.Querier, digest string) (RefreshToken, error) {
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
