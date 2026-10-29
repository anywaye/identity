package oauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)

const uniqueViolation = "23505"

var (
	ErrNotFound = errors.New("connected account not found")

	ErrAlreadyLinked = errors.New("that provider identity is already linked to another user")
)

// Account is a row in connected_accounts: one provider identity, and the
// credentials this service holds for it.
//
// AccessTokenCiphertext and RefreshTokenCiphertext are sealed values, never
// tokens. Nothing in this package decrypts one; that happens in the use case that
// is about to make a provider call, and never on a path that renders a response.
type Account struct {
	ID          id.UUID
	UserID      id.UUID
	Provider    string
	ProviderUID string
	AccessTokenCiphertext string
	RefreshTokenCiphertext string
	ExpiresAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewAccount is the input to Store.Create.
type NewAccount struct {
	UserID                id.UUID
	Provider              string
	ProviderUID           string
	AccessTokenCiphertext string
	RefreshTokenCiphertext string
	ExpiresAt *time.Time
}

// StoredTokens is the input to Store.RefreshTokens.
type StoredTokens struct {
	AccessTokenCiphertext string
	RefreshTokenCiphertext string
	ExpiresAt              *time.Time
}

// Store is the connected_accounts table.
//
// UNWIRED. Every method here is tested against a real database and nothing calls
// any of them, because the social-login surface is not mounted — see the package
// doc in cipher.go. This is AGENTS.md's "tested but unwired" case, and the reason
// it is kept rather than deleted is recorded there and in README.md's "Social
// login is not built": the migration backing it is applied, an applied migration is
// not edited, and this is the correct schema access for the packet that will use it.
type Store struct {
	pool db.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool db.Pool) *Store { return &Store{pool: pool} }

const accountColumns = `id, user_id, provider, provider_uid, access_token_ciphertext, refresh_token_ciphertext, expires_at, created_at, updated_at`

// Create inserts a connected account.
//
// q is a db.Querier rather than the pool because the first OAuth login writes
// three things that are one transaction or none: the user, the connected account
// and the event announcing the user.
func (s *Store) Create(ctx context.Context, q db.Querier, n NewAccount) (Account, error) {
	const query = `
		INSERT INTO connected_accounts (user_id, provider, provider_uid, access_token_ciphertext, refresh_token_ciphertext, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING ` + accountColumns

	var out Account
	var refreshToken *string

	err := q.QueryRow(ctx, query,
		n.UserID, n.Provider, n.ProviderUID, n.AccessTokenCiphertext,
		nullIfEmpty(n.RefreshTokenCiphertext), n.ExpiresAt,
	).Scan(
		&out.ID, &out.UserID, &out.Provider, &out.ProviderUID,
		&out.AccessTokenCiphertext, &refreshToken,
		&out.ExpiresAt, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		if isAlreadyLinked(err) {
			return Account{}, ErrAlreadyLinked
		}
		return Account{}, fmt.Errorf("inserting a connected account: %w", err)
	}
	if refreshToken != nil {
		out.RefreshTokenCiphertext = *refreshToken
	}

	return out, nil
}

// ErrNoGitHubAccount is returned by GitHubIDForUser when the user has linked no
// GitHub account.
//
// It is this package's own name rather than a reference to `oidc`'s, because the
// dependency runs the other way: `oidc` asks this package a question and
// translates. Two names for one condition is how the two drift apart.
var ErrNoGitHubAccount = errors.New("no linked github account")

// GitHubIDReader is what `oidc` asks for the `github_id` claim, declared here so
// `oidc` does not import this package for one method.
//
// It is an interface on the consuming side for the same reason `oidc`'s
// `ProfileReader` is: the OIDC adapter's job is to answer the library's
// questions, and how this service stores a linked account is not the adapter's
// business. It also keeps the claim testable without a database tier.
type GitHubIDReader interface {
	GitHubIDForUser(ctx context.Context, q db.Querier, userID id.UUID) (string, error)
}

var _ GitHubIDReader = (*Store)(nil)

// GitHubIDForUser returns one user's verified GitHub account id, the value
// `connected_accounts.provider_uid` holds for a `github` row.
//
// It is keyed on the USER rather than on the provider identity, because the
// caller is minting a claim about somebody who is already signed in — the
// direction the rest of this file's lookups run is the other way round.
//
// The id is returned as the STRING the column already holds and is NOT parsed
// into an integer here, and the reason is MD21 rather than laziness: the value
// crosses `gateway` as a JSON claim, and `gateway` copies claims through a
// JavaScript `JSON.parse`. A `github_id` emitted as a JSON **number** is already
// a float64 by the time `gateway` re-signs it, and every digit past 2^53 is
// silently rewritten inside a correctly-signed assertion — measured in node,
// 107346492749283471920 comes back as ...3485475456. The string survives. So the
// string is what leaves this function, and nothing downstream may "helpfully"
// convert it.
//
// ErrNotFound means this user has linked no GitHub account, which is an
// ordinary state and not an error the caller should surface: a token with no
// `github_id` is the correct token for a user who has not linked one.
func (s *Store) GitHubIDForUser(ctx context.Context, q db.Querier, userID id.UUID) (string, error) {
	const query = `
		SELECT provider_uid
		FROM connected_accounts
		WHERE user_id = $1 AND provider = 'github'`

	var out string
	err := q.QueryRow(ctx, query, userID).Scan(&out)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoGitHubAccount
	}
	if err != nil {
		return "", fmt.Errorf("looking up a user's github id: %w", err)
	}
	if out == "" {
		return "", ErrNoGitHubAccount
	}
	return out, nil
}

// ByProviderUID finds the account for one provider identity.
//
// The lookup key is the provider plus the provider's own identifier, never the
// email: an address can be changed at the provider and two provider accounts can
// share one, so an email-keyed lookup is both a takeover and a duplicate waiting
// to happen.
func (s *Store) ByProviderUID(ctx context.Context, q db.Querier, provider, providerUID string) (Account, error) {
	const query = `SELECT ` + accountColumns + ` FROM connected_accounts WHERE provider = $1 AND provider_uid = $2`

	var out Account
	var refreshToken *string

	err := q.QueryRow(ctx, query, provider, providerUID).Scan(
		&out.ID, &out.UserID, &out.Provider, &out.ProviderUID,
		&out.AccessTokenCiphertext, &refreshToken,
		&out.ExpiresAt, &out.CreatedAt, &out.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	if err != nil {
		return Account{}, fmt.Errorf("looking up a connected account: %w", err)
	}
	if refreshToken != nil {
		out.RefreshTokenCiphertext = *refreshToken
	}

	return out, nil
}

// RefreshTokens writes a newly issued credential onto an existing link.
//
// The refresh token is written only when a new one was issued. Google reissues it
// on some flows and not others, and treating "absent from this response" as
// "clear the stored one" would quietly leave the account holding a credential
// that expires in an hour with no way to renew it.
func (s *Store) RefreshTokens(ctx context.Context, q db.Querier, accountID id.UUID, t StoredTokens) error {
	const query = `
		UPDATE connected_accounts
		SET access_token_ciphertext = $2,
		    refresh_token_ciphertext = COALESCE($3, refresh_token_ciphertext),
		    expires_at = $4,
		    updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, accountID, t.AccessTokenCiphertext, nullIfEmpty(t.RefreshTokenCiphertext), t.ExpiresAt)
	if err != nil {
		return fmt.Errorf("refreshing a connected account's tokens: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isAlreadyLinked(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == uniqueViolation
}
