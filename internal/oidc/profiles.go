package oidc

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)


// Profile is one user's claims, before scopes have been applied.
type Profile struct {
	UserID id.UUID
	Email  string
	Name string
	EmailVerified bool
	Accounts []Membership
}

// Membership is one account a user belongs to, and what they may do in it.
type Membership struct {
	AccountID id.UUID
	Name      string
	Slug      string
	Role      string
	Personal  bool
}

// ProfileReader assembles a Profile from this service's own tables.
//
// It is an interface so the storage adapter has no dependency on the users or
// accounts packages: the adapter's job is to answer the library's questions, and
// how this service stores a user's claims is not the adapter's business. The
// implementation is NewProfileReader below.
type ProfileReader interface {
	Profile(ctx context.Context, q db.Querier, userID id.UUID) (Profile, error)
}

// ErrNoProfile means the subject on a token is not a user this service has.
var ErrNoProfile = errors.New("no such user")

type pgProfileReader struct{}

// NewProfileReader returns the ProfileReader over this service's tables.
func NewProfileReader() ProfileReader { return pgProfileReader{} }

// Profile assembles the claims for one user.
//
// Two statements rather than one, and the order is not arbitrary: the user row
// first, because a subject with no user is a bug the caller has to hear about
// rather than a profile of empty strings, and the memberships second because they
// are the part that can legitimately be empty.
func (pgProfileReader) Profile(ctx context.Context, q db.Querier, userID id.UUID) (Profile, error) {
	p := Profile{UserID: userID, Accounts: []Membership{}}

	const userQuery = `SELECT email, email_verified_at IS NOT NULL FROM users WHERE id = $1`
	if err := q.QueryRow(ctx, userQuery, userID).Scan(&p.Email, &p.EmailVerified); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Profile{}, fmt.Errorf("%w: %s", ErrNoProfile, userID)
		}
		return Profile{}, fmt.Errorf("oidc: reading a user for a token: %w", err)
	}

	const nameQuery = `
		SELECT a.name
		FROM accounts a
		JOIN account_users au ON au.account_id = a.id
		WHERE au.user_id = $1 AND a.personal
		ORDER BY a.created_at, a.id
		LIMIT 1`
	if err := q.QueryRow(ctx, nameQuery, userID).Scan(&p.Name); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Profile{}, fmt.Errorf("oidc: reading the personal account name for a token: %w", err)
	}

	const accountsQuery = `
		SELECT a.id, a.name, a.slug, au.role::text, a.personal
		FROM account_users au
		JOIN accounts a ON a.id = au.account_id
		WHERE au.user_id = $1
		ORDER BY a.created_at, a.id`
	rows, err := q.Query(ctx, accountsQuery, userID)
	if err != nil {
		return Profile{}, fmt.Errorf("oidc: reading an account's memberships for a token: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.AccountID, &m.Name, &m.Slug, &m.Role, &m.Personal); err != nil {
			return Profile{}, fmt.Errorf("oidc: scanning a membership for a token: %w", err)
		}
		p.Accounts = append(p.Accounts, m)
	}
	if err := rows.Err(); err != nil {
		return Profile{}, fmt.Errorf("oidc: reading an account's memberships for a token: %w", err)
	}

	return p, nil
}

type claimAccount struct {
	AccountID string `json:"account_id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Role      string `json:"role"`
	Personal  bool   `json:"personal"`
}

func accountsClaim(memberships []Membership) []claimAccount {
	out := make([]claimAccount, 0, len(memberships))
	for _, m := range memberships {
		out = append(out, claimAccount{
			AccountID: m.AccountID.String(),
			Name:      m.Name,
			Slug:      m.Slug,
			Role:      m.Role,
			Personal:  m.Personal,
		})
	}
	return out
}
