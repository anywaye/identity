package sessions

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)

var errNoRows = pgx.ErrNoRows

// ErrNotFound means no live session matches. It covers four situations that must
// be indistinguishable to the caller: no such token, a revoked token, an expired
// token, and a token belonging to a deleted user. One error, one status code, one
// response time.
var ErrNotFound = errors.New("session not found")

// Session is a row in the sessions table.
type Session struct {
	ID        id.UUID
	UserID    id.UUID
	ExpiresAt time.Time
	UserAgent string
	IP        *netip.Addr
	CreatedAt time.Time
}

// NewSession is the input to Store.Create.
//
// TokenDigest, not Token. The store is given the hash and has no way to produce
// the token, so the raw credential cannot be written by accident from here.
type NewSession struct {
	UserID      id.UUID
	TokenDigest string
	ExpiresAt   time.Time
	UserAgent   string
	IP          *netip.Addr
}

// Store is the sessions table.
type Store struct {
	pool db.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool db.Pool) *Store { return &Store{pool: pool} }

const sessionColumns = `id, user_id, expires_at, user_agent, ip, created_at`

// Create inserts a session and returns the stored row.
func (s *Store) Create(ctx context.Context, q db.Querier, n NewSession) (Session, error) {
	const query = `
		INSERT INTO sessions (user_id, token_digest, expires_at, user_agent, ip)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING ` + sessionColumns

	var out Session
	if err := scanSession(q.QueryRow(ctx, query, n.UserID, n.TokenDigest, n.ExpiresAt, nullString(n.UserAgent), n.IP), &out); err != nil {
		return Session{}, fmt.Errorf("inserting a session: %w", err)
	}

	return out, nil
}

// ByToken resolves a presented token to a live session.
//
// now comes from the caller rather than from the database's clock() on purpose:
// the service reads time through an injected Clock, and a row that expires
// mid-request has to be judged against the same instant the response is
// timestamped with. See internal/platform/clock.
//
// The expiry comparison happens in the WHERE clause, not after the row is read,
// so an expired session is never returned even to be discarded by the caller.
func (s *Store) ByToken(ctx context.Context, q db.Querier, token string, now time.Time) (Session, error) {
	const query = `
		SELECT ` + sessionColumns + `
		FROM sessions
		WHERE token_digest = $1 AND expires_at > $2`

	var out Session
	err := scanSession(q.QueryRow(ctx, query, Digest(token), now), &out)
	if errors.Is(err, errNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("looking up a session: %w", err)
	}

	return out, nil
}

// Revoke deletes a session. Revoking a session that is already gone succeeds: a
// client retrying a logout should not get an error for having retried it.
func (s *Store) Revoke(ctx context.Context, q db.Querier, sessionID id.UUID) error {
	const query = `DELETE FROM sessions WHERE id = $1`

	if _, err := q.Exec(ctx, query, sessionID); err != nil {
		return fmt.Errorf("deleting a session: %w", err)
	}
	return nil
}

// ListLiveForUser returns a user's live sessions, newest first.
//
// LIVE MEANS NOT EXPIRED, and the comparison is in the WHERE clause for the same
// reason ByToken puts it there: a row that cannot authenticate is not a session a
// person should be shown, and "sign out of that other laptop" must not offer them
// a button for a credential that stopped working hours ago.
//
// The order is `created_at DESC, id DESC` rather than `created_at DESC` alone.
// created_at is the DATABASE's now() and two logins in the same millisecond are
// ordinary, so a bare created_at leaves the order of two rows undefined and the
// list renders differently on two runs with the same data — which is the shape of
// "the list jitters" that gets reported as a bug and fixed by sorting in the
// client. The id tiebreaker is free: it is the primary key, so it is already in
// every index on this table.
func (s *Store) ListLiveForUser(ctx context.Context, q db.Querier, userID id.UUID, now time.Time) ([]Session, error) {
	const query = `
		SELECT ` + sessionColumns + `
		FROM sessions
		WHERE user_id = $1 AND expires_at > $2
		ORDER BY created_at DESC, id DESC`

	rows, err := q.Query(ctx, query, userID, now)
	if err != nil {
		return nil, fmt.Errorf("listing a user's sessions: %w", err)
	}
	defer rows.Close()

	out := make([]Session, 0, 4)
	for rows.Next() {
		var one Session
		if err := scanSession(rows, &one); err != nil {
			return nil, fmt.Errorf("reading one of a user's sessions: %w", err)
		}
		out = append(out, one)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading a user's sessions: %w", err)
	}

	return out, nil
}

// RevokeOneForUser deletes one session that belongs to userID, and reports whether
// there was one to delete.
//
// # RED PROOF, AND IT IS THE CLAUSE NOT THE TEST
//
// `AND user_id = $2` was removed from the statement below and
// `TestRevokeOneForUserRefusesAnotherUsersSession` in store_listing_test.go went
// red on its own line:
//
//	RevokeOneForUser reported that it deleted a session belonging to another
//	user. The owner has to be in the DELETE's WHERE clause; a check above it is
//	a window.
//
// An earlier version of that fault — leaving the `$2` argument in place while the
// clause came out — failed for the wrong reason and is worth recording too. pgx
// rejected it with `mismatched param and argument count`, which is a build-time
// kind of error wearing a runtime's clothes: a green-looking "the database
// complained" is not the same evidence as "the row survived", and a test that
// settled for the first would have been satisfied by any statement with a typo in
// it.
//
// # THE USER_ID IS IN THE WHERE CLAUSE AND NOT IN A CHECK ABOVE IT
//
// This is the single-row version of RevokeAllForUser, and the whole difference
// between the two is this clause. `DELETE FROM sessions WHERE id = $1` would delete
// a stranger's session for any caller who can guess a uuid, so the caller is part
// of the predicate: a session id in the path is only ever a candidate, and the row
// that answers is one this user already owns.
//
// It is in the statement rather than in a preceding SELECT for three reasons, and
// only the first is about the bug:
//
//  1. A check-then-delete is a check and a delete separated by time, and the row
//     can change underneath it. One statement is atomic, so there is no window in
//     which the answer to "is this mine" and the answer to "delete it" disagree.
//  2. It is one round trip on the path of a request a browser makes while somebody
//     is looking at a list, rather than two.
//  3. A handler that receives only a bool cannot forget to check the owner,
//     because there is nothing to forget — the alternative signature hands the
//     caller a session and asks it to decide.
//
// THE FALSE IS NOT AN ERROR, and it is the shape of the four refusals ErrNotFound
// already covers. "No such session", "a session that has expired", "a session that
// belongs to somebody else" and "a session this caller already revoked" are one
// answer, because they are one situation as far as the caller is concerned: there
// is no session of yours with that id. Differentiating them would turn a uuid in a
// URL into an oracle for whether that uuid is a live session at all.
func (s *Store) RevokeOneForUser(ctx context.Context, q db.Querier, userID, sessionID id.UUID) (bool, error) {
	const query = `DELETE FROM sessions WHERE id = $1 AND user_id = $2`

	tag, err := q.Exec(ctx, query, sessionID, userID)
	if err != nil {
		return false, fmt.Errorf("deleting one of a user's sessions: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// RevokeAllForUser deletes every session belonging to a user, in one statement.
//
// It exists for the two events in this service that mean "a session that was
// already in somebody's browser is no longer a credential": MFA being enabled
// and MFA being disabled. Both are answers to the same question — a session minted
// under the old security posture should not outlive the change — and both would
// otherwise need a SELECT followed by a DELETE per row, in a loop, inside the
// transaction that made the change. A loop is a partial write waiting to happen.
//
// Revoking zero sessions is a success, not an error. A user who has never signed
// in, and a user whose last session expired an hour ago, are both in the state
// this is called for and both are already where it wants them to be.
func (s *Store) RevokeAllForUser(ctx context.Context, q db.Querier, userID id.UUID) error {
	const query = `DELETE FROM sessions WHERE user_id = $1`

	if _, err := q.Exec(ctx, query, userID); err != nil {
		return fmt.Errorf("deleting a user's sessions: %w", err)
	}
	return nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func scanSession(row pgx.Row, out *Session) error {
	var userAgent *string

	if err := row.Scan(&out.ID, &out.UserID, &out.ExpiresAt, &userAgent, &out.IP, &out.CreatedAt); err != nil {
		return err
	}
	if userAgent != nil {
		out.UserAgent = *userAgent
	}

	return nil
}
