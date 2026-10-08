package users

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// Postgres SQLSTATE 23505, unique_violation. The store maps exactly this, and
// only for the email index, onto ErrEmailTaken. Any other unique violation is
// left as-is: a 23505 on some future index is a different problem and deserves
// to be visible as one.
const uniqueViolation = "23505"

// CreateParams is everything a new user needs. It carries an already-normalized
// email and an already-hashed digest: this package does not decide what a valid
// address is or how to hash a password, and the store does not try to help.
type CreateParams struct {
	Email          string
	PasswordDigest string
}

// Store is the users table.
type Store struct {
	pool db.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool db.Pool) *Store { return &Store{pool: pool} }

// userColumns is the select list, in the order scan expects. One constant, so a
// column added here cannot be forgotten in one query and present in another.
const userColumns = `id, email, display_name, preferences, password_digest, failed_login_attempts, locked_until, ` +
	`email_verified_at, disabled_at, is_staff, created_at, updated_at`

// Create inserts a user and returns the stored row.
//
// q is a db.Querier, not the pool, so the caller decides the transaction
// boundary: registering a user also writes an outbox event, and those two writes
// are one transaction or neither. See internal/outbox.
func (s *Store) Create(ctx context.Context, q db.Querier, p CreateParams) (User, error) {
	const query = `
		INSERT INTO users (email, password_digest)
		VALUES ($1, $2)
		RETURNING ` + userColumns

	var u User
	err := q.QueryRow(ctx, query, p.Email, p.PasswordDigest).Scan(
		&u.ID, &u.Email, &u.DisplayName, &u.Preferences, &u.PasswordDigest, &u.FailedLoginAttempts, &u.LockedUntil,
		&u.EmailVerifiedAt, &u.DisabledAt, &u.IsStaff, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if isEmailTaken(err) {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("inserting a user: %w", err)
	}

	return u, nil
}

// ByEmail looks a user up by address. The email must already be normalized; the
// store does not normalize on read, because a lookup that silently repairs its
// argument hides the bug in whatever wrote the row.
func (s *Store) ByEmail(ctx context.Context, q db.Querier, email string) (User, error) {
	const query = `SELECT ` + userColumns + ` FROM users WHERE email = $1`

	return scanOne(q.QueryRow(ctx, query, email))
}

// ByID looks a user up by primary key. The zero id is rejected before the query
// runs: it is not a value any row can have, and a lookup that treated it as a
// wildcard would hand out an arbitrary account.
func (s *Store) ByID(ctx context.Context, q db.Querier, want id.UUID) (User, error) {
	if want.IsZero() {
		return User{}, ErrNotFound
	}

	const query = `SELECT ` + userColumns + ` FROM users WHERE id = $1`

	return scanOne(q.QueryRow(ctx, query, want))
}

// RecordFailedLogin persists the state a wrong password produced: the current
// consecutive-failure count, and the lock expiry when the policy decided on one.
//
// lockedUntil is a pointer so "the fifth failure, not yet locked" writes SQL NULL
// rather than a zero timestamp. The two are not the same value.
func (s *Store) RecordFailedLogin(ctx context.Context, q db.Querier, userID id.UUID, attempts int, lockedUntil *time.Time) error {
	const query = `
		UPDATE users
		SET failed_login_attempts = $2, locked_until = $3, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, userID, attempts, lockedUntil)
	if err != nil {
		return fmt.Errorf("recording a failed login: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearFailures resets the consecutive-failure run and lifts any lock. A
// successful login is the only thing that calls it: the run has to restart from
// zero, or each sign-in makes the next lockout one attempt sooner.
func (s *Store) ClearFailures(ctx context.Context, q db.Querier, userID id.UUID) error {
	const query = `
		UPDATE users
		SET failed_login_attempts = 0, locked_until = NULL, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("clearing login failures: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPassword replaces the credential and clears the lockout, in one statement.
//
// THE LOCKOUT GOES WITH IT, and that is the decision rather than an oversight. A
// password reset is proved by a link delivered to the account's mailbox, which is
// strictly stronger evidence than the password that a run of failures was guessing
// at — so leaving a user who has just recovered their account locked out for the
// remainder of the window would punish them for somebody else's attempts, and the
// account would be unreachable for up to LockoutDuration after the very request
// that was supposed to get them back in.
//
// It takes the digest and never the password, for the reason NewSession does: the
// store has no way to hash and therefore no way to be handed the plaintext.
func (s *Store) SetPassword(ctx context.Context, q db.Querier, userID id.UUID, digest string) error {
	const query = `
		UPDATE users
		SET password_digest = $2, failed_login_attempts = 0, locked_until = NULL, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, userID, digest)
	if err != nil {
		return fmt.Errorf("setting a new password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetEmail moves the address and CLEARS THE VERIFICATION, in one statement.
//
// The clearing is the half that matters and it is why this is a method rather than
// a raw UPDATE the caller writes. `email_verified_at` is a claim about the address
// on THIS row; a row whose address has just changed while still carrying a
// verification timestamp would be asserting that somebody proved they can read an
// address they have never been sent anything at — which is precisely the claim the
// column exists to make impossible, and precisely how an account takeover becomes a
// matter of pointing your email at somebody else's inbox.
//
// A unique violation is ErrEmailTaken, for the same reason and the same index
// Create's is: 23505 on this table can only mean the address is registered.
func (s *Store) SetEmail(ctx context.Context, q db.Querier, userID id.UUID, email string) error {
	const query = `
		UPDATE users
		SET email = $2, email_verified_at = NULL, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, userID, email)
	if err != nil {
		if isEmailTaken(err) {
			return ErrEmailTaken
		}
		return fmt.Errorf("setting a new email: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateName sets the display name, or clears it.
//
// name is A POINTER, and nil is the clearing case rather than a zero value: an
// empty display name and no display name are the same state — the column is
// NULL — and the two ways of asking for it (sending an empty string and
// sending nothing at all) both arrive here as nil. A "" parameter would make
// "clear" and "set to the empty string" different spellings of one answer, and
// the second spelling is a lie about what is stored.
//
// The value is expected to be already trimmed and already length-checked; this
// method is the table's surface and the rules live in ValidateDisplayName, for
// the reason every other method here gives: the store does not decide what a
// valid name is, it decides what a valid UPDATE is.
//
// NO UNIQUENESS, and that is the point rather than an omission: a display name
// is not an identifier. Nothing in this service looks a user up by name — the
// email is the identifier and it is the one with the unique index — so two
// people named "Kaka" are two people and the database has no opinion about it.
func (s *Store) UpdateName(ctx context.Context, q db.Querier, userID id.UUID, name *string) error {
	const query = `
		UPDATE users
		SET display_name = $2, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, userID, name)
	if err != nil {
		return fmt.Errorf("setting a display name: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateTheme writes the preferences document, setting the theme or clearing it.
//
// theme is A POINTER for the reason UpdateName's is: nil is the clearing case
// rather than a zero value. A cleared theme and a never-set theme are the same
// state — the key is absent from the document — and both arrive here as nil, so
// the document written is the empty one and not {"theme":null}. A non-nil value
// writes {"theme": *theme}; the value is expected to be already checked against
// the closed set, because the rules live in ValidateTheme for the reason every
// other method here gives: the store does not decide what a valid theme is, it
// decides what a valid UPDATE is.
//
// THE DOCUMENT IS WHOLE, not merged: this method writes the one key the
// document has, and a merge would be a read-modify-write against a column
// nothing else writes. The caller is the use case that owns the profile
// surface, and it is the only writer.
func (s *Store) UpdateTheme(ctx context.Context, q db.Querier, userID id.UUID, theme *string) error {
	var prefs Preferences
	if theme != nil {
		prefs.Theme = theme
	}

	const query = `
		UPDATE users
		SET preferences = $2, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, userID, prefs)
	if err != nil {
		return fmt.Errorf("setting a theme: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Disable stamps `disabled_at` and does nothing else to the row.
//
// # IT IS NOT A LOCKOUT, AND IT IS NOT A PASSWORD RESET
//
// The address and the digest are untouched, deliberately. A disabled account is
// still an account: its recovery mail still arrives, its password still works,
// and the moment somebody calls Enable the owner is exactly where they were. A
// disable that scrambled the credential would make Enable irreversible, which is a
// different feature with a different name and would belong in its own packet.
//
// # IT DOES NOT REVOKE THE SESSIONS, AND THAT IS THE OTHER HALF OF THIS PACKET
//
// This method writes one column and one column only. Ending the user's live
// sessions is a second statement against a second table, and it must happen in
// the SAME transaction as this write or not at all — which is why this takes a
// `db.Querier` and is called from inside a caller's transaction rather than
// opening one of its own. `auth.Service.Disable` is that caller; a bare
// `users.Store.Disable` against the pool is a disable that leaves a live session
// behind, and it is exported because the store is the table's surface and the
// composition is the use case's. Any caller that wants the whole concept must go
// through the use case.
//
// at is the caller's clock, like every other timestamp in this repository, so the
// row and whatever this is announced alongside it agree on one instant under test
// control.
func (s *Store) Disable(ctx context.Context, q db.Querier, userID id.UUID, at time.Time) error {
	const query = `
		UPDATE users
		SET disabled_at = $2, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, userID, at)
	if err != nil {
		return fmt.Errorf("disabling a user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteForAccount removes the user row itself, and it is the only method on this
// Store that DELETES.
//
// # WHY IT TAKES AN ACCOUNT ID IT DOES NOT USE
//
// `accounts` and `users` have no foreign key between them in either direction,
// and that is a decision rather than an oversight (00005, and the header of the
// account-scoped query above): a personal account is not derived from its user.
// So "remove the user and their personal account" is two unrelated writes that
// belong in one transaction, and this signature is what makes the pairing
// explicit — the account being taken on behalf of the caller is named at the
// call site rather than inferred at the reader's convenience. It is used by
// `internal/deletion`, whose transaction removes the account first.
//
// # WHAT ONE STATEMENT DISPATCHES
//
// `DELETE FROM users WHERE id = $1` fires the ON DELETE CASCADE on six tables:
// `sessions`, `connected_accounts`, `account_users`, `api_keys`,
// `recovery_tokens`, `mfa_credentials`, `mfa_challenges`, `oidc_auth_requests`
// and `oidc_access_tokens` (00003, 00008, 00006, 00011, 00015, 00010, 00009).
// None of them is reversible, which is the property this package's own
// `Delete` doc comment on the service repeats: a credential for a user who no
// longer exists is a credential that can only ever be refused, so leaving the
// rows would grow the table for accounts that are already gone.
//
// # AND THE FOUR THAT DID NOT CASCADE ARE WHY MIGRATION 00024 EXISTS
//
// `oidc_clients.created_by`, `oidc_clients.revoked_by`, `api_keys.revoked_by`
// and `account_invitations.invited_by` are all `ON DELETE RESTRICT`, because
// each of them records a fact about a record SOMEBODY ELSE OWNS — a
// registration an account keeps for its audit, a key the account still holds, an
// invitation the account still wants. A RESTRICT is the right constraint and it
// is also, without 00024, a refusal to let a person ever leave. 00024 keeps the
// constraint and the fact and gives up only the pointer: the row survives with
// `NULL` where the departing person's id was.
//
// `user_audit_log` is in neither list. It has no foreign key at all, deliberately
// (00022): a cascade is a delete, and this table does not delete.
func (s *Store) DeleteForAccount(ctx context.Context, q db.Querier, accountID, userID id.UUID) error {
	if userID.IsZero() {
		return ErrNotFound
	}

	tag, err := q.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		// A foreign-key violation here is a THIRD-PARTY RECORD still naming this
		// user, and it is reported rather than swallowed: after migrations/00024
		// the four known cases cannot produce it, so a 23503 from here means a
		// later migration added a fifth `RESTRICT` column and this method needs to
		// know about it.
		return fmt.Errorf("deleting a user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Enable clears `disabled_at`.
//
// IT IS THE REVERSE AND NOTHING ELSE: no session comes back, no invitation is
// restored, nothing is re-sent. A session minted before the disable was deleted
// with it and the owner signs in again like anybody else — which is the reason
// re-enabling is safe to ship at all, and the reason it is worth saying out loud
// rather than letting a reader assume "enabled" means "as if it never happened".
//
// The column goes to SQL NULL rather than to a zero timestamp, for the reason
// User.DisabledAt has no `false`: 'never disabled' and 'disabled since 1970' are
// different answers and only one of them is true.
func (s *Store) Enable(ctx context.Context, q db.Querier, userID id.UUID) error {
	const query = `
		UPDATE users
		SET disabled_at = NULL, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("enabling a user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetStaff grants or revokes the staff property.
//
// # THE ONLY WRITER, AND NOTHING IN THE HTTP SURFACE CALLS IT
//
// No route, no use case and no registration path reaches this method: the only
// caller is the `identity-staff` operator command, which an operator runs with
// the database URL in hand. A grant reachable by the subject themselves would be
// a privilege escalation, and a grant reachable through a tenant-admin API would
// let one tenant mint platform authority — so the method lives on the store
// (the table's surface) rather than behind a use case anybody could mount.
//
// It takes the value rather than toggling, so re-applying a state from a script
// is not a mistake: setting what is already set is a success.
func (s *Store) SetStaff(ctx context.Context, q db.Querier, userID id.UUID, staff bool) error {
	const query = `
		UPDATE users
		SET is_staff = $2, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, userID, staff)
	if err != nil {
		return fmt.Errorf("setting a user's staff property: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DirectoryEntry is the staff directory's minimal projection of a user.
//
// IT IS A DEDICATED TYPE RATHER THAN User, for the reason userResponse is not
// users.User: a digest cannot reach a response body by being added to one. This
// projection carries no password digest, no API key, no recovery token, no MFA
// secret and no session token — the fields Parlor needs to render a row and act
// on it, and nothing a reader could mistake for a credential.
//
// THE TIMESTAMPS ARE NULLABLE AND PRESENT, not omitted and not folded into a
// boolean. `disabled_at` is nil for an active account and `email_verified_at`
// is nil for an address nobody has proved; the wire carries both keys with null
// rather than omitting them, so a client can tell "never" from "missing" and a
// future timestamp cannot arrive unannounced.
type DirectoryEntry struct {
	ID              id.UUID
	Email           string
	DisplayName     *string
	DisabledAt      *time.Time
	EmailVerifiedAt *time.Time
	CreatedAt       time.Time
}

// Search bounds for the staff directory. The handler validates the request; the
// store clamps defensively, so a caller that forgot is bounded rather than
// open-ended.
const (
	// MinSearchLength is the shortest useful search term. A one-character query
	// matches a large fraction of every deployment's addresses, which is a
	// directory dump wearing a query string — and a bounded one is still a dump
	// the caller did not have to think about.
	MinSearchLength = 2
	// DefaultSearchLimit is the page size when the caller names none.
	DefaultSearchLimit = 25
	// MaxSearchLimit is the ceiling. Over it is a refusal, never a silent
	// truncation: a client that asked for 500 rows and received 50 has been
	// told a lie about how much directory it has read.
	MaxSearchLimit = 50
)

// Search returns the users whose email or display name contains query,
// ordered by email, bounded by limit.
//
// THE MATCH IS A SUBSTRING, not a prefix: an operator looking for "kaka" finds
// "kaka@example.com" wherever the address carries it. LIKE metacharacters in
// the term are escaped, so a query for "%" matches a literal percent rather
// than the whole table — without the escape the search box is a wildcard box,
// and the shortest path to "everybody" is one character the handler already
// refused to require.
//
// limit is clamped into [1, MaxSearchLimit] here as well as validated at the
// handler, because a store that trusted its callers would hand an unbounded
// query to the table the day somebody added one.
func (s *Store) Search(ctx context.Context, q db.Querier, query string, limit int) ([]DirectoryEntry, error) {
	if limit < 1 {
		limit = DefaultSearchLimit
	}
	if limit > MaxSearchLimit {
		limit = MaxSearchLimit
	}

	// Escape before wrapping: the term is text, and `%` and `_` in it must match
	// themselves rather than become wildcards.
	pattern := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(query) + "%"

	const sql = `
		SELECT id, email, display_name, disabled_at, email_verified_at, created_at
		FROM users
		WHERE email ILIKE $1 ESCAPE '\' OR display_name ILIKE $1 ESCAPE '\'
		ORDER BY email ASC
		LIMIT $2`

	rows, err := q.Query(ctx, sql, pattern, limit)
	if err != nil {
		return nil, fmt.Errorf("searching users: %w", err)
	}
	defer rows.Close()

	// Non-nil, so an empty directory renders `[]` and not `null`.
	out := make([]DirectoryEntry, 0, limit)
	for rows.Next() {
		var e DirectoryEntry
		if err := rows.Scan(&e.ID, &e.Email, &e.DisplayName, &e.DisabledAt, &e.EmailVerifiedAt, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning a directory entry: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("searching users: %w", err)
	}
	return out, nil
}

// MarkEmailVerified records that somebody proved they can read the address on
// this row.
//
// IT IS CONDITIONAL ON THE COLUMN STILL BEING NULL, so it is idempotent by
// construction rather than by a caller remembering to check: redeeming two live
// verification links for the same address updates one row and leaves the other
// token to expire unused, and the instant recorded is the FIRST proof rather than
// the most recent one. Overwriting it would make "when did this address get
// verified" answer a question that moves every time somebody clicks a second
// link. Zero rows updated is therefore a SUCCESS, not an error.
//
// The user id is deliberately NOT the only thing in the WHERE clause, and the
// caller is deliberately not in it at all: proving you can read an inbox is not a
// thing a session authorizes. The verification token names the row, and a WHERE
// that also had to match a presented user would turn a correct token presented by
// the wrong party into a silent no-op rather than a refusal.
func (s *Store) MarkEmailVerified(ctx context.Context, q db.Querier, userID id.UUID, at time.Time) (bool, error) {
	const query = `
		UPDATE users
		SET email_verified_at = $2, updated_at = now()
		WHERE id = $1 AND email_verified_at IS NULL`

	tag, err := q.Exec(ctx, query, userID, at)
	if err != nil {
		return false, fmt.Errorf("marking an email verified: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// scanOne turns "no rows" into ErrNotFound. pgx reports it as pgx.ErrNoRows, and
// a caller that has to know that is a caller that will get it wrong.
func scanOne(row interface{ Scan(...any) error }) (User, error) {
	var u User

	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Preferences, &u.PasswordDigest, &u.FailedLoginAttempts, &u.LockedUntil,
		&u.EmailVerifiedAt, &u.DisabledAt, &u.IsStaff, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("scanning a user: %w", err)
	}

	return u, nil
}

// isEmailTaken reports whether err is a unique violation raised by the email
// index.
//
// It matches on the SQLSTATE alone, and that is load-bearing rather than lazy: the
// users table has exactly one unique index, on email, so 23505 can only mean the
// address is taken. Matching the constraint *name* instead would be more precise
// in principle and is in practice brittle — Postgres renames an index when a table
// is cloned with LIKE ... INCLUDING INDEXES, which is exactly what the integration
// tests do, and a future migration could rename it legitimately. A silently
// mis-detected duplicate turns a 409 into a 500.
//
// TestUsersHasExactlyOneUniqueIndex fails if a second unique index is ever added,
// which is the point at which this has to become precise.
func isEmailTaken(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == uniqueViolation
}
