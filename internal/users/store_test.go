package users

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// These are integration tests: they need a real Postgres with the migrations
// applied. See dbtest.Pool for the gate and migrations/README.md for the setup.

func TestStoreCreateAndReadBack(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	want := CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$fake"}

	created, err := store.Create(ctx, pool, want)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if created.ID.IsZero() {
		t.Error("Create returned a zero id")
	}
	// The address is stored normalized, not as it was typed. This is what makes
	// "Kaka@Example.com" and "kaka@example.com" one account rather than two.
	if created.Email != strings.ToLower(want.Email) {
		t.Errorf("Email = %q, want the normalized %q", created.Email, strings.ToLower(want.Email))
	}
	if created.PasswordDigest != want.PasswordDigest {
		t.Errorf("PasswordDigest = %q, want it stored verbatim", created.PasswordDigest)
	}
	if created.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts = %d, want 0", created.FailedLoginAttempts)
	}
	if created.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil", created.LockedUntil)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Errorf("timestamps not set: created_at=%v updated_at=%v", created.CreatedAt, created.UpdatedAt)
	}

	byEmail, err := store.ByEmail(ctx, pool, NormalizeEmail(strings.ToUpper(want.Email)))
	if err != nil {
		t.Fatalf("ByEmail: %v", err)
	}
	if byEmail.ID != created.ID {
		t.Errorf("ByEmail returned id %s, want %s", byEmail.ID, created.ID)
	}

	byID, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if byID.Email != created.Email {
		t.Errorf("ByID email = %q, want %q", byID.Email, created.Email)
	}
	if byID.PasswordDigest != created.PasswordDigest {
		t.Error("ByID lost the password digest")
	}
}

// A second registration of the same address must be refused by the database and
// surfaced as ErrEmailTaken, not as a raw pgx error. Registration is the one
// endpoint allowed to reveal this, and it does so as a 409.
func TestStoreCreateRejectsADuplicateEmail(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	params := CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$first"}

	if _, err := store.Create(ctx, pool, params); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	// The same normalized address again. This is the collision that matters: the
	// unique index is what makes one account per address true.
	//
	// Note what is *not* tested here: re-inserting the same address in a
	// different case. That cannot reach the unique index at all — the
	// users_email_is_normalized CHECK rejects it first, which is
	// TestStoreCreateRefusesAnUnnormalizedEmail's job. Case collapsing is proven
	// by TestStoreCreateAndReadBack, which stores a normalized address and finds
	// it again through an upper-cased lookup.
	params.PasswordDigest = "$argon2id$second"
	_, err := store.Create(ctx, pool, params)

	if !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("second Create error = %v, want errors.Is(_, ErrEmailTaken)", err)
	}
}

func TestStoreLookupsMissCleanly(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()

	if _, err := store.ByEmail(ctx, pool, "nobody@example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ByEmail on a missing row = %v, want errors.Is(_, ErrNotFound)", err)
	}

	if _, err := store.ByID(ctx, pool, id.MustNew()); !errors.Is(err, ErrNotFound) {
		t.Errorf("ByID on a missing row = %v, want errors.Is(_, ErrNotFound)", err)
	}
}

// A zero id must not match a row. A query that forgot its WHERE clause would
// otherwise return the first user in the table to anyone who passed the nil UUID.
func TestStoreByIDRejectsTheZeroID(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	if _, err := store.ByID(context.Background(), pool, id.UUID{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("ByID with the zero id = %v, want errors.Is(_, ErrNotFound)", err)
	}
}

func TestStoreCreateRefusesAnUnnormalizedEmail(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	// The CHECK constraint is the last line of defence. CreateParams carrying an
	// unnormalized address is a caller bug, and the failure should be the
	// database's constraint violation, not a silently corrected row.
	_, err := store.Create(context.Background(), pool, CreateParams{
		Email:          "Kaka@Example.com",
		PasswordDigest: "$argon2id$fake",
	})
	if err == nil {
		t.Fatal("Create accepted an unnormalized email, want the users_email_is_normalized CHECK to reject it")
	}
}

func TestStoreRecordFailedLogin(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	user, err := store.Create(ctx, pool, CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$fake"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	lockUntil := time.Date(2026, 9, 30, 12, 15, 0, 0, time.UTC)
	if err := store.RecordFailedLogin(ctx, pool, user.ID, 3, &lockUntil); err != nil {
		t.Fatalf("RecordFailedLogin: %v", err)
	}

	got, err := store.ByID(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.FailedLoginAttempts != 3 {
		t.Errorf("FailedLoginAttempts = %d, want 3", got.FailedLoginAttempts)
	}
	if got.LockedUntil == nil || !got.LockedUntil.Equal(lockUntil) {
		t.Errorf("LockedUntil = %v, want %s", got.LockedUntil, lockUntil)
	}
}

// Clearing a null lock must store SQL NULL, not a zero timestamp. A zero
// timestamp is "locked until 1970", which reads as unlocked today and as locked
// for any clock set before it.
func TestStoreRecordFailedLoginStoresNullForAnUnlockedAccount(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	user, err := store.Create(ctx, pool, CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$fake"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.RecordFailedLogin(ctx, pool, user.ID, 1, nil); err != nil {
		t.Fatalf("RecordFailedLogin: %v", err)
	}

	got, err := store.ByID(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil", *got.LockedUntil)
	}
}

func TestStoreRecordFailedLoginRejectsANegativeCount(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	user, err := store.Create(ctx, pool, CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$fake"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The users_failed_login_attempts_non_negative CHECK is the backstop for a
	// bug that decrements the counter, which would otherwise quietly raise the
	// number of attempts needed to trigger a lockout.
	if err := store.RecordFailedLogin(ctx, pool, user.ID, -1, nil); err == nil {
		t.Error("RecordFailedLogin accepted a negative count, want the CHECK constraint to reject it")
	}
}

func TestStoreClearFailures(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	user, err := store.Create(ctx, pool, CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$fake"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	lockUntil := time.Now().UTC().Add(time.Hour)
	if err := store.RecordFailedLogin(ctx, pool, user.ID, 5, &lockUntil); err != nil {
		t.Fatalf("RecordFailedLogin: %v", err)
	}

	if err := store.ClearFailures(ctx, pool, user.ID); err != nil {
		t.Fatalf("ClearFailures: %v", err)
	}

	got, err := store.ByID(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	// A successful login has to reset the run, not just the lock: otherwise the
	// fifth failure is one attempt sooner every time the user signs in.
	if got.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts = %d, want 0 after a successful login", got.FailedLoginAttempts)
	}
	if got.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil after a successful login", *got.LockedUntil)
	}
	if !got.UpdatedAt.After(user.UpdatedAt) && !got.UpdatedAt.Equal(user.UpdatedAt) {
		t.Errorf("UpdatedAt = %s, want it moved to or past %s", got.UpdatedAt, user.UpdatedAt)
	}
}

// isEmailTaken matches on the SQLSTATE alone, which is only sound while email is
// the table's only *application-level* unique index. This test is what makes that
// assumption self-enforcing: add a second one and this fails, at which point the
// detection has to start distinguishing them.
//
// The primary key is excluded. It is also a unique index and also raises 23505,
// but it covers a server-generated UUID whose collision probability is around
// 2^-122 — reporting one as "that address is taken" is a confusing message for an
// event that will not happen, and refusing to report it at all would be worse.
func TestUsersHasExactlyOneApplicationUniqueIndexAndItIsOnEmail(t *testing.T) {
	pool := dbtest.Pool(t)

	rows, err := pool.Query(context.Background(), `
		SELECT a.attname
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
		WHERE i.indrelid = 'users'::regclass AND i.indisunique AND NOT i.indisprimary
		ORDER BY a.attname`)
	if err != nil {
		t.Fatalf("listing unique indexes on users: %v", err)
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatalf("scanning an index column: %v", err)
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading the index list: %v", err)
	}

	if len(columns) != 1 || columns[0] != "email" {
		t.Errorf("users has application-level unique indexes on %v, want exactly one on "+
			"email. isEmailTaken matches on SQLSTATE 23505 alone and can no longer tell a "+
			"duplicate address from a violation of a new constraint", columns)
	}
}

func TestStoreCreateInsideATransactionRollsBackWithIt(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	email := dbtest.UniqueEmail(t)
	if _, err := store.Create(ctx, tx, CreateParams{Email: email, PasswordDigest: "$argon2id$fake"}); err != nil {
		t.Fatalf("Create inside the transaction: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// This is the property the Querier seam exists for: registering a user writes
	// two rows, and if the second one fails neither survives.
	if _, err := store.ByEmail(ctx, pool, email); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Rollback the user is still readable: %v", err)
	}
}

// A new user has no display name: the column is NULL and the field is nil.
// This is the state every existing user is in after the migration.
func TestStoreCreateLeavesDisplayNameNull(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	created, err := store.Create(ctx, pool, CreateParams{
		Email:          dbtest.UniqueEmail(t),
		PasswordDigest: "$argon2id$fake",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.DisplayName != nil {
		t.Errorf("DisplayName = %v, want nil for a new user", *created.DisplayName)
	}

	byID, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if byID.DisplayName != nil {
		t.Errorf("ByID DisplayName = %v, want nil for a new user", *byID.DisplayName)
	}
}

// UpdateName sets the display name and reads it back.
func TestStoreUpdateNameSetsAndReadsBack(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	created, err := store.Create(ctx, pool, CreateParams{
		Email:          dbtest.UniqueEmail(t),
		PasswordDigest: "$argon2id$fake",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	name := "Kaka"
	if err := store.UpdateName(ctx, pool, created.ID, &name); err != nil {
		t.Fatalf("UpdateName: %v", err)
	}

	byID, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if byID.DisplayName == nil || *byID.DisplayName != "Kaka" {
		t.Errorf("DisplayName = %v, want Kaka", byID.DisplayName)
	}
}

// UpdateName with nil clears the name, returning the column to NULL.
func TestStoreUpdateNameClearsWithNil(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	created, err := store.Create(ctx, pool, CreateParams{
		Email:          dbtest.UniqueEmail(t),
		PasswordDigest: "$argon2id$fake",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	name := "Kaka"
	if err := store.UpdateName(ctx, pool, created.ID, &name); err != nil {
		t.Fatalf("UpdateName set: %v", err)
	}
	if err := store.UpdateName(ctx, pool, created.ID, nil); err != nil {
		t.Fatalf("UpdateName clear: %v", err)
	}

	byID, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if byID.DisplayName != nil {
		t.Errorf("DisplayName = %v, want nil after clearing", *byID.DisplayName)
	}
}

// UpdateName on a missing user returns ErrNotFound.
func TestStoreUpdateNameMissesCleanly(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	name := "Kaka"
	if err := store.UpdateName(ctx, pool, id.MustNew(), &name); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateName on a missing user = %v, want errors.Is(_, ErrNotFound)", err)
	}
}

// A row that has always had no display name reads fine, and that is the state
// every user who existed before this migration is in.
//
// The column is read directly with a cast rather than through the store, because
// the store's select list carries the value as a *string and a scan failure there
// is indistinguishable from a column that is not there — this asks the catalog
// what the column actually is, so the assertion is about the migration and not
// about this package's ability to read NULL.
func TestADisplayNameColumnExistsAndIsNullableWithNoDefault(t *testing.T) {
	pool := dbtest.Pool(t)

	// The row this creates predates nothing — it is inserted the way every other
	// user is, through a statement that never mentions display_name, which is the
	// property that matters: an INSERT written before the column existed still
	// works, because the column has no default it would have to satisfy.
	store := NewStore(pool)
	ctx := context.Background()
	created, err := store.Create(ctx, pool, CreateParams{
		Email:          dbtest.UniqueEmail(t),
		PasswordDigest: "$argon2id$fake",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// column_default is a nullable catalog text, so it is a POINTER here for the
	// same reason the column itself is: "no default" is not an empty string.
	var isNullable string
	var hasDefault *string
	const query = `
		SELECT is_nullable, column_default
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'display_name'`

	row := pool.QueryRow(ctx, query)
	if err := row.Scan(&isNullable, &hasDefault); err != nil {
		t.Fatalf("reading users.display_name from the catalog: %v", err)
	}

	// NULLABLE, because every existing user has no name and there is no honest
	// default to give them. A NOT NULL column would need a backfill inventing a
	// name for every account in the fleet.
	if isNullable != "YES" {
		t.Errorf("users.display_name is_nullable = %q, want YES (existing users have no name)", isNullable)
	}

	// NO DEFAULT, for the reason 00023 argues: a default of '' would be a second
	// representation of "no name", and the first person to clear a name they had
	// set would be the one who found the two disagreeing.
	if hasDefault != nil {
		t.Errorf("users.display_name has default %v, want none (NULL is the one way to say no name)", *hasDefault)
	}

	var stored *string
	if err := pool.QueryRow(ctx, `SELECT display_name FROM users WHERE id = $1`, created.ID).Scan(&stored); err != nil {
		t.Fatalf("reading the column back: %v", err)
	}
	if stored != nil {
		t.Errorf("a user created without mentioning display_name reads %q, want NULL", *stored)
	}
}

// The column carries no unique constraint and no index, because a display name
// is not an identifier. Two people named "Kaka" are two people, and a unique
// constraint would be a promise about a lookup that never happens.
//
// Asserted against the catalog rather than left to the migration's comment,
// because the migration's comment is prose and this is the property: a future
// packet that adds "just an index, it is probably useful" would be refused here
// rather than becoming a maintenance cost on every write to users that nothing
// reads.
//
// THE COUNT IS OVER pg_index, which is where both kinds of index live — a
// unique constraint is implemented as an index, so this one query covers the
// unique case and the plain case. The leading column is what indkey[0] names:
// a composite index that merely CONTAINS the column would still serve a lookup
// leading with it, and there is none to serve.
func TestDisplayNameCarriesNoIndexAndNoUniqueConstraint(t *testing.T) {
	pool := dbtest.Pool(t)

	const query = `
		SELECT count(*)
		FROM pg_index i
		JOIN pg_class t ON t.oid = i.indrelid
		JOIN pg_namespace n ON n.oid = t.relnamespace
		WHERE n.nspname = 'public' AND t.relname = $1
		  AND i.indkey[0] = (
		      SELECT attnum FROM pg_attribute
		      WHERE attrelid = 'public.users'::regclass AND attname = $2)`

	// THE CONTROL, and it is the half that makes the assertion below mean
	// anything: the same query shape run against email — a column that DOES
	// have a unique index leading with it — must find at least one. A query
	// that finds nothing agrees with another query that finds nothing, and
	// without this line the count below would pass against a database where
	// the whole catalog had been dropped.
	var control int
	if err := pool.QueryRow(context.Background(), query, "users", "email").Scan(&control); err != nil {
		t.Fatalf("the control count: %v", err)
	}
	if control == 0 {
		t.Fatalf("the control found no index leading with users.email, so this query shape finds nothing at all — " +
			"fix the query before trusting the assertion below")
	}

	var n int
	if err := pool.QueryRow(context.Background(), query, "users", "display_name").Scan(&n); err != nil {
		t.Fatalf("counting indexes on users.display_name: %v", err)
	}
	if n != 0 {
		t.Errorf("%d indexes lead with users.display_name, want 0 (the email is the identifier)", n)
	}
}
