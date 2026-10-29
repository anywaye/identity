package users

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
)


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

func TestStoreCreateRejectsADuplicateEmail(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	params := CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$first"}

	if _, err := store.Create(ctx, pool, params); err != nil {
		t.Fatalf("first Create: %v", err)
	}

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

	if _, err := store.ByEmail(ctx, pool, email); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Rollback the user is still readable: %v", err)
	}
}

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

func TestStoreUpdateNameMissesCleanly(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	name := "Kaka"
	if err := store.UpdateName(ctx, pool, id.MustNew(), &name); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateName on a missing user = %v, want errors.Is(_, ErrNotFound)", err)
	}
}

func TestStoreUpdateThemeSetsAndReadsBack(t *testing.T) {
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

	if created.Preferences.Theme != nil {
		t.Errorf("Preferences.Theme for a new user = %q, want nil", *created.Preferences.Theme)
	}

	for _, want := range []string{"light", "dark"} {
		t.Run(want, func(t *testing.T) {
			if err := store.UpdateTheme(ctx, pool, created.ID, &want); err != nil {
				t.Fatalf("UpdateTheme(%q): %v", want, err)
			}

			byID, err := store.ByID(ctx, pool, created.ID)
			if err != nil {
				t.Fatalf("ByID: %v", err)
			}
			if byID.Preferences.Theme == nil || *byID.Preferences.Theme != want {
				t.Errorf("Preferences.Theme = %v, want %q", byID.Preferences.Theme, want)
			}
		})
	}
}

func TestStoreUpdateThemeClearsWithNil(t *testing.T) {
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

	dark := "dark"
	if err := store.UpdateTheme(ctx, pool, created.ID, &dark); err != nil {
		t.Fatalf("UpdateTheme set: %v", err)
	}
	if err := store.UpdateTheme(ctx, pool, created.ID, nil); err != nil {
		t.Fatalf("UpdateTheme clear: %v", err)
	}

	byID, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if byID.Preferences.Theme != nil {
		t.Errorf("Preferences.Theme = %v, want nil after clearing", *byID.Preferences.Theme)
	}
}

func TestStoreUpdateThemeMissesCleanly(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	dark := "dark"
	if err := store.UpdateTheme(ctx, pool, id.MustNew(), &dark); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateTheme on a missing user = %v, want errors.Is(_, ErrNotFound)", err)
	}
}

func TestADisplayNameColumnExistsAndIsNullableWithNoDefault(t *testing.T) {
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

	if isNullable != "YES" {
		t.Errorf("users.display_name is_nullable = %q, want YES (existing users have no name)", isNullable)
	}

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
