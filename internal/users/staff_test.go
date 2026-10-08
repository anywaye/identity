package users

import (
	"context"
	"testing"

	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// MIGRATION 00030's TEST, on disabled_test.go's terms: the suite is red on a
// machine with no database by design, because a test that skipped without
// TEST_DATABASE_URL would go green and prove nothing.
//
// A new row is NOT STAFF, and that is the whole meaning of the default. The
// assertion is on the value the store hands back rather than on the database
// directly, because a column that exists and is never scanned is a column
// whose default nothing depends on.
func TestANewUserIsNotStaff(t *testing.T) {
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

	if created.IsStaff {
		t.Error("IsStaff on a fresh row = true, want false — staff is granted, never initial")
	}

	// Read back through ByID rather than trusting the INSERT's RETURNING: the
	// read path is a different query with its own column list, and a migration
	// applied to the table but not to `userColumns` produces a row that is
	// silently not staff.
	read, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if read.IsStaff {
		t.Error("IsStaff read back = true, want false: the read query does not select the column")
	}
}

// SetStaff grants and revokes, and reports a user id this service never
// issued. Asserted through re-reads, so the test proves the column moved and
// not just the absence of an error.
func TestSetStaffGrantsAndRevokes(t *testing.T) {
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

	if err := store.SetStaff(ctx, pool, created.ID, true); err != nil {
		t.Fatalf("SetStaff(true): %v", err)
	}
	granted, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID after grant: %v", err)
	}
	if !granted.IsStaff {
		t.Error("IsStaff = false after grant, want true")
	}

	if err := store.SetStaff(ctx, pool, created.ID, false); err != nil {
		t.Fatalf("SetStaff(false): %v", err)
	}
	revoked, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID after revoke: %v", err)
	}
	if revoked.IsStaff {
		t.Error("IsStaff = true after revoke, want false")
	}

	if err := store.SetStaff(ctx, pool, id.MustNew(), true); err != ErrNotFound {
		t.Errorf("SetStaff for an unknown user = %v, want ErrNotFound", err)
	}
}
