package users

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// MIGRATION 00021's TEST, and it runs first because the file it needs does not
// exist yet.
//
// The failure it is written to produce is `column "disabled_at" does not exist`,
// which is the honest shape of "the schema has not been migrated". A test that
// skipped without TEST_DATABASE_URL would go green and prove nothing, so this is
// an integration test through dbtest.Pool like every other store test here: the
// suite is red on a machine with no database by design (see AGENTS.md, "Tests
// that need infrastructure").

// A new row is ACTIVE, and that is the whole meaning of the null.
//
// The assertion is on the value the store hands back rather than on the database
// directly, because a column that exists and is never scanned is a column whose
// default nothing depends on — the store would return a zero time for every row
// and every test below would still pass, with `IsDisabled` reading the zero value
// as "disabled" for the whole fleet.
func TestANewUsersDisabledAtIsNullAndTheUserIsActive(t *testing.T) {
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

	if created.DisabledAt != nil {
		t.Errorf("DisabledAt on a fresh row = %v, want nil — null means active", created.DisabledAt)
	}
	if created.IsDisabled() {
		t.Error("IsDisabled() on a fresh row = true, want false")
	}

	// Read back through ByID rather than trusting the INSERT's RETURNING: the
	// read path is a different query with its own column list, and a migration
	// applied to the table but not to `userColumns` produces a row that is
	// silently not-disabled.
	read, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if read.DisabledAt != nil {
		t.Errorf("DisabledAt read back = %v, want nil: the read query does not select the column", read.DisabledAt)
	}
}

// Disable and Enable are two directions of one column, so they are one table.
//
// The round trip is the assertion, and the middle of it matters: `Enable` is the
// direction that has to clear a value rather than set one, and a bug that made it
// write a zero timestamp instead of NULL would produce a user whose account is
// disabled since 1970 and would be caught by nothing else on this table.
func TestDisableAndEnableRoundTripThroughTheColumn(t *testing.T) {
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

	at := time.Date(2026, 10, 5, 9, 30, 0, 0, time.UTC)

	if err := store.Disable(ctx, pool, created.ID, at); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	disabled, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID after Disable: %v", err)
	}
	if disabled.DisabledAt == nil {
		t.Fatal("DisabledAt after Disable = nil, want the instant it was disabled at")
	}
	if !disabled.DisabledAt.Equal(at) {
		t.Errorf("DisabledAt = %v, want %v", disabled.DisabledAt, at)
	}
	if !disabled.IsDisabled() {
		t.Error("IsDisabled() after Disable = false, want true")
	}

	// The address and the credential are untouched. A disabled account is not a
	// deleted one and not a reset one: this service has no "disable also scrambles
	// the password" behaviour, and a test that let one be introduced silently
	// would be describing a different feature.
	if disabled.Email != created.Email {
		t.Errorf("Email after Disable = %q, want it unchanged at %q", disabled.Email, created.Email)
	}
	if disabled.PasswordDigest != created.PasswordDigest {
		t.Error("Disable changed the password digest; disabled is not a password reset")
	}

	if err := store.Enable(ctx, pool, created.ID); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	enabled, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID after Enable: %v", err)
	}
	if enabled.DisabledAt != nil {
		t.Errorf("DisabledAt after Enable = %v, want SQL NULL and not a zero timestamp: "+
			"'never disabled' and 'disabled since the epoch' are different answers", enabled.DisabledAt)
	}
	if enabled.IsDisabled() {
		t.Error("IsDisabled() after Enable = true, want false")
	}
}

// Both writes refuse a user that is not there rather than reporting success.
//
// Zero rows updated is a silent no-op on an UPDATE that reports nothing, and the
// caller of a disable is an operator who is about to tell somebody their access
// has ended. "Succeeded" for a user id that does not exist is a false claim about
// a security-relevant state, and it is the same rule RecordFailedLogin and
// ClearFailures already hold.
func TestDisablingAndEnablingAnAbsentUserAreRefused(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	ctx := context.Background()

	if err := store.Disable(ctx, pool, id.MustNew(), time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("Disable on a missing row = %v, want errors.Is(_, ErrNotFound)", err)
	}
	if err := store.Enable(ctx, pool, id.MustNew()); !errors.Is(err, ErrNotFound) {
		t.Errorf("Enable on a missing row = %v, want errors.Is(_, ErrNotFound)", err)
	}
}
