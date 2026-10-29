package users

import (
	"context"
	"errors"
	"testing"

	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
)

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

	read, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if read.IsStaff {
		t.Error("IsStaff read back = true, want false: the read query does not select the column")
	}
}

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

	if err := store.SetStaff(ctx, pool, id.MustNew(), true); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetStaff for an unknown user = %v, want ErrNotFound", err)
	}
}
