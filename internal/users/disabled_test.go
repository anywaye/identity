package users

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
)


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

	read, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if read.DisabledAt != nil {
		t.Errorf("DisabledAt read back = %v, want nil: the read query does not select the column", read.DisabledAt)
	}
}

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
