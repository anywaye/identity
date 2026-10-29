package main


import (
	"context"
	"errors"
	"testing"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/users"
)

func testStore(t *testing.T) (*users.Store, db.Querier) {
	t.Helper()
	pool := dbtest.Pool(t)
	return users.NewStore(pool), pool
}

func TestGrantRevokeAndStatusMoveTheColumn(t *testing.T) {
	store, q := testStore(t)
	ctx := context.Background()

	created, err := store.Create(ctx, q, users.CreateParams{
		Email:          dbtest.UniqueEmail(t),
		PasswordDigest: "$argon2id$fake",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.IsStaff {
		t.Fatal("a new user is staff, want the default false — staff is granted, never initial")
	}

	if _, err := apply(ctx, store, q, actionGrant, created.Email); err != nil {
		t.Fatalf("grant: %v", err)
	}
	read, err := store.ByID(ctx, q, created.ID)
	if err != nil {
		t.Fatalf("ByID after grant: %v", err)
	}
	if !read.IsStaff {
		t.Error("is_staff is false after grant, want true")
	}

	if _, err := apply(ctx, store, q, actionGrant, created.Email); err != nil {
		t.Errorf("a second grant = %v, want success", err)
	}

	status, err := apply(ctx, store, q, actionStatus, created.Email)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !status.IsStaff {
		t.Error("status reports staff=false for a granted user")
	}

	if _, err := apply(ctx, store, q, actionRevoke, created.Email); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	cleared, err := store.ByID(ctx, q, created.ID)
	if err != nil {
		t.Fatalf("ByID after revoke: %v", err)
	}
	if cleared.IsStaff {
		t.Error("is_staff is true after revoke, want false")
	}
}

func TestApplyReportsAnUnknownAddress(t *testing.T) {
	store, q := testStore(t)

	if _, err := apply(context.Background(), store, q, actionGrant, dbtest.UniqueEmail(t)); !errors.Is(err, users.ErrNotFound) {
		t.Errorf("grant for an unknown address = %v, want errors.Is(_, users.ErrNotFound)", err)
	}
}

func TestAGrantedUserIsSearchable(t *testing.T) {
	store, q := testStore(t)
	ctx := context.Background()

	email := dbtest.UniqueEmail(t)
	created, err := store.Create(ctx, q, users.CreateParams{Email: email, PasswordDigest: "$argon2id$fake"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := apply(ctx, store, q, actionGrant, email); err != nil {
		t.Fatalf("grant: %v", err)
	}

	entries, err := store.Search(ctx, q, localPart(email), users.DefaultSearchLimit)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.ID == created.ID {
			found = true
			if e.Email != email {
				t.Errorf("the entry's email = %q, want %q", e.Email, email)
			}
			if e.DisplayName != nil {
				t.Errorf("the entry's display name = %q, want nil", *e.DisplayName)
			}
			if e.DisabledAt != nil {
				t.Errorf("the entry's disabled_at = %v, want nil for a fresh account", *e.DisabledAt)
			}
			if e.EmailVerifiedAt != nil {
				t.Errorf("the entry's email_verified_at = %v, want nil for a fresh account", *e.EmailVerifiedAt)
			}
			if e.CreatedAt.IsZero() {
				t.Error("the entry carries no creation time")
			}
		}
	}
	if !found {
		t.Errorf("a granted user is not in the directory search for %q", localPart(email))
	}
}

func TestSearchEscapesLikeMetacharacters(t *testing.T) {
	store, q := testStore(t)
	ctx := context.Background()

	if _, err := store.Create(ctx, q, users.CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$fake"}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	entries, err := store.Search(ctx, q, "%", users.DefaultSearchLimit)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("a search for %% returned %d rows, want 0: the wildcard was not escaped", len(entries))
	}
}

func TestSearchClampsAnOutOfRangeLimit(t *testing.T) {
	store, q := testStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := store.Create(ctx, q, users.CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$fake"}); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	entries, err := store.Search(ctx, q, "example", 5000)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(entries) > users.MaxSearchLimit {
		t.Errorf("an unbounded search returned %d rows, want at most %d", len(entries), users.MaxSearchLimit)
	}
}

func localPart(email string) string {
	for i := 0; i < len(email); i++ {
		if email[i] == '@' {
			return email[:i]
		}
	}
	return email
}
