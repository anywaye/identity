package main

// THE DATABASE HALF: grant, revoke and status against a real table.
//
// The suite is red on a machine with no Postgres by design (see AGENTS.md,
// "Tests that need infrastructure"): every test here is a database test, so
// without one the file would prove nothing and a green suite would report
// something false.

import (
	"context"
	"errors"
	"testing"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/users"
)

func testStore(t *testing.T) (*users.Store, db.Querier) {
	t.Helper()
	pool := dbtest.Pool(t)
	return users.NewStore(pool), pool
}

// Grant marks the row, revoke clears it, and status reports without writing —
// each asserted through a re-read rather than through the returned struct, so
// the test proves the column moved and not just the response.
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

	// Granting twice is a success: an operator re-applying a state from a
	// runbook is not making a mistake.
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

// An unknown address is ErrNotFound, which run renders as "no user with
// address" rather than as a stack trace.
func TestApplyReportsAnUnknownAddress(t *testing.T) {
	store, q := testStore(t)

	if _, err := apply(context.Background(), store, q, actionGrant, dbtest.UniqueEmail(t)); !errors.Is(err, users.ErrNotFound) {
		t.Errorf("grant for an unknown address = %v, want errors.Is(_, users.ErrNotFound)", err)
	}
}

// The search this packet adds sees the grant: a staff user is findable by the
// console, which is the whole point of granting them.
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
			// Nullable and present: a fresh account was never disabled and
			// never proved its address, and both keys arrive as null rather
			// than omitted.
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

// A LIKE metacharacter matches itself rather than becoming a wildcard: without
// the escape the search box is a wildcard box, and "%" is the shortest path to
// everybody.
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
	// "%" is one character, which the handler refuses — but the STORE takes
	// what it is given, and the escape means it matches a literal percent
	// rather than the whole table.
	if len(entries) != 0 {
		t.Errorf("a search for %% returned %d rows, want 0: the wildcard was not escaped", len(entries))
	}
}

// The store clamps rather than trusting: a caller that forgot the bound gets a
// page, not the table.
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
