package sessions

// THE LISTING AND THE SINGLE REVOCATION, AGAINST A REAL DATABASE.
//
// Three properties, and the third is the one the other two are arranged around:
// a caller cannot end somebody else's session by naming its id.
//
// That cannot be proven with a double, and it cannot be proven at the HTTP layer
// alone either — the HTTP layer's proof is that it passes a credential and not a
// user id (that is `internal/auth`'s test), and this file's is that the DELETE
// carries the owner in its predicate. A `WHERE id = $1` with a check above it would
// pass every test in internal/auth and internal/httpapi and delete a stranger's
// session in production, which is why the assertion below is on the ROW and not on
// a return value.
//
// The red proof for the ownership case is in REPORT-identity-sessions-01: the
// owner clause was removed from the statement, this file went red on
// `TestRevokeOneForUserRefusesAnotherUsersSession`, and the clause came back.

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// mintSession writes one live session and returns the row with its token, so a
// test can both look the session up by its digest and authenticate with it.
func mintSession(t *testing.T, pool *pgxpool.Pool, store *Store, userID id.UUID, agent string) (Session, string) {
	t.Helper()

	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	ip := netip.MustParseAddr("198.51.100.9")

	created, err := store.Create(context.Background(), pool, NewSession{
		UserID:      userID,
		TokenDigest: digest,
		ExpiresAt:   issuedAt.Add(24 * time.Hour),
		UserAgent:   agent,
		IP:          &ip,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return created, token
}

// TestListLiveForUserReturnsOnlyThatUsersSessions is the listing's boundary, and it
// is asserted on BOTH SIDES: the caller's own session is present AND the stranger's
// is absent.
//
// Asserting only the presence would pass against a query that returned every row in
// the table, which is the failure this file exists to catch. A shared database and
// a parallel suite mean "the table has at least two users in it" is not something to
// assume — but it is not something to rely on either, so the stranger is created
// here rather than borrowed.
func TestListLiveForUserReturnsOnlyThatUsersSessions(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	mine := newTestUser(t, pool)
	theirs := newTestUser(t, pool)

	ctx := context.Background()
	want, _ := mintSession(t, pool, store, mine.ID, "Mine/1.0")
	stranger, _ := mintSession(t, pool, store, theirs.ID, "Theirs/1.0")

	list, err := store.ListLiveForUser(ctx, pool, mine.ID, issuedAt)
	if err != nil {
		t.Fatalf("ListLiveForUser: %v", err)
	}

	seen := map[id.UUID]bool{}
	for _, s := range list {
		seen[s.ID] = true
	}
	if !seen[want.ID] {
		t.Errorf("the caller's own session %s is missing from %d rows", want.ID, len(list))
	}
	if seen[stranger.ID] {
		t.Errorf("ListLiveForUser returned session %s, which belongs to another user. "+
			"The user id is in the WHERE clause; this row exists only if it is not.", stranger.ID)
	}
}

// TestListLiveForUserOmitsAnExpiredSession is why the expiry test is here rather
// than in the auth layer: "live" is a claim about what the user is shown, and a
// revoked-by-expiry row is a button that does nothing.
func TestListLiveForUserOmitsAnExpiredSession(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	ctx := context.Background()
	live, _ := mintSession(t, pool, store, user.ID, "Live/1.0")

	// A session that expired an hour before `issuedAt`.
	_, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if _, err := store.Create(ctx, pool, NewSession{
		UserID:      user.ID,
		TokenDigest: digest,
		ExpiresAt:   issuedAt.Add(-time.Hour),
		UserAgent:   "Stale/1.0",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	list, err := store.ListLiveForUser(ctx, pool, user.ID, issuedAt)
	if err != nil {
		t.Fatalf("ListLiveForUser: %v", err)
	}
	if len(list) != 1 || list[0].ID != live.ID {
		t.Errorf("ListLiveForUser returned %d rows (%v), want exactly the one live session %s. "+
			"An expired row cannot authenticate, so offering to revoke it is a button that does nothing.",
			len(list), list, live.ID)
	}
}

// TestListLiveForUserIsNewestFirstAndTotallyOrdered asserts the ORDER BY rather
// than describing it.
//
// `created_at` alone leaves two sessions minted in the same millisecond in an
// undefined order, so a client rendering the list twice sees it jitter. The test
// creates three rows whose created_at values are close enough that the tiebreaker
// is what decides, and asserts the whole sequence rather than the head — a
// descending-order test that only looks at row zero passes against a reversed sort.
func TestListLiveForUserIsNewestFirstAndTotallyOrdered(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	ctx := context.Background()
	var made []Session
	for range 3 {
		s, _ := mintSession(t, pool, store, user.ID, "Ordered/1.0")
		made = append(made, s)
	}

	list, err := store.ListLiveForUser(ctx, pool, user.ID, issuedAt)
	if err != nil {
		t.Fatalf("ListLiveForUser: %v", err)
	}
	if len(list) != len(made) {
		t.Fatalf("ListLiveForUser returned %d rows, want %d", len(list), len(made))
	}

	for i := 1; i < len(list); i++ {
		older, newer := list[i-1], list[i]
		if older.CreatedAt.Before(newer.CreatedAt) {
			t.Errorf("row %d (%s) is older than row %d (%s); the list is not newest-first",
				i-1, older.CreatedAt, i, newer.CreatedAt)
		}
		if older.CreatedAt.Equal(newer.CreatedAt) && older.ID.String() < newer.ID.String() {
			t.Errorf("rows %d and %d share created_at %s and the ids are not descending, so the "+
				"order of two rows minted in the same instant is undefined and the list jitters",
				i-1, i, older.CreatedAt)
		}
	}
}

// TestRevokeOneForUserRefusesAnotherUsersSession is THE test in this file.
//
// It asserts on the ROW, through the digest, and in both directions: the stranger's
// token still resolves and the caller's own session did not get deleted instead.
// The second half matters because a `RevokeOneForUser` written as "find the row,
// then delete whatever id I was given" would delete the caller's session and leave
// the stranger's, which is the mirror image and just as wrong.
func TestRevokeOneForUserRefusesAnotherUsersSession(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	caller := newTestUser(t, pool)
	stranger := newTestUser(t, pool)

	ctx := context.Background()
	_, myToken := mintSession(t, pool, store, caller.ID, "Mine/1.0")
	theirs, theirToken := mintSession(t, pool, store, stranger.ID, "Theirs/1.0")

	revoked, err := store.RevokeOneForUser(ctx, pool, caller.ID, theirs.ID)
	if err != nil {
		t.Fatalf("RevokeOneForUser: %v", err)
	}
	if revoked {
		t.Fatal("RevokeOneForUser reported that it deleted a session belonging to another user. " +
			"The owner has to be in the DELETE's WHERE clause; a check above it is a window.")
	}

	if _, err := store.ByToken(ctx, pool, theirToken, issuedAt); err != nil {
		t.Errorf("the other user's session no longer authenticates after a revoke aimed at it: %v", err)
	}

	// And the caller's own session is untouched, which is the half a mirror-image
	// bug fails.
	if _, err := store.ByToken(ctx, pool, myToken, issuedAt); err != nil {
		t.Errorf("the caller's own session was deleted by a revoke that named somebody else's: %v", err)
	}
}

// TestRevokeOneForUserRevokesTheCallersOwnSession is the positive case, so the
// refusal above is a boundary rather than a method that never does anything.
func TestRevokeOneForUserRevokesTheCallersOwnSession(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	ctx := context.Background()
	target, targetToken := mintSession(t, pool, store, user.ID, "Target/1.0")
	_, keepToken := mintSession(t, pool, store, user.ID, "Keep/1.0")

	revoked, err := store.RevokeOneForUser(ctx, pool, user.ID, target.ID)
	if err != nil {
		t.Fatalf("RevokeOneForUser: %v", err)
	}
	if !revoked {
		t.Fatal("RevokeOneForUser reported false for the caller's own live session")
	}

	if _, err := store.ByToken(ctx, pool, targetToken, issuedAt); !errors.Is(err, ErrNotFound) {
		t.Errorf("the revoked session still resolves: %v, want ErrNotFound", err)
	}
	if _, err := store.ByToken(ctx, pool, keepToken, issuedAt); err != nil {
		t.Errorf("revoking one session also revoked another of the same user's: %v", err)
	}
}

// TestRevokeOneForUserIsFalseForAMissingSession is the idempotence half, and it is
// a false rather than an error for the reason the store's own comment gives: a
// client retrying a revoke should not get a 500 for having retried it.
//
// It is also the answer that keeps the route from being a uuid oracle — see the
// comment on Store.RevokeOneForUser.
func TestRevokeOneForUserIsFalseForAMissingSession(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	revoked, err := store.RevokeOneForUser(context.Background(), pool, user.ID, id.MustNew())
	if err != nil {
		t.Fatalf("RevokeOneForUser of a missing session = %v, want no error", err)
	}
	if revoked {
		t.Error("RevokeOneForUser reported true for an id no row has")
	}

	// And the nil uuid, which is a value no row can hold and which a store that
	// treated it as a wildcard would delete every session for.
	revoked, err = store.RevokeOneForUser(context.Background(), pool, user.ID, id.UUID{})
	if err != nil {
		t.Fatalf("RevokeOneForUser with the nil id = %v, want no error", err)
	}
	if revoked {
		t.Error("RevokeOneForUser reported true for the nil uuid")
	}
}

// TestSessionsAreRemovedWithTheirUserOnListing is the cascade, restated for the new
// query: a user deleted underneath a session listing leaves no row that the listing
// can return, so a stale session id is not something a client holds forever.
func TestSessionsAreRemovedWithTheirUserOnListing(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	user := newTestUser(t, pool)
	ctx := context.Background()
	_, _ = mintSession(t, pool, store, user.ID, "Doomed/1.0")

	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, user.ID); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}

	list, err := store.ListLiveForUser(ctx, pool, user.ID, issuedAt)
	if err != nil {
		t.Fatalf("ListLiveForUser: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("listing a deleted user's sessions returned %d rows: %v", len(list), list)
	}
}
