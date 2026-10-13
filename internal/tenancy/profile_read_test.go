package tenancy

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestTenancyTheProfileReadSeesOneUsersMembershipsAndNothingElse is the proof for
// the file tg-a1 added to the declaration's `scope.sources`:
// `internal/oidc/profiles.go`.
//
// WHAT THE FILE DOES AND WHY IT NEEDED A PROOF. `pgProfileReader.Profile` reads
// `account_users` twice while assembling a token's claims — the personal-account
// name, and the membership list behind the `accounts` claim. Neither read carries
// an `account_id` predicate: both are `where au.user_id = $1`, because the subject
// IS the caller at that point and there is no account to name. Until the file was
// written into the declaration, `tenancy-check` never scanned it, so nothing
// outside this package had ever established that the two reads are narrow under
// the policies. Every existing accounts-claim test asserts through a fake
// ProfileReader, so the real read was a statement about the boundary nobody had
// run.
//
// THE STATEMENT UNDER TEST IS THE ONE IN THE FILE, shape for shape (it is copied
// below rather than imported, because a test that reached into internal/oidc for
// its SQL would pin this package's query to that package's next edit):
//
//	select a.id, a.name, a.slug, au.role::text, a.personal
//	from account_users au
//	join accounts a on a.id = au.account_id
//	where au.user_id = $1
//	order by a.created_at, a.id
//
// THE FOUR STATES, and each is a state the read can actually be run in:
//
//	no identity      what production does — the userinfo path reads through
//	                 `db.Direct{Pool: pool}`, and a bare pooled connection
//	                 carries no GUC. The answer is ZERO rows.
//	begin_user(sub)  the subject's own identity, the state that makes the read
//	                 do its job. Exactly the subject's rows.
//	begin_user(other) another user's identity against the subject's predicate.
//	                 ZERO rows — an identity must not widen a predicate it does
//	                 not name.
//	begin_account(other) the other tenant's ACCOUNT identity. ZERO rows.
//
// WHY HERE AND NOT IN internal/oidc: the same reason
// `credential_join_test.go` gives. Tests there run on cloned fixture schemas
// `LIKE … INCLUDING ALL`, which copies indexes and not row-level security, so a
// read asserted there would pass whether or not the policies hold it. The real
// tables are the only place this statement's boundary exists.
//
// WHY THE APP ROLE, REACHED BY SET ROLE: production connects as identity_app. The
// owner is named in every policy too, so an owner-seated read proves less than
// the answer production gives.
func TestTenancyTheProfileReadSeesOneUsersMembershipsAndNothingElse(t *testing.T) {
	ownerDSN := dsnOrSkip(t)

	ctx, cancel := context.WithTimeout(context.Background(), oneMinute)
	defer cancel()

	owner, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("connecting as the owner: %v", err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })

	// A second connection for the assertions, impersonating the login production
	// uses. Seeding stays on the owner connection: the app role cannot write the
	// membership rows this fixture needs, and the seed is not what is under test.
	app, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("connecting for the app-role assertions: %v", err)
	}
	t.Cleanup(func() { _ = app.Close(context.Background()) })
	if _, err := app.Exec(ctx, `SET ROLE identity_app`); err != nil {
		t.Fatalf("assuming the app role: %v", err)
	}

	tenantA, userA, tenantB, userB := seedProfileRows(ctx, t, owner)

	// The read itself. `profiles.go`'s shape, verbatim — plus the transaction the
	// identity needs. `cafaye.begin_user/1` is `set_config(..., is_local => true)`,
	// so its value lasts as long as the TRANSACTION that set it and no longer: on
	// an autocommit statement it is gone before the next statement starts, which
	// is the same trap `tenancy.BeginUser`'s own doc comment describes. A test
	// that ran the read outside a transaction would read zero rows everywhere and
	// prove nothing.
	const memberships = `
		select a.id::text, au.role::text
		from account_users au
		join accounts a on a.id = au.account_id
		where au.user_id = $1
		order by a.created_at, a.id`

	// One identity step: the statement and its argument, or nil for the ones that
	// take none (`begin_user(null)` clears rather than names).
	type step struct {
		sql string
		arg any
	}

	readWith := func(t *testing.T, subject string, identity []step) []string {
		t.Helper()
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatalf("beginning the read's transaction: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		for _, s := range identity {
			var err error
			if s.arg == nil {
				_, err = tx.Exec(ctx, s.sql)
			} else {
				_, err = tx.Exec(ctx, s.sql, s.arg)
			}
			if err != nil {
				t.Fatalf("setting the identity (%s): %v", s.sql, err)
			}
		}
		rows, err := tx.Query(ctx, memberships, subject)
		if err != nil {
			t.Fatalf("running the profile read as the app role: %v", err)
		}
		defer rows.Close()
		var got []string
		for rows.Next() {
			var accountID, role string
			if err := rows.Scan(&accountID, &role); err != nil {
				t.Fatalf("scanning a membership: %v", err)
			}
			got = append(got, accountID+":"+role)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterating the memberships: %v", err)
		}
		return got
	}

	// 0. THE FIXTURE IS REAL, which is what makes every zero below mean
	// something. Each membership is counted under its OWN tenant's identity —
	// the owner is subject to these policies too (force row-level security), so
	// an identity-less count on the owner connection reads zero and would prove
	// nothing. Two separate reads, because no single identity sees both rows and
	// that is the point.
	for _, tc := range []struct{ tenant, user string }{{tenantA, userA}, {tenantB, userB}} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatalf("beginning the fixture count: %v", err)
		}
		if _, err := tx.Exec(ctx, `select cafaye.begin_account($1)`, tc.tenant); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("setting the tenant identity for the count: %v", err)
		}
		var seeded int
		if err := tx.QueryRow(ctx, `select count(*) from account_users where user_id = $1`,
			tc.user).Scan(&seeded); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("counting the seeded memberships: %v", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatalf("rolling the fixture count back: %v", err)
		}
		if seeded != 1 {
			t.Fatalf("tenant %s's fixture holds %d memberships, want 1: a zero-row "+
				"read below would prove nothing against an empty table", tc.tenant[:8], seeded)
		}
	}

	// 1. NO IDENTITY — the state production's userinfo path actually runs in. A
	// bare pool carries no GUC, and both policies filter an unnamed caller out.
	cleared := []step{{sql: `select cafaye.begin_user(null)`}, {sql: `select cafaye.begin_account(null)`}}
	if got := readWith(t, userA, cleared); len(got) != 0 {
		t.Errorf("with NO identity the profile read returned %v: a request that "+
			"authenticated nobody is reading account data", got)
	}

	// 2. THE SUBJECT'S OWN IDENTITY. The positive control, and the only arm a
	// deny-everything policy set cannot pass.
	ownUser := []step{{sql: `select cafaye.begin_user($1)`, arg: userA}, {sql: `select cafaye.begin_account(null)`}}
	if got := readWith(t, userA, ownUser); len(got) != 1 || got[0] != tenantA+":owner" {
		t.Errorf("with the subject's own identity the profile read returned %v, "+
			"want exactly [%s:owner]", got, tenantA)
	}

	// 3. ANOTHER USER'S IDENTITY against the subject's predicate. Zero rows: the
	// identity a session carries must not widen a WHERE clause it does not name.
	// The twin query — user B's predicate under user B's identity — is the
	// positive control, so a zero here cannot be RLS being broken.
	otherUser := []step{{sql: `select cafaye.begin_user($1)`, arg: userB}, {sql: `select cafaye.begin_account(null)`}}
	if got := readWith(t, userA, otherUser); len(got) != 0 {
		t.Errorf("with ANOTHER user's identity the profile read returned %v, want "+
			"none: an identity widened a predicate it does not name", got)
	}
	if got := readWith(t, userB, otherUser); len(got) != 1 || got[0] != tenantB+":owner" {
		t.Errorf("with user B's own identity the profile read returned %v, want "+
			"exactly [%s:owner] — a zero above must be narrowness, not a broken read",
			got, tenantB)
	}

	// 4. THE OTHER TENANT'S ACCOUNT IDENTITY against the subject's predicate.
	// Zero rows: the account side of the boundary holds the read too.
	otherAccount := []step{{sql: `select cafaye.begin_user(null)`}, {sql: `select cafaye.begin_account($1)`, arg: tenantB}}
	if got := readWith(t, userA, otherAccount); len(got) != 0 {
		t.Errorf("with ANOTHER tenant's account identity the profile read returned "+
			"%v, want none", got)
	}

	// 5. AND THE READ IS NOT SIMPLY BROKEN UNDER THE APP ROLE: an account
	// identity naming tenant A returns tenant A's row. This is the arm that
	// tells narrowness apart from an empty set.
	ownAccount := []step{{sql: `select cafaye.begin_user(null)`}, {sql: `select cafaye.begin_account($1)`, arg: tenantA}}
	if got := readWith(t, userA, ownAccount); len(got) != 1 || got[0] != tenantA+":owner" {
		t.Errorf("with tenant A's own account identity the profile read returned "+
			"%v, want exactly [%s:owner]", got, tenantA)
	}
}

// seedProfileRows writes two accounts, one user each and one membership each, and
// removes them when the test ends. The shape of the other seeders in this package:
// fixture rows are written by the OWNER under `begin_account`, because the insert
// policy is `with check (account_id = (select cafaye.current_account_id()))` and a
// writer with no identity is refused — the write-side twin of the denial these
// tests are about.
func seedProfileRows(ctx context.Context, t *testing.T, owner *pgx.Conn) (tenantA, userA, tenantB, userB string) {
	t.Helper()

	if err := owner.QueryRow(ctx, `select gen_random_uuid()::text, gen_random_uuid()::text`).
		Scan(&tenantA, &tenantB); err != nil {
		t.Fatalf("minting tenant ids: %v", err)
	}

	userIDs := make([]string, 0, 2)
	for _, accountID := range []string{tenantA, tenantB} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatalf("beginning a transaction: %v", err)
		}
		if _, err := tx.Exec(ctx, `insert into users (id, email, password_digest)
			values (gen_random_uuid(), 'profile-' || $1 || '@example.test', 'seed')`,
			accountID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture user: %v", err)
		}
		var userID string
		if err := tx.QueryRow(ctx, `select id::text from users where email = 'profile-' || $1 || '@example.test'`,
			accountID).Scan(&userID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("reading back the fixture user: %v", err)
		}
		if _, err := tx.Exec(ctx, `select cafaye.begin_account($1)`, accountID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("setting the identity: %v", err)
		}
		if _, err := tx.Exec(ctx, `insert into accounts (id, name, slug) values ($1, $2, $3)`,
			accountID, "Profile "+accountID[:8], "profile-"+accountID[:8]); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture account: %v", err)
		}
		if _, err := tx.Exec(ctx, `insert into account_users (account_id, user_id, role)
			values ($1, $2, 'owner')`, accountID, userID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture membership: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("committing tenant %s: %v", accountID[:8], err)
		}
		userIDs = append(userIDs, userID)
	}

	t.Cleanup(func() {
		bg := context.Background()
		for _, accountID := range []string{tenantA, tenantB} {
			if _, err := owner.Exec(bg, `delete from accounts where id = $1`, accountID); err != nil {
				t.Errorf("cleaning up tenant %s's account: %v", accountID[:8], err)
			}
		}
		for _, userID := range userIDs {
			if _, err := owner.Exec(bg, `delete from users where id = $1`, userID); err != nil {
				t.Errorf("cleaning up fixture user %s: %v", userID[:8], err)
			}
		}
	})

	return tenantA, userIDs[0], tenantB, userIDs[1]
}
