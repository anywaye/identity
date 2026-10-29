package tenancy

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestTenancyTheProfileReadSeesOneUsersMembershipsAndNothingElse(t *testing.T) {
	ownerDSN := dsnOrSkip(t)

	ctx, cancel := context.WithTimeout(context.Background(), oneMinute)
	defer cancel()

	owner, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("connecting as the owner: %v", err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })

	app, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("connecting for the app-role assertions: %v", err)
	}
	t.Cleanup(func() { _ = app.Close(context.Background()) })
	if _, err := app.Exec(ctx, `SET ROLE identity_app`); err != nil {
		t.Fatalf("assuming the app role: %v", err)
	}

	tenantA, userA, tenantB, userB := seedProfileRows(ctx, t, owner)

	const memberships = `
		select a.id::text, au.role::text
		from account_users au
		join accounts a on a.id = au.account_id
		where au.user_id = $1
		order by a.created_at, a.id`

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

	for _, tc := range []struct{ tenant, user string }{{tenantA, userA}, {tenantB, userB}} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatalf("beginning the fixture count: %v", err)
		}
		if _, err := tx.Exec(ctx, `select anywaye.begin_account($1)`, tc.tenant); err != nil {
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

	cleared := []step{{sql: `select anywaye.begin_user(null)`}, {sql: `select anywaye.begin_account(null)`}}
	if got := readWith(t, userA, cleared); len(got) != 0 {
		t.Errorf("with NO identity the profile read returned %v: a request that "+
			"authenticated nobody is reading account data", got)
	}

	ownUser := []step{{sql: `select anywaye.begin_user($1)`, arg: userA}, {sql: `select anywaye.begin_account(null)`}}
	if got := readWith(t, userA, ownUser); len(got) != 1 || got[0] != tenantA+":owner" {
		t.Errorf("with the subject's own identity the profile read returned %v, "+
			"want exactly [%s:owner]", got, tenantA)
	}

	otherUser := []step{{sql: `select anywaye.begin_user($1)`, arg: userB}, {sql: `select anywaye.begin_account(null)`}}
	if got := readWith(t, userA, otherUser); len(got) != 0 {
		t.Errorf("with ANOTHER user's identity the profile read returned %v, want "+
			"none: an identity widened a predicate it does not name", got)
	}
	if got := readWith(t, userB, otherUser); len(got) != 1 || got[0] != tenantB+":owner" {
		t.Errorf("with user B's own identity the profile read returned %v, want "+
			"exactly [%s:owner] — a zero above must be narrowness, not a broken read",
			got, tenantB)
	}

	otherAccount := []step{{sql: `select anywaye.begin_user(null)`}, {sql: `select anywaye.begin_account($1)`, arg: tenantB}}
	if got := readWith(t, userA, otherAccount); len(got) != 0 {
		t.Errorf("with ANOTHER tenant's account identity the profile read returned "+
			"%v, want none", got)
	}

	ownAccount := []step{{sql: `select anywaye.begin_user(null)`}, {sql: `select anywaye.begin_account($1)`, arg: tenantA}}
	if got := readWith(t, userA, ownAccount); len(got) != 1 || got[0] != tenantA+":owner" {
		t.Errorf("with tenant A's own account identity the profile read returned "+
			"%v, want exactly [%s:owner]", got, tenantA)
	}
}

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
		if _, err := tx.Exec(ctx, `select anywaye.begin_account($1)`, accountID); err != nil {
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
