package tenancy

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestTenancyACredentialJoinSeesItsMembership(t *testing.T) {
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

	tenantA, tenantB := seedJoinRows(ctx, t, owner)

	for _, tc := range []struct {
		name      string
		digest    string
		wantAcct  string
		wantRole  string
		wantCount int
	}{
		{"tenant A's credential resolves with its role", digestFor(tenantA), tenantA, "owner", 1},
		{"tenant B's credential resolves with its role", digestFor(tenantB), tenantB, "owner", 1},
		{"a digest no row has resolves nothing", digestNoRowHas(digestFor(tenantA)), "", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := byDigestJoinAs(ctx, app, tc.digest, time.Now())
			if err != nil {
				t.Fatalf("running the ByDigest join as the app role: %v", err)
			}
			if len(got) != tc.wantCount {
				t.Fatalf("the ByDigest join presenting %.8s… returned %d rows, want %d.\n"+
					"  On master this is 0 for a live key: the api_keys half resolves by digest\n"+
					"  but the account_users half reads nothing in a digest-only transaction,\n"+
					"  so the JOIN is empty and the key 401s.", tc.digest, len(got), tc.wantCount)
			}
			if tc.wantCount == 1 && (got[0].accountID != tc.wantAcct || got[0].role != tc.wantRole) {
				t.Errorf("the ByDigest join returned account %s role %s, want account %s role %s: "+
					"a resolution that returns the wrong tenant's row is a cross-tenant read.",
					got[0].accountID, got[0].role, tc.wantAcct, tc.wantRole)
			}
		})
	}

	t.Run("a resolution sees exactly the presented credential's membership", func(t *testing.T) {
		var members []string
		err := inTransaction(ctx, app, `select anywaye.begin_credential($1)`, digestFor(tenantA),
			func(ctx context.Context, tx pgx.Tx) error {
				rows, err := tx.Query(ctx, `select account_id::text from account_users`)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					var id string
					if err := rows.Scan(&id); err != nil {
						return err
					}
					members = append(members, id)
				}
				return rows.Err()
			})
		if err != nil {
			t.Fatalf("reading account_users in a digest-A session: %v", err)
		}
		if len(members) != 1 || members[0] != tenantA {
			t.Errorf("a digest-A session saw memberships %v, want exactly [%s]: "+
				"the membership half of the resolution must be scoped to the credential "+
				"presented, never to the table.", members, tenantA)
		}

		var other int
		err = inTransaction(ctx, app, `select anywaye.begin_credential($1)`, digestFor(tenantA),
			func(ctx context.Context, tx pgx.Tx) error {
				return tx.QueryRow(ctx,
					`select count(*) from api_keys where token_digest = $1`, digestFor(tenantB)).Scan(&other)
			})
		if err != nil {
			t.Fatalf("reading another tenant's key in a digest-A session: %v", err)
		}
		if other != 0 {
			t.Errorf("a digest-A session saw tenant B's key row: that is a cross-tenant read.")
		}
	})

	t.Run("a revoked credential resolves nothing", func(t *testing.T) {
		if err := inTransaction(ctx, owner, `select anywaye.begin_account($1)`, tenantA,
			func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx,
					`update api_keys set revoked_at = now(), revoked_by = user_id where token_digest = $1`, digestFor(tenantA))
				return err
			}); err != nil {
			t.Fatalf("revoking tenant A's key: %v", err)
		}
		got, err := byDigestJoinAs(ctx, app, digestFor(tenantA), time.Now())
		if err != nil {
			t.Fatalf("running the ByDigest join for a revoked key: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("the ByDigest join returned %d rows for a REVOKED key, want 0: "+
				"a withdrawn credential must not resolve, membership or no.", len(got))
		}
	})
}

type joinRow struct {
	accountID string
	role      string
}

func byDigestJoinAs(ctx context.Context, conn *pgx.Conn, digest string, now time.Time) ([]joinRow, error) {
	const query = `
		SELECT k.account_id::text, au.role::text
		FROM api_keys k
		JOIN account_users au ON au.account_id = k.account_id AND au.user_id = k.user_id
		WHERE k.token_digest = $1
		  AND k.revoked_at IS NULL
		  AND k.expires_at > $2`

	var out []joinRow
	err := inTransaction(ctx, conn, `select anywaye.begin_credential($1)`, digest,
		func(ctx context.Context, tx pgx.Tx) error {
			rows, err := tx.Query(ctx, query, digest, now)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var r joinRow
				if err := rows.Scan(&r.accountID, &r.role); err != nil {
					return err
				}
				out = append(out, r)
			}
			return rows.Err()
		})
	return out, err
}

func seedJoinRows(ctx context.Context, t *testing.T, owner *pgx.Conn) (tenantA, tenantB string) {
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
			values (gen_random_uuid(), $1 || '-' || gen_random_uuid()::text || '@example.test', $2)`,
			accountID, credentialTestDigest); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture user: %v", err)
		}
		if _, err := tx.Exec(ctx, `select anywaye.begin_account($1)`, accountID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("setting the identity: %v", err)
		}
		if _, err := tx.Exec(ctx, `insert into accounts (id, name, slug) values ($1, $2, $3)`,
			accountID, "Join "+accountID[:8], "join-"+accountID[:8]); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture account: %v", err)
		}
		var userID string
		if err := tx.QueryRow(ctx, `select id::text from users where email like $1 || '-%'`, accountID).Scan(&userID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("reading back the fixture user: %v", err)
		}
		userIDs = append(userIDs, userID)
		if _, err := tx.Exec(ctx, `insert into account_users (account_id, user_id, role)
			values ($1, $2, 'owner')`, accountID, userID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture membership: %v", err)
		}
		if _, err := tx.Exec(ctx, `insert into api_keys
			(user_id, account_id, name, token_digest, scopes, expires_at)
			values ($1, $2, $3, $4, array['accounts:read'], $5)`,
			userID, accountID, keyNameFor(accountID), digestFor(accountID), time.Now().Add(24*time.Hour)); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture api key: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("committing tenant %s: %v", accountID[:8], err)
		}
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

	return tenantA, tenantB
}
