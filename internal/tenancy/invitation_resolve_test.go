package tenancy

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestTenancyAnInvitationResolvesByTheDigestTheCallerPresentedAndNothingElse(t *testing.T) {
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

	tenantA, tenantB := seedInvitationRows(ctx, t, owner)

	for _, tenant := range []string{tenantA, tenantB} {
		var own int
		if err := inTransaction(ctx, owner, `select anywaye.begin_account($1)`, tenant,
			func(ctx context.Context, tx pgx.Tx) error {
				return tx.QueryRow(ctx, `select count(*) from account_invitations where account_id = $1`, tenant).Scan(&own)
			}); err != nil {
			t.Fatalf("counting tenant %s's own invitation: %v", tenant[:8], err)
		}
		if own != 1 {
			t.Fatalf("tenant %s holds %d invitations of its own, want 1: the seed is wrong "+
				"and every assertion below measures the wrong table.", tenant[:8], own)
		}
	}

	var seen int
	if err := app.QueryRow(ctx,
		`select count(*) from account_invitations where token_digest = $1`, digestFor(tenantA)).Scan(&seen); err != nil {
		t.Fatalf("counting invitations with no identity and no digest: %v", err)
	}
	if seen != 0 {
		t.Errorf("an invitation lookup with NO identity and NO digest saw %d rows, want 0.", seen)
	}

	for _, tc := range []struct {
		name   string
		digest string
		want   int
	}{
		{"the invitation it presented", digestFor(tenantA), 1},
		{"the other tenant's invitation", digestFor(tenantB), 1},
		{"a digest no row has", digestNoRowHas(digestFor(tenantA)), 0},
	} {
		t.Run("resolve "+tc.name, func(t *testing.T) {
			if tc.want == 0 {
				for _, seeded := range []string{digestFor(tenantA), digestFor(tenantB)} {
					if tc.digest == seeded {
						t.Fatalf("this case presents a digest the fixture seeded, so it is not " +
							"a digest no row has. Build it with digestNoRowHas.")
					}
				}
			}
			var got int
			if err := inTransaction(ctx, app, `select anywaye.begin_credential($1)`, tc.digest,
				func(ctx context.Context, tx pgx.Tx) error {
					return tx.QueryRow(ctx,
						`select count(*) from account_invitations where token_digest = $1`, tc.digest).Scan(&got)
				}); err != nil {
				t.Fatalf("resolving by digest: %v", err)
			}
			if got != tc.want {
				t.Errorf("a resolution session presenting %.8s… saw %d rows, want %d.", tc.digest, got, tc.want)
			}
		})
	}

	t.Run("a resolution cannot browse", func(t *testing.T) {
		var accounts []string
		if err := inTransaction(ctx, app, `select anywaye.begin_credential($1)`, digestFor(tenantA),
			func(ctx context.Context, tx pgx.Tx) error {
				rows, err := tx.Query(ctx, `select account_id::text from account_invitations`)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					var id string
					if err := rows.Scan(&id); err != nil {
						return err
					}
					accounts = append(accounts, id)
				}
				return rows.Err()
			}); err != nil {
			t.Fatalf("selecting every invitation in a resolution session: %v", err)
		}
		if len(accounts) != 1 || accounts[0] != tenantA {
			t.Errorf("select * in a digest-A session returned %v, want exactly [%s]: the predicate "+
				"is in the POLICY, so it narrows an unqualified SELECT too.", accounts, tenantA)
		}
	})

	t.Run("a resolution cannot write", func(t *testing.T) {
		accepted := false
		err := inTransaction(ctx, app, `select anywaye.begin_credential($1)`, digestFor(tenantA),
			func(ctx context.Context, tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `savepoint invitation_write`); err != nil {
					return err
				}
				_, err := tx.Exec(ctx,
					`insert into account_invitations (account_id, email, role, token_digest, created_at, expires_at, invited_by)
					 values ($1, $2, 'member', $3, now(), now() + interval '7 days', (select id from users limit 1))`,
					tenantA, "browse-write@example.test", digestNoRowHas(digestFor(tenantA)))
				if err != nil {
					if _, rbErr := tx.Exec(ctx, `rollback to savepoint invitation_write`); rbErr != nil {
						return rbErr
					}
					return nil
				}
				accepted = true
				return nil
			})
		if err != nil {
			t.Fatalf("attempting a write in a resolution session returned a transport error: %v", err)
		}
		if accepted {
			t.Error("an INSERT into account_invitations SUCCEEDED inside a resolution session: " +
				"presenting a token must grant no write scope.")
		}
	})

	seen = 0
	if err := app.QueryRow(ctx,
		`select count(*) from account_invitations where token_digest = $1`, digestFor(tenantA)).Scan(&seen); err != nil {
		t.Fatalf("counting invitations after the resolution transaction: %v", err)
	}
	if seen != 0 {
		t.Errorf("after the resolution committed the same connection still saw %d rows, want 0: "+
			"the digest outlived its transaction.", seen)
	}
}

func TestTheInvitationResolvePolicyIsInstalled(t *testing.T) {
	ownerDSN := dsnOrSkip(t)

	ctx, cancel := context.WithTimeout(context.Background(), oneMinute)
	defer cancel()

	owner, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("connecting as the owner: %v", err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })

	var qual string
	err = owner.QueryRow(ctx,
		`SELECT pg_get_expr(polqual, polrelid) FROM pg_policy
		  WHERE polrelid = 'account_invitations'::regclass
		    AND polname = 'account_invitations_anywaye_resolve'`,
	).Scan(&qual)
	if err != nil {
		t.Fatalf("reading the invitation resolve policy: %v. Without it, every resolution "+
			"case in this file reads zero rows for the wrong reason — the policy is their subject.", err)
	}
	if !strings.Contains(strings.ToLower(qual), "current_credential_digest") {
		t.Errorf("account_invitations_anywaye_resolve filters on %q, want a predicate naming "+
			"anywaye.current_credential_digest().", qual)
	}

	var idx int
	if err := owner.QueryRow(ctx,
		`select count(*) from pg_class where relname = 'account_invitations_anywaye_token_digest_idx'`,
	).Scan(&idx); err != nil {
		t.Fatalf("reading the digest index: %v", err)
	}
	if idx != 1 {
		t.Error("the digest index is missing: the table was protected without the credential " +
			"call, which is the half of the paired change that breaks redemption.")
	}
}

func seedInvitationRows(ctx context.Context, t *testing.T, owner *pgx.Conn) (tenantA, tenantB string) {
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
			accountID, "Invitation "+accountID[:8], "inv-"+accountID[:8]); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture account: %v", err)
		}
		var userID string
		if err := tx.QueryRow(ctx, `select id::text from users where email like $1 || '-%'`, accountID).Scan(&userID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("reading back the fixture user: %v", err)
		}
		userIDs = append(userIDs, userID)
		if _, err := tx.Exec(ctx, `insert into account_invitations
			(account_id, email, role, token_digest, created_at, expires_at, invited_by)
			values ($1, $2, 'member', $3, now(), now() + interval '7 days', $4)`,
			accountID, "invitee-"+accountID[:8]+"@example.test", digestFor(accountID), userID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture invitation: %v", err)
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
