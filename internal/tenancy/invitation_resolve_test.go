package tenancy

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestTenancyAnInvitationResolvesByTheDigestTheCallerPresentedAndNothingElse
// is the invitation half of the credential mechanism, asserted against the real
// protected table.
//
// # WHAT IT EXERCISES
//
// `Service.Accept` resolves an invitation by `WHERE token_digest = $1` with no
// account to predicate on, because the account is what the lookup is FOR — the
// same shape that made every scoped token 401 before migrations/00016 gave
// `api_keys` a digest-scoped policy. `account_invitations` carried only account
// policies, so the same lookup read zero rows and every fresh invitation 404'd
// on redemption (the site-loop walk proved it live). migrations/00029 extends
// the same call to this table —
// `cafaye.protect_credential_table('account_invitations', 'token_digest')` —
// and `Accept` opens its transaction with `tenancy.BeginCredential`.
//
// # WHY HERE AND NOT ONLY IN internal/accounts
//
// The accounts proof drives the use case and would pass with the wiring while
// a widened policy stood behind it: a resolve policy of `using (true)` returns
// the invitation too. This file proves the NARROWNESS — exactly the presented
// row, no browse, no write, nothing after the transaction — as the application
// role, on the real tables. One is the proof the redemption works; the other
// is the proof it works for the reason stated.
//
// # WHY THE APP ROLE, REACHED BY SET ROLE
//
// Same reason as the credential-join proof: the tenancy proof connects as the
// owner and sets identities, which proves the policies exist; this proves what
// production answers, and production connects as identity_app.
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

	tenantA, tenantB := seedInvitationRows(t, ctx, owner)

	// 0. THE FIXTURE REALLY HOLDS TWO INVITATIONS, one per tenant. Every
	// "exactly one row" assertion below is only meaningful against a table
	// holding more than one: with a single row, "the table" and "that row"
	// are the same set and a table-wide SELECT would pass all of them. Both
	// counts run under their own account identity, so they hold whatever the
	// account policies do — they are a precondition on the seed, not on the
	// resolve policy under test.
	for _, tenant := range []string{tenantA, tenantB} {
		var own int
		if err := inTransaction(ctx, owner, `select cafaye.begin_account($1)`, tenant,
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

	// 1. NO DIGEST AND NO IDENTITY: nothing. This also catches the boundary
	// being ABSENT rather than too narrow: with no RLS at all the digest
	// predicate in the query would still match the row, so a non-zero here is
	// either a widened resolve policy or no policy.
	var seen int
	if err := app.QueryRow(ctx,
		`select count(*) from account_invitations where token_digest = $1`, digestFor(tenantA)).Scan(&seen); err != nil {
		t.Fatalf("counting invitations with no identity and no digest: %v", err)
	}
	if seen != 0 {
		t.Errorf("an invitation lookup with NO identity and NO digest saw %d rows, want 0.", seen)
	}

	// 2. THE RESOLUTION ITSELF: the presented digest returns its row, with NO
	// account identity set — which is the whole claim, because the account is
	// what the query is FOR and cannot also be what it is scoped by.
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
			if err := inTransaction(ctx, app, `select cafaye.begin_credential($1)`, tc.digest,
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

	// 3. IT CANNOT BROWSE. `select account_id` with no WHERE, inside a
	// digest-A session, returns exactly A's account — WHICH row, not merely
	// how many, because the fixture holds two and "one row" alone would also
	// describe a session that can see nothing.
	t.Run("a resolution cannot browse", func(t *testing.T) {
		var accounts []string
		if err := inTransaction(ctx, app, `select cafaye.begin_credential($1)`, digestFor(tenantA),
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

	// 4. IT CANNOT WRITE. `for select` and nothing else: a resolution session
	// meets the ordinary account policies on the write side, where a NULL
	// identity is 42501. The assertion is that the STATEMENT fails, unwound
	// to a savepoint so the refusal costs nothing else.
	t.Run("a resolution cannot write", func(t *testing.T) {
		accepted := false
		err := inTransaction(ctx, app, `select cafaye.begin_credential($1)`, digestFor(tenantA),
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

	// 5. AFTER THE TRANSACTION THE SESSION HAS NO IDENTITY. The digest is
	// transaction-local: a session-level digest would survive the pool and
	// hand one redemption's bearer token to the next connection leased.
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

// TestTheInvitationResolvePolicyIsInstalled is the control this file's
// resolution proof depends on: without the digest-scoped policy every case
// above reads zero rows and the file is green for the reason of asserting a
// defect. It names the policy and the qualifier, so a policy that stopped
// scoping by the presented digest is a red build here rather than a quiet one.
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
		    AND polname = 'account_invitations_cafaye_resolve'`,
	).Scan(&qual)
	if err != nil {
		t.Fatalf("reading the invitation resolve policy: %v. Without it, every resolution "+
			"case in this file reads zero rows for the wrong reason — the policy is their subject.", err)
	}
	if !strings.Contains(strings.ToLower(qual), "current_credential_digest") {
		t.Errorf("account_invitations_cafaye_resolve filters on %q, want a predicate naming "+
			"cafaye.current_credential_digest().", qual)
	}

	var idx int
	if err := owner.QueryRow(ctx,
		`select count(*) from pg_class where relname = 'account_invitations_cafaye_token_digest_idx'`,
	).Scan(&idx); err != nil {
		t.Fatalf("reading the digest index: %v", err)
	}
	if idx != 1 {
		t.Error("the digest index is missing: the table was protected without the credential " +
			"call, which is the half of the paired change that breaks redemption.")
	}
}

// seedInvitationRows writes one account, user and invitation per tenant, each
// under its own identity, and returns the account ids.
//
// The identities have to be set per row because the owner's INSERT is itself
// subject to `with check` — FORCE removed the exemption. The invitation's
// digest is digestFor(accountID), so each tenant's invitation has a stable,
// distinct value the test can present; the column's 64-character CHECK is what
// makes that shape mandatory rather than convenient.
func seedInvitationRows(t *testing.T, ctx context.Context, owner *pgx.Conn) (tenantA, tenantB string) {
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
		if _, err := tx.Exec(ctx, `select cafaye.begin_account($1)`, accountID); err != nil {
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
