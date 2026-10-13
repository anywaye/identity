package tenancy

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestTenancyACredentialJoinSeesItsMembership is the class of test the F2
// site-loop walk found missing: every suite in the repository is green while
// every API key 401s on introspection, because no test runs ByDigest's JOIN
// under the enforced boundary.
//
// WHAT IT EXERCISES. The exact shape of apikeys.Store.ByDigest —
// `api_keys JOIN account_users … WHERE token_digest = $1` — inside a
// transaction that carries ONLY the digest GUC, as the application role, on
// the real protected tables. `api_keys` resolves by digest since 00016, but
// the JOIN's other half, `account_users`, carries only account/user
// predicates, and the credential transaction sets neither — so the join reads
// zero rows and the lookup answers ErrNotFound (401) for a live key.
//
// WHY HERE AND NOT IN internal/apikeys. Every test there runs on a private
// fixture schema that dbtest.Schema clones with LIKE INCLUDING ALL, which does
// not copy row-level security. The RLS half is absent from those tests by
// construction, so a ByDigest test there passes with the wiring and would
// pass with no wiring at all. This is the same reason
// TestTenancyACredentialResolvesByTheDigestTheCallerPresentedAndNothingElse
// runs against the real tables.
//
// WHY THE APP ROLE, REACHED BY SET ROLE. The tenancy proof connects as the
// owner and sets identities; the owner is named in every policy, so that
// proves the policies exist. This test proves what production answers, and
// production connects as identity_app. The connection below is the owner DSN
// with `SET ROLE identity_app` — the same impersonation the package proof
// uses, possible because the cluster grants the app role to the owner — so
// every policy evaluates for exactly the role production answers under. What
// SET ROLE does not prove is that the role can log in at all; that is proven
// everywhere dbtest.Pool connects as it, and is not this test's claim.
func TestTenancyACredentialJoinSeesItsMembership(t *testing.T) {
	ownerDSN := dsnOrSkip(t)

	ctx, cancel := context.WithTimeout(context.Background(), oneMinute)
	defer cancel()

	owner, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("connecting as the owner: %v", err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })

	// A second connection for the assertions, impersonating the login
	// production uses. Seeding stays on the owner connection: the app role
	// cannot write the unprotected tables the fixture is built from, and the
	// seed is not what is under test.
	app, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("connecting for the app-role assertions: %v", err)
	}
	t.Cleanup(func() { _ = app.Close(context.Background()) })
	if _, err := app.Exec(ctx, `SET ROLE identity_app`); err != nil {
		t.Fatalf("assuming the app role: %v", err)
	}

	tenantA, tenantB := seedJoinRows(ctx, t, owner)

	// 1. THE RESOLUTION ITSELF. A live key's digest returns its row and its
	// owner's live role, with no account identity set — the account is what
	// the lookup is FOR and cannot also be what it is scoped by.
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

	// 2. THE NARROWNESS. A digest-A session reading account_users sees exactly
	// A's membership row — the row the presented credential names — and a
	// digest-A session naming B's digest directly sees nothing. The fix must
	// open the membership of the presented credential and nothing else.
	t.Run("a resolution sees exactly the presented credential's membership", func(t *testing.T) {
		var members []string
		err := inTransaction(ctx, app, `select cafaye.begin_credential($1)`, digestFor(tenantA),
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
		err = inTransaction(ctx, app, `select cafaye.begin_credential($1)`, digestFor(tenantA),
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

	// 3. A WITHDRAWN CREDENTIAL OPENS NOTHING. Revoking A's key must close the
	// membership half again: the row is still there, the digest still matches,
	// and the resolution must still answer nothing.
	t.Run("a revoked credential resolves nothing", func(t *testing.T) {
		// The revocation sets the whole triple: the table's CHECK refuses a
		// revoked_at without its revoked_by, so a one-column UPDATE is a
		// 23514 rather than a revocation. revoked_by is the key's own user,
		// read back rather than threaded through the seed.
		if err := inTransaction(ctx, owner, `select cafaye.begin_account($1)`, tenantA,
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

// joinRow is one row of the ByDigest-shaped join: whose key, and the role its
// owner holds right now.
type joinRow struct {
	accountID string
	role      string
}

// byDigestJoinAs runs the ByDigest query TEXT inside a digest-only
// transaction as the connected role.
//
// It is the query rather than the method, for the reason the package's other
// RLS proofs give: internal/apikeys cannot be imported here (it reaches this
// package through internal/accounts), so the shape is copied and the comment
// on Store.ByDigest names this test as the proof that shape holds under RLS.
// If the query changes there, this copy must change with it — a drift that
// shows up as a red join, which is the loud direction.
func byDigestJoinAs(ctx context.Context, conn *pgx.Conn, digest string, now time.Time) ([]joinRow, error) {
	const query = `
		SELECT k.account_id::text, au.role::text
		FROM api_keys k
		JOIN account_users au ON au.account_id = k.account_id AND au.user_id = k.user_id
		WHERE k.token_digest = $1
		  AND k.revoked_at IS NULL
		  AND k.expires_at > $2`

	var out []joinRow
	err := inTransaction(ctx, conn, `select cafaye.begin_credential($1)`, digest,
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

// seedJoinRows writes one account, user, MEMBERSHIP and api key per tenant,
// each under its own identity, and returns the account ids.
//
// The membership row is the difference from seedCredentialRows: without it the
// join under test has nothing to find even on a correct database, and the
// resolution would read zero rows for a reason the test built rather than the
// boundary. Every assertion in this file is only meaningful with it present.
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
		if _, err := tx.Exec(ctx, `select cafaye.begin_account($1)`, accountID); err != nil {
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
