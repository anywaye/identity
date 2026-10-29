package tenancy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestTenancyACredentialResolvesByTheDigestTheCallerPresentedAndNothingElse(t *testing.T) {
	dsn := dsnOrSkip(t)

	ctx, cancel := context.WithTimeout(context.Background(), oneMinute)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })

	tenantA, tenantB := seedCredentialRows(ctx, t, conn)

	var fixtureOwn, fixtureVisible int
	if err := countOwnKeysAs(ctx, conn, tenantA, &fixtureOwn); err != nil {
		t.Fatalf("counting the fixture's own api keys under tenant A: %v", err)
	}
	if fixtureOwn != 1 {
		t.Fatalf("the fixture holds %d api keys OF ITS OWN under tenant A, want 1. The seed is wrong "+
			"and every assertion below would be measuring the wrong table.", fixtureOwn)
	}
	if err := countAsAccount(ctx, conn, tenantA, "", &fixtureVisible); err != nil {
		t.Fatalf("counting the fixture's api keys under tenant A: %v", err)
	}
	if fixtureVisible != 1 {
		t.Fatalf("tenant A can see %d api keys, want 1. Every assertion below reads 'a resolution sees "+
			"exactly one row', which is only a statement about browsing if the table holds more than one "+
			"row — and this is also where a resolve policy that has been widened past the presented digest "+
			"is caught first.", fixtureVisible)
	}

	var seen int
	if err := conn.QueryRow(ctx,
		`select count(*) from api_keys where token_digest = $1`, digestFor(tenantA)).Scan(&seen); err != nil {
		t.Fatalf("counting api_keys with no identity and no digest: %v", err)
	}
	if seen != 0 {
		t.Errorf("a credential lookup with NO identity and NO digest saw %d rows, want 0.\n"+
			"  The resolve policy's qualifier is the digest the caller presented, and a session that has\n"+
			"  presented nothing must read nothing. A non-zero here means the policy was widened.", seen)
	}

	for _, tc := range []struct {
		name      string
		accountID string
		digest    string
		want      int
	}{
		{"the credential it presented", tenantA, digestFor(tenantA), 1},
		{"the other tenant's credential", tenantB, digestFor(tenantB), 1},
		{"a digest no row has", tenantA, digestNoRowHas(digestFor(tenantA)), 0},
	} {
		t.Run("resolve "+tc.name, func(t *testing.T) {
			if tc.want == 0 {
				for _, seeded := range []string{digestFor(tenantA), digestFor(tenantB)} {
					if tc.digest == seeded {
						t.Fatalf("this case presents a digest the fixture seeded a row with, so it is " +
							"not a digest no row has, and asserting 0 rows against it asserts that the " +
							"policy hides a row that exists. Build it with digestNoRowHas, which " +
							"cannot return the digest it was given.")
					}
				}
			}

			seen, err := countAsCredential(ctx, conn, tc.digest)
			if err != nil {
				t.Fatalf("resolving by digest: %v", err)
			}
			if seen != tc.want {
				t.Errorf("a resolution session presenting %s… saw %d rows, want %d.\n"+
					"  The resolve policy's qualifier IS the presented digest, so this is either a row that\n"+
					"  does not exist being returned, or the row it names not being returned.",
					tc.digest[:8], seen, tc.want)
			}
		})
	}

	names, err := namesInResolution(ctx, conn, digestFor(tenantA))
	if err != nil {
		t.Fatalf("selecting every api_keys row in a resolution session: %v", err)
	}
	if len(names) != 1 || names[0] != keyNameFor(tenantA) {
		t.Errorf("select * from api_keys in a resolution session returned %v, want exactly [%s].\n"+
			"  The fixture holds TWO keys, so this is the assertion that says a resolution session reads one\n"+
			"  row rather than the table: the predicate is in the POLICY, so it narrows an unqualified SELECT\n"+
			"  too. Returning two rows here is a credential table-wide browse; returning none is a broken\n"+
			"  boundary or a resolution that did not open.",
			names, keyNameFor(tenantA))
	}

	var members int
	if err := countInResolution(ctx, conn, digestFor(tenantA),
		`select count(*) from account_users`, &members); err != nil {
		t.Fatalf("reading account_users in a resolution session: %v", err)
	}
	if members != 0 {
		t.Errorf("a resolution session read %d rows of account_users, want 0: the resolve policy is on\n"+
			"  api_keys and names one table, and opening a second one would be the mechanism having become a\n"+
			"  general bypass rather than a resolution.", members)
	}

	wrote, err := writeInResolution(ctx, conn, digestFor(tenantA), tenantA)
	if err != nil {
		t.Fatalf("attempting a write in a resolution session returned a transport error: %v", err)
	}
	if wrote {
		t.Error("an INSERT into api_keys SUCCEEDED inside a resolution session.\n" +
			"  The resolve policy is `for select`, so the ordinary insert policy still applies and a NULL\n" +
			"  account identity must be refused. A resolution session that can mint a credential is not a\n" +
			"  resolution.")
	}

	seen = 0
	if err := conn.QueryRow(ctx,
		`select count(*) from api_keys where token_digest = $1`, digestFor(tenantA)).Scan(&seen); err != nil {
		t.Fatalf("counting api_keys after the resolution transaction: %v", err)
	}
	if seen != 0 {
		t.Errorf("after the resolution transaction committed, the same connection still saw %d rows, want 0.\n"+
			"  The digest expired with its transaction, so this connection is an ordinary no-identity session\n"+
			"  again until requireAccountRole sets the account. A digest that outlived its transaction would\n"+
			"  travel back to the pool with the connection.", seen)
	}

	seen = 0
	if err := countAsAccount(ctx, conn, tenantA, digestFor(tenantA), &seen); err != nil {
		t.Fatalf("counting api_keys with its own identity: %v", err)
	}
	if seen != 1 {
		t.Errorf("a credential lookup with the credential's OWN account saw %d rows, want 1: adding a resolve\n"+
			"  policy must not have broken the ordinary account-scoped read, or the three-way denial this\n"+
			"  package exists to prove no longer holds on api_keys.", seen)
	}
	seen = 0
	if err := countAsAccount(ctx, conn, tenantA, digestFor(tenantB), &seen); err != nil {
		t.Fatalf("counting another tenant's credential: %v", err)
	}
	if seen != 0 {
		t.Errorf("with account A's identity set, account B's credential was VISIBLE (%d rows). "+
			"That is a cross-tenant read and it is the one failure this whole package exists to prevent.", seen)
	}
}

func countAsAccount(ctx context.Context, conn *pgx.Conn, accountID, digest string, out *int) error {
	return inTransaction(ctx, conn, `select anywaye.begin_account($1)`, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if digest == "" {
			return tx.QueryRow(ctx, `select count(*) from api_keys`).Scan(out)
		}
		return tx.QueryRow(ctx,
			`select count(*) from api_keys where token_digest = $1`, digest).Scan(out)
	})
}

func countOwnKeysAs(ctx context.Context, conn *pgx.Conn, accountID string, out *int) error {
	return inTransaction(ctx, conn, `select anywaye.begin_account($1)`, accountID,
		func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `select count(*) from api_keys where account_id = $1`, accountID).Scan(out)
		})
}

func countAsCredential(ctx context.Context, conn *pgx.Conn, digest string) (int, error) {
	var out int
	err := inTransaction(ctx, conn, `select anywaye.begin_credential($1)`, digest,
		func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`select count(*) from api_keys where token_digest = $1`, digest).Scan(&out)
		})
	return out, err
}

func namesInResolution(ctx context.Context, conn *pgx.Conn, digest string) ([]string, error) {
	var names []string
	err := inTransaction(ctx, conn, `select anywaye.begin_credential($1)`, digest,
		func(ctx context.Context, tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `select name from api_keys`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var name string
				if err := rows.Scan(&name); err != nil {
					return err
				}
				names = append(names, name)
			}
			return rows.Err()
		})
	return names, err
}

func countInResolution(ctx context.Context, conn *pgx.Conn, digest, query string, out *int) error {
	return inTransaction(ctx, conn, `select anywaye.begin_credential($1)`, digest,
		func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, query).Scan(out)
		})
}

func writeInResolution(ctx context.Context, conn *pgx.Conn, digest, accountID string) (bool, error) {
	var userID string
	if err := conn.QueryRow(ctx,
		`select id::text from users where email like $1 || '-%'`, accountID).Scan(&userID); err != nil {
		return false, fmt.Errorf("reading tenant %s's fixture user: %w", accountID[:8], err)
	}

	accepted := false
	err := inTransaction(ctx, conn, `select anywaye.begin_credential($1)`, digest,
		func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `savepoint resolution_write`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx,
				`insert into api_keys (user_id, account_id, name, token_digest, scopes, expires_at)
				 values ($1, $2, 'minted-in-a-resolution', $3, array['accounts:read'], $4)`,
				userID, accountID, digestNoRowHas(digest), time.Now().Add(24*time.Hour))
			if err != nil {
				if _, rbErr := tx.Exec(ctx, `rollback to savepoint resolution_write`); rbErr != nil {
					return rbErr
				}
				return nil
			}
			accepted = true
			return nil
		})
	return accepted, err
}

func inTransaction(ctx context.Context, conn *pgx.Conn, begin, arg string, fn func(context.Context, pgx.Tx) error) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning a transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, begin, arg); err != nil {
		return fmt.Errorf("issuing %s: %w", begin, err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	return nil
}

func seedCredentialRows(ctx context.Context, t *testing.T, conn *pgx.Conn) (tenantA, tenantB string) {
	t.Helper()

	if err := conn.QueryRow(ctx, `select gen_random_uuid()::text, gen_random_uuid()::text`).
		Scan(&tenantA, &tenantB); err != nil {
		t.Fatalf("minting tenant ids: %v", err)
	}

	userIDs := make([]string, 0, 2)

	for _, accountID := range []string{tenantA, tenantB} {
		tx, err := conn.Begin(ctx)
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
			accountID, "Credential "+accountID[:8], "cred-"+accountID[:8]); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture account: %v", err)
		}
		var userID string
		if err := tx.QueryRow(ctx, `select id::text from users where email like $1 || '-%'`, accountID).Scan(&userID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("reading back the fixture user: %v", err)
		}
		userIDs = append(userIDs, userID)
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
			if _, err := conn.Exec(bg, `delete from accounts where id = $1`, accountID); err != nil {
				t.Errorf("cleaning up tenant %s's account: %v", accountID[:8], err)
			}
		}
		for _, userID := range userIDs {
			if _, err := conn.Exec(bg, `delete from users where id = $1`, userID); err != nil {
				t.Errorf("cleaning up a fixture user: %v", err)
			}
		}
	})

	return tenantA, tenantB
}

func keyNameFor(accountID string) string { return "key-" + accountID[:8] }

func digestFor(accountID string) string {
	d := accountID + accountID
	if len(d) < 64 {
		d += d
	}
	return d[:64]
}

func digestNoRowHas(real string) string {
	if real[0] == '0' {
		return "1" + real[1:]
	}
	return "0" + real[1:]
}

func TestTheNoRowDigestIsNeverTheDigestItWasDerivedFrom(t *testing.T) {
	const idWithZeroInCharacter28 = "a1b2c3d4-e5f6-4a8b-9c0d-1e203a4b5c6d"


	for _, tc := range []struct {
		name string
		real string
	}{
		{"a digest that already begins with 0", "0" + strings.Repeat("a", 63)},
		{"a digest that begins with 1", "1" + strings.Repeat("a", 63)},
		{"a digest that begins with f", "f" + strings.Repeat("a", 63)},
		{"and the one that broke the old form", digestFor(idWithZeroInCharacter28)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := digestNoRowHas(tc.real)

			if got == tc.real {
				t.Errorf("digestNoRowHas returned the digest it was given, so a case built on it is " +
					"asserting that the policy hides a row that exists.")
			}
			if len(got) != 64 {
				t.Errorf("digestNoRowHas returned %d characters, want 64: it has to satisfy "+
					"api_keys_token_digest_length.", len(got))
			}
			if want := tc.real[1:]; got[1:] != want {
				t.Errorf("digestNoRowHas changed more than the first character: got %q, want the first "+
					"character replaced and characters 2-64 of %q", got, tc.real)
			}

			wantFirst := "0"
			if tc.real[0] == '0' {
				wantFirst = "1"
			}
			if string(got[0]) != wantFirst {
				t.Errorf("digestNoRowHas opened with %q, want %q", got[:1], wantFirst)
			}
		})
	}

	t.Run("and never, over generated tenant ids, with a control that can still fail", func(t *testing.T) {
		const samples = 100_000

		raw := make([]byte, samples*16)
		if _, err := rand.Read(raw); err != nil {
			t.Fatalf("reading entropy for the sample: %v", err)
		}

		var collided, controlCollided int
		for i := 0; i < samples; i++ {
			real := digestFor(uuidText(raw[i*16 : i*16+16]))
			if digestNoRowHas(real) == real {
				collided++
			}
			if control := real[:63] + "0"; control == real {
				controlCollided++
			}
		}

		if collided != 0 {
			t.Errorf("digestNoRowHas returned its input for %d of %d generated tenant ids; it must "+
				"never, and one is enough to put a security case back to one run in sixteen.",
				collided, samples)
		}
		if controlCollided < 1_000 {
			t.Errorf("the negative control collided %d times in %d, want more than 1000 (1/16 predicts "+
				"about %d). The sampler has stopped detecting collisions, so the count above is a green "+
				"that proves nothing.", controlCollided, samples, samples/16)
		}
		t.Logf("digestNoRowHas collided %d/%d; the form it replaced collided %d/%d (%.4f, 1/16 predicts 0.0625)",
			collided, samples, controlCollided, samples, float64(controlCollided)/float64(samples))
	})
}

func uuidText(b []byte) string {
	s := hex.EncodeToString(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

const credentialTestDigest = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$" +
	"bG9uZy1ub3QtaGEzaC1hLWZpeHR1cmUtZml4dHVyZQ"
