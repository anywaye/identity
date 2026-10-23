// Package dbtest gives integration tests a real Postgres.
//
// It is a normal package rather than a _test.go file so that every package's
// tests can share it. Nothing imports it outside tests, so it contributes
// nothing to the service binary — `go list -deps ./cmd/identity` does not reach
// it.
//
// # Isolation
//
// `go test ./...` runs packages in parallel, and every package in this service
// shares one TEST_DATABASE_URL. So the tests here must not assume they have the
// database to themselves, and there is deliberately no TRUNCATE helper called
// from ordinary tests: a global truncate from internal/users would delete
// internal/sessions' fixtures mid-run, and the failure looks like a
// non-deterministic bug in the code under test rather than in the harness.
//
// Each test instead claims a unique email address, which makes it independent of
// every other test in every other package. Reset is available for a deliberate
// wipe and is not called automatically.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/platform/db"
)

// EnvVar names the environment variable that points at a throwaway database.
//
// IT IS THE OWNER, and that is a decision with two credentials behind it rather
// than one. `docker-compose.yml` logs the running service in as `identity_app`;
// the role here is the OWNER, because a test has to do two things at once and no
// single role can do both. It applies migrations, creates the private schemas in
// Schema, truncates in Reset, and seeds fixture rows the application is then
// supposed to be unable to see — none of which the application role may do at
// all. Meanwhile the pool UNDER TEST is the app role, so a query in a test is
// answered under the same policies and the same grants production answers it
// under. One DSN, two roles, and the split is the only arrangement in which both
// claims are true at once.
const EnvVar = "TEST_DATABASE_URL"

// appRoleSuffix is kit's rule for the login role's name, and it is the same rule
// migrations/00016's `protect_table` defaults to (`current_user || '_app'`).
//
// Writing it here as a suffix rather than taking a second variable is the point:
// a second DSN would be a second thing to configure, and a second thing to get
// wrong in a way nothing notices — a test DSN left naming the owner is a suite
// that reports the boundary proven while running as the one role the boundary
// exempts. Deriving it means there is no configuration in which the pool under
// test is the owner, and assertAppRole reads the role back off the connection so
// a derivation that stops deriving is a red build rather than a quiet one.
const appRoleSuffix = "_app"

// AppDSN returns EnvVar with the user replaced by the app login role, and is the
// DSN every pool under test is opened with.
//
// IT IS DERIVED, NOT CONFIGURED, and the reason is appRoleSuffix's. The password
// is left alone: every role in a development cluster takes the cluster password by
// design (kit's `10-cluster.sh`), and CI's job creates `identity_app` with the same
// literal it creates the owner with, so this is a real login with real
// authentication — not a `SET ROLE`, which would succeed against a role that
// cannot log in at all and so would prove nothing about the one that can.
func AppDSN(t *testing.T) string {
	t.Helper()

	owner := dsn(t)
	parsed, err := url.Parse(owner)
	if err != nil {
		// Pool already validated this DSN, so a parse failure here would be a bug
		// in this helper rather than bad configuration.
		panic("dbtest: parsing " + EnvVar + ": " + err.Error())
	}

	login := parsed.User.Username() + appRoleSuffix
	if login == appRoleSuffix {
		t.Fatalf("%s carries no user name, so the app role derived from it is %q. "+
			"%s is the OWNER credential: it has to name a role, and the pool under "+
			"test connects as that role plus %q.", EnvVar, login, EnvVar, appRoleSuffix)
	}
	password, _ := parsed.User.Password()
	parsed.User = url.UserPassword(login, password)

	return parsed.String()
}

// Pool returns a pool connected as the app login role, skipping the test when
// EnvVar is unset. The schema must already be applied — migrations are a deploy
// step, not a test step — so run `goose -dir migrations postgres "$DATABASE_URL"
// up` first, as migrations/README.md describes.
//
// NOT the owner, and assertAppRole below is what stops that from being a claim.
// Postgres exempts a table's owner from its own row-level-security policies, so
// every account boundary in migrations/00016 was inert for a pool that ran as it:
// `select count(*) from account_users` would have answered with the whole table
// and the assertion beside it would have passed for the wrong reason.
func Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := AppDSN(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, dsn, db.DefaultOptions())
	if err != nil {
		t.Fatalf("opening a pool against %s as the app role: %v", EnvVar, err)
	}
	t.Cleanup(pool.Close)

	// A pool is lazy, so Open succeeding says nothing about the server being
	// there. Ping here, where the failure can name the variable that is wrong,
	// rather than inside an assertion about a users row.
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("%s is set but not reachable (%v). Is the server up, and are the "+
			"migrations applied? `goose -dir migrations postgres \"$DATABASE_URL\" up`", EnvVar, err)
	}

	assertAppRole(t, pool)

	return pool
}

// assertAppRole fails the test unless the pool is logged in as the app role.
//
// It is four lines and it is the only thing standing between this package and a
// silent regression to the owner: nothing about connecting successfully says which
// role you are, and a pool that had quietly gone back to the owner would pass
// every test in the repository while testing nothing about the boundary.
// `current_user` is the name a policy is evaluated against, so it is the one worth
// reading back.
func assertAppRole(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var who string
	if err := pool.QueryRow(ctx, `select current_user`).Scan(&who); err != nil {
		t.Fatalf("reading current_user from the pool under test: %v", err)
	}
	if !strings.HasSuffix(who, appRoleSuffix) {
		t.Fatalf("the pool under test is logged in as %q, which is not an app login role. "+
			"A pool on the owner bypasses every row-level-security policy in "+
			"migrations/00016, so this run did not test the account boundary.", who)
	}
}

// OwnerPool returns a pool on EnvVar — the OWNER — skipping the test when the
// variable is unset.
//
// FOR SETUP THAT IS NOT DML, and only for that. DDL, TRUNCATE and the private
// schemas of Schema are ownership privileges, `identity_app` cannot hold any of
// them, and migrations/00019 grants it DML and nothing else on purpose: a role
// that can drop a table can drop the row-level-security policies on it, which is
// the one privilege this architecture exists to withhold.
//
// The distinction to keep is WHERE the privilege is used, not who holds it. Setup
// through here, assertions through Pool. A test that asserted through an owner
// pool would report the account boundary proven while running as the one role the
// boundary exempts.
func OwnerPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, dsn(t), db.DefaultOptions())
	if err != nil {
		t.Fatalf("opening an owner pool against %s: %v", EnvVar, err)
	}
	t.Cleanup(pool.Close)

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("%s is set but not reachable as the owner (%v).", EnvVar, err)
	}

	return pool
}

// UniqueEmail returns an address no other test, in any package, in any run, will
// use.
//
// It is built from the test's name so a failing test is greppable in the table,
// plus random bytes so a second run against the same database does not collide
// with the first. The result satisfies users.ValidateEmail — including the RFC
// 5321 limit of 64 characters on the local part, which a long test name will
// otherwise blow through.
func UniqueEmail(t *testing.T) string {
	t.Helper()

	var noise [6]byte
	if _, err := rand.Read(noise[:]); err != nil {
		t.Fatalf("generating a unique test email: %v", err)
	}

	// The local part has to survive the users.email rules, so anything that is not
	// a lowercase letter or digit becomes a dash.
	label := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, t.Name())
	label = strings.Trim(label, "-")

	// 64 is the local-part ceiling; 12 is the hex noise; one is the separator.
	if len(label) > 64-12-1 {
		label = label[:64-12-1]
		label = strings.TrimRight(label, "-")
	}

	return fmt.Sprintf("%s-%s@example.com", label, hex.EncodeToString(noise[:]))
}

// Reset truncates every table this service owns.
//
// It is deliberately not used by ordinary tests — see the package comment. Call
// it from a single test, or run it by hand, when you want to inspect the
// database or reproduce a failure from an empty state. Calling it from two tests
// at once, or from a test running beside another package's tests, will delete
// their rows.
//
// IT OPENS ITS OWN POOL ON EnvVar, and the argument it used to take is gone.
// TRUNCATE is an OWNER privilege: it is not in the grant set migrations/00019
// gives the app role and could not be, because a role that can truncate its own
// tables can empty an account boundary from underneath it. A pool handed in by a
// caller is the app role by construction — see Pool — so passing one would have
// been a way to call this with a credential guaranteed to fail. There were no
// callers when it changed, which is the only reason a signature change was
// available at all rather than a second function with a misleading name.
func Reset(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, dsn(t), db.DefaultOptions())
	if err != nil {
		t.Fatalf("opening an owner pool against %s: %v", EnvVar, err)
	}
	defer pool.Close()

	// user_audit_log is first, beside account_audit_log, and the position is
	// load-bearing in the ordinary way this list works: it has NO foreign keys and no
	// dependency on `users` (00022 — a cascade is a delete), so it could sit anywhere.
	// It is named anyway, because a table missing from this list is not an error: it
	// is rows from one package's test run surviving into the next one's, which is the
	// non-deterministic failure this function's own package comment warns about.
	if _, err := pool.Exec(ctx, `TRUNCATE TABLE user_audit_log, account_audit_log, api_keys, mfa_challenges, mfa_used_totp_steps, mfa_recovery_codes, mfa_credentials, oidc_access_tokens, oidc_auth_requests, oidc_clients, outbox_events, connected_accounts, sessions, account_invitations, account_users, accounts, users CASCADE`); err != nil {
		t.Fatalf("truncating: %v", err)
	}
}

// Schema returns a pool whose search_path is a private schema containing a fresh
// copy of the three tables. Nothing any other test does can be seen by, or
// interfere with, a test using this pool.
//
// It exists for the tests that need an *empty* database rather than a private
// corner of a shared one — the outbox claim tests, which assert on which rows a
// SELECT returns, cannot do that while a backlog from another package is in the
// table. A unique email gives isolation for row *identity*; it cannot give
// isolation for a query's result set.
//
// The tables are cloned with LIKE ... INCLUDING ALL, which copies columns,
// defaults, CHECK constraints and indexes from whatever the migrations currently
// define — so a schema change is picked up with no edit here. Two things LIKE does
// not copy, both declared explicitly below: foreign keys (they would point at the
// original tables) and enum types (Postgres has no LIKE for a type). Re-read the
// migrations when adding a table, a constraint or an enum value; this list has to
// stay in step with them.
//
// 00009 added three more tables and no new enum type, so the two CREATE TYPE
// statements below are still the whole list. 00010 added four more and no enum
// either, and 00011 added api_keys, which is a text[] and two timestamps. A
// registration's grant types and scopes are text arrays validated in Go, because
// those closed sets are a code fact — adding a scope must not be a migration. An
// api key's scopes are validated in Go for exactly the same reason. 00012 added
// account_audit_log, whose `action` column is the same kind of closed set and is
// validated in Go for the same reason.
func Schema(t *testing.T) *pgxpool.Pool {
	t.Helper()

	pool, _ := SchemaWithOwner(t)
	return pool
}

// SchemaWithOwner is Schema plus a second pool on the SAME private schema, logged
// in as the owner.
//
// It exists for the handful of assertions that cannot be made as the application
// role, because the thing they do is DDL: `ALTER TABLE … ADD CONSTRAINT`,
// `ALTER TABLE … DISABLE TRIGGER`, `CREATE INDEX`. Those are ownership
// privileges, migrations/00019 cannot grant them to `identity_app` and should
// not, and a test that reaches for one now fails with `must be owner of table …`.
// That failure is correct — the fix is not a grant, it is a second credential in
// the test — and this is where the second credential is.
//
// THE OWNER POOL IS FOR SETUP, NOT FOR THE ASSERTION. A test that seeded its
// fixture and then asserted through the owner would prove nothing about the
// boundary, which is the entire reason Pool is the app role at all. The split is
// the same one production makes: the owner migrates, the app role serves.
func SchemaWithOwner(t *testing.T) (app, owner *pgxpool.Pool) {
	t.Helper()

	base := dsn(t)

	var noise [6]byte
	if _, err := rand.Read(noise[:]); err != nil {
		t.Fatalf("generating a schema name: %v", err)
	}
	schema := "test_" + hex.EncodeToString(noise[:])

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	admin, err := db.Open(ctx, base, db.DefaultOptions())
	if err != nil {
		t.Fatalf("opening an admin pool against %s: %v", EnvVar, err)
	}
	// Registered first so that it runs *last*: cleanups are LIFO, and the DROP
	// SCHEMA below still needs this pool to be open.
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		t.Fatalf("%s is set but not reachable (%v). Is the server up, and are the migrations applied?", EnvVar, err)
	}

	stmts := []string{
		`CREATE SCHEMA ` + schema,
		`CREATE TABLE ` + schema + `.users (LIKE public.users INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.sessions (LIKE public.sessions INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.outbox_events (LIKE public.outbox_events INCLUDING ALL)`,
		// connected_accounts carries an enum-typed column. LIKE copies the column
		// with its type, which for an enum is a reference to the type in `public` —
		// so the values still resolve even though search_path is the private
		// schema. No CREATE TYPE here: the type is shared, not cloned, and a second
		// one in the private schema would not be the type the column refers to.
		`CREATE TABLE ` + schema + `.connected_accounts (LIKE public.connected_accounts INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.accounts (LIKE public.accounts INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.account_users (LIKE public.account_users INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.account_invitations (LIKE public.account_invitations INCLUDING ALL)`,
		// Postgres has no LIKE for a type, so the two enums are declared here
		// rather than cloned. That is a second copy of the migrations' enum
		// labels: re-read 00005 and 00007 when either changes, and note that
		// adding a role to public does NOT add it here — a test would then fail
		// on an enum value the database accepts and the private schema does not.
		`CREATE TYPE ` + schema + `.account_role AS ENUM ('owner', 'admin', 'member')`,
		`CREATE TYPE ` + schema + `.account_invitation_role AS ENUM ('admin', 'member')`,
		`ALTER TABLE ` + schema + `.sessions ADD CONSTRAINT sessions_user_id_fkey
			FOREIGN KEY (user_id) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.connected_accounts ADD CONSTRAINT connected_accounts_user_id_fkey
			FOREIGN KEY (user_id) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.account_users ADD CONSTRAINT account_users_account_id_fkey
			FOREIGN KEY (account_id) REFERENCES ` + schema + `.accounts (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.account_users ADD CONSTRAINT account_users_user_id_fkey
			FOREIGN KEY (user_id) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.account_invitations ADD CONSTRAINT account_invitations_account_id_fkey
			FOREIGN KEY (account_id) REFERENCES ` + schema + `.accounts (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.account_invitations ADD CONSTRAINT account_invitations_invited_by_fkey
			FOREIGN KEY (invited_by) REFERENCES ` + schema + `.users (id) ON DELETE SET NULL`,
		// The enums are schema-local, so the clones below would otherwise resolve
		// their role columns against public.account_role and account_invitation_role.
		// Two casts, and the private schema is genuinely private.
		`ALTER TABLE ` + schema + `.account_users ALTER COLUMN role TYPE ` + schema + `.account_role
			USING role::text::` + schema + `.account_role`,
		`ALTER TABLE ` + schema + `.account_invitations ALTER COLUMN role TYPE ` + schema + `.account_invitation_role
			USING role::text::` + schema + `.account_invitation_role`,
		// The OIDC tables. No enum types here, which is why the list above stops
		// at two CREATE TYPE statements: a client registration is text arrays and
		// timestamps, and a grant type or a scope is validated in Go because the
		// closed sets are a code fact rather than a schema fact.
		`CREATE TABLE ` + schema + `.oidc_clients (LIKE public.oidc_clients INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.oidc_auth_requests (LIKE public.oidc_auth_requests INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.oidc_access_tokens (LIKE public.oidc_access_tokens INCLUDING ALL)`,
		`ALTER TABLE ` + schema + `.oidc_clients ADD CONSTRAINT oidc_clients_account_id_fkey
			FOREIGN KEY (account_id) REFERENCES ` + schema + `.accounts (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.oidc_clients ADD CONSTRAINT oidc_clients_created_by_fkey
			FOREIGN KEY (created_by) REFERENCES ` + schema + `.users (id) ON DELETE SET NULL`,
		`ALTER TABLE ` + schema + `.oidc_clients ADD CONSTRAINT oidc_clients_revoked_by_fkey
			FOREIGN KEY (revoked_by) REFERENCES ` + schema + `.users (id) ON DELETE SET NULL`,
		`ALTER TABLE ` + schema + `.oidc_auth_requests ADD CONSTRAINT oidc_auth_requests_client_row_id_fkey
			FOREIGN KEY (client_row_id) REFERENCES ` + schema + `.oidc_clients (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.oidc_auth_requests ADD CONSTRAINT oidc_auth_requests_subject_fkey
			FOREIGN KEY (subject) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.oidc_access_tokens ADD CONSTRAINT oidc_access_tokens_client_row_id_fkey
			FOREIGN KEY (client_row_id) REFERENCES ` + schema + `.oidc_clients (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.oidc_access_tokens ADD CONSTRAINT oidc_access_tokens_subject_fkey
			FOREIGN KEY (subject) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
		// The refresh tokens. Cloned for the reason the access tokens are: TG-C2
		// gives the token endpoint a third credential table, and a private schema
		// without it fails the whole grant with "relation ... does not exist",
		// which reads like a migration that was not applied.
		//
		// THE SELF-REFERENTIAL FOREIGN KEY IS HERE, and it is the one that was
		// missing when this list was written. Its absence made the private schema
		// MORE PERMISSIVE than production on the one constraint that orders two
		// statements: 00035 declares
		// `replaced_by ... REFERENCES oidc_refresh_tokens (id)`, so a row may
		// only name a successor that already exists. Production obeys that —
		// Storage.CreateRefreshToken inserts the successor and THEN calls
		// ReplaceRefreshToken — but the refresh-token tests wrote the link first,
		// and against a schema without the constraint the write is simply
		// accepted. Statement order was a fact nobody could observe, and the
		// observable version of it is a 500 on the first rotation a real
		// deployment performs.
		//
		// ON DELETE SET NULL, exactly as the migration has it: a matching action
		// is what keeps the two schemas' behavior identical rather than merely
		// similar, and "similar" is the word for a harness that agrees with a
		// deferred failure.
		`CREATE TABLE ` + schema + `.oidc_refresh_tokens (LIKE public.oidc_refresh_tokens INCLUDING ALL)`,
		`ALTER TABLE ` + schema + `.oidc_refresh_tokens ADD CONSTRAINT oidc_refresh_tokens_replaced_by_fkey
			FOREIGN KEY (replaced_by) REFERENCES ` + schema + `.oidc_refresh_tokens (id) ON DELETE SET NULL`,
		`ALTER TABLE ` + schema + `.oidc_refresh_tokens ADD CONSTRAINT oidc_refresh_tokens_client_row_id_fkey
			FOREIGN KEY (client_row_id) REFERENCES ` + schema + `.oidc_clients (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.oidc_refresh_tokens ADD CONSTRAINT oidc_refresh_tokens_subject_fkey
			FOREIGN KEY (subject) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
		// The MFA tables. No enum types, no AAD, nothing the LIKE clause cannot
		// copy; the three foreign keys below point at the private schema rather
		// than at public.users, which is the whole reason they are written out
		// instead of inherited.
		`CREATE TABLE ` + schema + `.mfa_credentials (LIKE public.mfa_credentials INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.mfa_recovery_codes (LIKE public.mfa_recovery_codes INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.mfa_used_totp_steps (LIKE public.mfa_used_totp_steps INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.mfa_challenges (LIKE public.mfa_challenges INCLUDING ALL)`,
		`ALTER TABLE ` + schema + `.mfa_credentials ADD CONSTRAINT mfa_credentials_user_id_fkey
			FOREIGN KEY (user_id) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.mfa_recovery_codes ADD CONSTRAINT mfa_recovery_codes_credential_id_fkey
			FOREIGN KEY (credential_id) REFERENCES ` + schema + `.mfa_credentials (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.mfa_used_totp_steps ADD CONSTRAINT mfa_used_totp_steps_credential_id_fkey
			FOREIGN KEY (credential_id) REFERENCES ` + schema + `.mfa_credentials (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.mfa_challenges ADD CONSTRAINT mfa_challenges_user_id_fkey
			FOREIGN KEY (user_id) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
		// The api_keys table. No enum types, so LIKE copies everything — including
		// the partial unique index on (account_id, lower(name)), which is what
		// makes the "one live name per account" test mean something here: a schema
		// without it would accept a duplicate and the test would pass for the
		// wrong reason. The three foreign keys are written out because LIKE does
		// not copy them and they would otherwise point at public.
		`CREATE TABLE ` + schema + `.api_keys (LIKE public.api_keys INCLUDING ALL)`,
		`ALTER TABLE ` + schema + `.api_keys ADD CONSTRAINT api_keys_user_id_fkey
			FOREIGN KEY (user_id) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.api_keys ADD CONSTRAINT api_keys_account_id_fkey
			FOREIGN KEY (account_id) REFERENCES ` + schema + `.accounts (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.api_keys ADD CONSTRAINT api_keys_revoked_by_fkey
			FOREIGN KEY (revoked_by) REFERENCES ` + schema + `.users (id) ON DELETE RESTRICT`,
		// The admin audit log. LIKE copies the table and its indexes, and NOT the
		// trigger — LIKE does not copy triggers, so the append-only guarantee has to
		// be re-established here or a test in a private schema would run against a
		// table the production one can never UPDATE. It is created rather than
		// copied so that the test which forces an audit write to fail can replace
		// the function body with one that raises, in this schema only.
		//
		// The foreign keys are deliberately absent: 00012 declares none on this
		// table, and adding them here would make the private schema stricter than
		// production, which is the direction that hides a bug.
		`CREATE TABLE ` + schema + `.account_audit_log (LIKE public.account_audit_log INCLUDING ALL)`,
		`CREATE FUNCTION ` + schema + `.account_audit_log_is_append_only() RETURNS trigger AS $$
			BEGIN
				RAISE EXCEPTION 'account_audit_log is append-only; % is not permitted', TG_OP
					USING ERRCODE = 'restrict_violation';
			END;
		$$ LANGUAGE plpgsql`,
		`CREATE TRIGGER account_audit_log_append_only
			BEFORE UPDATE OR DELETE ON ` + schema + `.account_audit_log
			FOR EACH ROW EXECUTE FUNCTION ` + schema + `.account_audit_log_is_append_only()`,
		// 00014 and 00015: the verification column and the recovery token table.
		//
		// The COLUMN needs nothing here — the LIKE clause above picks it up, which is
		// what LIKE does — so a test in a private schema reads the same column the
		// production table has rather than a copy of it.
		//
		// recovery_tokens gets its foreign key written out for the reason every other
		// table's are: LIKE does not copy it and it would otherwise point at
		// public.users. Its partial unique index on `target_token_digest` and all of
		// its CHECK constraints DO come across with INCLUDING ALL, which is what makes
		// "an email change's second token cannot exist before the first is confirmed"
		// enforceable in a private schema and not only in production.
		`CREATE TABLE ` + schema + `.recovery_tokens (LIKE public.recovery_tokens INCLUDING ALL)`,
		`ALTER TABLE ` + schema + `.recovery_tokens ADD CONSTRAINT recovery_tokens_user_id_fkey
			FOREIGN KEY (user_id) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
		// 00022's user_audit_log, and it needs BOTH halves of the treatment
		// account_audit_log gets above: the table, and the trigger.
		//
		// The trigger is the half that is easy to miss and the half that matters. LIKE
		// does not copy triggers, so a private schema without this statement has a
		// `user_audit_log` that IS append-only in production and freely editable here —
		// which means a test asserting the append-only property would PASS against a
		// table production does not have. The check would be measuring the harness.
		//
		// No foreign keys are written out, and this time that is not an omission to be
		// tidied away: 00022 declares none, deliberately, because a CASCADE from users
		// is a DELETE and a DELETE is what the trigger refuses. Adding one here would
		// make the private schema STRICTER than production, which is the direction that
		// hides a bug rather than the direction that finds one — and it would make
		// this table cascade the one thing its migration was written to prevent.
		`CREATE TABLE ` + schema + `.user_audit_log (LIKE public.user_audit_log INCLUDING ALL)`,
		`CREATE FUNCTION ` + schema + `.user_audit_log_is_append_only() RETURNS trigger AS $$
			BEGIN
				RAISE EXCEPTION 'user_audit_log is append-only; % is not permitted', TG_OP
					USING ERRCODE = 'restrict_violation';
			END;
		$$ LANGUAGE plpgsql`,
		`CREATE TRIGGER user_audit_log_append_only
			BEFORE UPDATE OR DELETE ON ` + schema + `.user_audit_log
			FOR EACH ROW EXECUTE FUNCTION ` + schema + `.user_audit_log_is_append_only()`,
		// 00031: the agent principal, its credentials and its trail. All three get
		// the treatment, and each for its own reason.
		//
		// `agents` carries an enum-typed `status` column, and LIKE copies the
		// column with its type as a REFERENCE to `public.agent_status` — the same
		// arrangement connected_accounts has, and the reason no CREATE TYPE appears
		// here. The private schema's `agents.status` therefore accepts exactly the
		// three labels production accepts, which is what makes "unclaimed →
		// disabled is unrepresentable" a statement that holds under test.
		//
		// Its `claimed_by_account_id` foreign key is written out because LIKE does
		// not copy it and it would otherwise point at public.accounts — and a
		// private schema whose claim bound a PUBLIC account would be a schema in
		// which two tests could claim the same row.
		`CREATE TABLE ` + schema + `.agents (LIKE public.agents INCLUDING ALL)`,
		`ALTER TABLE ` + schema + `.agents ADD CONSTRAINT agents_claimed_by_account_id_fkey
			FOREIGN KEY (claimed_by_account_id) REFERENCES ` + schema + `.accounts (id) ON DELETE CASCADE`,
		// agent_tokens' foreign key to agents is written out for the same reason,
		// and its TWO partial unique indexes come across with INCLUDING ALL — the
		// one on token_digest and the one on (agent_id, lower(name)) WHERE
		// revoked_at IS NULL. The second is the load-bearing half: a schema
		// without it would accept two live credentials of one name and the
		// "one live token per agent" test would pass for the wrong reason.
		`CREATE TABLE ` + schema + `.agent_tokens (LIKE public.agent_tokens INCLUDING ALL)`,
		`ALTER TABLE ` + schema + `.agent_tokens ADD CONSTRAINT agent_tokens_agent_id_fkey
			FOREIGN KEY (agent_id) REFERENCES ` + schema + `.agents (id) ON DELETE CASCADE`,
		// agent_events needs BOTH halves of the treatment account_audit_log gets:
		// the table, and the trigger.
		//
		// The trigger is the half that is easy to miss and the half that matters.
		// LIKE does not copy triggers, so a private schema without this statement
		// has an `agent_events` that IS append-only in production and freely
		// editable here — which means a test asserting the append-only property
		// would PASS against a table production does not have. The check would be
		// measuring the harness.
		//
		// No foreign keys are written out, and that is not an omission to be
		// tidied away: 00031 declares none, deliberately, because a CASCADE from
		// agents is a DELETE and a DELETE is what the trigger refuses — the claim
		// must not be undoable by deleting the account that claimed it. Adding
		// one here would make the private schema STRICTER than production, which
		// is the direction that hides a bug.
		`CREATE TABLE ` + schema + `.agent_events (LIKE public.agent_events INCLUDING ALL)`,
		`CREATE FUNCTION ` + schema + `.agent_events_is_append_only() RETURNS trigger AS $$
			BEGIN
				RAISE EXCEPTION 'agent_events is append-only; % is not permitted', TG_OP
					USING ERRCODE = 'restrict_violation';
			END;
		$$ LANGUAGE plpgsql`,
		`CREATE TRIGGER agent_events_append_only
			BEFORE UPDATE OR DELETE ON ` + schema + `.agent_events
			FOR EACH ROW EXECUTE FUNCTION ` + schema + `.agent_events_is_append_only()`,
	}
	for _, stmt := range stmts {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("preparing the %s schema: %v\n%s", schema, err, stmt)
		}
	}

	// THE APP ROLE GETS ITS OWN SCHEMA TOO, and this is the only statement in this
	// function that is about credentials rather than about schema.
	//
	// `CREATE SCHEMA` grants nothing. From PostgreSQL 15 the owner of a new schema
	// holds everything on it and PUBLIC holds nothing, so a private schema built by
	// the owner is invisible to the pool under test: every unqualified name in the
	// test's SQL resolves to nothing, and the first statement fails with `permission
	// denied for schema test_…`. The clones likewise carry no grants, because
	// `LIKE … INCLUDING ALL` copies columns, indexes and constraints and not
	// privileges.
	//
	// The grant is at SCHEMA scope and covers every clone in one statement rather
	// than naming the twenty tables above, for the reason 00019 gives: a list that
	// names its tables is a list somebody has to remember to extend, and a list that
	// does not name them cannot quietly lose one. These clones carry no row-level
	// security — LIKE does not copy it, which is exactly why the tests that use them
	// can read a fixture the production table would refuse — so there is no policy
	// to grant and nothing here is a second copy of the boundary.
	for _, grant := range []string{
		`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + appRoleName(t),
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ` + schema + ` TO ` + appRoleName(t),
	} {
		if _, err := admin.Exec(ctx, grant); err != nil {
			t.Fatalf("granting the app role access to the %s schema: %v\n%s", schema, err, grant)
		}
	}

	t.Cleanup(func() {
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer dropCancel()
		if _, err := admin.Exec(dropCtx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
			t.Logf("dropping the %s schema: %v", schema, err)
		}
	})

	// search_path is a plain GUC, so pgx passes it as a connection runtime
	// parameter. Every unqualified name in the test's SQL then resolves inside the
	// private schema.
	pool, err := db.Open(ctx, withSearchPath(AppDSN(t), schema), db.DefaultOptions())
	if err != nil {
		t.Fatalf("opening a pool scoped to %s: %v", schema, err)
	}
	t.Cleanup(pool.Close)

	assertAppRole(t, pool)

	// The owner's pool on the same schema, opened after the app role's so that the
	// two cleanups run in the reverse of this order: the app pool closes first, then
	// this one, then the schema drop, which still has the admin pool above.
	ownerPool, err := db.Open(ctx, withSearchPath(base, schema), db.DefaultOptions())
	if err != nil {
		t.Fatalf("opening an owner pool scoped to %s: %v", schema, err)
	}
	t.Cleanup(ownerPool.Close)

	return pool, ownerPool
}

// appRoleName is the role the grants above name, read off the DSN the pool will
// actually use rather than spelled out here.
//
// The name is derived in one place — AppDSN — and a GRANT is SQL, so it cannot
// take a parameter the way a DSN can. Writing `identity_app` into a second file
// is a second answer to a question that already has one, and the way it fails is
// the quiet way: the grant lands on a role nobody logs in as and the schema is
// then unreadable by the pool for a reason that names a permission and not a
// role.
func appRoleName(t *testing.T) string {
	t.Helper()

	parsed, err := url.Parse(AppDSN(t))
	if err != nil {
		panic("dbtest: parsing the app DSN: " + err.Error())
	}
	return parsed.User.Username()
}

// dsn returns the configured DSN, skipping the test when it is unset.
func dsn(t *testing.T) string {
	t.Helper()

	value := os.Getenv(EnvVar)
	if value == "" {
		t.Skipf("%s is not set; skipping the integration test", EnvVar)
	}
	return value
}

// withSearchPath appends search_path to the DSN, preserving whatever query
// parameters it already carries.
func withSearchPath(dsnValue, schema string) string {
	parsed, err := url.Parse(dsnValue)
	if err != nil {
		// Pool already validated this DSN, so a parse failure here would be a
		// bug in this helper rather than bad configuration.
		panic("dbtest: parsing " + EnvVar + ": " + err.Error())
	}

	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()

	return parsed.String()
}
