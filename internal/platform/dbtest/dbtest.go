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

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("%s is set but not reachable (%v). Is the server up, and are the "+
			"migrations applied? `goose -dir migrations postgres \"$DATABASE_URL\" up`", EnvVar, err)
	}

	assertAppRole(t, pool)

	return pool
}

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
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		t.Fatalf("%s is set but not reachable (%v). Is the server up, and are the migrations applied?", EnvVar, err)
	}

	stmts := []string{
		`CREATE SCHEMA ` + schema,
		`CREATE TABLE ` + schema + `.users (LIKE public.users INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.sessions (LIKE public.sessions INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.outbox_events (LIKE public.outbox_events INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.connected_accounts (LIKE public.connected_accounts INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.accounts (LIKE public.accounts INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.account_users (LIKE public.account_users INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.account_invitations (LIKE public.account_invitations INCLUDING ALL)`,
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
		`ALTER TABLE ` + schema + `.account_users ALTER COLUMN role TYPE ` + schema + `.account_role
			USING role::text::` + schema + `.account_role`,
		`ALTER TABLE ` + schema + `.account_invitations ALTER COLUMN role TYPE ` + schema + `.account_invitation_role
			USING role::text::` + schema + `.account_invitation_role`,
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
		`CREATE TABLE ` + schema + `.oidc_refresh_tokens (LIKE public.oidc_refresh_tokens INCLUDING ALL)`,
		`ALTER TABLE ` + schema + `.oidc_refresh_tokens ADD CONSTRAINT oidc_refresh_tokens_replaced_by_fkey
			FOREIGN KEY (replaced_by) REFERENCES ` + schema + `.oidc_refresh_tokens (id) ON DELETE SET NULL`,
		`ALTER TABLE ` + schema + `.oidc_refresh_tokens ADD CONSTRAINT oidc_refresh_tokens_client_row_id_fkey
			FOREIGN KEY (client_row_id) REFERENCES ` + schema + `.oidc_clients (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.oidc_refresh_tokens ADD CONSTRAINT oidc_refresh_tokens_subject_fkey
			FOREIGN KEY (subject) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
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
		`CREATE TABLE ` + schema + `.api_keys (LIKE public.api_keys INCLUDING ALL)`,
		`ALTER TABLE ` + schema + `.api_keys ADD CONSTRAINT api_keys_user_id_fkey
			FOREIGN KEY (user_id) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.api_keys ADD CONSTRAINT api_keys_account_id_fkey
			FOREIGN KEY (account_id) REFERENCES ` + schema + `.accounts (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.api_keys ADD CONSTRAINT api_keys_revoked_by_fkey
			FOREIGN KEY (revoked_by) REFERENCES ` + schema + `.users (id) ON DELETE RESTRICT`,
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
		`CREATE TABLE ` + schema + `.recovery_tokens (LIKE public.recovery_tokens INCLUDING ALL)`,
		`ALTER TABLE ` + schema + `.recovery_tokens ADD CONSTRAINT recovery_tokens_user_id_fkey
			FOREIGN KEY (user_id) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
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
		`CREATE TABLE ` + schema + `.agents (LIKE public.agents INCLUDING ALL)`,
		`ALTER TABLE ` + schema + `.agents ADD CONSTRAINT agents_claimed_by_account_id_fkey
			FOREIGN KEY (claimed_by_account_id) REFERENCES ` + schema + `.accounts (id) ON DELETE CASCADE`,
		`CREATE TABLE ` + schema + `.agent_tokens (LIKE public.agent_tokens INCLUDING ALL)`,
		`ALTER TABLE ` + schema + `.agent_tokens ADD CONSTRAINT agent_tokens_agent_id_fkey
			FOREIGN KEY (agent_id) REFERENCES ` + schema + `.agents (id) ON DELETE CASCADE`,
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

	pool, err := db.Open(ctx, withSearchPath(AppDSN(t), schema), db.DefaultOptions())
	if err != nil {
		t.Fatalf("opening a pool scoped to %s: %v", schema, err)
	}
	t.Cleanup(pool.Close)

	assertAppRole(t, pool)

	ownerPool, err := db.Open(ctx, withSearchPath(base, schema), db.DefaultOptions())
	if err != nil {
		t.Fatalf("opening an owner pool scoped to %s: %v", schema, err)
	}
	t.Cleanup(ownerPool.Close)

	return pool, ownerPool
}

func appRoleName(t *testing.T) string {
	t.Helper()

	parsed, err := url.Parse(AppDSN(t))
	if err != nil {
		panic("dbtest: parsing the app DSN: " + err.Error())
	}
	return parsed.User.Username()
}

func dsn(t *testing.T) string {
	t.Helper()

	value := os.Getenv(EnvVar)
	if value == "" {
		t.Skipf("%s is not set; skipping the integration test", EnvVar)
	}
	return value
}

func withSearchPath(dsnValue, schema string) string {
	parsed, err := url.Parse(dsnValue)
	if err != nil {
		panic("dbtest: parsing " + EnvVar + ": " + err.Error())
	}

	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()

	return parsed.String()
}
