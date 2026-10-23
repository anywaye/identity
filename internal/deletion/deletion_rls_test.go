package deletion

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/users"
)

// # THE DELETION AGAINST THE REAL POLICIES AND THE REAL FOREIGN KEYS.
//
// Everything in service_test.go is service logic, and none of it decides whether
// a user row CAN go. That is the schema's half, and `dbtest.Schema` cannot ask it
// the question: it clones tables with `LIKE … INCLUDING ALL` and re-adds the
// foreign keys BY HAND, and it says in its own comments that the clones carry no
// row-level security. A test against the clones would answer questions about
// tables that permit what production refuses, which is the failure this file
// exists to avoid — the same shape as the one
// `internal/accounts/account_writes_rls_test.go` documents.
//
// So this file uses `dbtest.Pool`, which opens the APP ROLE against the real
// tables with migrations/00016's policies and migrations/00007/00009/00011's
// foreign keys live. Four of those keys are `ON DELETE RESTRICT` and every one
// of them is a record somebody else wants kept; migrations/00024 is what turns
// them into `SET NULL`, and the three tests named after them are the reason that
// migration exists rather than a description of it.
//
// THE FIXTURES ARE SEEDED INSIDE A TRANSACTION CARRYING THE ACCOUNT IDENTITY,
// because the tables the seeds write to are policy-protected and the INSERT
// policies demand it. A seed written on a bare pooled connection would be
// refused with SQLSTATE 42501 — which is correct, and which is why the seed
// helper below opens one.

// realPool is the app-role pool against the tables whose policies are live.
//
// IT IS THE REAL `public` SCHEMA AND NOT A CLONE, which is the whole reason this
// file exists — and the reason every fixture below is given a UNIQUE name and
// registers its own cleanup. `dbtest.Pool` hands out a pool on the migrated
// schema that every other package in this repository also writes to, so a
// fixture with a fixed email or slug collides with the run before it and fails
// for a reason that has nothing to do with the deletion. `unq` is what stops
// that, and the cleanup is what stops a hundred runs from filling the table.
func realPool(t *testing.T) db.Pool { return dbtest.Pool(t) }

// unq is a per-test unique suffix, drawn once from the same id package the
// service uses.
//
// It is 12 hex characters because the slugs have to satisfy the accounts table's
// own CHECK (`^[a-z0-9]+(-[a-z0-9]+)*$`) and the emails its length bound, and a
// random hex string satisfies both without a second sanitiser.
func unq() string { return id.MustNew().String()[0:12] }

// seed writes rows as the app role, standing in an account where one is needed.
//
// It is a helper rather than a fixture table because every one of these rows is
// about a DIFFERENT reason the deletion is hard, and a shared fixture would have
// to satisfy the constraints of all of them at once.
// # WHY THE CALLBACK RETURNS AN ERROR RATHER THAN CALLING t.Fatalf
//
// The first version of this helper called `t.Fatalf` from inside the
// transaction callback, and it HANGS THE POOL rather than failing the test:
// `t.Fatalf` is `runtime.Goexit`, so `db.TxRunner.Do` never regains control,
// never rolls back, and never returns the connection — the next test blocks on a
// pool with one connection gone and the suite dies on the timeout with a stack in
// `puddle`. So the callback propagates and the failure is raised after the
// transaction has closed. The lesson generalises past this file: never fail a test
// from inside a `UnitOfWork.Do` callback.
func seed(t *testing.T, pool db.Pool, asAccount id.UUID, fn func(ctx context.Context, q db.Querier) error) {
	t.Helper()

	err := db.TxRunner{Pool: pool}.Do(t.Context(), func(ctx context.Context, q db.Querier) error {
		if !asAccount.IsZero() {
			if _, err := q.Exec(ctx, `SELECT anywaye.begin_account($1)`, asAccount); err != nil {
				return fmt.Errorf("standing in the account: %w", err)
			}
		}
		return fn(ctx, q)
	})
	if err != nil {
		t.Fatalf("seeding: %v", err)
	}
}

func newUser(t *testing.T, pool db.Pool, email string) id.UUID {
	t.Helper()

	uid := id.MustNew()
	mail := email + unq() + "@fixture.test"
	seed(t, pool, id.UUID{}, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx,
			`INSERT INTO users (id, email, password_digest) VALUES ($1, $2, 'digest')`,
			uid, mail)
		return err
	})
	t.Cleanup(func() {
		// The users row cascades its memberships, sessions and keys, so this one
		// statement is the whole teardown for a user fixture.
		if _, err := pool.Exec(context.WithoutCancel(t.Context()),
			`DELETE FROM users WHERE id = $1`, uid); err != nil {
			t.Logf("cleaning up the user fixture: %v", err)
		}
	})
	return uid
}

func newAccount(t *testing.T, pool db.Pool, name, slug string, personal bool) id.UUID {
	t.Helper()

	aid := id.MustNew()
	unique := slug + "-" + unq()
	seed(t, pool, id.UUID{}, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx,
			`INSERT INTO accounts (id, name, slug, personal) VALUES ($1, $2, $3, $4)`,
			aid, name, unique, personal)
		return err
	})
	t.Cleanup(func() {
		if _, err := pool.Exec(context.WithoutCancel(t.Context()),
			`DELETE FROM accounts WHERE id = $1`, aid); err != nil {
			t.Logf("cleaning up the account fixture: %v", err)
		}
	})
	return aid
}

func addMember(t *testing.T, pool db.Pool, accountID, userID id.UUID, role accounts.Role) {
	t.Helper()

	seed(t, pool, accountID, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx,
			`INSERT INTO account_users (account_id, user_id, role) VALUES ($1, $2, $3)`,
			accountID, userID, role)
		return err
	})
}

// newSession writes a session whose digest the test knows, which is how
// "the credential no longer authenticates" is asked: the query is a digest
// lookup, exactly what `auth.Service.Authenticate` does with a presented token.
func newSession(t *testing.T, pool db.Pool, userID id.UUID, digest string) {
	t.Helper()

	seed(t, pool, id.UUID{}, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx,
			`INSERT INTO sessions (user_id, token_digest, expires_at) VALUES ($1, $2, $3)`,
			userID, digest, time.Now().Add(24*time.Hour))
		return err
	})
}

func count(t *testing.T, pool db.Pool, query string, args ...any) int {
	t.Helper()

	var n int
	if err := pool.QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatalf("counting: %v\n%s", err, query)
	}
	return n
}

// countInAccount counts rows of a POLICY-PROTECTED table, standing in as the
// account that owns them.
//
// # WHY THE OBVIOUS HELPER WAS WRONG FOR HALF THESE ASSERTIONS
//
// `count` above runs on a bare pooled connection with no identity, which is
// correct for `users` and `accounts` — neither carries a policy, and 00016 says
// so — and silently returns ZERO for `account_users`, `account_invitations` and
// `oidc_clients`. Every one of them is `FORCE ROW LEVEL SECURITY` behind a
// `anywaye.current_account_id()` predicate that is NULL here.
//
// So `SELECT count(*) FROM account_users WHERE account_id = $1` on a bare pool
// answers 0 for "the membership was deleted" AND for "the membership is right
// there and you may not see it". Three of these tests failed on exactly that
// after the fix they were written for had already landed — the invitation had
// survived, the registration had survived, the other member was still a member,
// and the assertions said otherwise.
//
// This is the second time this codebase has been bitten by comparing two empty
// things (`internal/useraudit`'s `tableExists` guard documents the first), and it
// is why every assertion here about another account's rows goes through THIS
// helper rather than `count`.
//
// # AND WHY A POSITIVE CONTROL IS STILL REQUIRED
//
// Standing in correctly is not the same as being able to read the row. If the
// account identity were refused, or the policies changed, every count here would
// return 0 and every "the row survived" assertion would pass. `mustSee` is the
// control: it runs BEFORE the deletion and fails loudly if the row is not visible,
// so a green run means the row was read and found — not that nothing was looked
// at.
func countInAccount(t *testing.T, pool db.Pool, accountID id.UUID, query string, args ...any) int {
	t.Helper()

	var n int
	err := db.TxRunner{Pool: pool}.Do(t.Context(), func(ctx context.Context, q db.Querier) error {
		if _, err := q.Exec(ctx, `SELECT anywaye.begin_account($1)`, accountID); err != nil {
			return err
		}
		return q.QueryRow(ctx, query, args...).Scan(&n)
	})
	if err != nil {
		t.Fatalf("counting as the account: %v\n%s", err, query)
	}
	return n
}

// mustSee asserts a fixture row is READABLE under its account identity, before
// the deletion under test runs.
//
// It is the control that makes the "it survived" assertions meaningful, and it is
// a separate helper rather than a line in each test because a control written
// thirteen times is a control written once and forgotten eleven.
func mustSee(t *testing.T, pool db.Pool, what string, accountID id.UUID, query string, args ...any) {
	t.Helper()

	if n := countInAccount(t, pool, accountID, query, args...); n == 0 {
		t.Fatalf("the control failed: %s is not visible as the account that owns it, so every "+
			"\"it survived\" assertion in this test would pass for the wrong reason.\n%s", what, query)
	}
}

// newDeletionService wires the production collaborators: the real stores and the
// real outbox, on the real-policy pool.
//
// `*accounts.Store` satisfies `AccountReader` directly and `*users.Store`
// satisfies `UserStore` directly — both were given the methods this needs rather
// than this package wrapping them, because a wrapper would be a second place for
// the SQL to live.
func newDeletionService(t *testing.T, pool db.Pool) *Service {
	t.Helper()

	sweeper, err := NewSweeper(sessions.NewStore(pool), oidc.NewStore(pool))
	if err != nil {
		t.Fatalf("building the credential sweeper: %v", err)
	}

	return NewService(
		db.TxRunner{Pool: pool},
		users.NewStore(pool),
		accounts.NewStore(pool),
		sweeper,
		outbox.NewStore(pool),
	)
}

func fixedNow() time.Time { return time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC) }

// TestTheUserRowActuallyGoes is the claim, measured: after the transaction,
// there is no `users` row, and the query that asks is run by the app role
// against the real table.
func TestTheUserRowActuallyGoes(t *testing.T) {
	pool := realPool(t)
	leaver := newUser(t, pool, "leaver-basic@x.test")
	personal := newAccount(t, pool, "leaver-basic", "leaver-basic", true)
	addMember(t, pool, personal, leaver, accounts.RoleOwner)

	if err := newDeletionService(t, pool).Delete(t.Context(), DeleteInput{
		UserID: leaver, At: fixedNow(),
	}); err != nil {
		t.Fatalf("deleting a user with nothing in the way: %v", err)
	}

	if n := count(t, pool, `SELECT count(*) FROM users WHERE id = $1`, leaver); n != 0 {
		t.Errorf("the users row survived: %d rows remain", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM accounts WHERE id = $1`, personal); n != 0 {
		t.Errorf("the PERSONAL account survived a deletion that removes the user: %d rows remain.\n"+
			"Nothing cascades from `users` into `accounts` — there is no foreign key between them "+
			"in either direction — so the account a registration creates for its user is an "+
			"orphan unless the transaction removes it by name", n)
	}
}

// TestAMembershipGoesAndTheOtherMembersAccountSurvives is the tenancy half: the
// user's own memberships go, a team account they merely belonged to keeps its
// other members, and the membership row is the only thing removed from it.
func TestAMembershipGoesAndTheOtherMembersAccountSurvives(t *testing.T) {
	pool := realPool(t)
	leaver := newUser(t, pool, "leaver-team@x.test")
	stay := newUser(t, pool, "stayer-team@x.test")

	personal := newAccount(t, pool, "leaver-team-p", "leaver-team-p", true)
	addMember(t, pool, personal, leaver, accounts.RoleOwner)

	// THE SECOND OWNER IS THE POINT of this fixture, and getting it wrong was a
	// real finding rather than a slip: with `stay` as a plain member, `leaver` IS
	// the sole owner, the deletion is correctly REFUSED, and this test asserted a
	// survival it had not set up. A second owner is what makes the account carry
	// on without `leaver`, which is the property the test is about.
	team := newAccount(t, pool, "Shared Team", "shared-team-deletion", false)
	addMember(t, pool, team, leaver, accounts.RoleOwner)
	addMember(t, pool, team, stay, accounts.RoleOwner)

	// THE CONTROL. `stay`'s membership is on a policy-protected table, so the
	// survival assertion below is only meaningful if this row is readable first.
	mustSee(t, pool, "the other member's membership", team,
		`SELECT count(*) FROM account_users WHERE account_id = $1 AND user_id = $2`, team, stay)

	if err := newDeletionService(t, pool).Delete(t.Context(), DeleteInput{
		UserID: leaver, At: fixedNow(),
	}); err != nil {
		t.Fatalf("deleting a user who is one of two in a team: %v", err)
	}

	// The team account is OTHER PEOPLE'S data. Its row, and its other member,
	// are what a cascade would have destroyed.
	if n := count(t, pool, `SELECT count(*) FROM accounts WHERE id = $1`, team); n != 1 {
		t.Errorf("the team account was deleted with its owner: %d rows remain. Its other member "+
			"still had an account to be in", n)
	}
	// Standing in as the TEAM, because this row is on a policy-protected table and
	// `count` cannot see it. See `countInAccount` for why that distinction is the
	// whole test.
	if n := countInAccount(t, pool, team,
		`SELECT count(*) FROM account_users WHERE account_id = $1 AND user_id = $2`,
		team, stay); n != 1 {
		t.Errorf("the other member's membership is gone: %d rows remain", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM account_users WHERE user_id = $1`, leaver); n != 0 {
		t.Errorf("the deleted user still holds %d membership(s). `account_users_user_id_fkey` is "+
			"ON DELETE CASCADE, so the rows go with the users row", n)
	}
}

// TestTheRefusalIsRaisedForATeamAccountTheUserSolelyOwns is the decision, against
// a real schema: a team account with one owner is not deleted, and neither is
// the user.
func TestTheRefusalIsRaisedForATeamAccountTheUserSolelyOwns(t *testing.T) {
	pool := realPool(t)
	sole := newUser(t, pool, "sole-owner@x.test")
	personal := newAccount(t, pool, "sole-owner-p", "sole-owner-p", true)
	addMember(t, pool, personal, sole, accounts.RoleOwner)

	team := newAccount(t, pool, "Their Startup", "their-startup-deletion", false)
	addMember(t, pool, team, sole, accounts.RoleOwner)

	err := newDeletionService(t, pool).Delete(t.Context(), DeleteInput{UserID: sole, At: fixedNow()})
	if err == nil {
		t.Fatal("a user who solely owns a team account was deleted anyway")
	}
	if !errors.Is(err, ErrSolelyOwnedAccounts) {
		t.Fatalf("error is %v, want one wrapping ErrSolelyOwnedAccounts", err)
	}
	if !strings.Contains(err.Error(), "Their Startup") {
		t.Errorf("the refusal does not name the account. Full message: %v", err)
	}
	if n := count(t, pool, `SELECT count(*) FROM users WHERE id = $1`, sole); n != 1 {
		t.Errorf("the user row is gone despite the refusal: %d rows remain", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM accounts WHERE id = $1`, team); n != 1 {
		t.Errorf("the team account is gone despite the refusal: %d rows remain", n)
	}
}

// TestTheCredentialsStopAuthenticating is the property the packet cares most
// about, and it is asked in the only way that can be falsified: the session row
// is gone, so `SELECT … WHERE token_digest = $1` finds nothing to hash.
func TestTheCredentialsStopAuthenticating(t *testing.T) {
	pool := realPool(t)
	leaver := newUser(t, pool, "creds@x.test")
	personal := newAccount(t, pool, "creds-p", "creds-p", true)
	addMember(t, pool, personal, leaver, accounts.RoleOwner)
	digest := strings.Repeat("d", 60) + unq()
	newSession(t, pool, leaver, digest)

	if err := newDeletionService(t, pool).Delete(t.Context(), DeleteInput{
		UserID: leaver, At: fixedNow(),
	}); err != nil {
		t.Fatalf("deleting: %v", err)
	}

	if n := count(t, pool,
		`SELECT count(*) FROM sessions WHERE token_digest = $1`,
		digest); n != 0 {
		t.Errorf("the session row survived and would still authenticate: %d rows remain", n)
	}
}

// TestAPendingInvitationDoesNotBlockTheDeletion is the first of the three
// migrations/00024 tests, and it is here rather than in a schema test because
// what it proves is that a USER CAN LEAVE, not that a constraint has a shape.
//
// `account_invitations_invited_by_fkey` is ON DELETE RESTRICT (00007), and 00007
// says why in its own words: "an invitation outlives the person who sent it —
// the account still wants the invitee, and silently dropping the invitation
// because an admin left is not something the account asked for. Deleting a user
// with pending invitations is therefore refused by the database until they are
// revoked, which is a later packet."
//
// This IS that packet, and the resolution is NOT to revoke: revoking is the
// account owner's decision and this is the departing user's own request. The
// invitation survives with `invited_by` NULL, which is 00024's change and the
// only way to keep both facts true at once.
func TestAPendingInvitationDoesNotBlockTheDeletion(t *testing.T) {
	pool := realPool(t)
	inviter := newUser(t, pool, "inviter@x.test")
	personal := newAccount(t, pool, "inviter-p", "inviter-p", true)
	addMember(t, pool, personal, inviter, accounts.RoleOwner)

	// ADMIN, not the only owner. The account owner is somebody else here, which is
	// the realistic case for an invitation: they invited a colleague, and the
	// colleague is the one leaving. An owner here would trip the sole-owner
	// refusal first and this test would pass for the wrong reason.
	team := newAccount(t, pool, "Inviting Team", "inviting-team-deletion", false)
	addMember(t, pool, team, inviter, accounts.RoleAdmin)
	seed(t, pool, team, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO account_invitations
				(account_id, email, token_digest, invited_by, role, expires_at)
			VALUES ($1, $2, $3, $4, 'member', $5)`,
			team, "invitee-"+unq()+"@else.test", strings.Repeat("c", 52)+unq(), inviter,
			time.Now().Add(7*24*time.Hour))
		return err
	})

	mustSee(t, pool, "the pending invitation", team,
		`SELECT count(*) FROM account_invitations WHERE account_id = $1`, team)

	if err := newDeletionService(t, pool).Delete(t.Context(), DeleteInput{
		UserID: inviter, At: fixedNow(),
	}); err != nil {
		t.Fatalf("deleting a user who has a pending invitation out: %v\n"+
			"The team account still wants the invitee, and 00007 refused to let the inviter's "+
			"departure drop it — so the answer is ON DELETE SET NULL, not revoking the row", err)
	}

	if n := countInAccount(t, pool, team,
		`SELECT count(*) FROM account_invitations WHERE account_id = $1`, team); n != 1 {
		t.Errorf("the pending invitation was dropped: %d rows remain. 00007 is explicit that an "+
			"invitation outlives its sender because the ACCOUNT still wants the invitee", n)
	}
}

// TestARevokedKeyTheUserHeldGoesWithThem is what migration 00024 turned out NOT
// to need, and it is here because a test written on a wrong premise is worse than
// no test.
//
// The premise was that `api_keys.revoked_by` is ON DELETE RESTRICT (00011) and
// would therefore block. Measured, it does not, and the reason is a coincidence
// worth writing down: `RevokeAllForMember` sets `revoked_by` to the SAME user it
// filters `user_id` on, so the row referencing the departing person through
// `revoked_by` is always also the row referencing them through
// `api_keys_user_id_fkey ... ON DELETE CASCADE`. PostgreSQL removes it through the
// cascade, and the RESTRICT check then finds no referencing row. The restriction
// is unreachable.
//
// So `api_keys.revoked_by` is left alone by 00024, and the property asserted here
// is the one that is actually true and actually matters: a revoked key the
// departed user HELD is removed with them, and it is removed as a deletion rather
// than as a revocation — the row is gone, not revived.
//
// A hypothetical path where an admin revokes a colleague's key (which would make
// `revoked_by` differ from `user_id`, and so make the RESTRICT live) does not exist
// today. If it is added, this test is where the change shows up.
func TestARevokedKeyTheUserHeldGoesWithThem(t *testing.T) {
	pool := realPool(t)
	leaver := newUser(t, pool, "revoker")
	personal := newAccount(t, pool, "revoker-p", "revoker-p", true)
	addMember(t, pool, personal, leaver, accounts.RoleOwner)

	other := newAccount(t, pool, "Someone Elses Team", "someone-elses-deletion", false)
	addMember(t, pool, other, leaver, accounts.RoleAdmin)
	digest := strings.Repeat("d", 52) + unq()
	seed(t, pool, other, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO api_keys
				(id, user_id, account_id, name, token_digest, scopes, created_at,
				 expires_at, revoked_at, revoked_by, revoke_reason)
			VALUES ($1, $2, $3, 'theirs', $4, $5, now(), now() + interval '1 day',
			        now(), $6, 'membership removed')`,
			id.MustNew(), leaver, other, digest,
			[]string{"accounts:read"}, leaver)
		return err
	})

	if err := newDeletionService(t, pool).Delete(t.Context(), DeleteInput{
		UserID: leaver, At: fixedNow(),
	}); err != nil {
		t.Fatalf("deleting a user who is recorded as a key's revoker: %v", err)
	}

	// GONE, not un-revoked. A row that survived with `revoked_at` cleared would be
	// the one genuinely dangerous outcome of relaxing this constraint, and it is
	// the assertion this test exists for.
	if n := count(t, pool,
		`SELECT count(*) FROM api_keys WHERE token_digest = $1`, digest); n != 0 {
		t.Errorf("the revoked key row survived its holder: %d rows remain. A key for a user who "+
			"no longer exists can only ever be refused, and a survivor with revoked_at cleared "+
			"would be a LIVE credential belonging to nobody", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM accounts WHERE id = $1`, other); n != 1 {
		t.Errorf("the account the key belonged to was deleted: %d rows remain", n)
	}
}

// TestAnOIDCRegistrationTheUserMadeDoesNotBlockTheDeletion is the third.
//
// `oidc_clients_created_by` and `oidc_clients_revoked_by` are ON DELETE RESTRICT
// (00009), and 00009 keeps revoked registrations rather than deleting them
// precisely so that "which credentials existed" survives. A RESTRICT on the
// creator's id undoes that for the one person most likely to delete their
// account: somebody who set up an integration.
func TestAnOIDCRegistrationTheUserMadeDoesNotBlockTheDeletion(t *testing.T) {
	pool := realPool(t)
	maker := newUser(t, pool, "maker@x.test")
	personal := newAccount(t, pool, "maker-p", "maker-p", true)
	addMember(t, pool, personal, maker, accounts.RoleOwner)

	other := newAccount(t, pool, "Products Team", "products-team-deletion", false)
	addMember(t, pool, other, maker, accounts.RoleAdmin)
	clientID := strings.Repeat("k", 32) + unq()
	seed(t, pool, other, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO oidc_clients
				(id, account_id, client_id, name, secret_digest, redirect_uris, grant_types,
				 scopes, created_by)
			VALUES ($1, $2, $3, 'A Product', $4, $5, $6, $7, $8)`,
			id.MustNew(), other, clientID, strings.Repeat("e", 52)+unq(),
			[]string{"https://product.test/callback"}, []string{"authorization_code"},
			[]string{"openid"}, maker)
		return err
	})

	mustSee(t, pool, "the OIDC registration", other,
		`SELECT count(*) FROM oidc_clients WHERE client_id = $1`, clientID)

	if err := newDeletionService(t, pool).Delete(t.Context(), DeleteInput{
		UserID: maker, At: fixedNow(),
	}); err != nil {
		t.Fatalf("deleting a user who registered an OIDC client: %v", err)
	}
	if n := countInAccount(t, pool, other,
		`SELECT count(*) FROM oidc_clients WHERE client_id = $1`, clientID); n != 1 {
		t.Errorf("the registration was dropped: %d rows remain. 00009 keeps it rather than "+
			"deleting so that an audit of which credentials existed survives", n)
	}
}

// TestTheEventIsWrittenInTheSameTransaction is the outbox property, asked the
// only way that can be falsified: a failing deletion leaves NO event behind.
//
// An event for a deletion that rolled back is the worst shape this table can
// hold — a consumer would delete a billing customer whose account is still
// there — so the assertion is about the rollback, not about the happy path.
func TestTheEventIsWrittenInTheSameTransaction(t *testing.T) {
	pool := realPool(t)
	refused := newUser(t, pool, "no-event@x.test")
	personal := newAccount(t, pool, "no-event-p", "no-event-p", true)
	addMember(t, pool, personal, refused, accounts.RoleOwner)
	team := newAccount(t, pool, "No Event Team", "no-event-team", false)
	addMember(t, pool, team, refused, accounts.RoleOwner)

	before := count(t, pool, `SELECT count(*) FROM outbox_events WHERE type = $1`, outbox.EventUserDeleted)

	err := newDeletionService(t, pool).Delete(t.Context(), DeleteInput{UserID: refused, At: fixedNow()})
	if err == nil {
		t.Fatal("the deletion was supposed to be refused")
	}

	after := count(t, pool, `SELECT count(*) FROM outbox_events WHERE type = $1`, outbox.EventUserDeleted)
	if after != before {
		t.Errorf("the outbox holds %d %s events and held %d before the refused deletion.\n"+
			"An event for a transaction that rolled back tells a consumer to clean up a user "+
			"who is still here", after, outbox.EventUserDeleted, before)
	}
}

// TestTheHappyPathEmitsTheEvent is the positive half of the pair above, because a
// check that only ever sees "no event" would be satisfied by an implementation
// that never emits one.
func TestTheHappyPathEmitsTheEvent(t *testing.T) {
	pool := realPool(t)
	leaver := newUser(t, pool, "emits@x.test")
	personal := newAccount(t, pool, "emits-p", "emits-p", true)
	addMember(t, pool, personal, leaver, accounts.RoleOwner)

	if err := newDeletionService(t, pool).Delete(t.Context(), DeleteInput{
		UserID: leaver, At: fixedNow(),
	}); err != nil {
		t.Fatalf("deleting: %v", err)
	}

	var subject string
	err := pool.QueryRow(t.Context(), `
		SELECT subject FROM outbox_events WHERE type = $1 AND subject = $2`,
		outbox.EventUserDeleted, leaver.String()).Scan(&subject)
	if err != nil {
		t.Fatalf("no %s event for the deleted user: %v", outbox.EventUserDeleted, err)
	}
	if subject != leaver.String() {
		t.Errorf("event subject = %q, want %q", subject, leaver)
	}
}
