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


func realPool(t *testing.T) db.Pool { return dbtest.Pool(t) }

func unq() string { return id.MustNew().String()[0:12] }

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

func mustSee(t *testing.T, pool db.Pool, what string, accountID id.UUID, query string, args ...any) {
	t.Helper()

	if n := countInAccount(t, pool, accountID, query, args...); n == 0 {
		t.Fatalf("the control failed: %s is not visible as the account that owns it, so every "+
			"\"it survived\" assertion in this test would pass for the wrong reason.\n%s", what, query)
	}
}

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

func TestAMembershipGoesAndTheOtherMembersAccountSurvives(t *testing.T) {
	pool := realPool(t)
	leaver := newUser(t, pool, "leaver-team@x.test")
	stay := newUser(t, pool, "stayer-team@x.test")

	personal := newAccount(t, pool, "leaver-team-p", "leaver-team-p", true)
	addMember(t, pool, personal, leaver, accounts.RoleOwner)

	team := newAccount(t, pool, "Shared Team", "shared-team-deletion", false)
	addMember(t, pool, team, leaver, accounts.RoleOwner)
	addMember(t, pool, team, stay, accounts.RoleOwner)

	mustSee(t, pool, "the other member's membership", team,
		`SELECT count(*) FROM account_users WHERE account_id = $1 AND user_id = $2`, team, stay)

	if err := newDeletionService(t, pool).Delete(t.Context(), DeleteInput{
		UserID: leaver, At: fixedNow(),
	}); err != nil {
		t.Fatalf("deleting a user who is one of two in a team: %v", err)
	}

	if n := count(t, pool, `SELECT count(*) FROM accounts WHERE id = $1`, team); n != 1 {
		t.Errorf("the team account was deleted with its owner: %d rows remain. Its other member "+
			"still had an account to be in", n)
	}
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

func TestAPendingInvitationDoesNotBlockTheDeletion(t *testing.T) {
	pool := realPool(t)
	inviter := newUser(t, pool, "inviter@x.test")
	personal := newAccount(t, pool, "inviter-p", "inviter-p", true)
	addMember(t, pool, personal, inviter, accounts.RoleOwner)

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
