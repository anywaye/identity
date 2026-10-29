package apikeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/users"
)


var testInstant = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

type fixture struct {
	pool  *pgxpool.Pool
	clk   *clock.Fake
	store *Store
	user  id.UUID
	account id.UUID
	other   id.UUID
	owner id.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(testInstant)

	f := &fixture{pool: pool, clk: clk, store: NewStore(pool)}
	f.seed(t)
	return f
}

func (f *fixture) seed(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	f.user = id.MustNew()
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO users (id, email, password_digest) VALUES ($1, $2, $3)`,
		f.user, dbtest.UniqueEmail(t), testPasswordDigest); err != nil {
		t.Fatalf("inserting the user: %v", err)
	}

	f.owner = id.MustNew()
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO users (id, email, password_digest) VALUES ($1, $2, $3)`,
		f.owner, dbtest.UniqueEmail(t), testPasswordDigest); err != nil {
		t.Fatalf("inserting the second user: %v", err)
	}

	for _, owner := range []id.UUID{f.user, f.owner} {
		_ = owner
	}

	f.account = f.makeAccount(t, f.user)
	f.other = f.makeAccount(t, f.owner)
}

const testPasswordDigest = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$" +
	"bG9uZy1ub3QtaGEzaC1hLWZpeHR1cmUtZml4dHVyZQ"

func (f *fixture) makeAccount(t *testing.T, owner id.UUID) id.UUID {
	t.Helper()
	accountID := id.MustNew()
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO accounts (id, name, slug) VALUES ($1, $2, $3)`,
		accountID, "Fixture "+accountID.String()[:8], "fixture-"+accountID.String()[:8]); err != nil {
		t.Fatalf("inserting an account: %v", err)
	}
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO account_users (account_id, user_id, role) VALUES ($1, $2, 'owner')`,
		accountID, owner); err != nil {
		t.Fatalf("inserting the membership: %v", err)
	}
	return accountID
}

func (f *fixture) issue(t *testing.T, name string, scopes ...string) Key {
	t.Helper()
	key, err := f.store.Create(context.Background(), f.pool, NewKey{
		UserID:    f.user,
		AccountID: f.account,
		Name:      name,
		Digest:    Digest("anywaye_" + strings.Repeat("k", 43) + name),
		Scopes:    scopes,
		ExpiresAt: testInstant.Add(DefaultTTL),
		CreatedAt: testInstant,
	})
	if err != nil {
		t.Fatalf("creating the token %q: %v", name, err)
	}
	return key
}

func TestTheDigestIsTheOnlyThingStored(t *testing.T) {
	f := newFixture(t)

	token, _, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	secret := strings.TrimPrefix(token, Prefix)

	key, err := f.store.Create(context.Background(), f.pool, NewKey{
		UserID:    f.user,
		AccountID: f.account,
		Name:      "paranoia",
		Digest:    Digest(token),
		Scopes:    []string{ScopeAccountsRead},
		ExpiresAt: testInstant.Add(DefaultTTL),
		CreatedAt: testInstant,
	})
	if err != nil {
		t.Fatalf("creating the token: %v", err)
	}

	row := f.readRow(t, key.ID)
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("rendering the row: %v", err)
	}
	rendered := string(raw)

	for _, forbidden := range []string{token, secret, strings.ToLower(token)} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("the row carries the plaintext token: the whole row is %s", rendered)
		}
	}

	if row["token_digest"] != Digest(token) {
		t.Errorf("token_digest = %v, want the SHA-256 of the presented value", row["token_digest"])
	}
	if Digest(token) == token || Digest(token) == secret {
		t.Error("the digest is the credential")
	}

	var everyRow string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT coalesce(string_agg(row_to_json(api_keys)::text, E'\n'), '') FROM api_keys`).Scan(&everyRow); err != nil {
		t.Fatalf("rendering the table: %v", err)
	}
	if strings.Contains(everyRow, token) || strings.Contains(everyRow, secret) {
		t.Error("the table carries the plaintext token somewhere other than the row read above")
	}
}

func TestANonMemberTokenIsNotAnAccountToken(t *testing.T) {
	f := newFixture(t)
	key := f.issue(t, "cross-tenant", ScopeAccountsRead)

	bystander := f.makeAccountWithoutMembership(t, f.user)

	if _, err := f.pool.Exec(context.Background(),
		`UPDATE api_keys SET account_id = $2 WHERE id = $1`, key.ID, bystander); err != nil {
		t.Fatalf("pointing the token at a foreign account: %v", err)
	}

	_, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("resolving a token whose owner is not a member of its account = %v, want ErrNotFound", err)
	}
}

func TestALiveTokenResolves(t *testing.T) {
	f := newFixture(t)
	key := f.issue(t, "live", ScopeAccountsRead, ScopeAccountsWrite)

	resolved, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant)
	if err != nil {
		t.Fatalf("a live token did not resolve: %v", err)
	}
	if resolved.ID != key.ID {
		t.Errorf("resolved id = %s, want %s", resolved.ID, key.ID)
	}
	if resolved.UserID != f.user || resolved.AccountID != f.account {
		t.Errorf("resolved to user %s account %s, want %s and %s",
			resolved.UserID, resolved.AccountID, f.user, f.account)
	}
	if !resolved.Role.Valid() {
		t.Errorf("the resolved row carries no role: %q", resolved.Role)
	}
	assertScopes(t, resolved.Scopes, []string{ScopeAccountsRead, ScopeAccountsWrite})
}

func TestAMembershipRemovedAfterIssuanceStopsTheToken(t *testing.T) {
	f := newFixture(t)
	key := f.issue(t, "will-be-removed", ScopeAccountsRead)

	if _, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant); err != nil {
		t.Fatalf("the token does not resolve before the removal: %v", err)
	}

	if _, err := f.pool.Exec(context.Background(),
		`DELETE FROM account_users WHERE account_id = $1 AND user_id = $2`,
		f.account, f.user); err != nil {
		t.Fatalf("removing the membership: %v", err)
	}

	_, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("after the membership was removed the token resolved to %v, want ErrNotFound", err)
	}

	stored, err := f.store.ByID(context.Background(), f.pool, key.ID)
	if err != nil {
		t.Fatalf("the row was deleted by a membership removal: %v", err)
	}
	if stored.ID != key.ID {
		t.Error("the surviving row is not the token that was issued")
	}
}

func TestADemotionIsVisibleToTheTokenOnTheNextRequest(t *testing.T) {
	f := newFixture(t)
	key := f.issue(t, "will-be-demoted", ScopeAccountsWrite)

	before, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant)
	if err != nil {
		t.Fatalf("the token does not resolve: %v", err)
	}
	if before.Role != "owner" {
		t.Fatalf("the fixture's role is %q, want owner", before.Role)
	}

	if _, err := f.pool.Exec(context.Background(),
		`UPDATE account_users SET role = 'member' WHERE account_id = $1 AND user_id = $2`,
		f.account, f.user); err != nil {
		t.Fatalf("demoting the membership: %v", err)
	}

	after, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant)
	if err != nil {
		t.Fatalf("the token stopped resolving after a demotion: %v", err)
	}
	if after.Role != "member" {
		t.Errorf("the resolved role is %q after a demotion, want member", after.Role)
	}
}

func TestRevokedAndExpiredAreBothJustNotFound(t *testing.T) {
	f := newFixture(t)

	t.Run("revoked", func(t *testing.T) {
		key := f.issue(t, "to-be-revoked", ScopeAccountsRead)
		if _, err := f.store.Revoke(context.Background(), f.pool, key.ID, f.account, f.user, testInstant, "test"); err != nil {
			t.Fatalf("revoking: %v", err)
		}
		if _, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant); !errors.Is(err, ErrNotFound) {
			t.Errorf("a revoked token resolved to %v, want ErrNotFound", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		key := f.issue(t, "to-expire", ScopeAccountsRead)
		after := testInstant.Add(DefaultTTL).Add(time.Nanosecond)
		if _, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, after); !errors.Is(err, ErrNotFound) {
			t.Errorf("an expired token resolved to %v, want ErrNotFound", err)
		}
		justBefore := testInstant.Add(DefaultTTL).Add(-time.Nanosecond)
		if _, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, justBefore); err != nil {
			t.Errorf("a token one nanosecond before its expiry did not resolve: %v", err)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		if _, err := f.store.ByDigest(context.Background(), f.pool,
			Digest("anywaye_"+strings.Repeat("z", 43)), testInstant); !errors.Is(err, ErrNotFound) {
			t.Errorf("an unknown token resolved to %v, want ErrNotFound", err)
		}
	})
}

func TestRevokeIsConditionalAndScoped(t *testing.T) {
	f := newFixture(t)
	key := f.issue(t, "revoke-once", ScopeAccountsRead)

	first, err := f.store.Revoke(context.Background(), f.pool, key.ID, f.account, f.user, testInstant, "leaked")
	if err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if first.RevokedAt == nil {
		t.Fatal("the revocation did not stamp revoked_at")
	}
	if first.RevokedBy == nil || *first.RevokedBy != f.user {
		t.Errorf("revoked_by = %v, want %s", first.RevokedBy, f.user)
	}
	if first.RevokeReason == nil || *first.RevokeReason != "leaked" {
		t.Errorf("revoke_reason = %v, want \"leaked\"", first.RevokeReason)
	}

	_, err = f.store.Revoke(context.Background(), f.pool, key.ID, f.account, f.user, testInstant.Add(time.Hour), "again")
	if !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("a second revocation = %v, want ErrAlreadyRevoked", err)
	}

	after, err := f.store.ByID(context.Background(), f.pool, key.ID)
	if err != nil {
		t.Fatalf("reading the revoked row: %v", err)
	}
	if !after.RevokedAt.Equal(testInstant) {
		t.Errorf("revoked_at is %s after a second attempt at %s, want the first", after.RevokedAt, testInstant)
	}

	foreign := f.issueAs(t, f.owner, f.other, "someone-elses", ScopeAccountsRead)
	if _, err := f.store.Revoke(context.Background(), f.pool, foreign.ID, f.account, f.user, testInstant, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking a token in another account = %v, want ErrNotFound", err)
	}
	if _, err := f.store.Revoke(context.Background(), f.pool, id.MustNew(), f.account, f.user, testInstant, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking an id that does not exist = %v, want ErrNotFound", err)
	}

	bare := f.issue(t, "no-reason", ScopeAccountsRead)
	revoked, err := f.store.Revoke(context.Background(), f.pool, bare.ID, f.account, f.user, testInstant, "")
	if err != nil {
		t.Fatalf("revoking without a reason: %v", err)
	}
	if revoked.RevokeReason != nil {
		t.Errorf("revoke_reason = %q for an empty reason, want NULL", *revoked.RevokeReason)
	}
}

func TestOneLiveNamePerAccountAndRotationIsPossible(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	f.issue(t, "ci-deploy", ScopeAccountsRead)

	_, err := f.store.Create(ctx, f.pool, NewKey{
		UserID: f.user, AccountID: f.account, Name: "ci-deploy",
		Digest: Digest("anywaye_" + strings.Repeat("a", 43)),
		Scopes: []string{ScopeAccountsRead}, ExpiresAt: testInstant.Add(DefaultTTL), CreatedAt: testInstant,
	})
	if !errors.Is(err, ErrNameTaken) {
		t.Fatalf("a second live token with the same name = %v, want ErrNameTaken", err)
	}

	_, err = f.store.Create(ctx, f.pool, NewKey{
		UserID: f.user, AccountID: f.account, Name: "CI-Deploy",
		Digest: Digest("anywaye_" + strings.Repeat("b", 43)),
		Scopes: []string{ScopeAccountsRead}, ExpiresAt: testInstant.Add(DefaultTTL), CreatedAt: testInstant,
	})
	if !errors.Is(err, ErrNameTaken) {
		t.Errorf("a name differing only in case = %v, want ErrNameTaken", err)
	}

	if _, err := f.store.Create(ctx, f.pool, NewKey{
		UserID: f.owner, AccountID: f.other, Name: "ci-deploy",
		Digest: Digest("anywaye_" + strings.Repeat("c", 43)),
		Scopes: []string{ScopeAccountsRead}, ExpiresAt: testInstant.Add(DefaultTTL), CreatedAt: testInstant,
	}); err != nil {
		t.Errorf("the same name in another account was refused: %v", err)
	}

	rows, err := f.store.ListForAccount(ctx, f.pool, f.account)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("the account holds %d tokens, want 1", len(rows))
	}
	if _, err := f.store.Revoke(ctx, f.pool, rows[0].ID, f.account, f.user, testInstant, "rotating"); err != nil {
		t.Fatalf("revoking for rotation: %v", err)
	}
	if _, err := f.store.Create(ctx, f.pool, NewKey{
		UserID: f.user, AccountID: f.account, Name: "ci-deploy",
		Digest: Digest("anywaye_" + strings.Repeat("d", 43)),
		Scopes: []string{ScopeAccountsRead}, ExpiresAt: testInstant.Add(DefaultTTL), CreatedAt: testInstant,
	}); err != nil {
		t.Errorf("creating the replacement after a revocation: %v", err)
	}

	rows, err = f.store.ListForAccount(ctx, f.pool, f.account)
	if err != nil {
		t.Fatalf("listing after the rotation: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("after a rotation the account holds %d rows, want 2: a revoked token is kept", len(rows))
	}
	if rows[0].RevokedAt == nil && rows[1].RevokedAt == nil {
		t.Error("neither row is marked revoked, so the rotation lost the old token")
	}
}

func TestTouchIsRateLimitedByResolution(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	key := f.issue(t, "hot", ScopeAccountsRead)

	if err := f.store.Touch(ctx, f.pool, key.ID, testInstant); err != nil {
		t.Fatalf("touching: %v", err)
	}
	first, err := f.store.ByID(ctx, f.pool, key.ID)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if first.LastUsedAt == nil {
		t.Fatal("the first use did not stamp last_used_at")
	}
	if !first.LastUsedAt.Equal(testInstant) {
		t.Errorf("last_used_at = %s, want %s", first.LastUsedAt, testInstant)
	}

	later := testInstant.Add(time.Second)
	if err := f.store.Touch(ctx, f.pool, key.ID, later); err != nil {
		t.Fatalf("touching again: %v", err)
	}
	second, err := f.store.ByID(ctx, f.pool, key.ID)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if second.LastUsedAt == nil || !second.LastUsedAt.Equal(testInstant) {
		t.Errorf("last_used_at = %v after a use %s later, want it left at %s",
			second.LastUsedAt, later.Sub(testInstant), testInstant)
	}

	past := testInstant.Add(LastUsedResolution).Add(time.Second)
	if err := f.store.Touch(ctx, f.pool, key.ID, past); err != nil {
		t.Fatalf("touching past the window: %v", err)
	}
	third, err := f.store.ByID(ctx, f.pool, key.ID)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if third.LastUsedAt == nil || !third.LastUsedAt.Equal(past) {
		t.Errorf("last_used_at = %v after a use past the resolution window, want %s", third.LastUsedAt, past)
	}
}

func TestTouchOnARevokedTokenIsANoOp(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	key := f.issue(t, "dead", ScopeAccountsRead)

	if _, err := f.store.Revoke(ctx, f.pool, key.ID, f.account, f.user, testInstant, "test"); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if err := f.store.Touch(ctx, f.pool, key.ID, testInstant.Add(time.Minute)); err != nil {
		t.Fatalf("touching a revoked token returned an error: %v", err)
	}
	after, err := f.store.ByID(ctx, f.pool, key.ID)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if after.LastUsedAt != nil {
		t.Errorf("last_used_at = %v on a revoked token, want NULL", after.LastUsedAt)
	}
}

func TestTheSchemaRefusesAPermanentCredential(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	cases := []struct {
		name      string
		expiresAt time.Time
	}{
		{"before creation", testInstant.Add(-time.Hour)},
		{"the creation instant itself", testInstant},
		{"past the year ceiling", testInstant.Add(MaxTTL + time.Hour)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.pool.Exec(ctx, `
				INSERT INTO api_keys (user_id, account_id, name, token_digest, scopes, created_at, expires_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				f.user, f.account, "boundary-"+tc.name,
				Digest("anywaye_"+strings.Repeat("e", 43)),
				[]string{ScopeAccountsRead}, testInstant, tc.expiresAt)
			if err == nil {
				t.Fatalf("the table accepted expires_at = %s, which the migration says it must not", tc.expiresAt)
			}
			if !strings.Contains(err.Error(), "api_keys_") {
				t.Errorf("the refusal came from %v, which is not one of this table's CHECK constraints", err)
			}
		})
	}
}

func TestTheSchemaRefusesAnEmptyScopeList(t *testing.T) {
	f := newFixture(t)

	_, err := f.pool.Exec(context.Background(), `
		INSERT INTO api_keys (user_id, account_id, name, token_digest, scopes, created_at, expires_at)
		VALUES ($1, $2, 'no-scopes', $3, $4, $5, $6)`,
		f.user, f.account, Digest("anywaye_"+strings.Repeat("f", 43)),
		[]string{}, testInstant, testInstant.Add(DefaultTTL))
	if err == nil {
		t.Fatal("the table accepted a token with no scopes")
	}
	if !strings.Contains(err.Error(), "api_keys_scopes_not_empty") {
		t.Errorf("the refusal came from %v, which is not api_keys_scopes_not_empty", err)
	}
}

func TestTheSchemaRefusesAHalfRevocation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	digest := Digest("anywaye_" + strings.Repeat("9", 43))
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO api_keys (user_id, account_id, name, token_digest, scopes, created_at, expires_at, revoked_at)
		VALUES ($1, $2, 'half-revoked', $3, $4, $5, $6, $5)`,
		f.user, f.account, digest, []string{ScopeAccountsRead}, testInstant, testInstant.Add(DefaultTTL)); err == nil {
		t.Fatal("the table accepted a revocation with no revoker")
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO api_keys (user_id, account_id, name, token_digest, scopes, created_at, expires_at, revoked_by)
		VALUES ($1, $2, 'half-revoked-2', $3, $4, $5, $6, $7)`,
		f.user, f.account, Digest("anywaye_"+strings.Repeat("8", 43)), []string{ScopeAccountsRead},
		testInstant, testInstant.Add(DefaultTTL), f.user); err == nil {
		t.Fatal("the table accepted a revoker with no revocation")
	}
	_ = digest
}

func TestRevokeAllForMemberIsScopedToOneAccount(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	mine := f.issue(t, "mine-a", ScopeAccountsRead)
	also := f.issue(t, "mine-b", ScopeAccountsRead)

	elsewhere := f.issueAs(t, f.user, f.other, "elsewhere", ScopeAccountsRead)
	theirs := f.issueAs(t, f.owner, f.account, "theirs", ScopeAccountsRead)

	if err := f.store.RevokeAllForMember(ctx, f.pool, f.account, f.user, testInstant); err != nil {
		t.Fatalf("sweeping: %v", err)
	}

	for _, key := range []Key{mine, also} {
		row, err := f.store.ByID(ctx, f.pool, key.ID)
		if err != nil {
			t.Fatalf("a swept token's row was deleted rather than revoked: %v", err)
		}
		if row.RevokedAt == nil {
			t.Errorf("token %q was not revoked by the sweep", key.Name)
		}
		if row.RevokeReason == nil || *row.RevokeReason != "membership removed" {
			t.Errorf("token %q has reason %v, want %q", key.Name, row.RevokeReason, "membership removed")
		}
		if _, err := f.store.ByDigest(ctx, f.pool, key.TokenDigest, testInstant); !errors.Is(err, ErrNotFound) {
			t.Errorf("a swept token resolved to %v, want ErrNotFound", err)
		}
	}

	for _, key := range []Key{elsewhere, theirs} {
		row, err := f.store.ByID(ctx, f.pool, key.ID)
		if err != nil {
			t.Fatalf("reading a token the sweep must not have touched: %v", err)
		}
		if row.RevokedAt != nil {
			t.Errorf("the sweep revoked %q, which it was not scoped to", key.Name)
		}
	}

	if err := f.store.RevokeAllForMember(ctx, f.pool, f.account, id.MustNew(), testInstant); err != nil {
		t.Errorf("sweeping a member with no credentials: %v", err)
	}
	if err := f.store.RevokeAllForMember(ctx, f.pool, id.MustNew(), f.user, testInstant); err != nil {
		t.Errorf("sweeping with no account: %v", err)
	}
}

func TestTheSweepIsIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	key := f.issue(t, "once", ScopeAccountsRead)
	if err := f.store.RevokeAllForMember(ctx, f.pool, f.account, f.user, testInstant); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	first, err := f.store.ByID(ctx, f.pool, key.ID)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	later := testInstant.Add(24 * time.Hour)
	if err := f.store.RevokeAllForMember(ctx, f.pool, f.account, f.user, later); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	second, err := f.store.ByID(ctx, f.pool, key.ID)
	if err != nil {
		t.Fatalf("re-reading: %v", err)
	}

	if second.RevokedAt == nil || !second.RevokedAt.Equal(*first.RevokedAt) {
		t.Errorf("a second sweep moved revoked_at from %v to %v; the moment the credential "+
			"actually died is the field an incident is written from",
			first.RevokedAt, second.RevokedAt)
	}
}

func TestTheStoreTakesAQuerierAndRunsInsideTheCallersTransaction(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	rolledBack := db.TxRunner{Pool: f.pool}.Do(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := f.store.Create(ctx, q, NewKey{
			UserID: f.user, AccountID: f.account, Name: "rolled-back",
			Digest: Digest("anywaye_" + strings.Repeat("1", 43)),
			Scopes: []string{ScopeAccountsRead}, ExpiresAt: testInstant.Add(DefaultTTL), CreatedAt: testInstant,
		})
		if err != nil {
			return err
		}
		rows, err := f.store.ListForAccount(ctx, q, f.account)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return errors.New("the insert was not visible inside the transaction")
		}
		return errors.New("the second write failed")
	})
	if rolledBack == nil {
		t.Fatal("the transaction was expected to fail")
	}

	rows, err := f.store.ListForAccount(ctx, f.pool, f.account)
	if err != nil {
		t.Fatalf("listing after the rollback: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("%d rows survived a rolled-back transaction, want 0", len(rows))
	}
}

func TestTheDatabaseTierActuallyRan(t *testing.T) {
	if os.Getenv(dbtest.EnvVar) == "" {
		t.Fatalf("%s is not set, so every test in this file skipped. A green run without it verifies nothing: "+
			"`docker compose up -d postgres`, `goose -dir migrations postgres \"$DATABASE_URL\" up`, and re-run with %s set.",
			dbtest.EnvVar, dbtest.EnvVar)
	}
	pool := dbtest.Pool(t)
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("the test database is not reachable: %v", err)
	}
}


func (f *fixture) issueAs(t *testing.T, userID, accountID id.UUID, name string, scopes ...string) Key {
	t.Helper()
	key, err := f.store.Create(context.Background(), f.pool, NewKey{
		UserID:    userID,
		AccountID: accountID,
		Name:      name,
		Digest:    Digest("anywaye_" + strings.Repeat("r", 43) + name),
		Scopes:    scopes,
		ExpiresAt: testInstant.Add(DefaultTTL),
		CreatedAt: testInstant,
	})
	if err != nil {
		t.Fatalf("issuing %q for another user: %v", name, err)
	}
	return key
}

func (f *fixture) makeAccountWithoutMembership(t *testing.T, _ id.UUID) id.UUID {
	t.Helper()
	accountID := id.MustNew()
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO accounts (id, name, slug) VALUES ($1, $2, $3)`,
		accountID, "Empty "+accountID.String()[:8], "empty-"+accountID.String()[:8]); err != nil {
		t.Fatalf("inserting an account with no members: %v", err)
	}
	return accountID
}

func (f *fixture) readRow(t *testing.T, keyID id.UUID) map[string]any {
	t.Helper()
	var raw []byte
	if err := f.pool.QueryRow(context.Background(),
		`SELECT row_to_json(api_keys)::text FROM api_keys WHERE id = $1`, keyID).Scan(&raw); err != nil {
		t.Fatalf("rendering the row: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("the rendered row is not JSON: %v", err)
	}
	return out
}

var _ = fmt.Sprintf
var _ = users.User{}
