package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
)


var storeTestNow = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

type storeFixture struct {
	pool    *pgxpool.Pool
	store   *Store
	querier db.QuerierSource
	ctx     context.Context
	account id.UUID
	owner   id.UUID
}

func (f storeFixture) q() db.Querier { return f.querier.Queryer() }

func newStoreFixture(t *testing.T) storeFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	ctx := t.Context()

	f := storeFixture{
		pool:    pool,
		store:   NewStore(pool),
		querier: db.Direct{Pool: pool},
		ctx:     ctx,
	}
	f.account, f.owner = f.seedAccount(t, "primary")

	return f
}

func (f storeFixture) seedAccount(t *testing.T, label string) (account, owner id.UUID) {
	t.Helper()

	email := dbtest.UniqueEmail(t)
	if _, err := f.pool.Exec(f.ctx,
		`INSERT INTO users (email, password_digest) VALUES ($1, $2)`, email, "not-a-real-digest"); err != nil {
		t.Fatalf("inserting a user: %v", err)
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&owner); err != nil {
		t.Fatalf("reading the user back: %v", err)
	}

	account = id.MustNew()
	if _, err := f.pool.Exec(f.ctx,
		`INSERT INTO accounts (id, name, slug) VALUES ($1, $2, $3)`,
		account, "OIDC test "+label, "oidc-"+label+"-"+account.String()[:8]); err != nil {
		t.Fatalf("inserting an account: %v", err)
	}
	return account, owner
}

func (f storeFixture) mustCreateClient(t *testing.T, account, by id.UUID) Client {
	t.Helper()

	clientID, secret, err := NewClientCredentials()
	if err != nil {
		t.Fatalf("NewClientCredentials: %v", err)
	}
	created, err := f.store.CreateClient(f.ctx, f.q(), CreateClientParams{
		AccountID:    account,
		ClientID:     clientID,
		Name:         "Anytalk",
		SecretDigest: SecretDigest(secret),
		RedirectURIs: []string{"https://app.example.com/cb"},
		GrantTypes:   []string{GrantAuthorizationCode},
		Scopes:       []string{"accounts", "email", "openid"},
		CreatedBy:    by,
		CreatedAt:    storeTestNow,
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	return created
}

func TestStoreClientRoundTrip(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)

	created, err := f.store.CreateClient(f.ctx, f.q(), CreateClientParams{
		AccountID:    f.account,
		ClientID:     "a-client-id-that-is-long-enough-to-pass-the-check",
		Name:         "Anytalk",
		SecretDigest: SecretDigest("s3cret"),
		RedirectURIs: []string{"https://app.example.com/cb"},
		GrantTypes:   []string{GrantAuthorizationCode},
		Scopes:       []string{"accounts", "email", "openid"},
		CreatedBy:    f.owner,
		CreatedAt:    storeTestNow,
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	if created.Name != "Anytalk" {
		t.Errorf("name = %q, want Anytalk", created.Name)
	}
	if created.SecretDigest == "s3cret" {
		t.Error("the row holds the secret itself")
	}
	if !created.IsActive() {
		t.Error("a fresh registration is not active")
	}
	if !created.AllowsScope(ScopeAccounts) {
		t.Error("the registered accounts scope is not on the scope list")
	}

	byHandle, err := f.store.ClientByClientID(f.ctx, f.q(), created.ClientID)
	if err != nil {
		t.Fatalf("ClientByClientID: %v", err)
	}
	if byHandle.ID != created.ID {
		t.Errorf("looked up row %s, want %s", byHandle.ID, created.ID)
	}

	byRow, err := f.store.ClientByRowID(f.ctx, f.q(), created.ID)
	if err != nil {
		t.Fatalf("ClientByRowID: %v", err)
	}
	if byRow.ClientID != created.ClientID {
		t.Errorf("ClientByRowID returned client_id %q, want %q", byRow.ClientID, created.ClientID)
	}
}

func TestStoreClientRedirectMatchingIsExact(t *testing.T) {
	t.Parallel()

	client := Client{RedirectURIs: []string{"https://app.example.com/cb"}}

	refusals := []string{
		"https://app.example.com.evil.com/cb",
		"https://app.example.com/cb/../evil",
		"https://app.example.com/cb?next=https://evil.com",
		"https://app.example.com/CB",
		"http://app.example.com/cb",
		"https://app.example.com/cb#x",
		"https://app.example.com:443/cb",
		"",
	}
	for _, candidate := range refusals {
		if client.AllowsRedirectURI(candidate) {
			t.Errorf("AllowsRedirectURI(%q) = true, want false: it is not the registered URI", candidate)
		}
	}
	if !client.AllowsRedirectURI("https://app.example.com/cb") {
		t.Error("the registered URI itself is refused")
	}
}

func TestStoreClientLookupsMissCleanly(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)

	if _, err := f.store.ClientByClientID(f.ctx, f.q(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ClientByClientID = %v, want ErrNotFound", err)
	}
	if _, err := f.store.ClientByRowID(f.ctx, f.q(), id.MustNew()); !errors.Is(err, ErrNotFound) {
		t.Errorf("ClientByRowID = %v, want ErrNotFound", err)
	}
}

func TestStoreRevokeClientIsOnceOnly(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	created := f.mustCreateClient(t, f.account, f.owner)
	other, by := f.seedAccount(t, "revoker")

	if _, err := f.store.RevokeClient(f.ctx, f.q(), created.ID, f.account, by, storeTestNow.Add(time.Minute), "rotated"); err != nil {
		t.Fatalf("RevokeClient: %v", err)
	}

	revoked, err := f.store.ClientByRowID(f.ctx, f.q(), created.ID)
	if err != nil {
		t.Fatalf("ClientByRowID: %v", err)
	}
	if revoked.IsActive() {
		t.Error("the registration is still active after a revocation")
	}
	if revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(storeTestNow.Add(time.Minute)) {
		t.Errorf("revoked_at = %v, want the injected instant", revoked.RevokedAt)
	}
	if revoked.RevokeReason == nil || *revoked.RevokeReason != "rotated" {
		t.Errorf("revoke_reason = %v, want rotated", revoked.RevokeReason)
	}

	if _, err := f.store.RevokeClient(f.ctx, f.q(), created.ID, f.account, other, storeTestNow.Add(time.Hour), "again"); !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("the second RevokeClient = %v, want ErrAlreadyRevoked", err)
	}
	again, err := f.store.ClientByRowID(f.ctx, f.q(), created.ID)
	if err != nil {
		t.Fatalf("ClientByRowID: %v", err)
	}
	if !again.RevokedAt.Equal(storeTestNow.Add(time.Minute)) {
		t.Errorf("revoked_at moved to %v; a second revocation overwrote the first", again.RevokedAt)
	}

	if _, err := f.store.RevokeClient(f.ctx, f.q(), id.MustNew(), f.account, by, storeTestNow, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking an unknown client = %v, want ErrNotFound", err)
	}
}

func TestStoreListClientsForAccount(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)

	empty, err := f.store.ClientsForAccount(f.ctx, f.q(), f.account)
	if err != nil {
		t.Fatalf("ClientsForAccount: %v", err)
	}
	if empty == nil {
		t.Fatal("ClientsForAccount returned nil, want an empty slice")
	}
	if len(empty) != 0 {
		t.Errorf("got %d clients for an account with none", len(empty))
	}

	f.mustCreateClient(t, f.account, f.owner)
	f.mustCreateClient(t, f.account, f.owner)

	elsewhere, elsewhereOwner := f.seedAccount(t, "elsewhere")
	f.mustCreateClient(t, elsewhere, elsewhereOwner)

	list, err := f.store.ClientsForAccount(f.ctx, f.q(), f.account)
	if err != nil {
		t.Fatalf("ClientsForAccount: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d clients, want 2", len(list))
	}
	for _, c := range list {
		if c.AccountID != f.account {
			t.Errorf("the list carries client %s from account %s", c.ID, c.AccountID)
		}
	}
}

func TestStoreAccessTokenRoundTripAndRevocation(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	tokenID := id.MustNew()

	if err := f.store.CreateAccessToken(f.ctx, f.q(), NewAccessToken{
		ID:          tokenID,
		ClientRowID: client.ID,
		Subject:     f.owner,
		Scopes:      []string{"openid", "email"},
		IssuedAt:    storeTestNow,
		ExpiresAt:   storeTestNow.Add(AccessTokenTTL),
	}); err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	loaded, err := f.store.AccessToken(f.ctx, f.q(), tokenID)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if loaded.Subject != f.owner {
		t.Errorf("subject = %s, want %s", loaded.Subject, f.owner)
	}
	if len(loaded.Scopes) != 2 {
		t.Errorf("scopes = %v, want the two that were stored", loaded.Scopes)
	}

	if err := f.store.RevokeAccessToken(f.ctx, f.q(), tokenID, storeTestNow.Add(time.Minute)); err != nil {
		t.Fatalf("RevokeAccessToken: %v", err)
	}
	if _, err := f.store.AccessToken(f.ctx, f.q(), tokenID); !errors.Is(err, ErrNoAccessToken) {
		t.Errorf("AccessToken after revocation = %v, want ErrNoAccessToken", err)
	}
	if err := f.store.RevokeAccessToken(f.ctx, f.q(), tokenID, storeTestNow.Add(2*time.Minute)); err != nil {
		t.Errorf("the second RevokeAccessToken = %v, want nil", err)
	}
	if _, err := f.store.AccessToken(f.ctx, f.q(), id.MustNew()); !errors.Is(err, ErrNoAccessToken) {
		t.Errorf("AccessToken for an unknown id = %v, want ErrNoAccessToken", err)
	}
}

func TestStoreRefusesAnAccessTokenLongerThanFifteenMinutes(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)

	err := f.store.CreateAccessToken(f.ctx, f.q(), NewAccessToken{
		ID:          id.MustNew(),
		ClientRowID: client.ID,
		Subject:     f.owner,
		Scopes:      []string{"openid"},
		IssuedAt:    storeTestNow,
		ExpiresAt:   storeTestNow.Add(AccessTokenTTL + time.Second),
	})
	if err == nil {
		t.Fatal("CreateAccessToken accepted a token past the fifteen-minute cap")
	}
}
