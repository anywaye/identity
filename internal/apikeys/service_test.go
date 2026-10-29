package apikeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/tenancy"
	"github.com/anywaye/identity/internal/users"
)


func realService(pool *pgxpool.Pool, clk clock.Clock) *Service {
	return NewService(
		db.TxRunner{Pool: pool},
		resolver(pool),
		db.Direct{Pool: pool},
		NewStore(pool),
		outbox.NewStore(pool),
		realTenancy(pool, clk),
		users.NewStore(pool),
		clk,
	)
}

func resolver(pool *pgxpool.Pool) tenancy.CredentialResolver {
	return tenancy.CredentialResolver{TxRunner: db.TxRunner{Pool: pool}}
}

func realTenancy(pool *pgxpool.Pool, clk clock.Clock) *accounts.Service {
	return accounts.NewService(
		db.TxRunner{Pool: pool},
		accounts.NewStore(pool),
		users.NewStore(pool),
		outbox.NewStore(pool),
		NewStore(pool),
		clk,
		db.Direct{Pool: pool},
		nil,
	)
}

type serviceFixture struct {
	pool *pgxpool.Pool
	ownerPool *pgxpool.Pool
	clk       *clock.Fake
	svc       *Service
	store     *Store
	tenancy   *accounts.Service
	seq int

	owner  id.UUID
	member id.UUID
	account   id.UUID
	elsewhere id.UUID
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()

	ctx := context.Background()
	pool, ownerPool := dbtest.SchemaWithOwner(t)
	clk := clock.NewFake(testInstant)
	tenancy := realTenancy(pool, clk)

	f := &serviceFixture{
		pool: pool, ownerPool: ownerPool, clk: clk, tenancy: tenancy,
		store: NewStore(pool),
		svc:   realService(pool, clk),
	}

	f.owner = f.user(t)
	f.member = f.user(t)

	created, err := tenancy.Create(ctx, accounts.CreateInput{Name: f.label("Owner"), Owner: f.owner})
	if err != nil {
		t.Fatalf("creating the owner's account: %v", err)
	}
	f.account = created.Account.ID

	elsewhere, err := tenancy.Create(ctx, accounts.CreateInput{Name: f.label("Elsewhere"), Owner: f.member})
	if err != nil {
		t.Fatalf("creating the second account: %v", err)
	}
	f.elsewhere = elsewhere.Account.ID

	if _, err := accounts.NewStore(f.pool).AddMember(ctx, f.pool, accounts.Membership{
		AccountID: f.account, UserID: f.member, Role: accounts.RoleMember,
	}); err != nil {
		t.Fatalf("adding the member: %v", err)
	}

	return f
}

func (f *serviceFixture) label(prefix string) string {
	f.seq++
	return fmt.Sprintf("Apikeys %s %d", prefix, f.seq)
}

func (f *serviceFixture) user(t *testing.T) id.UUID {
	t.Helper()
	userID := id.MustNew()
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO users (id, email, password_digest) VALUES ($1, $2, $3)`,
		userID, dbtest.UniqueEmail(t), testPasswordDigest); err != nil {
		t.Fatalf("inserting a user: %v", err)
	}
	return userID
}

func (f *serviceFixture) apiKeyEvents(t *testing.T) []outbox.Envelope {
	t.Helper()
	all := f.outboxRows(t)
	var out []outbox.Envelope
	for _, e := range all {
		if strings.HasPrefix(e.Type, outbox.SourceIdentity+".api_key.") {
			out = append(out, e)
		}
	}
	return out
}

func (f *serviceFixture) outboxRows(t *testing.T) []outbox.Envelope {
	t.Helper()
	rows, err := f.pool.Query(context.Background(),
		`SELECT envelope FROM outbox_events ORDER BY created_at, id`)
	if err != nil {
		t.Fatalf("reading the outbox: %v", err)
	}
	defer rows.Close()

	var out []outbox.Envelope
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatalf("scanning an outbox row: %v", err)
		}
		var e outbox.Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("the stored envelope is not JSON: %v\n%s", err, raw)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading the outbox: %v", err)
	}
	return out
}

func (f *serviceFixture) breakTheOutbox(t *testing.T) {
	t.Helper()
	if _, err := f.ownerPool.Exec(context.Background(),
		`ALTER TABLE outbox_events ADD CONSTRAINT reject_everything CHECK (false) NOT VALID`); err != nil {
		t.Fatalf("disabling the outbox: %v", err)
	}
}

func TestMintReturnsTheSecretExactlyOnce(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account,
		Name:      "ci-deploy",
		Scopes:    []string{ScopeAccountsRead},
		MintedBy:  f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	if !strings.HasPrefix(issued.Token, Prefix) {
		t.Fatalf("the issued token %q does not carry the %q prefix", issued.Token, Prefix)
	}

	resolved, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now())
	if err != nil {
		t.Fatalf("the freshly issued token does not authenticate: %v", err)
	}
	if resolved.Key.ID != issued.Key.ID {
		t.Errorf("the issued token authenticates as %s, want the token that was issued (%s)",
			resolved.Key.ID, issued.Key.ID)
	}

	if issued.Key.TokenDigest == issued.Token {
		t.Error("TokenDigest is the token")
	}
	if strings.Contains(issued.Key.Name, issued.Token) {
		t.Error("the name carries the token")
	}
	if issued.Key.TokenDigest != Digest(issued.Token) {
		t.Errorf("TokenDigest = %q, want the SHA-256 of the presented value", issued.Key.TokenDigest)
	}
	if issued.Key.IsRevoked() {
		t.Error("a freshly minted token came back revoked")
	}
	if issued.Key.LastUsedAt != nil {
		t.Errorf("last_used_at = %v on a token that has never been presented", issued.Key.LastUsedAt)
	}
}

func TestTheSecretIsUnrecoverableFromEverythingElse(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "one-time", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	listed, err := f.svc.List(ctx, f.account)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("the list has %d entries, want 1", len(listed))
	}
	rendered := fmt.Sprintf("%+v", listed)

	for _, forbidden := range []string{issued.Token, strings.TrimPrefix(issued.Token, Prefix)} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("the list re-renders the secret: %s", rendered)
		}
	}

	resolved, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now())
	if err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", resolved), issued.Token) {
		t.Error("the resolved caller re-renders the presented token")
	}

	var _ = Digest
}

func TestMintingTwiceGivesTwoDifferentTokens(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	first, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "one", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting the first: %v", err)
	}
	second, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "two", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting the second: %v", err)
	}

	if first.Token == second.Token {
		t.Fatal("two mints produced the same token")
	}
	if first.Key.TokenDigest == second.Key.TokenDigest {
		t.Fatal("two mints produced the same digest, so the digests are not of the values")
	}
}

func TestAMintIsValidatedBeforeAnythingIsWritten(t *testing.T) {
	tests := []struct {
		name string
		give      func(f *serviceFixture) MintInput
		wantField string
		wantAuthorization bool
	}{
		{
			name:      "no name",
			give:      func(f *serviceFixture) MintInput { return MintInput{Name: "   ", Scopes: []string{ScopeAccountsRead}} },
			wantField: "name",
		},
		{
			name: "a name carrying a control character",
			give: func(f *serviceFixture) MintInput {
				return MintInput{Name: "ci\ndeploy", Scopes: []string{ScopeAccountsRead}}
			},
			wantField: "name",
		},
		{
			name:      "an unknown scope",
			give:      func(f *serviceFixture) MintInput { return MintInput{Name: "ci", Scopes: []string{"accounts:admin"}} },
			wantField: "scopes",
		},
		{
			name:      "no scopes at all",
			give:      func(f *serviceFixture) MintInput { return MintInput{Name: "ci", Scopes: nil} },
			wantField: "scopes",
		},
		{
			name: "a permanent credential",
			give: func(f *serviceFixture) MintInput {
				return MintInput{Name: "ci", Scopes: []string{ScopeAccountsRead}, ExpiresIn: ptr(time.Duration(0))}
			},
			wantField: "expires_in",
		},
		{
			name: "a lifetime beyond the ceiling",
			give: func(f *serviceFixture) MintInput {
				return MintInput{Name: "ci", Scopes: []string{ScopeAccountsRead}, ExpiresIn: ptr(MaxTTL + time.Hour)}
			},
			wantField: "expires_in",
		},
		{
			name: "a lifetime shorter than the floor",
			give: func(f *serviceFixture) MintInput {
				return MintInput{Name: "ci", Scopes: []string{ScopeAccountsRead}, ExpiresIn: ptr(time.Second)}
			},
			wantField: "expires_in",
		},
		{
			name: "an account that is not the caller's",
			give: func(f *serviceFixture) MintInput {
				return MintInput{AccountID: id.MustNew(), Name: "ci", Scopes: []string{ScopeAccountsRead}}
			},
			wantAuthorization: true,
		},
		{
			name: "an account the caller is a plain member of",
			give: func(f *serviceFixture) MintInput {
				return MintInput{AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.member}
			},
			wantAuthorization: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newServiceFixture(t)
			in := tt.give(f)
			if in.MintedBy.IsZero() {
				in.MintedBy = f.owner
			}
			if in.AccountID.IsZero() {
				in.AccountID = f.account
			}

			_, err := f.svc.Mint(context.Background(), in)
			if err == nil {
				t.Fatal("minting was accepted")
			}

			switch {
			case tt.wantAuthorization:
				if !errors.Is(err, ErrNotAuthorized) {
					t.Errorf("error = %v, want ErrNotAuthorized", err)
				}
			default:
				var fe *FieldError
				if !errors.As(err, &fe) {
					t.Fatalf("error = %v, want a *FieldError naming %q", err, tt.wantField)
				}
				if fe.Field != tt.wantField {
					t.Errorf("the failure names %q, want %q", fe.Field, tt.wantField)
				}
			}

			var rows int
			if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM api_keys`).Scan(&rows); err != nil {
				t.Fatalf("counting rows: %v", err)
			}
			if rows != 0 {
				t.Errorf("a rejected mint wrote %d rows", rows)
			}
			if events := f.apiKeyEvents(t); len(events) != 0 {
				t.Errorf("a rejected mint announced %d events", len(events))
			}
		})
	}
}

func TestAMintRequiresAMembership(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	_, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.member,
	})
	if !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("a plain member minted a credential: %v, want ErrNotAuthorized", err)
	}

	stranger := f.user(t)
	_, err = f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: stranger,
	})
	if !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("a stranger minted a credential in an account they are not in: %v, want ErrNotAuthorized", err)
	}

	if _, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	}); err != nil {
		t.Fatalf("the owner could not mint: %v", err)
	}
}

func TestAMintAnnouncesExactlyOneEvent(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci-deploy",
		Scopes: []string{ScopeAccountsRead, ScopeAccountsWrite}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	events := f.apiKeyEvents(t)
	if len(events) != 1 {
		t.Fatalf("a mint produced %d events, want exactly 1", len(events))
	}
	e := events[0]
	if e.Type != outbox.EventAPIKeyCreated {
		t.Errorf("type = %q, want %q", e.Type, outbox.EventAPIKeyCreated)
	}
	if e.Subject != issued.Key.ID.String() {
		t.Errorf("subject = %q, want the key's row id %q", e.Subject, issued.Key.ID)
	}

	payload := string(e.Data)
	for _, want := range []string{"accounts:read", "accounts:write", "ci-deploy", f.account.String()} {
		if !strings.Contains(payload, want) {
			t.Errorf("the payload %s does not carry %q", payload, want)
		}
	}
}

func TestAMintAndItsEventRollBackTogether(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	f.breakTheOutbox(t)

	_, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err == nil {
		t.Fatal("minting succeeded with a broken outbox")
	}

	var rows int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM api_keys`).Scan(&rows); err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	if rows != 0 {
		t.Errorf("a mint whose event failed committed %d token rows", rows)
	}
}

func TestOneLiveNamePerAccount(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	first, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci-deploy", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting the first: %v", err)
	}

	_, err = f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci-deploy", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if !errors.Is(err, ErrNameTaken) {
		t.Errorf("a second live token of the same name = %v, want ErrNameTaken", err)
	}

	if _, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.elsewhere, Name: "ci-deploy", Scopes: []string{ScopeAccountsRead}, MintedBy: f.member,
	}); err != nil {
		t.Fatalf("a different account could not use the same name: %v", err)
	}

	if _, err := f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.account, KeyID: first.Key.ID, RevokedBy: f.owner, Reason: "rotated",
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if _, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci-deploy", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	}); err != nil {
		t.Errorf("rotating under a live name failed: %v", err)
	}
}

func TestRevokeIsIdempotentlyDistinguishable(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	if _, err := f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.account, KeyID: issued.Key.ID, RevokedBy: f.owner, Reason: "leaked",
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	_, err = f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.account, KeyID: issued.Key.ID, RevokedBy: f.owner,
	})
	if !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("a second revoke = %v, want ErrAlreadyRevoked", err)
	}

	_, err = f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.account, KeyID: id.MustNew(), RevokedBy: f.owner,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking an unknown id = %v, want ErrNotFound", err)
	}

	if _, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("a revoked token authenticated: %v", err)
	}
}

func TestRevokeCannotCrossTenants(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	_, err = f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.elsewhere, KeyID: issued.Key.ID, RevokedBy: f.owner,
	})
	if !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("a cross-tenant revoke = %v, want ErrNotAuthorized", err)
	}

	_, err = f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.elsewhere, KeyID: issued.Key.ID, RevokedBy: f.member,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("an owner of another account revoking this one's key = %v, want ErrNotFound", err)
	}
	if _, err := f.store.Revoke(ctx, f.pool, issued.Key.ID, f.elsewhere, f.member, f.clk.Now(), ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("the store's own account_id scope did not hold: %v, want ErrNotFound", err)
	}

	if _, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now()); err != nil {
		t.Errorf("a cross-tenant revoke took effect anyway: %v", err)
	}
}

func TestRevokeAnnouncesTheEvent(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	if _, err := f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.account, KeyID: issued.Key.ID, RevokedBy: f.owner, Reason: "rotated",
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	events := f.apiKeyEvents(t)
	if len(events) != 2 {
		t.Fatalf("mint then revoke produced %d events, want 2", len(events))
	}
	revoked := events[1]
	if revoked.Type != outbox.EventAPIKeyRevoked {
		t.Errorf("the second event is %q, want %q", revoked.Type, outbox.EventAPIKeyRevoked)
	}
	if revoked.Subject != issued.Key.ID.String() {
		t.Errorf("subject = %q, want %q", revoked.Subject, issued.Key.ID)
	}
	if strings.Contains(string(revoked.Data), "rotated") {
		t.Errorf("the revocation event carries the operator's reason: %s", revoked.Data)
	}
}

func TestAuthenticateIsTheFourWayOneError(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	live, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "live", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	revoked, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "revoked", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	if _, err := f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.account, KeyID: revoked.Key.ID, RevokedBy: f.owner,
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	shortLived, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "short", Scopes: []string{ScopeAccountsRead},
		MintedBy: f.owner, ExpiresIn: ptr(MinTTL),
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	if _, err := f.pool.Exec(ctx,
		`UPDATE account_users SET role = 'owner' WHERE account_id = $1 AND user_id = $2`,
		f.account, f.member); err != nil {
		t.Fatalf("promoting the member: %v", err)
	}
	removedLive, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "removed-live", Scopes: []string{ScopeAccountsRead}, MintedBy: f.member,
	})
	if err != nil {
		t.Fatalf("minting for the promoted member: %v", err)
	}
	if _, err := f.svc.Authenticate(ctx, removedLive.Token, f.clk.Now()); err != nil {
		t.Fatalf("the promoted member's token does not resolve: %v", err)
	}

	if _, err := f.pool.Exec(ctx,
		`DELETE FROM account_users WHERE account_id = $1 AND user_id = $2`,
		f.account, f.member); err != nil {
		t.Fatalf("removing the membership: %v", err)
	}

	now := f.clk.Now()
	tests := []struct {
		name       string
		token      string
		at         time.Time
		wantCaller bool
	}{
		{name: "a live token", token: live.Token, at: now, wantCaller: true},
		{name: "a revoked token", token: revoked.Token, at: now},
		{name: "an expired token", token: shortLived.Token, at: testInstant.Add(MinTTL).Add(time.Nanosecond)},
		{name: "a token whose membership is gone", token: removedLive.Token, at: now},
		{name: "a token that never existed", token: Prefix + strings.Repeat("q", SecretBytes*8/6), at: now},
		{name: "an empty string", token: "", at: now},
		{name: "a session token, not this one", token: "a-session-token", at: now},
		{name: "the digest, presented as a token", token: Digest(live.Token), at: now},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caller, err := f.svc.Authenticate(ctx, tt.token, tt.at)
			if tt.wantCaller {
				if err != nil {
					t.Fatalf("a live token was refused: %v", err)
				}
				if caller.User.ID != f.owner {
					t.Errorf("the token authenticated as %s, want %s", caller.User.ID, f.owner)
				}
				return
			}
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("= %v, want ErrNotFound. A caller who can tell this from a live token "+
					"has an oracle, and the whole point of the one-error rule is that they cannot.",
					err)
			}
		})
	}

	if _, err := f.store.ByID(ctx, f.pool, removedLive.Key.ID); err != nil {
		t.Errorf("a membership removal deleted the token row: %v", err)
	}
	stored, err := f.store.ByID(ctx, f.pool, removedLive.Key.ID)
	if err != nil {
		t.Fatalf("re-reading: %v", err)
	}
	if stored.IsRevoked() {
		t.Error("the row is marked revoked, but nobody revoked it; the membership was removed")
	}
}

func TestAuthenticateRecordsUse(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	f.clk.Advance(time.Hour)
	caller, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now())
	if err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	if caller.Key.LastUsedAt == nil || !caller.Key.LastUsedAt.Equal(f.clk.Now()) {
		t.Errorf("last_used_at = %v, want the instant of use %s", caller.Key.LastUsedAt, f.clk.Now())
	}

	f.clk.Advance(time.Minute)
	if _, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now()); err != nil {
		t.Fatalf("authenticating again: %v", err)
	}
	firstUse := *caller.Key.LastUsedAt

	stored, err := f.store.ByID(ctx, f.pool, issued.Key.ID)
	if err != nil {
		t.Fatalf("re-reading: %v", err)
	}
	if stored.LastUsedAt == nil || !stored.LastUsedAt.Equal(firstUse) {
		t.Errorf("last_used_at moved within the %s resolution window: %s then %v",
			LastUsedResolution, firstUse, stored.LastUsedAt)
	}

	f.clk.Advance(LastUsedResolution)
	if _, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now()); err != nil {
		t.Fatalf("authenticating after the window: %v", err)
	}
	stored, err = f.store.ByID(ctx, f.pool, issued.Key.ID)
	if err != nil {
		t.Fatalf("re-reading: %v", err)
	}
	if stored.LastUsedAt == nil || stored.LastUsedAt.Equal(firstUse) {
		t.Error("last_used_at never moved, so the column is not being written at all")
	}
}

func TestATokenCannotDoWhatASessionCannot(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	caller, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now())
	if err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	if caller.Role != accounts.RoleOwner {
		t.Errorf("the resolved role is %q, want owner, read from the membership at this instant", caller.Role)
	}
	if !caller.Key.Allows(ScopeAccountsRead) {
		t.Error("the token does not allow the scope it was minted with")
	}
	if caller.Key.Allows(ScopeAccountsDelete) {
		t.Error("the token allows a scope it was never granted")
	}
}

func TestAMintRecordsTheServiceClock(t *testing.T) {
	f := newServiceFixture(t)
	fixed := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	f.clk.Set(fixed)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	if !issued.Key.CreatedAt.Equal(fixed) {
		t.Errorf("created_at = %s, want the injected clock's %s", issued.Key.CreatedAt, fixed)
	}
	if want := fixed.Add(DefaultTTL); !issued.Key.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %s, want created_at plus the default %s", issued.Key.ExpiresAt, want)
	}

	events := f.apiKeyEvents(t)
	if len(events) != 1 {
		t.Fatalf("the mint announced %d events, want 1", len(events))
	}
	if !events[0].Time.Equal(fixed) {
		t.Errorf("the event's time is %s, want the same instant as the row's %s", events[0].Time, fixed)
	}
}

func TestTheDefaultLifetimeIsUsedWhenNobodyAsks(t *testing.T) {
	f := newServiceFixture(t)

	issued, err := f.svc.Mint(context.Background(), MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	lifetime := issued.Key.ExpiresAt.Sub(issued.Key.CreatedAt)
	if lifetime != DefaultTTL {
		t.Errorf("the default lifetime is %s, want %s", lifetime, DefaultTTL)
	}
	if issued.Key.ExpiresAt.IsZero() {
		t.Error("expires_at is the zero time, so this credential never expires")
	}
}

func ptr[T any](v T) *T { return &v }

var (
	_ = users.User{}
	_ = clock.Fake{}
)
