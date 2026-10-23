package auth

// PACKET identity-disabled-03: THE OIDC HALF OF A DISABLE, AGAINST A REAL DATABASE.
//
// access_token_sweep_test.go proves the use case ASKS for the sweep and asks through
// the transaction's querier. Both are claims about this repository's own wiring, and
// every one of them would pass against a store that swept nothing — the double is
// what stands in for the real one on that path. So the two claims that are not about
// this repository go here, over real SQL:
//
//	THE ASK REACHES THE ROWS      a live `oidc_access_tokens` row comes back with the
//	                               disable's own instant in `revoked_at`, and another
//	                               user's row does not come back at all.
//	THE ASK IS IN THE TRANSACTION a trigger refusing the UPDATE rolls the session
//	                               DELETE and the column write back with it — and the
//	                               error the caller sees is the INJECTED one, so a
//	                               rollback for any other reason cannot pass.
//
// IT IS NOT MERELY `oidc.Store.RevokeAccessTokensForUser`'s own test: that one proves
// the store sweeps, and recovery_routes_integration_test.go already proves recovery
// reaches it. Neither knows that a DISABLE reaches it, which is the half that was
// missing on master.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/platform/id"
)

// seedAccessToken puts one live access-token row in the table for one subject, and
// hands back its id.
//
// THE CLIENT ROW GOES IN THROUGH THE REAL `CreateClient`, for the reason
// recovery_routes_integration_test.go gives: the row carries a secret digest, and
// the shortest way to write one is a literal inside a query — a value the service
// never holds and a reviewer cannot check. The token row itself is plain DML with
// no secret in it, so it is inserted as SQL.
//
// TWO SUBJECTS ARE SEEDED BY THE CALLER, not here, so a test that claims the sweep
// is scoped can point at a row it knows belongs to somebody else.
func seedAccessToken(t *testing.T, f integrationFixture, subject id.UUID, label string) id.UUID {
	t.Helper()
	ctx := context.Background()

	var accountID id.UUID
	if err := f.pool.QueryRow(ctx, `
		SELECT au.account_id FROM account_users au
		JOIN accounts a ON a.id = au.account_id
		WHERE au.user_id = $1 ORDER BY a.created_at, a.id LIMIT 1`, subject).Scan(&accountID); err != nil {
		t.Fatalf("finding %s's account: %v", label, err)
	}

	client, err := oidc.NewStore(f.pool).CreateClient(ctx, f.pool, oidc.CreateClientParams{
		AccountID:    accountID,
		ClientID:     "disabled-03-" + label + "-" + id.MustNew().String(),
		Name:         "disabled-03 fixture",
		SecretDigest: oidc.SecretDigest(strings.Repeat("a", 64)),
		RedirectURIs: []string{"https://example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "email"},
		CreatedBy:    subject,
		CreatedAt:    f.now,
	})
	if err != nil {
		t.Fatalf("creating the %s fixture client: %v", label, err)
	}

	tokenID := id.MustNew()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO oidc_access_tokens (id, client_row_id, subject, scopes, issued_at, expires_at)
		VALUES ($1, $2, $3, ARRAY['openid','email'], $4, $5)`,
		tokenID, client.ID, subject, f.now, f.now.Add(15*time.Minute)); err != nil {
		t.Fatalf("creating the %s fixture access token: %v", label, err)
	}
	return tokenID
}

// readRevokedAt reads one token row's `revoked_at`, so "the sweep moved it" is a
// fact about the column rather than about a count.
func readRevokedAt(t *testing.T, f integrationFixture, tokenID id.UUID) *time.Time {
	t.Helper()
	var revokedAt *time.Time
	if err := f.pool.QueryRow(context.Background(),
		`SELECT revoked_at FROM oidc_access_tokens WHERE id = $1`, tokenID).Scan(&revokedAt); err != nil {
		t.Fatalf("reading the access token %s: %v", tokenID, err)
	}
	return revokedAt
}

// The disable reaches the rows, and it reaches ONLY this user's rows.
//
// THE SUBJECT-SCOPING HALF IS NOT DECORATION. The sweep is one UPDATE, and the
// property that makes it safe is its `WHERE subject = $1 AND revoked_at IS NULL`.
// An UPDATE missing the second clause would look identical from this user's side —
// their token is revoked either way — and would quietly move `revoked_at` on
// tokens somebody else is still using. So a second subject is seeded and asserted
// UNTOUCHED, and its token is proven live first: without that, an untouched row
// could be a row that was never seeded.
func TestDisablingRevokesThisUsersAccessTokensAndNoBodysElse(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	mine := seedAccessToken(t, f, f.user.ID, "subject")

	// A second user on this database, with their own token. Registered through the
	// real use case rather than inserted, so the account_users row a client row
	// needs is one this service really wrote.
	otherEmail := "not-the-subject-" + id.MustNew().String() + "@example.com"
	other, err := f.svc.Register(ctx, RegisterInput{Email: otherEmail, Password: "correct horse battery"})
	if err != nil {
		t.Fatalf("Register for the second subject: %v", err)
	}
	otherID, err := id.Parse(other.ID.String())
	if err != nil {
		t.Fatalf("parsing the second subject's id: %v", err)
	}
	theirs := seedAccessToken(t, f, otherID, "other")

	// THE CONTROL ON BOTH SIDES. Without these two assertions the interesting ones
	// are satisfied by a table that holds nothing.
	if readRevokedAt(t, f, mine) != nil {
		t.Fatal("the subject's own access token was already revoked before the disable, so " +
			"the assertion below would pass against a sweep that revoked nothing")
	}
	if readRevokedAt(t, f, theirs) != nil {
		t.Fatal("the second subject's access token was already revoked before the disable")
	}

	if err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now)); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	revoked := readRevokedAt(t, f, mine)
	if revoked == nil {
		t.Fatal("the access token minted before the disable is still live: a JWT verifies " +
			"against the published JWKS until exp, and deleting a row elsewhere does not " +
			"change that")
	}
	if !revoked.Equal(f.now) {
		t.Errorf("revoked_at = %v, want the instant the disable was given (%v): the row and "+
			"the disabled_at column are then the same fact", revoked, f.now)
	}

	if got := readRevokedAt(t, f, theirs); got != nil {
		t.Errorf("the second subject's access token was revoked at %v by a disable of somebody "+
			"else: the sweep is scoped by subject, and this row is the only thing that says so", got)
	}
}

// IDEMPOTENCE, READ FROM THE COLUMN.
//
// `Disable` is documented as repeatable and the route is tested twice over in
// internal/httpapi. The column is the sharp end of that claim: the store's UPDATE
// says `AND revoked_at IS NULL`, so a second call changes no rows, and this asserts
// it did not — by STAMPING rather than by counting, because a second sweep that
// rewrote `revoked_at` with a later instant would satisfy every "is it revoked"
// assertion in the suite.
func TestASecondDisableDoesNotMoveTheRevocationOfTheFirst(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	token := seedAccessToken(t, f, f.user.ID, "repeatable")

	if err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now)); err != nil {
		t.Fatalf("the first Disable: %v", err)
	}
	first := readRevokedAt(t, f, token)
	if first == nil {
		t.Fatal("the first disable revoked nothing, so there is nothing for the second to leave alone")
	}

	later := f.now.Add(5 * time.Minute)
	if err := f.svc.Disable(ctx, disableFor(f.user.ID, later)); err != nil {
		t.Fatalf("the second Disable = %v, want success: revoking zero tokens is a success", err)
	}

	if got := readRevokedAt(t, f, token); got == nil || !got.Equal(*first) {
		t.Errorf("revoked_at after the second disable = %v, want %v: the store's UPDATE is "+
			"conditional on revoked_at IS NULL, and a sweep that re-stamped the column would "+
			"make the SECOND call a lie about when the revocation happened", got, first)
	}
}

// A USER WITH NO TOKENS IS A SUCCESS, NOT A FAILURE.
//
// The brief's own words, as an assertion: a disable of somebody who never signed in
// through a product has nothing to revoke, and an error there would make a
// legitimate operator action look like an outage. Zero rows is the state the sweep
// is called for.
func TestDisablingAUserWhoNeverSignedInThroughAProductSucceeds(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	if got := countAccessTokens(t, f, f.user.ID); got != 0 {
		t.Fatalf("the fixture holds %d access tokens, want 0: this test is about the zero case", got)
	}

	if err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now)); err != nil {
		t.Fatalf("Disable with no access tokens = %v, want success", err)
	}

	// And the other two statements still happened — a sweep that returned an error
	// on zero rows would be a sweep that stopped the disable before the column.
	if read := readUserByID(t, f.pool, f.user.ID); read.DisabledAt == nil {
		t.Error("the user is not disabled, so a sweep over zero rows aborted the transaction")
	}
}

// THE TRANSACTION, AND THE INJECTED ERROR.
//
// A trigger refuses the UPDATE on `oidc_access_tokens`, so the sweep fails inside
// the database, inside the transaction. Nothing may survive it: not the session
// DELETE, not the column write, not the revocation of a token that was already
// marked. This is the direction that matters most — a half-applied disable is an
// account an operator reads as turned off and that keeps working anyway.
//
// `injectedRefusal` and `refuseTableWrites` are disabled_integration_test.go's, and
// the message is asserted so a rollback caused by anything else cannot pass.
func TestAFailedAccessTokenSweepRollsBackTheSessionsAndTheColumnWithIt(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	token := seedAccessToken(t, f, f.user.ID, "rolled-back")

	refuseTableWrites(t, f.owner, "oidc_access_tokens", "UPDATE")

	err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now))
	if err == nil {
		t.Fatal("Disable succeeded while the oidc_access_tokens UPDATE was being refused, so " +
			"the column write committed without the revocation it was supposed to be atomic with")
	}
	if !strings.Contains(err.Error(), injectedRefusal) {
		t.Fatalf("Disable = %v, want the error the trigger raised (%q): a rollback caused by "+
			"something else proves nothing about the three writes being one transaction", err, injectedRefusal)
	}

	if got := countSessions(t, f.pool, f.user.ID); got != 1 {
		t.Errorf("%d session rows after a failed sweep, want 1: the whole transaction rolled "+
			"back, so a user who was not disabled was not signed out", got)
	}
	if read := readUserByID(t, f.pool, f.user.ID); read.DisabledAt != nil {
		t.Errorf("DisabledAt = %v after a failed sweep, want nil: the column write must roll "+
			"back with the revocations it was supposed to be atomic with", read.DisabledAt)
	}
	if got := readRevokedAt(t, f, token); got != nil {
		t.Errorf("the access token was revoked at %v even though the transaction rolled back: "+
			"an UPDATE outside the transaction would leave exactly this, which is why the "+
			"sweep is asked for through the transaction's querier", got)
	}

	// And the door is still open, through the real password path — the honest
	// consequence of a disable that did not happen.
	if _, err := f.svc.Login(ctx, LoginInput{
		Email: f.user.Email, Password: "correct horse battery",
	}); err != nil {
		t.Errorf("Login after a rolled-back disable = %v, want success", err)
	}
}

// countAccessTokens is the count that makes "nothing to revoke" a fact about the
// table rather than about the sweep's return value.
func countAccessTokens(t *testing.T, f integrationFixture, subject id.UUID) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM oidc_access_tokens WHERE subject = $1`, subject).Scan(&n); err != nil {
		t.Fatalf("counting access tokens: %v", err)
	}
	return n
}
