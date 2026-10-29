package auth


import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/platform/id"
)

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

func readRevokedAt(t *testing.T, f integrationFixture, tokenID id.UUID) *time.Time {
	t.Helper()
	var revokedAt *time.Time
	if err := f.pool.QueryRow(context.Background(),
		`SELECT revoked_at FROM oidc_access_tokens WHERE id = $1`, tokenID).Scan(&revokedAt); err != nil {
		t.Fatalf("reading the access token %s: %v", tokenID, err)
	}
	return revokedAt
}

func TestDisablingRevokesThisUsersAccessTokensAndNoBodysElse(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	mine := seedAccessToken(t, f, f.user.ID, "subject")

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

func TestDisablingAUserWhoNeverSignedInThroughAProductSucceeds(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	if got := countAccessTokens(t, f, f.user.ID); got != 0 {
		t.Fatalf("the fixture holds %d access tokens, want 0: this test is about the zero case", got)
	}

	if err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now)); err != nil {
		t.Fatalf("Disable with no access tokens = %v, want success", err)
	}

	if read := readUserByID(t, f.pool, f.user.ID); read.DisabledAt == nil {
		t.Error("the user is not disabled, so a sweep over zero rows aborted the transaction")
	}
}

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

	if _, err := f.svc.Login(ctx, LoginInput{
		Email: f.user.Email, Password: "correct horse battery",
	}); err != nil {
		t.Errorf("Login after a rolled-back disable = %v, want success", err)
	}
}

func countAccessTokens(t *testing.T, f integrationFixture, subject id.UUID) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM oidc_access_tokens WHERE subject = $1`, subject).Scan(&n); err != nil {
		t.Fatalf("counting access tokens: %v", err)
	}
	return n
}
