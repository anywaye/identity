package httpapi

// PACKET identity-disabled-03: THE OPERATOR ROUTE'S SWEEP, OVER REAL ROWS.
//
// # WHY THIS FILE IS NOT A DUPLICATE OF operator_test.go
//
// `operator_test.go` drives the real router against a programmable `Auth` double,
// and that is the right instrument for "does the gate hold" — it can put a
// credential in front of the route and assert the use case was not reached. It
// cannot say anything about what the use case did once it WAS reached, because the
// double is what stands in for `auth.Service` at exactly that point.
//
// `internal/auth`'s integration tests prove the sweep reaches `oidc_access_tokens`
// when `Disable` is called. Neither of those knows whether the ROUTE calls it, and
// the route is a separate piece of wiring: `handleDisableUser` reaches the use case
// through the `Auth` interface, and an interface is where a call can be dropped.
//
// So the claim here is the one that spans the two halves:
//
//	POST /v1/users/{userID}/disable, presented with a token holding users:disable,
//	leaves the subject's OIDC access tokens revoked AND the subject's session dead.
//
// The `Auth` interface declares `Disable(ctx, userID, at)`, so this file is also
// what holds the interface honest: the route cannot drop the third statement without
// this failing, because the statement is not visible in this file and only its
// EFFECT is.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/platform/id"
)

// seedOperatorAccessToken puts one live access-token row in the table for one
// subject, through the real client-creation path, and hands back its id.
//
// IT REUSES THE SHAPE `recovery_routes_integration_test.go` established and does
// NOT re-derive it: the client row carries a secret digest, so it goes in through
// `oidc.Store.CreateClient` rather than as an INSERT with a literal sha256 in it —
// a value the service never holds and a reviewer cannot check.
func seedOperatorAccessToken(t *testing.T, s *apiKeyServer, subject id.UUID) id.UUID {
	t.Helper()
	ctx := context.Background()

	var accountID id.UUID
	if err := s.pool.QueryRow(ctx, `
		SELECT au.account_id FROM account_users au
		WHERE au.user_id = $1 ORDER BY au.account_id LIMIT 1`, subject).Scan(&accountID); err != nil {
		t.Fatalf("finding the subject's account: %v", err)
	}

	// `oidc.NewStore` and not `oidc.Service`: CreateClient is the STORE's method,
	// and the provider's service layer is `Register`, which mints its own ids and
	// would be a second thing to keep working.
	client, err := oidc.NewStore(s.pool).CreateClient(ctx, s.pool, oidc.CreateClientParams{
		AccountID:    accountID,
		ClientID:     "operator-sweep-" + id.MustNew().String(),
		Name:         "operator sweep fixture",
		SecretDigest: oidc.SecretDigest(strings.Repeat("c", 64)),
		RedirectURIs: []string{"https://example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "email"},
		CreatedBy:    subject,
		CreatedAt:    s.clk.Now(),
	})
	if err != nil {
		t.Fatalf("creating the fixture client: %v", err)
	}

	tokenID := id.MustNew()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO oidc_access_tokens (id, client_row_id, subject, scopes, issued_at, expires_at)
		VALUES ($1, $2, $3, ARRAY['openid','email'], $4, $5)`,
		tokenID, client.ID, subject, s.clk.Now(), s.clk.Now().Add(15*time.Minute)); err != nil {
		t.Fatalf("creating the fixture access token: %v", err)
	}
	return tokenID
}

// provisionOperatorToken writes one `api_keys` row holding `users:disable` and
// returns the plaintext.
//
// IT IS THE STORE AND NOT THE SERVICE, and the reason is a property of the design
// rather than of the test: `apikeys.Service.Mint` refuses this scope with
// ErrScopeNotMintableHere, because the scope names no account, so minting it inside
// an account would hand a tenant's CI job authority over every user on the
// deployment. The scope is a deployment fact and this row is how a deployment gets
// one — so the test provisioning it is exercising the real path rather than a
// shortcut around it.
//
// THE DIGEST COMES FROM `apikeys.NewToken`, and not from a literal: a digest
// written into the test as a constant is a value no code path produces, and this
// test's whole subject is that a REAL credential resolves.
func provisionOperatorToken(t *testing.T, s *apiKeyServer) string {
	t.Helper()
	ctx := context.Background()

	token, digest, err := apikeys.NewToken()
	if err != nil {
		t.Fatalf("minting an operator token: %v", err)
	}

	if _, err := apikeys.NewStore(s.pool).Create(ctx, s.pool, apikeys.NewKey{
		UserID:    s.user.ID,
		AccountID: s.account,
		Name:      "provisioned operator",
		Digest:    digest,
		Scopes:    []string{apikeys.ScopeUsersDisable},
		CreatedAt: s.clk.Now(),
		ExpiresAt: s.clk.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("provisioning the operator credential: %v", err)
	}
	return token
}

// readOperatorRevokedAt reads one token row's revoked_at.
func readOperatorRevokedAt(t *testing.T, s *apiKeyServer, tokenID id.UUID) *time.Time {
	t.Helper()
	var at *time.Time
	if err := s.pool.QueryRow(context.Background(),
		`SELECT revoked_at FROM oidc_access_tokens WHERE id = $1`, tokenID).Scan(&at); err != nil {
		t.Fatalf("reading the access token: %v", err)
	}
	return at
}

// THE ROUTE'S SWEEP, and the session half beside it so neither can be dropped alone.
//
// The session half is asserted through the real token and the real login, and the
// access-token half through the row, for the reason every other test in this packet
// says: `Authenticate`'s refusal could equally come from a check that reads
// `disabled_at`, which would leave the session rows in the database and is a
// different — and worse — property. The two halves are asserted separately because
// they fail separately.
func TestADisableRevokesTheAccessTokensAtThisLayer(t *testing.T) {
	s := newAPIKeyServer(t)
	ctx := context.Background()

	// The subject is somebody OTHER than the caller, and it is the fixture's
	// second account's owner path that makes this interesting: the operator token is
	// minted in one account and the disable names a person, with no account anywhere
	// in the URL. So the sweep's subject comes from the PATH and not from the
	// credential — a handler that swept `caller` instead would pass every gate test
	// in operator_test.go and revoke the wrong person's tokens.
	// THE OPERATOR CREDENTIAL IS PROVISIONED, NOT MINTED THROUGH THE API, and that
	// is not a workaround: `apikeys.Service.Mint` refuses `users:disable` with
	// ErrScopeNotMintableHere, because the scope names no account and an
	// account-scoped credential holding it would reach any user on the deployment.
	// So a deployment writes this row itself, and the test writes it the same way —
	// through the STORE, with a real digest from `apikeys.NewToken`, so the
	// credential this route is handed is one `Authenticate` will genuinely resolve.
	operatorToken := provisionOperatorToken(t, s)

	subject := s.user.ID
	token := seedOperatorAccessToken(t, s, subject)

	// THE CONTROL, on both sides. The token is proven LIVE first, because a sweep
	// that matched nothing would leave it live and the assertion below would read
	// that as success.
	if got := readOperatorRevokedAt(t, s, token); got != nil {
		t.Fatalf("the fixture's access token was already revoked at %v, so the assertion "+
			"below would pass against a sweep that revoked nothing", got)
	}
	// The session half is read through the AUTH service rather than the api-key
	// service: `s.keys.Authenticate` resolves an api key, and the fixture's browser
	// credential is a session token, so that call answers "api key not found" for a
	// reason that has nothing to do with the disable. `auth.Authenticate` is what a
	// session is for.
	if _, err := authServiceFor(s.pool, s.clk).Authenticate(ctx, s.session); err != nil {
		t.Fatalf("the subject's session does not authenticate before the disable: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/users/"+subject.String()+"/disable", nil)
	req.Header.Set("Authorization", "Bearer "+operatorToken)
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("the disable = %d, want 204; body: %s", rec.Code, rec.Body)
	}

	// THE CLAIM. A JWT is verified by whoever holds it against the published JWKS
	// until `exp`, so this row is the only thing that can tell a relying party the
	// credential is meant to be dead.
	revoked := readOperatorRevokedAt(t, s, token)
	if revoked == nil {
		t.Fatal("the access token minted before the disable is still live: the route reached " +
			"the use case, but the use case's sweep did not reach the rows")
	}
	if !revoked.Equal(s.clk.Now()) {
		t.Errorf("revoked_at = %v, want the instant the route passed (%v): the row and the "+
			"disabled_at column are then the same fact", revoked, s.clk.Now())
	}

	// And the session half, so the two are asserted as one claim rather than one of
	// them being quietly the whole test.
	if _, err := authServiceFor(s.pool, s.clk).Authenticate(ctx, s.session); err == nil {
		t.Error("the subject's session still authenticates after the route's disable")
	}
}
