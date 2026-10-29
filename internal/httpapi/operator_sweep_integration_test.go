package httpapi


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

func seedOperatorAccessToken(t *testing.T, s *apiKeyServer, subject id.UUID) id.UUID {
	t.Helper()
	ctx := context.Background()

	var accountID id.UUID
	if err := s.pool.QueryRow(ctx, `
		SELECT au.account_id FROM account_users au
		WHERE au.user_id = $1 ORDER BY au.account_id LIMIT 1`, subject).Scan(&accountID); err != nil {
		t.Fatalf("finding the subject's account: %v", err)
	}

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

func readOperatorRevokedAt(t *testing.T, s *apiKeyServer, tokenID id.UUID) *time.Time {
	t.Helper()
	var at *time.Time
	if err := s.pool.QueryRow(context.Background(),
		`SELECT revoked_at FROM oidc_access_tokens WHERE id = $1`, tokenID).Scan(&at); err != nil {
		t.Fatalf("reading the access token: %v", err)
	}
	return at
}

func TestADisableRevokesTheAccessTokensAtThisLayer(t *testing.T) {
	s := newAPIKeyServer(t)
	ctx := context.Background()

	operatorToken := provisionOperatorToken(t, s)

	subject := s.user.ID
	token := seedOperatorAccessToken(t, s, subject)

	if got := readOperatorRevokedAt(t, s, token); got != nil {
		t.Fatalf("the fixture's access token was already revoked at %v, so the assertion "+
			"below would pass against a sweep that revoked nothing", got)
	}
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

	revoked := readOperatorRevokedAt(t, s, token)
	if revoked == nil {
		t.Fatal("the access token minted before the disable is still live: the route reached " +
			"the use case, but the use case's sweep did not reach the rows")
	}
	if !revoked.Equal(s.clk.Now()) {
		t.Errorf("revoked_at = %v, want the instant the route passed (%v): the row and the "+
			"disabled_at column are then the same fact", revoked, s.clk.Now())
	}

	if _, err := authServiceFor(s.pool, s.clk).Authenticate(ctx, s.session); err == nil {
		t.Error("the subject's session still authenticates after the route's disable")
	}
}
