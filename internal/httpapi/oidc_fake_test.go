package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)


func matrixOIDCClients(t *testing.T, pool *pgxpool.Pool, clk clock.Clock) *oidc.Service {
	t.Helper()

	store := oidc.NewStore(pool)
	storage := oidc.NewStorage(store, oidc.NewProfileReader(), oauth.NewStore(pool), generateTestKey(t), clk, db.Direct{Pool: pool}, oidc.PathLogin)

	return oidc.NewService(
		db.TxRunner{Pool: pool},
		store,
		outbox.NewStore(pool),
		storage,
		clk,
		db.Direct{Pool: pool},
	)
}

type fakeOIDCClients struct {
	registered  oidc.RegisteredClient
	registerErr error
	revokeErr   error
}

func newFakeOIDCClients() *fakeOIDCClients { return &fakeOIDCClients{} }

func (f *fakeOIDCClients) Register(context.Context, oidc.RegisterInput) (oidc.RegisteredClient, error) {
	return f.registered, f.registerErr
}

func (f *fakeOIDCClients) List(context.Context, id.UUID) ([]oidc.Client, error) {
	return []oidc.Client{}, nil
}

func (f *fakeOIDCClients) Get(context.Context, id.UUID, id.UUID) (oidc.Client, error) {
	return oidc.Client{}, nil
}

func (f *fakeOIDCClients) Revoke(context.Context, oidc.RevokeInput) (oidc.Client, error) {
	return oidc.Client{}, f.revokeErr
}

type fakeOIDC struct {
	banner      oidc.LoginBanner
	bannerErr   error
	completeErr error
	jwksErr     error
	loginRedirect string
	redirects []oidc.LoginRedirectParams
	requested []string
	minted  []mintRequest
	mintErr error
}

func newFakeOIDC() *fakeOIDC {
	return &fakeOIDC{loginRedirect: "https://login.example.com/sign-in/oidc"}
}

func (f *fakeOIDC) Handler() http.Handler { return http.NotFoundHandler() }

func (f *fakeOIDC) Discovery(*http.Request) any {
	return map[string]any{"issuer": "https://identity.test"}
}

func (f *fakeOIDC) JWKS() ([]byte, error) {
	if f.jwksErr != nil {
		return nil, f.jwksErr
	}
	return []byte(`{"keys":[]}`), nil
}

func (f *fakeOIDC) LoginBanner(_ context.Context, requestID string) (oidc.LoginBanner, error) {
	f.requested = append(f.requested, requestID)
	if f.bannerErr != nil {
		return oidc.LoginBanner{}, f.bannerErr
	}
	banner := f.banner
	banner.RequestID = requestID
	return banner, nil
}

func (f *fakeOIDC) LoginRedirect(params oidc.LoginRedirectParams) string {
	f.redirects = append(f.redirects, params)
	parsed, err := url.Parse(f.loginRedirect)
	if err != nil {
		panic("fakeOIDC: the login redirect address does not parse: " + err.Error())
	}
	parsed.RawQuery = params.Values().Encode()
	return parsed.String()
}

func (f *fakeOIDC) CompleteLogin(context.Context, string, id.UUID) error { return f.completeErr }

type mintRequest struct {
	subject   id.UUID
	accountID id.UUID
	audience  string
	at        time.Time
}

func (f *fakeOIDC) MintAccountToken(subject, accountID id.UUID, audience string, now time.Time) (oidc.MintedToken, error) {
	f.minted = append(f.minted, mintRequest{subject: subject, accountID: accountID, audience: audience, at: now})
	if f.mintErr != nil {
		return oidc.MintedToken{}, f.mintErr
	}
	expiresAt := now.Add(oidc.AccountTokenTTL)
	return oidc.MintedToken{Token: "fake-minted-token", ExpiresAt: expiresAt}, nil
}
