package oauth_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/platform/oauthtest"
)


const fakeRedirectURI = "https://identity.anywaye.com/v1/auth/oauth/google/callback"

func newTestClient(t *testing.T) *oauth.Client {
	t.Helper()
	return oauth.NewClient(oauth.ClientOptions{RedirectBaseURL: "https://identity.anywaye.com"})
}

func TestClientExchangeSendsTheCodeAndTheRedirectURI(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)
	provider := server.Provider(t, oauth.Google())

	tokens, err := newTestClient(t).Exchange(context.Background(), provider, server.Code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	form := server.LastTokenForm()
	if got := form.Get("code"); got != server.Code {
		t.Errorf("code = %q, want %q", got, server.Code)
	}
	if got := form.Get("redirect_uri"); got != fakeRedirectURI {
		t.Errorf("redirect_uri = %q, want %q", got, fakeRedirectURI)
	}
	if got := form.Get("grant_type"); got != "authorization_code" {
		t.Errorf("grant_type = %q, want authorization_code", got)
	}

	if tokens.AccessToken != server.AccessToken {
		t.Errorf("AccessToken = %q, want %q", tokens.AccessToken, server.AccessToken)
	}
	if tokens.RefreshToken != server.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", tokens.RefreshToken, server.RefreshToken)
	}
	if tokens.ExpiresAt == nil {
		t.Fatal("ExpiresAt is nil, want the token's one-hour expiry")
	}
	if want := time.Now().Add(time.Hour); !tokens.ExpiresAt.After(want.Add(-time.Minute)) || !tokens.ExpiresAt.Before(want.Add(time.Minute)) {
		t.Errorf("ExpiresAt = %s, want about %s", tokens.ExpiresAt, want)
	}
}

func TestClientExchangeWithNoExpiryLeavesExpiresAtNil(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).WithoutExpiry()

	tokens, err := newTestClient(t).Exchange(context.Background(), server.Provider(t, oauth.GitHub()), server.Code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tokens.ExpiresAt != nil {
		t.Errorf("ExpiresAt = %v, want nil when the provider issues no expiry", *tokens.ExpiresAt)
	}
}

func TestClientExchangeRefusesA200WithNoAccessToken(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)
	server.AccessToken = ""

	if _, err := newTestClient(t).Exchange(context.Background(), server.Provider(t, oauth.Google()), server.Code); err == nil {
		t.Error("Exchange accepted a 200 with no access token")
	}
}

func TestClientExchangeRefusesAnEmptyCodeWithoutCallingTheProvider(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)

	for _, code := range []string{"", "   "} {
		_, err := newTestClient(t).Exchange(context.Background(), server.Provider(t, oauth.Google()), code)
		if !errors.Is(err, oauth.ErrCodeRefused) {
			t.Errorf("Exchange(%q) = %v, want ErrCodeRefused", code, err)
		}
	}
	if calls := server.Calls(); len(calls) != 0 {
		t.Errorf("the provider was called %v for an empty code, want no call at all", calls)
	}
}

func TestClientExchangeMapsAProviderRefusal(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).FailToken(http.StatusBadRequest)

	_, err := newTestClient(t).Exchange(context.Background(), server.Provider(t, oauth.Google()), "a-code-the-provider-never-issued")
	if !errors.Is(err, oauth.ErrCodeRefused) {
		t.Errorf("Exchange = %v, want ErrCodeRefused", err)
	}
	if errors.Is(err, oauth.ErrProviderUnavailable) {
		t.Error("a refused code was also reported as an unavailable provider")
	}
}

func TestClientExchangeMapsAProviderOutage(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			server := oauthtest.NewServer(t).FailToken(status)
			_, err := newTestClient(t).Exchange(context.Background(), server.Provider(t, oauth.Google()), server.Code)
			if !errors.Is(err, oauth.ErrProviderUnavailable) {
				t.Errorf("Exchange with a %d = %v, want ErrProviderUnavailable", status, err)
			}
		})
	}
}

func TestClientExchangeMapsAnUnreachableProvider(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)
	provider := server.Provider(t, oauth.Google())
	server.Close()

	_, err := newTestClient(t).Exchange(context.Background(), provider, server.Code)
	if !errors.Is(err, oauth.ErrProviderUnavailable) {
		t.Errorf("Exchange against a dead server = %v, want ErrProviderUnavailable", err)
	}
}

func TestClientErrorsCarryTheProviderDetail(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).FailToken(http.StatusInternalServerError)

	_, err := newTestClient(t).Exchange(context.Background(), server.Provider(t, oauth.Google()), server.Code)
	if err == nil {
		t.Fatal("Exchange succeeded against a 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not mention the status the provider returned", err)
	}
}

func TestClientIdentityReadsGoogle(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).Person("107346492749283471920", "kaka@example.com", "Kaka")

	identity, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.Google()), oauth.Tokens{
		AccessToken: server.AccessToken,
	})
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}

	if identity.ProviderUID != "107346492749283471920" {
		t.Errorf("ProviderUID = %q, want the google sub", identity.ProviderUID)
	}
	if identity.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want kaka@example.com", identity.Email)
	}
	if identity.Name != "Kaka" {
		t.Errorf("Name = %q, want Kaka", identity.Name)
	}
	if got := server.LastAuthorization(); !strings.Contains(got, server.AccessToken) {
		t.Errorf("the identity call carried %q, want it to present the access token", got)
	}
}

func TestClientIdentityReadsGitHub(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).Person("583231", "kaka@example.com", "Kaka")

	identity, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.GitHub()), oauth.Tokens{
		AccessToken: server.AccessToken,
	})
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}

	if identity.ProviderUID != "583231" {
		t.Errorf("ProviderUID = %q, want 583231 as a string", identity.ProviderUID)
	}
	if identity.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want kaka@example.com", identity.Email)
	}
}

func TestClientIdentityReadsMicrosoft(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).Person("a1b2c3d4-e5f6-7890-abcd-ef1234567890", "kaka@example.com", "Kaka")

	identity, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.Microsoft()), oauth.Tokens{
		AccessToken: server.AccessToken,
	})
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}

	if identity.ProviderUID != "a1b2c3d4-e5f6-7890-abcd-ef1234567890" {
		t.Errorf("ProviderUID = %q, want the microsoft sub", identity.ProviderUID)
	}
	if identity.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want kaka@example.com", identity.Email)
	}
	if identity.Name != "Kaka" {
		t.Errorf("Name = %q, want Kaka", identity.Name)
	}
	if got := server.LastAuthorization(); !strings.Contains(got, server.AccessToken) {
		t.Errorf("the identity call carried %q, want it to present the access token", got)
	}
}

func TestClientIdentityReadsApple(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).Person("a1b2c3d4-e5f6-7890-abcd-ef1234567890", "kaka@example.com", "Kaka")

	provider := server.Provider(t, oauth.Apple())
	exchanged, err := newTestClient(t).Exchange(context.Background(), provider, server.Code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if exchanged.IDToken == "" {
		t.Fatal("the exchange extracted no id_token, so the Apple path has nothing to verify")
	}

	identity, err := newTestClient(t).Identity(context.Background(), provider, exchanged)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}

	if identity.ProviderUID != "a1b2c3d4-e5f6-7890-abcd-ef1234567890" {
		t.Errorf("ProviderUID = %q, want the apple sub", identity.ProviderUID)
	}
	if identity.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want kaka@example.com", identity.Email)
	}
	if identity.Name != "" {
		t.Errorf("Name = %q, want empty: the name scope is not requested", identity.Name)
	}

	oauthtest.RequireCalls(t, server, oauthtest.TokenEndpointPath, oauthtest.JWKSPath)
}

func TestClientIdentityRefusesAnAppleIDTokenSignedByAnUnpublishedKey(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).
		Person("a1b2c3d4-e5f6-7890-abcd-ef1234567890", "kaka@example.com", "Kaka").
		WithUnpublishedKey()

	provider := server.Provider(t, oauth.Apple())
	exchanged, err := newTestClient(t).Exchange(context.Background(), provider, server.Code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	identity, err := newTestClient(t).Identity(context.Background(), provider, exchanged)
	if err == nil {
		t.Fatalf("Identity accepted an id_token signed by a key the JWKS does not publish: %+v", identity)
	}
	if !errors.Is(err, oauth.ErrProviderUnavailable) {
		t.Errorf("Identity = %v, want ErrProviderUnavailable", err)
	}
	oauthtest.RequireCalls(t, server, oauthtest.TokenEndpointPath, oauthtest.JWKSPath)
}

func TestClientIdentityRefusesAnAppleIDTokenWithNoIDToken(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)

	_, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.Apple()), oauth.Tokens{
		AccessToken: server.AccessToken,
	})
	if !errors.Is(err, oauth.ErrProviderUnavailable) {
		t.Errorf("Identity with no id_token = %v, want ErrProviderUnavailable", err)
	}
	oauthtest.RequireCalls(t, server)
}

func TestClientIdentityFallsBackToTheGitHubEmailsEndpoint(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).
		Person("583231", "", "Kaka").
		WithoutEmail().
		WithEmails(
			oauthtest.Email{Address: "old@example.com", Verified: true},
			oauthtest.Email{Address: "kaka@example.com", Primary: true, Verified: true},
			oauthtest.Email{Address: "other@example.com"},
		)

	identity, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.GitHub()), oauth.Tokens{
		AccessToken: server.AccessToken,
	})
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}

	if identity.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want the primary verified address", identity.Email)
	}
	oauthtest.RequireCalls(t, server, oauthtest.UserInfoEndpointPath, oauthtest.EmailsEndpointPath)
}

func TestClientIdentityRefusesAnUnverifiedOnlyGitHubAccount(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).
		Person("583231", "", "Kaka").
		WithoutEmail().
		WithEmails(oauthtest.Email{Address: "attacker@example.com", Primary: true, Verified: false})

	_, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.GitHub()), oauth.Tokens{
		AccessToken: server.AccessToken,
	})
	if !errors.Is(err, oauth.ErrNoEmail) {
		t.Errorf("Identity = %v, want ErrNoEmail", err)
	}
}

func TestClientIdentityRefusesAnEmailThisServiceCannotUse(t *testing.T) {
	t.Parallel()

	for _, email := range []string{
		"",
		"   ",
		"not an address",
		"a@",
		"@example.com",
		"a b@example.com",
	} {
		t.Run(email, func(t *testing.T) {
			t.Parallel()

			server := oauthtest.NewServer(t).Person("583231", email, "Kaka")

			_, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.Google()), oauth.Tokens{
				AccessToken: server.AccessToken,
			})
			if !errors.Is(err, oauth.ErrNoEmail) {
				t.Errorf("Identity with the email %q = %v, want ErrNoEmail", email, err)
			}
		})
	}
}

func TestClientIdentityRefusesAResponseWithNoIdentifier(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).Person("", "kaka@example.com", "Kaka")

	for _, name := range []string{oauth.ProviderGoogle, oauth.ProviderGitHub} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			base := oauth.Google()
			if name == oauth.ProviderGitHub {
				base = oauth.GitHub()
			}

			_, err := newTestClient(t).Identity(context.Background(), server.Provider(t, base), oauth.Tokens{
				AccessToken: server.AccessToken,
			})
			if err == nil {
				t.Error("Identity accepted a response with no provider identifier")
			}
		})
	}
}

func TestClientIdentityMapsAProviderOutage(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).FailUserInfo(http.StatusInternalServerError)

	_, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.Google()), oauth.Tokens{
		AccessToken: server.AccessToken,
	})
	if !errors.Is(err, oauth.ErrProviderUnavailable) {
		t.Errorf("Identity = %v, want ErrProviderUnavailable", err)
	}
}

func TestClientIdentityMapsAnUnauthorizedIdentityCall(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)

	_, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.Google()), oauth.Tokens{
		AccessToken: "a-token-the-provider-never-issued",
	})
	if !errors.Is(err, oauth.ErrProviderUnavailable) {
		t.Errorf("Identity = %v, want ErrProviderUnavailable", err)
	}
}

func TestClientIdentityRefusesAnEmptyAccessToken(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)

	_, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.Google()), oauth.Tokens{})
	if !errors.Is(err, oauth.ErrProviderUnavailable) {
		t.Errorf("Identity with no access token = %v, want ErrProviderUnavailable", err)
	}
	oauthtest.RequireCalls(t, server)
}

func TestClientIdentityCapsTheResponseBody(t *testing.T) {
	t.Parallel()

	padding := strings.Repeat("x", 4<<20)
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"sub":"1","email":"`)
		_, _ = io.WriteString(w, padding)
		_, _ = io.WriteString(w, `","name":"Kaka"}`)
	}))
	defer big.Close()

	provider := oauth.Google()
	provider.UserInfoURL = big.URL + "/userinfo"

	client := oauth.NewClient(oauth.ClientOptions{
		HTTPClient:      &http.Client{Timeout: 5 * time.Second},
		RedirectBaseURL: "https://identity.anywaye.com",
	})
	if _, err := client.Identity(context.Background(), provider, oauth.Tokens{AccessToken: "t"}); err == nil {
		t.Error("Identity accepted a response past the size cap")
	}
}
