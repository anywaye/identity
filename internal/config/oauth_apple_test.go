package config


import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/oauth"
)

func appleTestPrivateKeyPEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the test EC key: %v", err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling the test EC key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
}

func TestAppleCredentialsAreMintedAtLoad(t *testing.T) {
	t.Parallel()

	env := oauthTestEnv()
	env[OAuthAppleClientIDVar] = "com.example.app"
	env[OAuthAppleTeamIDVar] = "ABCDE12345"
	env[OAuthAppleKeyIDVar] = "KEYID12345"
	env[OAuthApplePrivateKeyVar] = appleTestPrivateKeyPEM(t)

	cfg, err := Load(lookupFrom(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.OAuth.Apple.ClientID != "com.example.app" {
		t.Errorf("Apple ClientID = %q, want the services id", cfg.OAuth.Apple.ClientID)
	}
	if cfg.OAuth.Apple.ClientSecret == "" {
		t.Error("Apple ClientSecret is empty, want the minted JWT")
	}

	if parts := strings.Count(cfg.OAuth.Apple.ClientSecret, "."); parts != 2 {
		t.Errorf("Apple ClientSecret = %q, want a compact JWS (two dots)", cfg.OAuth.Apple.ClientSecret)
	}

	var apple oauth.Provider
	for _, p := range cfg.OAuth.Providers() {
		if p.Name == oauth.ProviderApple {
			apple = p
		}
	}
	if apple.Name == "" {
		t.Fatal("apple is not among the providers this deployment would serve")
	}
	if apple.ClientSecret != cfg.OAuth.Apple.ClientSecret {
		t.Errorf("the apple provider's ClientSecret = %q, want the minted %q", apple.ClientSecret, cfg.OAuth.Apple.ClientSecret)
	}
	if apple.JWKSURL != oauth.AppleJWKSURL {
		t.Errorf("apple JWKSURL = %q, want %q", apple.JWKSURL, oauth.AppleJWKSURL)
	}
}

func TestAHalfConfiguredAppleProviderFailsStartup(t *testing.T) {
	t.Parallel()

	for name, env := range map[string]map[string]string{
		"only the client id": {
			OAuthAppleClientIDVar: "com.example.app",
		},
		"only the private key": {
			OAuthApplePrivateKeyVar: appleTestPrivateKeyPEM(t),
		},
		"everything but the key id": {
			OAuthAppleClientIDVar:   "com.example.app",
			OAuthAppleTeamIDVar:     "ABCDE12345",
			OAuthApplePrivateKeyVar: appleTestPrivateKeyPEM(t),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			full := oauthTestEnv()
			for k, v := range env {
				full[k] = v
			}

			_, err := Load(lookupFrom(full))
			if !errors.Is(err, ErrInvalidOAuth) {
				t.Errorf("Load = %v, want ErrInvalidOAuth", err)
			}
			if !errors.Is(err, oauth.ErrIncompleteProvider) {
				t.Errorf("Load = %v, want it to wrap oauth.ErrIncompleteProvider — the same refusal the "+
					"other three providers get", err)
			}
		})
	}
}

func TestAppleEndpointOverridesReachTheBuiltProvider(t *testing.T) {
	t.Parallel()

	env := oauthTestEnv()
	env[OAuthAppleClientIDVar] = "com.example.app"
	env[OAuthAppleTeamIDVar] = "ABCDE12345"
	env[OAuthAppleKeyIDVar] = "KEYID12345"
	env[OAuthApplePrivateKeyVar] = appleTestPrivateKeyPEM(t)
	env[OAuthAppleAuthorizeURLVar] = "https://idp.test/fake/apple/authorize"
	env[OAuthAppleTokenURLVar] = "https://idp.test/fake/apple/token"

	cfg, err := Load(lookupFrom(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	var apple oauth.Provider
	for _, p := range cfg.OAuth.Providers() {
		if p.Name == oauth.ProviderApple {
			apple = p
		}
	}
	if apple.Name == "" {
		t.Fatal("apple is not among the providers this deployment would serve")
	}
	if apple.AuthorizeURL != "https://idp.test/fake/apple/authorize" {
		t.Errorf("AuthorizeURL = %q, want the override", apple.AuthorizeURL)
	}
	if apple.TokenURL != "https://idp.test/fake/apple/token" {
		t.Errorf("TokenURL = %q, want the override", apple.TokenURL)
	}
	if apple.JWKSURL != oauth.AppleJWKSURL {
		t.Errorf("JWKSURL = %q, want the pinned %q — it is not overridable", apple.JWKSURL, oauth.AppleJWKSURL)
	}
}

func TestWithNothingSetApplesEndpointsAreTheDefinitions(t *testing.T) {
	t.Parallel()

	env := oauthTestEnv()
	env[OAuthAppleClientIDVar] = "com.example.app"
	env[OAuthAppleTeamIDVar] = "ABCDE12345"
	env[OAuthAppleKeyIDVar] = "KEYID12345"
	env[OAuthApplePrivateKeyVar] = appleTestPrivateKeyPEM(t)

	cfg, err := Load(lookupFrom(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	var apple oauth.Provider
	for _, p := range cfg.OAuth.Providers() {
		if p.Name == oauth.ProviderApple {
			apple = p
		}
	}
	if apple.Name == "" {
		t.Fatal("apple is not among the providers this deployment would serve")
	}
	if apple.AuthorizeURL != oauth.AppleAuthorizeURL {
		t.Errorf("AuthorizeURL = %q, want the definition %q", apple.AuthorizeURL, oauth.AppleAuthorizeURL)
	}
	if apple.TokenURL != oauth.AppleTokenURL {
		t.Errorf("TokenURL = %q, want the definition %q", apple.TokenURL, oauth.AppleTokenURL)
	}
	if apple.JWKSURL != oauth.AppleJWKSURL {
		t.Errorf("JWKSURL = %q, want the definition %q", apple.JWKSURL, oauth.AppleJWKSURL)
	}
	if apple.UserInfoURL != "" {
		t.Errorf("UserInfoURL = %q, want empty — Apple has no userinfo endpoint", apple.UserInfoURL)
	}
}

func TestAnUnparseableApplePrivateKeyFailsStartup(t *testing.T) {
	t.Parallel()

	env := oauthTestEnv()
	env[OAuthAppleClientIDVar] = "com.example.app"
	env[OAuthAppleTeamIDVar] = "ABCDE12345"
	env[OAuthAppleKeyIDVar] = "KEYID12345"
	env[OAuthApplePrivateKeyVar] = "not a PEM block"

	_, err := Load(lookupFrom(env))
	if !errors.Is(err, ErrInvalidOAuth) {
		t.Fatalf("Load = %v, want ErrInvalidOAuth", err)
	}
	if !strings.Contains(err.Error(), OAuthApplePrivateKeyVar) {
		t.Errorf("Load = %q, want it to name %s", err, OAuthApplePrivateKeyVar)
	}
}
