package config

// THE APPLE CREDENTIAL WIRING — the one provider whose client secret is derived
// rather than read.
//
// Apple's client_secret is an ES256 JWT this service signs, minted once at
// startup from the four OAUTH_APPLE_* inputs by oauth.MintAppleClientSecret.
// These tests are the wiring: what Load does with the four inputs, and what it
// refuses. The minting itself — the header, the claims, the exp bound — is
// tested in internal/oauth/apple_test.go, where the helper lives.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/oauth"
)

// appleTestPrivateKeyPEM returns a valid .p8 PEM — the shape of
// OAUTH_APPLE_PRIVATE_KEY — for a freshly generated P-256 key.
func appleTestPrivateKeyPEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the test EC key: %v", err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling the test EC key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
}

// A deployment that sets the four inputs gets a provider whose ClientSecret is
// the minted JWT — and the provider it builds carries it, so the exchange path
// (oauth2Config, Client.Exchange) needs no change.
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

	// The minted secret is a three-part compact JWS.
	if parts := strings.Count(cfg.OAuth.Apple.ClientSecret, "."); parts != 2 {
		t.Errorf("Apple ClientSecret = %q, want a compact JWS (two dots)", cfg.OAuth.Apple.ClientSecret)
	}

	// And the provider it builds carries the minted secret and Apple's pinned
	// endpoints — the JWKS URL is not an override, so it is the constant.
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

// A half-configured Apple is the same failed deploy as a half-configured
// Google: some of the four inputs and not all is a mistake and never an
// intention, and the refusal is the same ErrIncompleteProvider the existing
// rule produces — "the existing rule, unchanged".
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

// Apple's two overridable endpoints follow the same pattern as the other three
// providers: a deployment can point the authorize and token calls at a server it
// controls, and the override reaches the built provider.
//
// The JWKS URL is NOT overridable and that absence is the security property (see
// the OAUTH_APPLE_AUTHORIZE_URL constant's comment): the key document is the trust
// root for the id_token, and a deployment that could choose it could forge
// identities. So this test asserts the two overrides reach the provider and the
// JWKS URL stays pinned to Apple's.
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
	// The JWKS URL is the trust root and stays pinned to Apple's.
	if apple.JWKSURL != oauth.AppleJWKSURL {
		t.Errorf("JWKSURL = %q, want the pinned %q — it is not overridable", apple.JWKSURL, oauth.AppleJWKSURL)
	}
}

// With nothing overridden, Apple's endpoints are the definitions — including the
// pinned JWKS URL, which no variable can move.
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
	// No userinfo endpoint: the identity comes from the id_token.
	if apple.UserInfoURL != "" {
		t.Errorf("UserInfoURL = %q, want empty — Apple has no userinfo endpoint", apple.UserInfoURL)
	}
}

// A private key that does not parse is a startup failure naming the variable —
// the same rule MFA_ENCRYPTION_KEY and the token encryption key follow, for
// the same reason: a deployment whose key is wrong should find out at boot.
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
