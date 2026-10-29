package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/config"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/platform/dbtest"
)


func testKeyPEM(t *testing.T) string {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling the signing key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func oidcConfig(t *testing.T, dsn string) config.Config {
	t.Helper()

	return config.Config{
		Port:           "0",
		LogLevel:       "error",
		DatabaseURL:    dsn,
		OIDCIssuer:     "https://identity.test",
		OIDCSigningKey: testKeyPEM(t),
		OIDCKeyID:      "anywaye-wiring-test",
		OIDCLoginUIURL: "https://login.example.com/sign-in/oidc",
		SignupSigningKeyValue: signupKeyValue,
	}
}

func TestNewAppServesTheOIDCProvider(t *testing.T) {
	dsn := testDatabaseURL(t)

	a, err := newApp(context.Background(), oidcConfig(t, dsn), discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	rec := serveBody(t, a, http.MethodGet, oidc.PathDiscovery, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200; body: %s", oidc.PathDiscovery, rec.Code, rec.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("the discovery document is not JSON: %v", err)
	}
	if doc["issuer"] != "https://identity.test" {
		t.Errorf("issuer = %v, want the configured one", doc["issuer"])
	}

	alias := serveBody(t, a, http.MethodGet, oidc.PathOAuthAuthorizationServer, "", nil)
	if alias.Code != http.StatusOK {
		t.Errorf("GET %s = %d, want 200", oidc.PathOAuthAuthorizationServer, alias.Code)
	}

	keys := serveBody(t, a, http.MethodGet, oidc.PathJWKS, "", nil)
	if keys.Code != http.StatusOK {
		t.Errorf("GET %s = %d, want 200", oidc.PathJWKS, keys.Code)
	}

	registered := serveBody(t, a, http.MethodPost, "/v1/accounts/00000000-0000-4000-8000-000000000000/oidc-clients", `{}`, nil)
	if registered.Code != http.StatusUnauthorized {
		t.Errorf("POST an OIDC client route anonymously = %d, want 401; a 404 means the route is not mounted",
			registered.Code)
	}
}

func TestNewAppWithoutOIDCKeysIsNotAProvider(t *testing.T) {
	dsn := testDatabaseURL(t)

	cfg := config.Config{Port: "0", LogLevel: "error", DatabaseURL: dsn}
	a, err := newApp(context.Background(), cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	for _, target := range []string{
		oidc.PathDiscovery,
		oidc.PathOAuthAuthorizationServer,
		oidc.PathJWKS,
		oidc.PathAuthorize,
		oidc.PathToken,
		oidc.PathUserinfo,
		oidc.PathLogin + "/00000000-0000-4000-8000-000000000000",
	} {
		rec := serveBody(t, a, http.MethodGet, target, "", nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 with no OIDC configuration; body: %s", target, rec.Code, rec.Body)
		}
	}

	registerUserWithPair(t, a, dbtest.UniqueEmail(t), "correct horse battery staple")
}

func TestNewAppWithOIDCKeysButNoDatabaseIsNotAProvider(t *testing.T) {
	cfg := oidcConfig(t, "")
	cfg.DatabaseURL = ""

	a, err := newApp(context.Background(), cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	rec := serveBody(t, a, http.MethodGet, "/healthz", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", rec.Code)
	}

	for _, target := range []string{oidc.PathDiscovery, oidc.PathJWKS, oidc.PathAuthorize} {
		got := serveBody(t, a, http.MethodGet, target, "", nil)
		if got.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 with no database; body: %s", target, got.Code, got.Body)
		}
	}
}

func TestNewAppRefusesAnUnparseableSigningKey(t *testing.T) {
	dsn := testDatabaseURL(t)

	cfg := oidcConfig(t, dsn)
	cfg.OIDCSigningKey = "-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n"

	if _, err := newApp(context.Background(), cfg, discardLogger()); err == nil {
		t.Fatal("newApp accepted an unparseable signing key")
	}
}

func TestNewAppRefusesToBeAProviderWithNoLoginUI(t *testing.T) {
	dsn := testDatabaseURL(t)

	cfg := oidcConfig(t, dsn)
	cfg.OIDCLoginUIURL = ""

	_, err := newApp(context.Background(), cfg, discardLogger())
	if err == nil {
		t.Fatal("newApp built a provider that cannot send a browser anywhere to sign in")
	}
	if !errors.Is(err, oidc.ErrNoLoginUI) {
		t.Errorf("newApp = %v, want an error matching oidc.ErrNoLoginUI", err)
	}
	if !strings.Contains(err.Error(), oidc.LoginUIEnvVar) {
		t.Errorf("the refusal does not name %s: %v", oidc.LoginUIEnvVar, err)
	}
}

func TestNewAppSendsTheBrowserToTheConfiguredLoginUI(t *testing.T) {
	dsn := testDatabaseURL(t)

	a, err := newApp(context.Background(), oidcConfig(t, dsn), discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	rec := serveBody(t, a, http.MethodGet, oidc.PathLogin+"/00000000-0000-4000-8000-000000000000", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET the login interaction = %d, want 404; body: %s", rec.Code, rec.Body)
	}
}
