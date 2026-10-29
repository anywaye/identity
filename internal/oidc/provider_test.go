package oidc

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)


func newTestProvider(t *testing.T) *Provider {
	t.Helper()

	key, err := LoadSigningKey(pemFor(t, 2048, pkcs8), "anywaye-test-key")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	storage := NewStorage(nil, NewProfileReader(), nil, key, testClock{}, nil, PathLogin)

	provider, err := NewProvider(Config{
		Issuer:        "https://identity.test",
		SigningKey:    key,
		AllowInsecure: false,
		LoginUIURL:    testLoginUIURL,
	}, storage)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return provider
}

func TestDiscoveryCarriesEveryRequiredField(t *testing.T) {
	t.Parallel()

	doc := newTestProvider(t).DiscoveryFor(contextWithIssuer(t, "https://identity.test"))

	required := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
		"jwks_uri",
		"scopes_supported",
		"response_types_supported",
		"grant_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
		"token_endpoint_auth_methods_supported",
		"claims_supported",
		"code_challenge_methods_supported",
	}

	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshaling the discovery document: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("the discovery document is not JSON: %v", err)
	}
	for _, name := range required {
		if _, present := fields[name]; !present {
			t.Errorf("the discovery document has no %q; a conformant client needs it", name)
		}
	}
}

func TestDiscoveryIssuerMatchesTheConfiguredOne(t *testing.T) {
	t.Parallel()

	const issuer = "https://identity.test"
	doc := newTestProvider(t).DiscoveryFor(contextWithIssuer(t, issuer))

	if doc.Issuer != issuer {
		t.Errorf("issuer = %q, want %q", doc.Issuer, issuer)
	}
	for name, value := range map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"userinfo_endpoint":      doc.UserinfoEndpoint,
		"jwks_uri":               doc.JwksURI,
	} {
		if !strings.HasPrefix(value, issuer+"/") {
			t.Errorf("%s = %q, want it under the issuer %q", name, value, issuer)
		}
	}
}

func TestDiscoveryPointsAtThePathGatewayHardcodes(t *testing.T) {
	t.Parallel()

	doc := newTestProvider(t).DiscoveryFor(contextWithIssuer(t, "https://identity.test"))

	if want := "https://identity.test" + PathJWKS; doc.JwksURI != want {
		t.Errorf("jwks_uri = %q, want %q; gateway appends %q to its issuer and never reads this field",
			doc.JwksURI, want, PathJWKS)
	}
}

func TestDiscoveryOmitsWhatThisServiceDoesNotServe(t *testing.T) {
	t.Parallel()

	doc := newTestProvider(t).DiscoveryFor(contextWithIssuer(t, "https://identity.test"))

	omitted := map[string]string{
		"introspection_endpoint":        doc.IntrospectionEndpoint,
		"revocation_endpoint":           doc.RevocationEndpoint,
		"end_session_endpoint":          doc.EndSessionEndpoint,
		"device_authorization_endpoint": doc.DeviceAuthorizationEndpoint,
		"check_session_iframe":          doc.CheckSessionIframe,
		"registration_endpoint":         doc.RegistrationEndpoint,

		"introspection_endpoint_auth_methods_supported": joinMethods(
			doc.IntrospectionEndpointAuthMethodsSupported),
		"introspection_endpoint_auth_signing_alg_values_supported": joinAlgs(
			doc.IntrospectionEndpointAuthSigningAlgValuesSupported),
		"revocation_endpoint_auth_methods_supported": joinMethods(
			doc.RevocationEndpointAuthMethodsSupported),
		"revocation_endpoint_auth_signing_alg_values_supported": joinAlgs(
			doc.RevocationEndpointAuthSigningAlgValuesSupported),

		"request_parameter_supported":           boolField(doc.RequestParameterSupported),
		"back_channel_logout_supported":         boolField(doc.BackChannelLogoutSupported),
		"back_channel_logout_session_supported": boolField(doc.BackChannelLogoutSessionSupported),
		"client_id_metadata_document_supp":      boolField(doc.ClientIDMetadataDocumentSupported),
	}
	for name, value := range omitted {
		if value != "" && value != "false" {
			t.Errorf("the discovery document advertises %s = %q; this service does not serve it", name, value)
		}
	}
}

func joinMethods(methods []oidc.AuthMethod) string {
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		out = append(out, string(m))
	}
	return strings.Join(out, ",")
}

func joinAlgs(algs []string) string { return strings.Join(algs, ",") }

func TestDiscoveryAdvertisesOnlyWhatIsImplemented(t *testing.T) {
	t.Parallel()

	doc := newTestProvider(t).DiscoveryFor(contextWithIssuer(t, "https://identity.test"))

	if !slices.Equal(doc.ResponseTypesSupported, []string{"code"}) {
		t.Errorf("response_types_supported = %v, want [code]; there is no implicit flow", doc.ResponseTypesSupported)
	}
	if !slices.Equal(doc.GrantTypesSupported, []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}) {
		t.Errorf("grant_types_supported = %v, want [authorization_code, refresh_token]; the refresh grant is mounted "+
			"this packet, and a document that hides a grant the token endpoint honors is a document a client library "+
			"reads and then does not use. Client credentials and the JWT profile remain absent, and they are absent "+
			"because there is no service identity and no client private key, not because the list is short.",
			doc.GrantTypesSupported)
	}
	if !slices.Equal(doc.CodeChallengeMethodsSupported, []oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256}) {
		t.Errorf("code_challenge_methods_supported = %v, want [S256]", doc.CodeChallengeMethodsSupported)
	}
	if !slices.Equal(doc.ScopesSupported, SupportedScopes) {
		t.Errorf("scopes_supported = %v, want %v", doc.ScopesSupported, SupportedScopes)
	}
	if !slices.Equal(doc.IDTokenSigningAlgValuesSupported, []string{"RS256"}) {
		t.Errorf("id_token_signing_alg_values_supported = %v, want [RS256]", doc.IDTokenSigningAlgValuesSupported)
	}
	if !slices.Equal(doc.TokenEndpointAuthMethodsSupported, []oidc.AuthMethod{oidc.AuthMethodBasic}) {
		t.Errorf("token_endpoint_auth_methods_supported = %v, want [client_secret_basic]; `none` would tell a "+
			"client it may skip authenticating, and every client here holds a secret",
			doc.TokenEndpointAuthMethodsSupported)
	}
}

func TestDiscoveryClaimsAreClaimsThisServiceAsserts(t *testing.T) {
	t.Parallel()

	doc := newTestProvider(t).DiscoveryFor(contextWithIssuer(t, "https://identity.test"))

	advertised := map[string]bool{}
	for _, claim := range doc.ClaimsSupported {
		advertised[claim] = true
	}
	for _, want := range []string{"sub", ScopeEmail, ClaimEmailVerified, "name", ClaimAccounts, "nonce", "iss", "aud", "exp", "iat", "jti"} {
		if !advertised[want] {
			t.Errorf("claims_supported does not advertise %q", want)
		}
	}
	for _, unwanted := range []string{"address", "phone_number", "phone_number_verified", "picture", "website", "birthdate", "gender", "zoneinfo", "locale", "family_name", "given_name", "preferred_username"} {
		if advertised[unwanted] {
			t.Errorf("claims_supported advertises %q, and this service has no column for it", unwanted)
		}
	}
}

func TestNewProviderRefusesAnIssuerItCannotBeVerifiedAgainst(t *testing.T) {
	t.Parallel()

	key, err := LoadSigningKey(pemFor(t, 2048, pkcs8), "anywaye-test-key")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}

	tests := []struct {
		name   string
		issuer string
	}{
		{name: "empty", issuer: ""},
		{name: "no scheme", issuer: "identity.test"},
		{name: "a path", issuer: "https://identity.test/oidc"},
		{name: "a query", issuer: "https://identity.test?a=1"},
		{name: "a fragment", issuer: "https://identity.test#x"},
		{name: "a scheme that is not http", issuer: "ftp://identity.test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			storage := NewStorage(nil, NewProfileReader(), nil, key, testClock{}, nil, PathLogin)
			if _, err := NewProvider(Config{Issuer: tt.issuer, SigningKey: key, LoginUIURL: testLoginUIURL}, storage); err == nil {
				t.Errorf("NewProvider accepted the issuer %q", tt.issuer)
			}
		})
	}
}

func TestNewProviderAcceptsATrailingSlash(t *testing.T) {
	t.Parallel()

	key, err := LoadSigningKey(pemFor(t, 2048, pkcs8), "anywaye-test-key")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	storage := NewStorage(nil, NewProfileReader(), nil, key, testClock{}, nil, PathLogin)

	provider, err := NewProvider(Config{Issuer: "https://identity.test/", SigningKey: key, LoginUIURL: testLoginUIURL}, storage)
	if err != nil {
		t.Fatalf("NewProvider with a trailing slash: %v", err)
	}
	doc := provider.DiscoveryFor(contextWithIssuer(t, "https://identity.test/"))
	if want := "https://identity.test" + PathToken; doc.TokenEndpoint != want {
		t.Errorf("token_endpoint = %q, want %q with no doubled slash", doc.TokenEndpoint, want)
	}
}

func TestNewProviderRefusesToBuildWithoutASigningKey(t *testing.T) {
	t.Parallel()

	storage := NewStorage(nil, NewProfileReader(), nil, nil, testClock{}, nil, PathLogin)
	if _, err := NewProvider(Config{Issuer: "https://identity.test", LoginUIURL: testLoginUIURL}, storage); err == nil {
		t.Fatal("NewProvider built a provider with no signing key")
	}
}

func TestDerivedEncryptionKeyIsNotTheSigningKey(t *testing.T) {
	t.Parallel()

	key, err := LoadSigningKey(pemFor(t, 2048, pkcs8), "anywaye-test-key")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}

	first, firstID := deriveEncryptionKey(key)
	second, secondID := deriveEncryptionKey(key)

	if first != second {
		t.Error("the derivation is not stable for one key; a restart would change the encryption key")
	}
	if firstID != secondID {
		t.Errorf("the derived key id changed between calls: %q then %q", firstID, secondID)
	}
	if first == ([32]byte{}) {
		t.Error("the derived key is all zeroes; the userinfo handler decrypts before it verifies, " +
			"so a zero key would let anybody encrypt a forged token and be believed")
	}
	if firstID == key.ID() {
		t.Error("the encryption key id equals the signing kid, so a rotation could not tell them apart in a log")
	}

	other, err := LoadSigningKey(pemFor(t, 2048, pkcs8), "anywaye-test-key")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	if otherKey, _ := deriveEncryptionKey(other); otherKey == first {
		t.Error("two different signing keys derived the same encryption key")
	}
}

type testClock struct{}

func (testClock) Now() time.Time { return time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC) }

func contextWithIssuer(t *testing.T, issuer string) context.Context {
	t.Helper()
	return op.ContextWithIssuer(context.Background(), issuer)
}

func boolField(v bool) string {
	if v {
		return "true"
	}
	return ""
}
