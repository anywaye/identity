package oidc

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/anywaye/identity/internal/platform/id"
)


const (
	PathAuthorize = "/oidc/authorize"
	PathToken = "/oidc/token"
	PathUserinfo = "/oidc/userinfo"
	PathLogin = "/oidc/login"
	PathJWKS = "/.well-known/jwks.json"
	PathDiscovery = "/.well-known/openid-configuration"
	PathOAuthAuthorizationServer = "/.well-known/oauth-authorization-server"
)

// Config is what it takes to be an OpenID Connect provider.
type Config struct {
	Issuer string
	SigningKey *SigningKey
	AllowInsecure bool
	LoginUIURL string
}

// Provider is the assembled OpenID Connect provider.
type Provider struct {
	op      *op.Provider
	storage *Storage
	issuer  string
	loginUI *url.URL
}

// NewProvider builds the provider.
//
// The issuer is static rather than derived from the request Host. A provider
// whose issuer depends on the Host header publishes a different `iss` per request
// and every token it mints is rejected by a verifier configured with any other
// name for it — which is the failure mode RFC 8414 §3.3 warns about by name.
func NewProvider(cfg Config, storage *Storage) (*Provider, error) {
	if err := validateIssuer(cfg.Issuer); err != nil {
		return nil, err
	}
	if cfg.SigningKey == nil {
		return nil, ErrNoSigningKey
	}
	if err := ValidateLoginUIURL(cfg.LoginUIURL); err != nil {
		return nil, fmt.Errorf("%w: set %s to the page that asks a person for their password, "+
			"for example https://parlor.anywaye.com/sign-in/oidc", err, LoginUIEnvVar)
	}
	loginUI, parseErr := url.Parse(cfg.LoginUIURL)
	if parseErr != nil {
		return nil, fmt.Errorf("%w: it is not a URL: %w", ErrInvalidLoginUI, parseErr)
	}

	encryptionKey, encryptionKeyID := deriveEncryptionKey(cfg.SigningKey)

	options := []op.Option{
		op.WithCustomEndpoints(
			op.NewEndpoint(strings.TrimPrefix(PathAuthorize, "/")),
			op.NewEndpoint(strings.TrimPrefix(PathToken, "/")),
			op.NewEndpoint(strings.TrimPrefix(PathUserinfo, "/")),
			op.NewEndpoint("oidc/revoke"),
			op.NewEndpoint("oidc/end-session"),
			op.NewEndpoint(strings.TrimPrefix(PathJWKS, "/")),
		),
	}
	if cfg.AllowInsecure {
		options = append(options, op.WithAllowInsecure())
	}

	handler, err := op.NewProvider(
		&op.Config{
			CryptoKey:   encryptionKey,
			CryptoKeyId: encryptionKeyID,

			CodeMethodS256: true,

			AuthMethodPost:          false,
			AuthMethodPrivateKeyJWT: false,

			GrantTypeRefreshToken: true,

			RequestObjectSupported: false,

			SupportedScopes: SupportedScopes,
			SupportedClaims: supportedClaims(),
		},
		storage,
		op.StaticIssuer(cfg.Issuer),
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("oidc: building the provider: %w", err)
	}

	return &Provider{op: handler, storage: storage, issuer: cfg.Issuer, loginUI: loginUI}, nil
}

// Handler is the library's router.
//
// It is mounted path by path on this service's own router rather than at the
// root. Mounting it at "/" would give it the unmatched-path case too, and this
// service's 404 is an RFC 9457 problem document with a trace id — the library's
// router answers a miss with net/http's plain-text one, and a client would then
// have two error shapes to parse depending on which route it guessed wrong.
func (p *Provider) Handler() http.Handler { return p.op }

// Storage is the adapter, for the routes that need to complete a login.
func (p *Provider) Storage() *Storage { return p.storage }

// Issuer is the configured issuer, which is also the expected `iss` on a token
// this service verifies.
func (p *Provider) Issuer() string { return p.issuer }

// Discovery is the document for one request.
//
// The issuer is put into the context here rather than read out of it, because the
// interceptor that would normally do that lives inside the library's router and
// this document is served by this service's own router. p.issuer is the same
// static value that interceptor would have installed, so the two paths cannot
// disagree.
func (p *Provider) Discovery(r *http.Request) any {
	return p.discovery(op.ContextWithIssuer(r.Context(), p.issuer))
}

// DiscoveryFor is the document for an explicit context, which is what the tests
// use so they can assert on it without a request in hand.
func (p *Provider) DiscoveryFor(ctx context.Context) *oidc.DiscoveryConfiguration {
	return p.discovery(ctx)
}

// JWKS is the published key set.
//
// It is rendered once per request rather than cached, and the cost is a
// base64url encoding of a 256-byte modulus — a few microseconds, against a
// document that a caching verifier may ask for every five minutes. Caching it
// would be a second place for the key to live.
func (p *Provider) JWKS() ([]byte, error) { return p.op.Storage().(*Storage).key.JWKS() }

// LoginBanner is what the login page renders.
func (p *Provider) LoginBanner(ctx context.Context, requestID string) (LoginBanner, error) {
	return p.storage.LoginBanner(ctx, requestID)
}

// CompleteLogin records that a user authenticated against a request.
func (p *Provider) CompleteLogin(ctx context.Context, requestID string, subject id.UUID) error {
	return p.storage.CompleteLogin(ctx, requestID, subject)
}

func validateIssuer(issuer string) error {
	if issuer == "" {
		return fmt.Errorf("oidc: the issuer is required; it is the `iss` on every token and the `issuer` in discovery")
	}
	parsed, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("oidc: the issuer is not a URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("oidc: the issuer scheme is %q, want https", parsed.Scheme)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("oidc: the issuer must not carry a query or a fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("oidc: the issuer must not carry a path; every endpoint URL is built by appending to it")
	}
	return nil
}

func deriveEncryptionKey(k *SigningKey) ([32]byte, string) {
	der, err := marshalPKCS8(k)
	if err != nil {
		der = []byte(k.ID())
	}
	sum := sha256.Sum256(append([]byte("anywaye/identity/oidc/token-encryption/v1\x00"), der...))
	return sum, k.ID() + "-enc"
}

func supportedClaims() []string {
	return []string{
		"sub",
		"iss",
		"aud",
		"exp",
		"iat",
		"jti",
		"nonce",
		"auth_time",
		"amr",
		"azp",
		"at_hash",
		"c_hash",
		"client_id",
		"scope",
		ScopeEmail,
		ClaimEmailVerified,
		"name",
		ClaimAccounts,
	}
}

func (p *Provider) discovery(ctx context.Context) *oidc.DiscoveryConfiguration {
	doc := op.CreateDiscoveryConfig(ctx, p.op, p.op.Storage())

	doc.AuthorizationEndpoint = p.op.AuthorizationEndpoint().Absolute(p.issuer)
	doc.TokenEndpoint = p.op.TokenEndpoint().Absolute(p.issuer)
	doc.UserinfoEndpoint = p.op.UserinfoEndpoint().Absolute(p.issuer)
	doc.JwksURI = p.op.KeysEndpoint().Absolute(p.issuer)

	doc.IntrospectionEndpoint = ""
	doc.RevocationEndpoint = ""
	doc.EndSessionEndpoint = ""
	doc.DeviceAuthorizationEndpoint = ""
	doc.CheckSessionIframe = ""

	doc.IntrospectionEndpointAuthMethodsSupported = nil
	doc.IntrospectionEndpointAuthSigningAlgValuesSupported = nil
	doc.RevocationEndpointAuthMethodsSupported = nil
	doc.RevocationEndpointAuthSigningAlgValuesSupported = nil

	doc.ResponseTypesSupported = []string{string(oidc.ResponseTypeCode)}
	doc.GrantTypesSupported = []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}

	doc.TokenEndpointAuthMethodsSupported = []oidc.AuthMethod{oidc.AuthMethodBasic}
	doc.TokenEndpointAuthSigningAlgValuesSupported = nil
	doc.RequestObjectSigningAlgValuesSupported = nil

	doc.CodeChallengeMethodsSupported = []oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256}

	doc.IDTokenSigningAlgValuesSupported = []string{"RS256"}
	doc.SubjectTypesSupported = []string{"public"}
	doc.ScopesSupported = SupportedScopes
	doc.ClaimsSupported = supportedClaims()

	doc.UILocalesSupported = nil
	doc.ScopesSupported = slices.Clone(SupportedScopes)
	return doc
}
