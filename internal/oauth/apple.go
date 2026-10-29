package oauth


import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const appleIssuer = "https://appleid.apple.com"

const appleClientSecretLifetime = 180 * 24 * time.Hour

// AppleSecretInputs are the four environment values Apple's client_secret is
// minted from.
//
// Apple is the one provider whose client secret is not a secret this service is
// issued: it is an ES256 JWT this service signs, with the team id as `iss`, the
// services id as `sub`, and the platform key as its signing key. So the
// "credentials" a deployment configures are the four inputs, and the secret
// itself is derived — minted once at startup and cached, because it is valid
// for months and there is no rotation machinery.
type AppleSecretInputs struct {
	ServicesID string
	TeamID string
	KeyID string
	PrivateKey string
}

// MintAppleClientSecret signs Apple's client_secret and returns it.
//
// The secret is an ES256 JWT with the header `{"alg":"ES256","kid":<key id>}`
// and the claims iss=<team id>, iat=now, exp=now+6 months, aud=apple's token
// endpoint, sub=<services id>. It is minted ONCE at startup and cached by the
// caller — the secret is valid for months, so there is no per-request signing
// and no rotation machinery.
//
// An empty input means Apple is not configured, which is the supported absent
// state and returns ("", nil). A PARTIAL input is the half-configured refusal:
// the existing ErrIncompleteProvider rule, unchanged — a deployment that sets
// one of the four and not the others has a provider it cannot mint a secret
// for, and that is a failed deploy rather than a disabled provider.
func MintAppleClientSecret(in AppleSecretInputs) (string, error) {
	present := 0
	for _, v := range []string{in.ServicesID, in.TeamID, in.KeyID, in.PrivateKey} {
		if v != "" {
			present++
		}
	}
	if present == 0 {
		return "", nil
	}
	if present < 4 {
		return "", fmt.Errorf("%w: OAUTH_APPLE_CLIENT_ID, OAUTH_APPLE_TEAM_ID, OAUTH_APPLE_KEY_ID and "+
			"OAUTH_APPLE_PRIVATE_KEY must all be set, or none of them", ErrIncompleteProvider)
	}

	block, _ := pem.Decode([]byte(in.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("OAUTH_APPLE_PRIVATE_KEY is not a PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("OAUTH_APPLE_PRIVATE_KEY is not a parseable .p8 private key: %w", err)
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("OAUTH_APPLE_PRIVATE_KEY is not an EC private key, which is what Apple's .p8 is")
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: ecdsaKey},
		(&jose.SignerOptions{}).WithHeader("kid", in.KeyID),
	)
	if err != nil {
		return "", fmt.Errorf("building the ES256 signer: %w", err)
	}

	now := time.Now()
	claims := appleClientSecretClaims{
		Issuer:    in.TeamID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(appleClientSecretLifetime).Unix(),
		Audience:  appleIssuer,
		Subject:   in.ServicesID,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encoding the client_secret claims: %w", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("signing the client_secret: %w", err)
	}
	return jws.CompactSerialize()
}

type appleClientSecretClaims struct {
	Issuer    string `json:"iss"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
}

type appleIDToken struct {
	Issuer        string        `json:"iss"`
	Subject       string        `json:"sub"`
	Audience      appleAudience `json:"aud"`
	Email         string        `json:"email"`
	EmailVerified *appleBool    `json:"email_verified"`
	ExpiresAt     int64         `json:"exp"`
	IssuedAt      int64         `json:"iat"`
}

type appleAudience []string

func (a *appleAudience) UnmarshalJSON(raw []byte) error {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

type appleBool bool

func (b *appleBool) UnmarshalJSON(raw []byte) error {
	var asBool bool
	if err := json.Unmarshal(raw, &asBool); err == nil {
		*b = appleBool(asBool)
		return nil
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err != nil {
		return err
	}
	switch asString {
	case "true":
		*b = true
	case "false":
		*b = false
	default:
		return fmt.Errorf("email_verified is neither a boolean nor \"true\"/\"false\": %q", asString)
	}
	return nil
}

func (c *Client) appleIdentity(ctx context.Context, p Provider, tokens Tokens) (Identity, error) {
	if tokens.IDToken == "" {
		return Identity{}, fmt.Errorf("%w: apple issued no id_token, so there is no identity to verify", ErrProviderUnavailable)
	}

	claims, err := c.verifyAppleIDToken(ctx, p, tokens.IDToken)
	if err != nil {
		return Identity{}, err
	}

	return identity(claims.Subject, claims.Email, "")
}

func (c *Client) verifyAppleIDToken(ctx context.Context, p Provider, idToken string) (*appleIDToken, error) {
	jws, err := jose.ParseSigned(idToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("%w: the id_token is not an ES256-signed JWT: %w", ErrProviderUnavailable, err)
	}
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("%w: the id_token carries %d signatures, want exactly 1", ErrProviderUnavailable, len(jws.Signatures))
	}

	kid := jws.Signatures[0].Header.KeyID
	if kid == "" {
		return nil, fmt.Errorf("%w: the id_token carries no kid, so apple's key cannot be identified", ErrProviderUnavailable)
	}

	jwks, err := c.getJWKS(ctx, p.JWKSURL)
	if err != nil {
		return nil, err
	}

	var pub *ecdsa.PublicKey
	for _, jwk := range jwks.Key(kid) {
		if jwk.Key == nil {
			continue
		}
		if key, ok := jwk.Key.(*ecdsa.PublicKey); ok {
			pub = key
			break
		}
	}
	if pub == nil {
		return nil, fmt.Errorf("%w: apple's jwks publishes no EC key for kid %q, so the id_token's "+
			"signature cannot be verified — a token signed by a key apple does not "+
			"publish is a token apple did not sign", ErrProviderUnavailable, kid)
	}

	payload, err := jws.Verify(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: the id_token's signature does not verify against apple's "+
			"published key: %w", ErrProviderUnavailable, err)
	}

	var claims appleIDToken
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: the verified id_token's claims are not readable: %w", ErrProviderUnavailable, err)
	}

	if claims.Issuer != appleIssuer {
		return nil, fmt.Errorf("%w: the id_token was issued by %q, want %q", ErrProviderUnavailable, claims.Issuer, appleIssuer)
	}
	if !slices.Contains(claims.Audience, p.ClientID) {
		return nil, fmt.Errorf("%w: the id_token was issued for audience %v, which does not include this "+
			"service's client id", ErrProviderUnavailable, claims.Audience)
	}
	if claims.ExpiresAt < time.Now().Unix() {
		return nil, fmt.Errorf("%w: the id_token expired at %d", ErrProviderUnavailable, claims.ExpiresAt)
	}
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		return nil, fmt.Errorf("%w: apple reports this address as unverified", ErrNoEmail)
	}

	return &claims, nil
}

func (c *Client) getJWKS(ctx context.Context, endpoint string) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: building the request: %w", ErrProviderUnavailable, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: the jwks endpoint answered %d", ErrProviderUnavailable, resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIdentityBytes)).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("%w: reading the jwks document: %w", ErrProviderUnavailable, err)
	}
	return &jwks, nil
}
