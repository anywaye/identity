package oauth

// APPLE, THE FOURTH PROVIDER — AND THE ONE WITH A MECHANISM RATHER THAN A
// CREDENTIAL.
//
// Two things about Apple are different from google, github and microsoft, and
// both are in this file:
//
//  1. The client_secret is not a secret this service is ISSUED. It is an ES256
//     JWT this service SIGNS, minted once at startup from four environment
//     inputs and cached, because it is valid for months and there is no
//     rotation machinery. `MintAppleClientSecret` is that minting.
//
//  2. There is no userinfo endpoint. The identity comes from the id_token — a
//     JWT in the token response — so the trust model is the OIDC one: the
//     claims are trusted because Apple's own published key signed them, not
//     because this service asked Apple about them with a bearer token. That is
//     a STRONGER guarantee than the userinfo call gets, and it is why the
//     verification below is the whole of the risk: an id_token whose signature
//     does not verify against Apple's JWKS is refused outright, and the
//     negative test for that refusal is the one that proves the verifier
//     verifies.

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

// appleIssuer is Apple's identity in both directions this service meets it: the
// `aud` of every client_secret this service mints, and the `iss` of every
// id_token it verifies.
const appleIssuer = "https://appleid.apple.com"

// appleClientSecretLifetime is how long a minted client_secret stays valid.
//
// Apple accepts a secret valid for up to six months, and this service mints ONE
// at startup and caches it — there is no per-request signing and no rotation
// machinery — so the lifetime is the maximum: a secret that expires sooner is
// a sign-in flow that breaks at 3am with nothing to renew it, and the fix is a
// redeploy rather than a rotation this service does not have.
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
	// ServicesID is Apple's Services ID: the OAuth client id, and the `sub` of
	// the minted secret.
	ServicesID string
	// TeamID is the Apple Developer Team ID: the `iss` of the minted secret.
	TeamID string
	// KeyID is the platform key's id: the `kid` of the minted secret's header.
	KeyID string
	// PrivateKey is the .p8 PEM contents of the platform key: what the secret
	// is signed with.
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
		return "", fmt.Errorf("OAUTH_APPLE_PRIVATE_KEY is not a parseable .p8 private key: %v", err)
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
		return "", fmt.Errorf("building the ES256 signer: %v", err)
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
		return "", fmt.Errorf("encoding the client_secret claims: %v", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("signing the client_secret: %v", err)
	}
	return jws.CompactSerialize()
}

// appleClientSecretClaims is the client_secret's claim set, in the shape
// Apple's token endpoint requires.
type appleClientSecretClaims struct {
	Issuer    string `json:"iss"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
}

// appleIDToken is the verified id_token's claims.
//
// Only the fields this service reads are here. Apple's id_token carries more
// (nonce, auth_time, and so on) and an OIDC client packet can add them; what
// matters for a relying party deciding whether to sign somebody in is that
// every field below is read from a payload whose signature verified against
// Apple's own published key.
type appleIDToken struct {
	Issuer        string        `json:"iss"`
	Subject       string        `json:"sub"`
	Audience      appleAudience `json:"aud"`
	Email         string        `json:"email"`
	EmailVerified *appleBool    `json:"email_verified"`
	ExpiresAt     int64         `json:"exp"`
	IssuedAt      int64         `json:"iat"`
}

// appleAudience is the `aud` claim, which RFC 7519 allows to be either a
// string or an array of strings and Apple has sent both. Normalised to a slice
// so the check is one comparison.
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

// appleBool is a JSON boolean that Apple has also sent as the string
// "true"/"false" — Apple's id_token has carried both shapes, and a decoder
// that handled only one would refuse every real token or accept every forged
// one depending on which shape Apple sent that day.
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

// appleIdentity reads the identity from Apple's verified id_token.
//
// # WHY THERE IS NO USERINFO CALL, AND WHAT REPLACES IT
//
// Apple has no userinfo endpoint. The identity comes from the id_token — a JWT
// in the token response — so the trust model is the OIDC one rather than the
// userinfo one: the claims are trusted because Apple's own published key
// signed them, not because this service asked Apple about them with a bearer
// token. That is a STRONGER guarantee than the userinfo call gets (a userinfo
// answer is only as good as the channel and the token that fetched it), and it
// is why the verification below is the whole of the risk: an id_token whose
// signature does not verify against Apple's JWKS is refused outright, and the
// negative test for that refusal is the one that proves the verifier verifies.
//
// There is no name: the `name` scope is what carries it, and this service does
// not request it (see Apple() for why).
func (c *Client) appleIdentity(ctx context.Context, p Provider, tokens Tokens) (Identity, error) {
	if tokens.IDToken == "" {
		// Not a refusal: there is nothing to verify. Reported as unavailable
		// because from here it is indistinguishable from a token response this
		// service cannot use, and the caller treats both the same way.
		return Identity{}, fmt.Errorf("%w: apple issued no id_token, so there is no identity to verify", ErrProviderUnavailable)
	}

	claims, err := c.verifyAppleIDToken(ctx, p, tokens.IDToken)
	if err != nil {
		return Identity{}, err
	}

	// Apple's `sub` is the account's stable, non-reassignable identifier. The
	// email can be changed; the sub cannot.
	return identity(claims.Subject, claims.Email, "")
}

// verifyAppleIDToken checks an id_token's signature against Apple's published
// keys and returns its claims.
//
// # THE ORDER IS THE SECURITY PROPERTY
//
// Every step is a refusal, and each one exists because the step before it is
// not sufficient on its own:
//
//  1. ParseSigned with an allowed-algorithm list is the algorithm-confusion
//     defense: a token whose header says "none" or "HS256" is refused here,
//     before any key is consulted. Without the list, a token signed with a
//     symmetric algorithm and this service's own public key as the HMAC
//     secret would verify.
//  2. The key is looked up by the token's OWN `kid` in Apple's JWKS. A token
//     signed by a key Apple does not publish has no key to verify against, and
//     that is the forged-token case the negative test exercises.
//  3. The signature is verified against that key. This is the whole of the
//     trust: everything after it reads a payload that only Apple could have
//     produced.
//  4. iss, aud and exp are checked against what this service expects. A
//     correctly-signed token minted for a different client or a different
//     issuer is not evidence about THIS service's caller.
func (c *Client) verifyAppleIDToken(ctx context.Context, p Provider, idToken string) (*appleIDToken, error) {
	jws, err := jose.ParseSigned(idToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("%w: the id_token is not an ES256-signed JWT: %v", ErrProviderUnavailable, err)
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
			"published key: %v", ErrProviderUnavailable, err)
	}

	var claims appleIDToken
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: the verified id_token's claims are not readable: %v", ErrProviderUnavailable, err)
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
	// A pointer, so "absent" is distinguishable from "false": Apple omits the
	// claim on some flows, and an absent claim is not a statement that the
	// address is unverified — but an explicit false is, and is refused the
	// same way every other provider's unverified address is.
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		return nil, fmt.Errorf("%w: apple reports this address as unverified", ErrNoEmail)
	}

	return &claims, nil
}

// getJWKS fetches and parses a provider's JSON Web Key Set.
//
// Every failure is ErrProviderUnavailable, including a non-200: from here a
// JWKS endpoint that cannot be read is indistinguishable from one that is down,
// and the caller treats both the same way.
func (c *Client) getJWKS(ctx context.Context, endpoint string) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: building the request: %v", ErrProviderUnavailable, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: the jwks endpoint answered %d", ErrProviderUnavailable, resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIdentityBytes)).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("%w: reading the jwks document: %v", ErrProviderUnavailable, err)
	}
	return &jwks, nil
}
