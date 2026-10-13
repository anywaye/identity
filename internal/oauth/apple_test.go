package oauth

// TESTS FOR APPLE'S TWO MECHANISMS: the client_secret this service signs, and
// the id_token it verifies.
//
// The minting tests are the safe half of the packet and are self-contained: the
// helper is pure (four strings in, one string out) and everything it produces
// can be asserted by parsing the JWT. The id_token verification tests live in
// client_test.go, because they need the fake provider to stand in for Apple.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// appleTestKey returns a P-256 key and its .p8 PEM — the shape of
// OAUTH_APPLE_PRIVATE_KEY.
func appleTestKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the test key: %v", err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling the test key: %v", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
}

// decodeCompactJWS splits a compact JWS and decodes its header and payload as
// JSON, WITHOUT verifying the signature: the shape under test here is what was
// minted, not whether it verifies.
func decodeCompactJWS(t *testing.T, token string) (header, payload map[string]any) {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("the minted secret = %q, want a three-part compact JWS", token)
	}
	decode := func(part string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatalf("decoding %q: %v", part, err)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decoding %q: %v", part, err)
		}
		return out
	}
	return decode(parts[0]), decode(parts[1])
}

// TestMintAppleClientSecret pins the minted secret's shape: the header Apple's
// token endpoint requires, the claims Apple checks, and the exp bound.
//
// The exp bound is the assertion that matters most. Apple accepts a secret valid
// for up to six months, and this service mints ONE at startup and caches it —
// there is no rotation machinery — so the lifetime is the maximum. A secret that
// expires sooner is a sign-in flow that breaks at 3am with nothing to renew it.
func TestMintAppleClientSecret(t *testing.T) {
	t.Parallel()

	key, keyPEM := appleTestKey(t)
	secret, err := MintAppleClientSecret(AppleSecretInputs{
		ServicesID: "com.example.app",
		TeamID:     "ABCDE12345",
		KeyID:      "KEYID12345",
		PrivateKey: keyPEM,
	})
	if err != nil {
		t.Fatalf("MintAppleClientSecret: %v", err)
	}
	if secret == "" {
		t.Fatal("MintAppleClientSecret returned an empty secret")
	}

	header, payload := decodeCompactJWS(t, secret)

	// The header Apple's token endpoint requires.
	if header["alg"] != "ES256" {
		t.Errorf("header alg = %v, want ES256", header["alg"])
	}
	if header["kid"] != "KEYID12345" {
		t.Errorf("header kid = %v, want KEYID12345", header["kid"])
	}

	// The claims.
	if payload["iss"] != "ABCDE12345" {
		t.Errorf("iss = %v, want the team id ABCDE12345", payload["iss"])
	}
	if payload["sub"] != "com.example.app" {
		t.Errorf("sub = %v, want the services id com.example.app", payload["sub"])
	}
	if payload["aud"] != "https://appleid.apple.com" {
		t.Errorf("aud = %v, want https://appleid.apple.com", payload["aud"])
	}

	// The exp bound: in the future, and no further out than Apple's maximum.
	exp, ok := payload["exp"].(float64)
	if !ok {
		t.Fatalf("exp = %v, want a number", payload["exp"])
	}
	now := time.Now().Unix()
	if int64(exp) <= now {
		t.Errorf("exp = %d, want it in the future", int64(exp))
	}
	if max := now + int64(appleClientSecretLifetime.Seconds()); int64(exp) > max {
		t.Errorf("exp = %d, want it no further out than the %s lifetime (%d)", int64(exp), appleClientSecretLifetime, max)
	}

	// iat is now.
	iat, ok := payload["iat"].(float64)
	if !ok {
		t.Fatalf("iat = %v, want a number", payload["iat"])
	}
	if iat < float64(now)-60 || iat > float64(now)+60 {
		t.Errorf("iat = %d, want about now (%d)", int64(iat), now)
	}

	// And the signature verifies against the public key: the minted secret is a
	// real ES256 JWT, not just a well-shaped string.
	jws, err := jose.ParseSigned(secret, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("the minted secret does not parse as an ES256 JWS: %v", err)
	}
	if _, err := jws.Verify(&key.PublicKey); err != nil {
		t.Errorf("the minted secret's signature does not verify: %v", err)
	}
}

// TestMintAppleClientSecretRefusesAHalfConfiguredInput holds the fourth provider
// to the existing rule: some of the four inputs and not all is a mistake and
// never an intention, and the refusal is ErrIncompleteProvider — the same
// sentinel the other three providers' half-configured credentials produce.
//
// Each of the four is missing in turn, because a test that only omitted the
// private key would pass against an implementation that only checked that one.
func TestMintAppleClientSecretRefusesAHalfConfiguredInput(t *testing.T) {
	t.Parallel()

	_, keyPEM := appleTestKey(t)
	full := AppleSecretInputs{
		ServicesID: "com.example.app",
		TeamID:     "ABCDE12345",
		KeyID:      "KEYID12345",
		PrivateKey: keyPEM,
	}

	for name, mutate := range map[string]func(*AppleSecretInputs){
		"no services id": func(in *AppleSecretInputs) { in.ServicesID = "" },
		"no team id":     func(in *AppleSecretInputs) { in.TeamID = "" },
		"no key id":      func(in *AppleSecretInputs) { in.KeyID = "" },
		"no private key": func(in *AppleSecretInputs) { in.PrivateKey = "" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			in := full
			mutate(&in)
			_, err := MintAppleClientSecret(in)
			if !errors.Is(err, ErrIncompleteProvider) {
				t.Errorf("MintAppleClientSecret = %v, want ErrIncompleteProvider", err)
			}
		})
	}
}

// An empty input means Apple is not configured, which is the supported absent
// state — not an error and not a secret.
func TestMintAppleClientSecretWithNoInputs(t *testing.T) {
	t.Parallel()

	secret, err := MintAppleClientSecret(AppleSecretInputs{})
	if err != nil {
		t.Errorf("MintAppleClientSecret on an empty input = %v, want nil — the supported absent state", err)
	}
	if secret != "" {
		t.Errorf("MintAppleClientSecret on an empty input = %q, want empty", secret)
	}
}

// A private key that does not parse is a startup failure, not a silently
// skipped provider: a deployment that believes it has Apple credentials and has
// a broken key is a failed deploy, and the alternative is a sign-in button
// that 404s.
func TestMintAppleClientSecretRefusesABadPrivateKey(t *testing.T) {
	t.Parallel()

	for name, key := range map[string]string{
		"not a PEM block":               "not a PEM block",
		"a PEM block that is not a key": "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := MintAppleClientSecret(AppleSecretInputs{
				ServicesID: "com.example.app",
				TeamID:     "ABCDE12345",
				KeyID:      "KEYID12345",
				PrivateKey: key,
			})
			if err == nil {
				t.Error("MintAppleClientSecret accepted an unparseable private key")
			}
		})
	}
}
