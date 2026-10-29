package oauth


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

	if header["alg"] != "ES256" {
		t.Errorf("header alg = %v, want ES256", header["alg"])
	}
	if header["kid"] != "KEYID12345" {
		t.Errorf("header kid = %v, want KEYID12345", header["kid"])
	}

	if payload["iss"] != "ABCDE12345" {
		t.Errorf("iss = %v, want the team id ABCDE12345", payload["iss"])
	}
	if payload["sub"] != "com.example.app" {
		t.Errorf("sub = %v, want the services id com.example.app", payload["sub"])
	}
	if payload["aud"] != "https://appleid.apple.com" {
		t.Errorf("aud = %v, want https://appleid.apple.com", payload["aud"])
	}

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

	iat, ok := payload["iat"].(float64)
	if !ok {
		t.Fatalf("iat = %v, want a number", payload["iat"])
	}
	if iat < float64(now)-60 || iat > float64(now)+60 {
		t.Errorf("iat = %d, want about now (%d)", int64(iat), now)
	}

	jws, err := jose.ParseSigned(secret, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("the minted secret does not parse as an ES256 JWS: %v", err)
	}
	if _, err := jws.Verify(&key.PublicKey); err != nil {
		t.Errorf("the minted secret's signature does not verify: %v", err)
	}
}

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
