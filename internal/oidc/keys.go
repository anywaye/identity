package oidc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	MinKeyBits = 2048

	keyUseSignature = "sig"
)

var (
	ErrNoSigningKey = errors.New("no OIDC signing key configured")
	ErrWeakSigningKey = errors.New("OIDC signing key is too small")
	ErrKeyID = errors.New("OIDC signing key id is missing or unsafe")
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// SigningKey is this service's one RSA signing key.
//
// It is immutable after construction and shared by every caller: it is read on
// every token the service issues and on every JWKS request, and it holds no
// per-request state, so there is nothing to synchronize and nothing to copy.
type SigningKey struct {
	kid  string
	priv *rsa.PrivateKey
}

// LoadSigningKey parses a PEM-encoded RSA private key and binds it to a key id.
//
// Both PKCS#1 (`BEGIN RSA PRIVATE KEY`, what `openssl genrsa` has written for
// years) and PKCS#8 (`BEGIN PRIVATE KEY`) are accepted. An operator following
// the wrong line of a runbook should get a service that starts, not one that
// fails on a container difference.
//
// Every failure is a refusal. A key that is absent, unparseable or too small is
// a startup error rather than a default, because the alternative — generating
// one — produces a service whose tokens nobody else can verify and whose trust
// anchor moves on every restart.
func LoadSigningKey(keyPEM, keyID string) (*SigningKey, error) {
	if keyPEM == "" {
		return nil, fmt.Errorf("%w: set OIDC_SIGNING_KEY to a PEM RSA private key", ErrNoSigningKey)
	}
	if !keyIDPattern.MatchString(keyID) {
		return nil, fmt.Errorf("%w: it must be 1-64 characters of A-Z a-z 0-9 . _ -", ErrKeyID)
	}

	priv, err := parseRSAPrivateKey([]byte(keyPEM))
	if err != nil {
		return nil, err
	}
	if priv.N.BitLen() < MinKeyBits {
		return nil, fmt.Errorf("%w: %d bits, want at least %d", ErrWeakSigningKey, priv.N.BitLen(), MinKeyBits)
	}

	return &SigningKey{kid: keyID, priv: priv}, nil
}

func parseRSAPrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%w: the value is not a PEM block", ErrNoSigningKey)
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: neither a PKCS#1 nor a PKCS#8 RSA private key", ErrNoSigningKey)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: the key is a %T, and this provider signs with RS256", ErrNoSigningKey, parsed)
	}
	return key, nil
}

// ID is the `kid` this key publishes and signs under. The name is the library's,
// not this package's: op.SigningKey declares it, and a method called KeyID that
// implemented it would be a rename waiting to be undone.
func (k *SigningKey) ID() string { return k.kid }

// Key returns the private key, for the library's signing path.
//
// It is the private half and it is exposed because op.SigningKey is defined in
// terms of it. The only caller is the library's token minting; the JWKS is
// served from PublicKeyOf and has no path to this method.
func (k *SigningKey) Key() any { return k.priv }

// SignatureAlgorithm is RS256.
//
// core's conventions allow RS256 and ES256 and forbid everything else, and
// gateway pins RS256 before it fetches anything. One algorithm, stated once: a
// provider that advertised a second one and then used the first is a provider
// whose tokens stop verifying the day it rotates.
func (k *SigningKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }

// PublicKeyOf returns the publishable half, as the library's op.Key.
//
// It is a function rather than a method on SigningKey so that a nil
// *SigningKey is representable: the storage layer hands out a key set on every
// JWKS request and on every signature check, and "there is no key" is a
// different answer from "a key with an empty id".
func PublicKeyOf(k *SigningKey) op.Key {
	return publicKey{signingKey: k}
}

type publicKey struct {
	signingKey *SigningKey
}

func (p publicKey) ID() string {
	if p.signingKey == nil {
		return ""
	}
	return p.signingKey.kid
}

func (p publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }

func (p publicKey) Use() string { return keyUseSignature }

func (p publicKey) Key() any {
	if p.signingKey == nil {
		return nil
	}
	return &p.signingKey.priv.PublicKey
}

// JWKS renders the published key set: RFC 7517, one key, no private material.
//
// The document is byte-stable for a given key: the same key and kid produce the
// same JSON on every call, which is what lets a consumer cache it for minutes
// (gateway's default is five) without re-fetching on every request. go-jose
// marshals a JSONWebKey struct, whose field order is fixed, so there is no map
// anywhere in the path.
func (k *SigningKey) JWKS() ([]byte, error) {
	if k == nil {
		return nil, ErrNoSigningKey
	}

	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		KeyID:     k.kid,
		Algorithm: string(jose.RS256),
		Use:       keyUseSignature,
		Key:       &k.priv.PublicKey,
	}}}

	document, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("oidc: marshaling the key set: %w", err)
	}
	return document, nil
}

func marshalPKCS8(k *SigningKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(k.priv)
}
