package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


var (
	ErrNotFound = errors.New("oidc client not found")
	ErrRevoked = errors.New("oidc client is revoked")
	ErrInvalidSecret = errors.New("oidc client secret is invalid")
	ErrAlreadyRevoked = errors.New("oidc client is already revoked")
)

const (
	CodeRequired       = "required"
	CodeInvalidFormat  = "invalid_format"
	CodeTooMany        = "too_many"
	CodeUnsupported    = "unsupported"
	CodeOpenIDRequired = "openid_required"
)

// FieldError is a per-field validation failure, rendered as one entry of a
// 422's errors[].
type FieldError struct {
	Field string
	Code  string
}

func (e *FieldError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Code) }

func fieldErr(field, code string) error { return &FieldError{Field: field, Code: code} }

const (
	clientIDBytes = 32

	MaxNameLength = 120

	MaxRedirectURIs = 10
)

const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
	GrantImplicit          = "implicit"
)

// Client is one OIDC registration.
type Client struct {
	ID id.UUID
	AccountID id.UUID
	ClientID string
	Name string
	SecretDigest string
	RedirectURIs []string
	GrantTypes []string
	Scopes    []string
	CreatedAt time.Time
	CreatedBy id.UUID

	RevokedAt    *time.Time
	RevokedBy    *id.UUID
	RevokeReason *string
}

// IsActive reports whether the registration may still be used.
func (c Client) IsActive() bool { return c.RevokedAt == nil }

// AllowsRedirectURI reports whether a redirect URI is on the allow-list.
//
// An exact string comparison, and that is the whole point. The library's
// checkURIAgainstRedirects asks the same question with slices.Contains before it
// considers the optional glob interface, so a client that does not implement
// op.HasRedirectGlobs can only ever be matched exactly. The prefix case
// `https://app.example.com.evil.com/cb` against a registered
// `https://app.example.com/cb` is the test that holds this line, and it is in
// the test suite rather than in a comment.
func (c Client) AllowsRedirectURI(candidate string) bool {
	return slices.Contains(c.RedirectURIs, candidate)
}

// AllowsScope reports whether this client may be granted a scope.
func (c Client) AllowsScope(scope string) bool { return slices.Contains(c.Scopes, scope) }

// NewClientCredentials mints a client id and a client secret.
//
// Both are 32 random bytes, base64url. The id is a handle that has to be
// unguessable because it is half of the credential pair on the token endpoint;
// the secret is a bearer credential that a database dump must not yield. They
// are generated together and returned together because the caller needs the id
// to put in a response body and the secret to hand over once, and a function
// returning only one of them is a function that will eventually return the wrong
// one.
func NewClientCredentials() (clientID, secret string, err error) {
	rawID, err := randomBytes(clientIDBytes)
	if err != nil {
		return "", "", fmt.Errorf("oidc: minting a client id: %w", err)
	}
	rawSecret, err := randomBytes(clientIDBytes)
	if err != nil {
		return "", "", fmt.Errorf("oidc: minting a client secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(rawID), base64.RawURLEncoding.EncodeToString(rawSecret), nil
}

// SecretDigest is the value stored in oidc_clients.secret_digest: the lower-case
// hex SHA-256 of the presented secret.
//
// SHA-256 rather than argon2id, and internal/sessions/token.go is the precedent
// and the argument: argon2id exists to make GUESSING expensive, and a 256-bit
// random value has no guessable structure for it to slow down. A memory-hard
// hash on this column would cost tens of milliseconds on every single token
// request across the platform and buy nothing. The rule that matters on both
// columns is the one that holds everywhere in this service — the presented value
// is never stored, so a dump of the table is not a set of credentials.
//
// The comparison is an indexed equality in SQL, as it is for session tokens, and
// the same reasoning covers it: the length is not secret and an unmatched lookup
// is an ordinary indexed read.
func SecretDigest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func randomBytes(n int) ([]byte, error) {
	raw := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	return raw, nil
}

// ValidateRedirectURIs checks and normalizes a registration's allow-list.
//
// Three rules, each of which would otherwise be a hole:
//
//   - at least one and at most MaxRedirectURIs. A client with no allow-list can
//     be sent anywhere; a client with two hundred is an allow-list nobody reads.
//   - absolute, https, no fragment, no wildcard. A wildcard turns the exact
//     match in AllowsRedirectURI into a suggestion.
//   - http only on loopback. The library permits any registered http URI for a
//     confidential client, which is the library's call to make about a
//     registration it did not write; refusing here means a plain-http origin
//     never reaches the table, and a product developing against a local parlor
//     still works.
func ValidateRedirectURIs(give []string) ([]string, error) {
	if len(give) == 0 {
		return nil, fieldErr("redirect_uris", CodeRequired)
	}
	if len(give) > MaxRedirectURIs {
		return nil, fieldErr("redirect_uris", CodeTooMany)
	}

	out := make([]string, 0, len(give))
	for _, raw := range give {
		trimmed := strings.TrimSpace(raw)
		if err := validateRedirectURI(trimmed); err != nil {
			return nil, err
		}
		if !slices.Contains(out, trimmed) {
			out = append(out, trimmed)
		}
	}
	slices.Sort(out)
	return out, nil
}

func validateRedirectURI(raw string) error {
	invalid := fieldErr("redirect_uris", CodeInvalidFormat)

	if raw == "" {
		return invalid
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return invalid
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return invalid
	}
	if parsed.Fragment != "" {
		return invalid
	}
	if strings.ContainsAny(parsed.Host, "*") {
		return invalid
	}

	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(parsed.Hostname()) {
			return nil
		}
		return invalid
	default:
		return invalid
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// ValidateGrantTypes checks and normalizes the grant list.
//
// What is implemented, and what is absent because it is a decision rather than
// a gap:
//
//	authorization_code  the flow this service is for
//	refresh_token       the code exchange mints one when the request carries
//	                    `offline_access`; see Storage.CreateAccessAndRefreshTokens
//	client_credentials  no service identity to authenticate as
//	implicit            the brief's flow is code + PKCE, and an implicit token
//	                    arrives in a URL fragment, which is a worse place for a
//	                    credential than a POST body
//
// A product configured with a grant this service does not implement gets a 422
// naming the field at registration time, which is a better outcome than a
// 400 `unsupported_grant_type` discovered during an outage.
func ValidateGrantTypes(give []string) ([]string, error) {
	if len(give) == 0 {
		return nil, fieldErr("grant_types", CodeRequired)
	}
	out := make([]string, 0, len(give))
	for _, raw := range give {
		trimmed := strings.TrimSpace(raw)
		if !slices.Contains(SupportedGrantTypes, trimmed) {
			return nil, fieldErr("grant_types", CodeUnsupported)
		}
		if !slices.Contains(out, trimmed) {
			out = append(out, trimmed)
		}
	}
	slices.Sort(out)
	return out, nil
}

// SupportedGrantTypes is what ValidateGrantTypes accepts.
//
// It is a list and not a check, so adding a grant is one line here and one in
// the discovery document, and a grant this service mounts but this list omits
// is a registration refused at 422 for a flow that would have worked.
var SupportedGrantTypes = []string{GrantAuthorizationCode, GrantRefreshToken}

// ValidateRegistrationScopes checks and normalizes a registration's scope list.
//
// Unlike the authorization endpoint, this one CURATES rather than refuses: a
// product registering itself asks for what it would like, and the operator
// decides what it gets. Unsupported names are dropped so the column cannot
// accumulate a promise this service does not keep, and `openid` is required
// because a client that cannot ask for openid gets tokens with no identity in
// them.
func ValidateRegistrationScopes(give []string) ([]string, error) {
	scopes := NormalizeScopes(give)
	if !slices.Contains(scopes, ScopeOpenID) {
		return nil, fieldErr("scopes", CodeOpenIDRequired)
	}
	if len(scopes) == 0 {
		return nil, fieldErr("scopes", CodeRequired)
	}
	return scopes, nil
}
