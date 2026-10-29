package apikeys

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


// ErrNoAccountID means a claim document was asked for from a token with no
// account, and one was refused rather than defaulted.
//
// It cannot come from a row — account_id is NOT NULL — so it is a guard on a
// future caller that assembles a Claims from something other than a stored key,
// and it is worth having because the failure it prevents is a cross-tenant read
// rather than a missing field.
var ErrNoAccountID = errors.New("an api key claim document requires an account_id and this token has none")

const (
	ClaimScopes = "scopes"
	ClaimScope = "scope"
	ClaimAccountID = "account_id"
)

// Claims is what a resource server is told about a token.
//
// Active is first and it is the load-bearing field. RFC 7662 says an
// introspection response for a token that is not usable is `{"active": false}`
// and nothing else, and the reason is the same one this package's ErrNotFound
// exists for: a response that distinguished "revoked" from "never existed" tells
// an attacker whether a leaked value was live, which is the second question they
// ask after "does this work". Every other field is zero when Active is false.
type Claims struct {
	Active bool `json:"active"`

	Subject string `json:"sub,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	Scopes string `json:"scopes,omitempty"`
	Scope  string `json:"scope,omitempty"`

	TokenID string `json:"jti,omitempty"`
	Name string `json:"name,omitempty"`
	Role string `json:"role,omitempty"`

	IssuedAt  int64 `json:"iat,omitempty"`
	ExpiresAt int64 `json:"exp,omitempty"`
	LastUsedAt int64 `json:"last_used_at,omitempty"`
}

// ClaimsFor renders the claim document for a live token.
//
// A revoked or expired token is not an error here: it is an inactive claim
// document, which is what a resource server needs to say so rather than to fail.
// A token with no account is ErrNoAccountID, which the caller renders as inactive
// too — and the reason is the one in the file comment: a token with no tenancy key
// cannot be used against any account, so "inactive" is the true answer and a
// document with a defaulted `sub` would not be.
func ClaimsFor(k Key, now time.Time) (Claims, error) {
	if k.AccountID.IsZero() {
		return Claims{}, ErrNoAccountID
	}
	if k.IsRevoked() || k.IsExpired(now) {
		return Claims{Active: false}, nil
	}

	scopes := slices.Clone(k.Scopes)
	slices.Sort(scopes)
	joined := strings.Join(scopes, " ")

	return Claims{
		Active:    true,
		Subject:   k.UserID.String(),
		AccountID: k.AccountID.String(),
		Scopes:    joined,
		Scope:     joined,
		TokenID:   k.ID.String(),
		Name:      k.Name,
		Role:      string(k.Role),
		IssuedAt:  k.CreatedAt.UTC().Unix(),
		ExpiresAt: k.ExpiresAt.UTC().Unix(),
	}, nil
}

// Document renders the claims as a map, for a consumer that wants to merge them
// into something else — a JWT, a log record, a proxy's context.
//
// IT IS DELIBERATELY NOT THE ONLY WAY OUT. Claims has JSON tags, so the common
// case is to hand the struct to an encoder; Document exists so that a caller
// building a map does not have to remember which two fields are mirrors, and a
// hand-written map here is exactly how the two names would drift apart.
func (c Claims) Document() map[string]any {
	doc := map[string]any{"active": c.Active}
	if !c.Active {
		return doc
	}
	doc["sub"] = c.Subject
	doc[ClaimAccountID] = c.AccountID
	doc[ClaimScopes] = c.Scopes
	doc[ClaimScope] = c.Scope
	doc["jti"] = c.TokenID
	doc["name"] = c.Name
	doc["role"] = c.Role
	doc["iat"] = c.IssuedAt
	doc["exp"] = c.ExpiresAt
	if c.LastUsedAt != 0 {
		doc["last_used_at"] = c.LastUsedAt
	}
	return doc
}

// InactiveClaims is the answer for a token nobody may be told about.
//
// It is a function rather than a variable so a caller cannot mutate the one value
// every inactive response shares, and it exists so the inactive shape is written
// down once — a hand-written `{"active": false}` in each handler is how one of
// them ends up carrying a `sub`.
func InactiveClaims() Claims { return Claims{Active: false} }

// String renders the claim document for a log line, and it is the ONLY place a
// token's scopes become a string in this service outside the wire.
//
// The reason it exists at all is that fmt on a struct would print every field
// including the subject and the token id, and a log line is the most-read copy of
// anything this process writes. This one prints the claim NAMES and the two scope
// strings and nothing else.
func (c Claims) String() string {
	if !c.Active {
		return "apikeys.claims{active=false}"
	}
	return fmt.Sprintf("apikeys.claims{active=true account_id=%s jti=%s %s=%q %s=%q}",
		c.AccountID, c.TokenID, ClaimScopes, c.Scopes, ClaimScope, c.Scope)
}

// ResolveAccountID is the tenancy key, and it never falls back.
//
// IT IS A SEPARATE FUNCTION rather than an expression at each use so the rule is
// testable on its own and so there is one place a future change would have to
// touch. A credential with no account is refused; the error is ErrNoAccountID and
// not a fabricated id, because a fabricated id is a cross-tenant read waiting for
// a request.
func ResolveAccountID(c Claims) (id.UUID, error) {
	if c.AccountID == "" {
		return id.UUID{}, ErrNoAccountID
	}
	parsed, err := id.Parse(c.AccountID)
	if err != nil {
		return id.UUID{}, ErrNoAccountID
	}
	return parsed, nil
}
