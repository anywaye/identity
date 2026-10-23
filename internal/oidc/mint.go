package oidc

import (
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/anywaye/identity/internal/platform/id"
)

// AccountTokenTTL is how long an exchanged access token lives.
//
// Fifteen minutes, and the number is a decision about what the token is FOR
// rather than a security dial. It is minted from a live session by a server-side
// caller (an app's own backend, holding the user's session credential) and handed
// to exactly one service for the length of one request-bearing burst; it is
// re-mintable for as long as the session is valid, so a short life costs a caller
// nothing and bounds the window in which a leaked token outlives the session that
// produced it. It is deliberately NOT the session's lifetime: a token that lives
// as long as the session is a second session, with none of the revocation.
const AccountTokenTTL = 15 * time.Minute

// MintedToken is one access token, ready to hand to the service that asked for it.
type MintedToken struct {
	// Token is the compact JWS. It is signed with the same key the JWKS
	// publishes, so any verifier that trusts this provider's key set can check
	// it without calling identity.
	Token string
	// ExpiresAt is the `exp` instant, told to the caller so it does not have to
	// parse the token it is about to hand on.
	ExpiresAt time.Time
}

// accountTokenClaims is the claim set of an exchanged token, written out so the
// names are greppable rather than living in a `map[string]any`.
//
// ## Why these claims and not the profile
//
// Minimal claims is the platform's rule for delegated credentials (MD19): what
// the receiving service is declared to need, not whatever identity happens to
// know. The receiving service here is one that scopes by a SINGLE account, so the
// token names one account (`account_id`, singular) and deliberately does NOT carry
// the `accounts` array a profile-scope access token carries. Sending both would be
// two answers to one question in the same token, and the first service that read
// the wrong one would be a tenancy bug that works.
//
// `email` is absent for the same rule: no receiver of this token has been
// declared to need the address, and a claim nothing reads is a claim that leaks.
type accountTokenClaims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	JWTID     string `json:"jti"`
	// AccountID is the account this token is bound to, singular, verified to be
	// one the subject is a member of before anything is signed.
	AccountID string `json:"account_id"`
}

// MintAccountToken signs a short-lived access token for one account.
//
// ## What it is, and what the membership check is not
//
// This is the session-to-token exchange: the caller has already proved, with a
// session credential, that it is the subject; it names the one account it wants
// to act in, and what happens HERE is the check that the subject is a member of
// that account. The check lives at mint time on purpose. The alternative — a
// token carrying every membership and each receiving service choosing one per
// request — is the option `internal/oidc/profiles.go` records the objection to:
// "whichever entry the client meant" is a tenancy key nobody chose, and the first
// service that guessed produces a cross-tenant read that looks like it works.
// Binding the account into the signature makes the choice explicit, made once, by
// the party that is allowed to make it.
//
// The check itself is NOT here: this method signs what it is told, and the HTTP
// layer resolves the membership through the tenancy use cases before calling it.
// A signer that re-derived authorization would be a second policy engine beside
// the one that owns membership.
//
// `now` is passed rather than read so the `iat` and `exp` of a token are the
// instant the caller already established — the same rule every store in this
// service follows (see httpapi's `clk`), and the reason a test can mint a token
// whose whole life is in a frozen second.
func (p *Provider) MintAccountToken(subject, accountID id.UUID, audience string, now time.Time) (MintedToken, error) {
	key := p.storage.key
	if key == nil {
		return MintedToken{}, ErrNoSigningKey
	}

	// The signer is built per call rather than cached on the provider, and that is
	// the honest shape: go-jose's signer holds the key and the header, both of
	// which are process-lifetime constants, and building one is a struct
	// allocation. Caching it would add a second place the key is held for no
	// measurable gain.
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: key.SignatureAlgorithm(), Key: key.Key()},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), key.ID()),
	)
	if err != nil {
		return MintedToken{}, fmt.Errorf("building the token signer: %w", err)
	}

	jwtID, err := id.New()
	if err != nil {
		return MintedToken{}, fmt.Errorf("minting a token id: %w", err)
	}

	expiresAt := now.Add(AccountTokenTTL)
	token, err := jwt.Signed(signer).Claims(accountTokenClaims{
		Issuer:    p.issuer,
		Audience:  audience,
		Subject:   subject.String(),
		IssuedAt:  now.Unix(),
		ExpiresAt: expiresAt.Unix(),
		JWTID:     jwtID.String(),
		AccountID: accountID.String(),
	}).Serialize()
	if err != nil {
		return MintedToken{}, fmt.Errorf("signing the access token: %w", err)
	}

	return MintedToken{Token: token, ExpiresAt: expiresAt}, nil
}
