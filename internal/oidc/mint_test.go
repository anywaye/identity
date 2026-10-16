package oidc

import (
	"encoding/json"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/cafaye/identity/internal/platform/id"
)

// The exchanged token's claim set, asserted against the SAME verifier shape a
// receiver uses: go-jose's own parser, the provider's published public key, and
// no access to anything private. A test that read the claims by decoding the
// payload would prove nothing about the signature — which is the half a
// consumer actually relies on.
func TestMintAccountTokenSignsTheAccountScopedClaimSet(t *testing.T) {
	t.Parallel()

	provider := newTestProvider(t)
	subject := id.MustNew()
	account := id.MustNew()
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

	minted, err := provider.MintAccountToken(subject, account, "billing", now)
	if err != nil {
		t.Fatalf("MintAccountToken: %v", err)
	}

	// The public half, straight out of the published key set: exactly what a
	// verifier that fetched /.well-known/jwks.json holds.
	jwksJSON, err := provider.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(jwksJSON, &set); err != nil {
		t.Fatalf("the published key set does not parse: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("the key set has %d keys, want 1", len(set.Keys))
	}

	parsed, err := jwt.ParseSigned(minted.Token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("the token does not parse as a JWS: %v", err)
	}
	if got := parsed.Headers[0].KeyID; got != set.Keys[0].KeyID {
		t.Errorf("kid = %q, want the published %q — a verifier selects the key by this", got, set.Keys[0].KeyID)
	}

	var claims struct {
		jwt.Claims
		AccountID string `json:"account_id"`
		// Accounts exists ONLY so its absence is assertable: a second answer to
		// "which account" in the same token is the defect the endpoint was built
		// to remove.
		Accounts []any `json:"accounts"`
	}
	if err := parsed.Claims(set.Keys[0].Key, &claims); err != nil {
		t.Fatalf("the signature does not verify against the published key: %v", err)
	}

	// Judged AT the mint instant: `iat` is the caller's clock, and validating
	// against wall time would make this test depend on when it runs.
	if err := claims.Validate(jwt.Expected{Issuer: "https://identity.test", AnyAudience: jwt.Audience{"billing"}, Time: now}); err != nil {
		t.Errorf("the standard claims do not validate: %v", err)
	}
	if claims.Subject != subject.String() {
		t.Errorf("sub = %q, want %q", claims.Subject, subject)
	}
	if claims.AccountID != account.String() {
		t.Errorf("account_id = %q, want %q — singular, and the one that was asked for", claims.AccountID, account)
	}
	if len(claims.Accounts) != 0 {
		t.Errorf("the token carries %d accounts; it must name exactly one account and no array", len(claims.Accounts))
	}
	if claims.ID == "" {
		t.Error("jti is empty; two tokens minted in the same second must not be the same token")
	}
	if want := now.Add(AccountTokenTTL); !minted.ExpiresAt.Equal(want) {
		t.Errorf("expires at %s, want %s", minted.ExpiresAt, want)
	}
	if got := time.Unix(claims.Expiry.Time().Unix(), 0).UTC(); !got.Equal(now.Add(AccountTokenTTL)) {
		t.Errorf("exp = %s, want %s", got, now.Add(AccountTokenTTL))
	}
	if got := time.Unix(claims.IssuedAt.Time().Unix(), 0).UTC(); !got.Equal(now) {
		t.Errorf("iat = %s, want %s — the caller's clock, not a second reading", got, now)
	}
}

// Two mints are two tokens, even in one frozen instant: the jti is what lets a
// receiver keep a replay ledger without comparing whole strings.
func TestMintAccountTokenIsUniquePerCall(t *testing.T) {
	t.Parallel()

	provider := newTestProvider(t)
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

	first, err := provider.MintAccountToken(id.MustNew(), id.MustNew(), "billing", now)
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	second, err := provider.MintAccountToken(id.MustNew(), id.MustNew(), "billing", now)
	if err != nil {
		t.Fatalf("second mint: %v", err)
	}
	if first.Token == second.Token {
		t.Error("two mints produced one token")
	}
}
