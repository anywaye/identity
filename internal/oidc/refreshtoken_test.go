package oidc

import (
	"errors"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The refresh token, over real SQL in a private schema.
//
// These are database tests rather than table tests because every property worth
// having here is a property of the RACE, not of the arithmetic: the single-use
// gate is a conditional UPDATE, the family revoke is a recursive CTE, and both
// are invisible to a fake. A fake would agree with all of this.

// mustDigest mints a value and returns only its digest, for the tests that need
// something to present without holding the value.
func mustDigest(t *testing.T) string {
	t.Helper()

	_, digest, err := NewRefreshTokenValue()
	if err != nil {
		t.Fatalf("NewRefreshTokenValue: %v", err)
	}
	return digest
}

// seedRefresh writes one refresh token for a registration and returns the row's
// id and the digest it was stored under.
func (f storeFixture) seedRefresh(t *testing.T, client Client, subject id.UUID, scopes []string, expires time.Time) (id.UUID, string) {
	t.Helper()

	digest := mustDigest(t)
	rowID := id.MustNew()
	if err := f.store.CreateRefreshToken(f.ctx, f.q(), NewRefreshToken{
		ID:          rowID,
		ClientRowID: client.ID,
		Subject:     subject,
		Scopes:      scopes,
		IssuedAt:    storeTestNow,
		ExpiresAt:   expires,
	}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	return rowID, digest
}

// A token is stored as a digest, and the value never reaches the table.
func TestARefreshTokenIsStoredAsADigest(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	rowID, digest := f.seedRefresh(t, client, f.owner, []string{"openid"}, storeTestNow.Add(RefreshTokenTTL))

	if len(digest) != 64 {
		t.Errorf("digest is %d characters, want the 64 of a hex SHA-256", len(digest))
	}

	// The column is read directly rather than through the store, because the
	// store never returns a digest and that is the point.
	var stored string
	if err := f.pool.QueryRow(f.ctx,
		`SELECT token_digest FROM oidc_refresh_tokens WHERE id = $1`, rowID).Scan(&stored); err != nil {
		t.Fatalf("reading the row back: %v", err)
	}
	if stored != digest {
		t.Errorf("stored digest = %q, want %q", stored, digest)
	}
}

// A token rotates: the claim consumes the row and the replacement links back.
func TestARefreshTokenRotates(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	rootID, rootDigest := f.seedRefresh(t, client, f.owner, []string{"openid", "email"}, storeTestNow.Add(RefreshTokenTTL))

	consumed, err := f.store.RotateRefreshToken(f.ctx, f.q(), rootDigest, storeTestNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("RotateRefreshToken = %v, want the token claimed", err)
	}
	if consumed.ID != rootID {
		t.Errorf("consumed id = %v, want %v", consumed.ID, rootID)
	}
	if consumed.UsedAt == nil {
		t.Fatal("rotating left used_at NULL, so a second presentation would be accepted")
	}

	// The replacement, as the token endpoint would write it.
	replacement := id.MustNew()
	replacementDigest := mustDigest(t)
	if err := f.store.ReplaceRefreshToken(f.ctx, f.q(), rootID, replacement); err != nil {
		t.Fatalf("ReplaceRefreshToken: %v", err)
	}
	if err := f.store.CreateRefreshToken(f.ctx, f.q(), NewRefreshToken{
		ID:          replacement,
		ClientRowID: client.ID,
		Subject:     f.owner,
		Scopes:      []string{"openid", "email"},
		IssuedAt:    storeTestNow.Add(time.Minute),
		ExpiresAt:   storeTestNow.Add(time.Minute + RefreshTokenTTL),
	}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	// The old value is spent and the new one works, which is the whole of
	// rotation seen from a client's side.
	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), rootDigest, storeTestNow.Add(2*time.Minute)); !errors.Is(err, ErrRefreshTokenReused) {
		t.Errorf("rotating the spent token again = %v, want ErrRefreshTokenReused", err)
	}
	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), replacementDigest, storeTestNow.Add(2*time.Minute)); err != nil {
		t.Errorf("rotating the replacement = %v, want it accepted", err)
	}
}

// Reuse is the one state that is never an accident, so it takes the family with
// it.
func TestAReusedRefreshTokenRevokesItsFamily(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	rootID, rootDigest := f.seedRefresh(t, client, f.owner, []string{"openid"}, storeTestNow.Add(RefreshTokenTTL))

	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), rootDigest, storeTestNow.Add(time.Minute)); err != nil {
		t.Fatalf("RotateRefreshToken: %v", err)
	}

	replacement := id.MustNew()
	replacementDigest := mustDigest(t)
	if err := f.store.ReplaceRefreshToken(f.ctx, f.q(), rootID, replacement); err != nil {
		t.Fatalf("ReplaceRefreshToken: %v", err)
	}
	if err := f.store.CreateRefreshToken(f.ctx, f.q(), NewRefreshToken{
		ID:          replacement,
		ClientRowID: client.ID,
		Subject:     f.owner,
		Scopes:      []string{"openid"},
		IssuedAt:    storeTestNow.Add(time.Minute),
		ExpiresAt:   storeTestNow.Add(time.Minute + RefreshTokenTTL),
	}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), rootDigest, storeTestNow.Add(2*time.Minute)); !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("reuse = %v, want ErrRefreshTokenReused", err)
	}

	// The replacement is a token nobody ever presented to anybody, and it is
	// dead too. Without this, detecting theft takes the token away from the
	// thief and leaves the legitimate client's next refresh working, which is a
	// defence measured in milliseconds.
	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), replacementDigest, storeTestNow.Add(3*time.Minute)); !errors.Is(err, ErrRefreshTokenRevoked) {
		t.Errorf("the replacement after a reuse = %v, want ErrRefreshTokenRevoked", err)
	}
}

// A token nobody ever issued, an expired one and a revoked one are three
// different refusals, and none of them is reuse.
func TestAnUnusableRefreshTokenIsRefusedAndRevokesNothing(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)

	unknown := mustDigest(t)
	_, expiredDigest := f.seedRefresh(t, client, f.owner, []string{"openid"}, storeTestNow.Add(-time.Second))
	_, revokedDigest := f.seedRefresh(t, client, f.owner, []string{"openid"}, storeTestNow.Add(RefreshTokenTTL))
	if err := f.store.RevokeRefreshTokensForClient(f.ctx, f.q(), client.ID, storeTestNow); err != nil {
		t.Fatalf("RevokeRefreshTokensForClient: %v", err)
	}

	tests := []struct {
		name string
		give string
		want error
	}{
		{name: "never issued", give: unknown, want: ErrNoRefreshToken},
		{name: "expired", give: expiredDigest, want: ErrRefreshTokenExpired},
		{name: "revoked", give: revokedDigest, want: ErrRefreshTokenRevoked},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := f.store.RotateRefreshToken(f.ctx, f.q(), tt.give, storeTestNow)
			if !errors.Is(err, tt.want) {
				t.Errorf("RotateRefreshToken = %v, want %v", err, tt.want)
			}
		})
	}
}

// Revoking a registration revokes its refresh tokens, and a second sweep is a
// success rather than an error.
func TestRevokingAClientRevokesItsRefreshTokens(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	_, digest := f.seedRefresh(t, client, f.owner, []string{"openid"}, storeTestNow.Add(RefreshTokenTTL))

	if err := f.store.RevokeRefreshTokensForClient(f.ctx, f.q(), client.ID, storeTestNow); err != nil {
		t.Fatalf("RevokeRefreshTokensForClient: %v", err)
	}
	if err := f.store.RevokeRefreshTokensForClient(f.ctx, f.q(), client.ID, storeTestNow); err != nil {
		t.Errorf("a second sweep = %v, want nil", err)
	}

	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), digest, storeTestNow); !errors.Is(err, ErrRefreshTokenRevoked) {
		t.Errorf("rotating a revoked client's token = %v, want ErrRefreshTokenRevoked", err)
	}
}

// The family walk follows replaced_by, and one statement takes the whole chain.
func TestRevokingAFamilyRevokesTheWholeChain(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)

	rootID, rootDigest := f.seedRefresh(t, client, f.owner, []string{"openid"}, storeTestNow.Add(RefreshTokenTTL))
	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), rootDigest, storeTestNow.Add(time.Minute)); err != nil {
		t.Fatalf("RotateRefreshToken: %v", err)
	}

	// Three links, each written by a rotation.
	previous := rootID
	digests := make([]string, 0, 3)
	for i := range 3 {
		next := id.MustNew()
		nextDigest := mustDigest(t)
		if err := f.store.ReplaceRefreshToken(f.ctx, f.q(), previous, next); err != nil {
			t.Fatalf("ReplaceRefreshToken: %v", err)
		}
		if err := f.store.CreateRefreshToken(f.ctx, f.q(), NewRefreshToken{
			ID:          next,
			ClientRowID: client.ID,
			Subject:     f.owner,
			Scopes:      []string{"openid"},
			IssuedAt:    storeTestNow.Add(time.Duration(i+1) * time.Minute),
			ExpiresAt:   storeTestNow.Add(time.Duration(i+1)*time.Minute + RefreshTokenTTL),
		}); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}
		previous = next
		digests = append(digests, nextDigest)
	}

	if err := f.store.RevokeRefreshTokenFamily(f.ctx, f.q(), rootID, storeTestNow.Add(time.Hour)); err != nil {
		t.Fatalf("RevokeRefreshTokenFamily: %v", err)
	}

	for i, d := range digests {
		_, err := f.store.RotateRefreshToken(f.ctx, f.q(), d, storeTestNow.Add(time.Hour))
		if !errors.Is(err, ErrRefreshTokenRevoked) {
			t.Errorf("chain link %d after a family revoke = %v, want ErrRefreshTokenRevoked", i, err)
		}
	}
}
