package oidc

import (
	"errors"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


func mustDigest(t *testing.T) string {
	t.Helper()

	_, digest, err := NewRefreshTokenValue()
	if err != nil {
		t.Fatalf("NewRefreshTokenValue: %v", err)
	}
	return digest
}

func (f storeFixture) seedRefresh(t *testing.T, client Client, subject id.UUID, scopes []string, expires time.Time) (id.UUID, string) {
	t.Helper()

	digest := mustDigest(t)
	rowID := id.MustNew()
	if err := f.store.CreateRefreshToken(f.ctx, f.q(), NewRefreshToken{
		ID:          rowID,
		ClientRowID: client.ID,
		Subject:     subject,
		TokenDigest: digest,
		Scopes:      scopes,
		IssuedAt:    storeTestNow,
		ExpiresAt:   expires,
	}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	return rowID, digest
}

func TestARefreshTokenIsStoredAsADigest(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	rowID, digest := f.seedRefresh(t, client, f.owner, []string{"openid"}, storeTestNow.Add(RefreshTokenTTL))

	if len(digest) != 64 {
		t.Errorf("digest is %d characters, want the 64 of a hex SHA-256", len(digest))
	}

	var stored string
	if err := f.pool.QueryRow(f.ctx,
		`SELECT token_digest FROM oidc_refresh_tokens WHERE id = $1`, rowID).Scan(&stored); err != nil {
		t.Fatalf("reading the row back: %v", err)
	}
	if stored != digest {
		t.Errorf("stored digest = %q, want %q", stored, digest)
	}
}

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

	replacement := id.MustNew()
	replacementDigest := mustDigest(t)
	if err := f.store.CreateRefreshToken(f.ctx, f.q(), NewRefreshToken{
		ID:          replacement,
		ClientRowID: client.ID,
		Subject:     f.owner,
		TokenDigest: replacementDigest,
		Scopes:      []string{"openid", "email"},
		IssuedAt:    storeTestNow.Add(time.Minute),
		ExpiresAt:   storeTestNow.Add(time.Minute + RefreshTokenTTL),
	}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	if err := f.store.ReplaceRefreshToken(f.ctx, f.q(), rootID, replacement); err != nil {
		t.Fatalf("ReplaceRefreshToken: %v", err)
	}

	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), replacementDigest, storeTestNow.Add(2*time.Minute)); err != nil {
		t.Errorf("rotating the replacement = %v, want it accepted", err)
	}
	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), rootDigest, storeTestNow.Add(2*time.Minute)); !errors.Is(err, ErrRefreshTokenReused) {
		t.Errorf("rotating the spent token again = %v, want ErrRefreshTokenReused", err)
	}
}

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
	if err := f.store.CreateRefreshToken(f.ctx, f.q(), NewRefreshToken{
		ID:          replacement,
		ClientRowID: client.ID,
		Subject:     f.owner,
		TokenDigest: replacementDigest,
		Scopes:      []string{"openid"},
		IssuedAt:    storeTestNow.Add(time.Minute),
		ExpiresAt:   storeTestNow.Add(time.Minute + RefreshTokenTTL),
	}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	if err := f.store.ReplaceRefreshToken(f.ctx, f.q(), rootID, replacement); err != nil {
		t.Fatalf("ReplaceRefreshToken: %v", err)
	}

	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), rootDigest, storeTestNow.Add(2*time.Minute)); !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("reuse = %v, want ErrRefreshTokenReused", err)
	}

	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), replacementDigest, storeTestNow.Add(3*time.Minute)); !errors.Is(err, ErrRefreshTokenRevoked) {
		t.Errorf("the replacement after a reuse = %v, want ErrRefreshTokenRevoked", err)
	}

	var live int
	if err := f.pool.QueryRow(f.ctx,
		`SELECT count(*) FROM oidc_refresh_tokens WHERE revoked_at IS NULL`).Scan(&live); err != nil {
		t.Fatalf("counting the live rows the reuse left behind: %v", err)
	}
	if live != 0 {
		t.Errorf("the reuse path left %d live rows, want 0: the chain had a root and a replacement", live)
	}
}

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

func TestRevokingAFamilyRevokesTheWholeChain(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)

	rootID, rootDigest := f.seedRefresh(t, client, f.owner, []string{"openid"}, storeTestNow.Add(RefreshTokenTTL))
	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), rootDigest, storeTestNow.Add(time.Minute)); err != nil {
		t.Fatalf("RotateRefreshToken: %v", err)
	}

	previous := rootID
	digests := make([]string, 0, 3)
	for i := range 3 {
		next := id.MustNew()
		nextDigest := mustDigest(t)
		if err := f.store.CreateRefreshToken(f.ctx, f.q(), NewRefreshToken{
			ID:          next,
			ClientRowID: client.ID,
			Subject:     f.owner,
			TokenDigest: nextDigest,
			Scopes:      []string{"openid"},
			IssuedAt:    storeTestNow.Add(time.Duration(i+1) * time.Minute),
			ExpiresAt:   storeTestNow.Add(time.Duration(i+1)*time.Minute + RefreshTokenTTL),
		}); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}
		if err := f.store.ReplaceRefreshToken(f.ctx, f.q(), previous, next); err != nil {
			t.Fatalf("ReplaceRefreshToken: %v", err)
		}
		previous = next
		digests = append(digests, nextDigest)
	}

	revoked, err := f.store.RevokeRefreshTokenFamily(f.ctx, f.q(), rootID, storeTestNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("RevokeRefreshTokenFamily: %v", err)
	}
	if want := int64(len(digests) + 1); revoked != want {
		t.Errorf("the family revoke touched %d rows, want the %d of the chain this test built", revoked, want)
	}

	for i, d := range digests {
		_, err := f.store.RotateRefreshToken(f.ctx, f.q(), d, storeTestNow.Add(time.Hour))
		if !errors.Is(err, ErrRefreshTokenRevoked) {
			t.Errorf("chain link %d after a family revoke = %v, want ErrRefreshTokenRevoked", i, err)
		}
	}
}

func TestARevocationFromTheMiddleOfAChainTakesTheSuccessors(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)

	rootID, rootDigest := f.seedRefresh(t, client, f.owner, []string{"openid"}, storeTestNow.Add(RefreshTokenTTL))
	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), rootDigest, storeTestNow.Add(time.Minute)); err != nil {
		t.Fatalf("RotateRefreshToken: %v", err)
	}

	previous := rootID
	ids := make([]id.UUID, 0, 3)
	digests := make([]string, 0, 3)
	for i := range 3 {
		next := id.MustNew()
		nextDigest := mustDigest(t)
		if err := f.store.CreateRefreshToken(f.ctx, f.q(), NewRefreshToken{
			ID:          next,
			ClientRowID: client.ID,
			Subject:     f.owner,
			TokenDigest: nextDigest,
			Scopes:      []string{"openid"},
			IssuedAt:    storeTestNow.Add(time.Duration(i+1) * time.Minute),
			ExpiresAt:   storeTestNow.Add(time.Duration(i+1)*time.Minute + RefreshTokenTTL),
		}); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}
		if err := f.store.ReplaceRefreshToken(f.ctx, f.q(), previous, next); err != nil {
			t.Fatalf("ReplaceRefreshToken: %v", err)
		}
		previous = next
		ids = append(ids, next)
		digests = append(digests, nextDigest)
	}

	revoked, err := f.store.RevokeRefreshTokenFamily(f.ctx, f.q(), ids[0], storeTestNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("RevokeRefreshTokenFamily: %v", err)
	}
	if revoked != 3 {
		t.Errorf("a revoke from the first link touched %d rows, want the 3 it and its successors make", revoked)
	}

	for i, d := range digests {
		_, err := f.store.RotateRefreshToken(f.ctx, f.q(), d, storeTestNow.Add(time.Hour))
		if !errors.Is(err, ErrRefreshTokenRevoked) {
			t.Errorf("successor %d after a revoke from the first link = %v, want ErrRefreshTokenRevoked", i, err)
		}
	}
	if _, err := f.store.RotateRefreshToken(f.ctx, f.q(), rootDigest, storeTestNow.Add(time.Hour)); !errors.Is(err, ErrRefreshTokenReused) {
		t.Errorf("the root after a revoke from the first link = %v, want ErrRefreshTokenReused: it spent, not revoked", err)
	}
}
