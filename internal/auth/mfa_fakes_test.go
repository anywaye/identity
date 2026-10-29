package auth

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/mfa"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
)


type fakeSecondFactor struct {
	enabled map[id.UUID]bool

	verifyErr error
	enabledErr error
	createErr error
	commitErr error

	challengeToken string
	claim mfa.Claim
	claimUser id.UUID

	enabledCalls  int
	challenges    []mfa.CreateChallengeInput
	verifications []CompleteSecondFactorInput
	commits       int
	committed id.UUID
}

func newFakeSecondFactor() *fakeSecondFactor {
	var user id.UUID
	user[1] = 1
	return &fakeSecondFactor{
		enabled:        map[id.UUID]bool{},
		challengeToken: "a-challenge-token",
		claimUser:      user,
	}
}

func (f *fakeSecondFactor) Enabled(_ context.Context, _ db.Querier, userID id.UUID) (bool, error) {
	f.enabledCalls++
	if f.enabledErr != nil {
		return false, f.enabledErr
	}
	return f.enabled[userID], nil
}

func (f *fakeSecondFactor) CreateChallenge(_ context.Context, in mfa.CreateChallengeInput) (mfa.NewChallenge, error) {
	f.challenges = append(f.challenges, in)
	if f.createErr != nil {
		return mfa.NewChallenge{}, f.createErr
	}
	expires := start.Add(10 * time.Minute)
	return mfa.NewChallenge{
		Challenge: mfa.Challenge{UserID: in.UserID, CreatedAt: start, ExpiresAt: expires},
		Token:     f.challengeToken,
		ExpiresAt: expires,
	}, nil
}

func (f *fakeSecondFactor) VerifyChallenge(_ context.Context, token, code string, _ time.Time) (mfa.Claim, error) {
	f.verifications = append(f.verifications, CompleteSecondFactorInput{ChallengeToken: token, Code: code})
	if f.verifyErr != nil {
		return mfa.Claim{}, f.verifyErr
	}
	return f.claim, nil
}

func (f *fakeSecondFactor) Commit(_ context.Context, _ db.Querier, claim mfa.Claim, _ time.Time) error {
	f.commits++
	f.committed = claim.UserID()
	return f.commitErr
}

func (f *fakeSecondFactor) claimFor(user id.UUID) mfa.Claim { return mfa.ClaimForTest(user) }

func realSecondFactor(t *testing.T, pool *pgxpool.Pool, clk clock.Clock) *mfa.Service {
	t.Helper()

	vault, err := mfa.NewAESCipher(testSecondFactorKey)
	if err != nil {
		t.Fatalf("building the MFA test vault: %v", err)
	}
	return mfa.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		mfa.NewStore(pool),
		outbox.NewStore(pool),
		sessions.NewStore(pool),
		vault,
		clk,
		"anywaye identity",
	)
}

var testSecondFactorKey = testKey32("identity-auth-mfa-key-32-bytes--")

func testKey32(literal string) []byte {
	var key [32]byte
	copy(key[:], literal)
	return key[:]
}
