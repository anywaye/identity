package signup

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"
)


var (
	mintKey  = []byte("a-test-key-that-is-32-bytes-long!!")
	otherKey = []byte("a-different-key-32-bytes-long!!!!!!")
	mintAt   = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	service  = New(mintKey)
	otherSvc = New(otherKey)
	minted   = service.Mint(mintAt)
)

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mint Pair
		key *Service
		presentAt time.Time
		want      bool
	}{
		{
			name:      "a pair verified inside the window",
			presentAt: mintAt.Add(30 * time.Second),
			want:      true,
		},
		{
			name:      "a pair verified at the floor verifies",
			presentAt: mintAt.Add(MinAge),
			want:      true,
		},
		{
			name:      "a pair one second under the floor is refused",
			presentAt: mintAt.Add(MinAge - time.Second),
			want:      false,
		},
		{
			name:      "a pair verified at the ceiling verifies",
			presentAt: mintAt.Add(MaxAge),
			want:      true,
		},
		{
			name:      "a pair one second past the ceiling is refused",
			presentAt: mintAt.Add(MaxAge + time.Second),
			want:      false,
		},
		{
			name:      "the pair verified the moment it was minted is refused",
			presentAt: mintAt,
			want:      false,
		},
		{
			name:      "a pair from the future is refused",
			mint:      service.Mint(mintAt.Add(time.Hour)),
			presentAt: mintAt,
			want:      false,
		},
		{
			name: "a forged signature is refused",
			mint: Pair{
				Timestamp: minted.Timestamp,
				Signature: sign(otherKey, minted.Timestamp),
			},
			presentAt: mintAt.Add(30 * time.Second),
			want:      false,
		},
		{
			name:      "a pair minted under another key is refused",
			mint:      otherSvc.Mint(mintAt),
			presentAt: mintAt.Add(30 * time.Second),
			want:      false,
		},
		{
			name: "a valid signature over another timestamp is refused",
			mint: Pair{
				Timestamp: minted.Timestamp + 1,
				Signature: minted.Signature,
			},
			presentAt: mintAt.Add(30 * time.Second),
			want:      false,
		},
		{
			name: "a non-base64url signature is refused",
			mint: Pair{
				Timestamp: minted.Timestamp,
				Signature: "not base64url!",
			},
			presentAt: mintAt.Add(30 * time.Second),
			want:      false,
		},
		{
			name: "an empty signature is refused",
			mint: Pair{
				Timestamp: minted.Timestamp,
			},
			presentAt: mintAt.Add(30 * time.Second),
			want:      false,
		},
		{
			name: "a truncated signature is refused",
			mint: Pair{
				Timestamp: minted.Timestamp,
				Signature: base64.RawURLEncoding.EncodeToString([]byte("short")),
			},
			presentAt: mintAt.Add(30 * time.Second),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pair := tt.mint
			if pair == (Pair{}) {
				pair = minted
			}
			svc := tt.key
			if svc == nil {
				svc = service
			}

			if got := svc.Verify(pair, tt.presentAt); got != tt.want {
				t.Errorf("Verify(%+v, %s) = %v, want %v", pair, tt.presentAt.Format(time.RFC3339), got, tt.want)
			}
		})
	}
}

func TestMintSignsTheCanonicalDecimalForm(t *testing.T) {
	t.Parallel()

	pair := service.Mint(mintAt)

	if pair.Timestamp != mintAt.Unix() {
		t.Errorf("Timestamp = %d, want %d", pair.Timestamp, mintAt.Unix())
	}
	if pair.Signature == "" {
		t.Fatal("Signature is empty, so the pair carries nothing to verify against")
	}

	want := base64.RawURLEncoding.EncodeToString(mac(mintKey, mintAt.Unix()))
	if pair.Signature != want {
		t.Errorf("Signature = %q, want the HMAC over %q", pair.Signature, strconv.FormatInt(mintAt.Unix(), 10))
	}

	if strings.ContainsAny(pair.Signature, "+/=") {
		t.Errorf("Signature = %q, want base64url without padding", pair.Signature)
	}
}

func TestMintProducesAFreshPairEachCall(t *testing.T) {
	t.Parallel()

	later := service.Mint(mintAt.Add(time.Hour))
	if later.Signature == minted.Signature {
		t.Error("an hour later, the service minted the same signature — the pair is not fresh")
	}
	if later.Timestamp != mintAt.Add(time.Hour).Unix() {
		t.Errorf("Timestamp = %d, want %d", later.Timestamp, mintAt.Add(time.Hour).Unix())
	}
}
