package signup

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"
)

// THE MINT/VERIFY CONTRACT, AS A TABLE OVER THE AGE OF THE PRESENTED PAIR.
//
// Every refusal is a plain false with no branch naming its cause, so the
// table's job is to pin the BOUNDARIES: the instant a pair stops verifying is
// the property, and a boundary off by a second in either direction is a bot
// admitted or a person refused. The times are absolute and the ages are
// derived, so a reader can see which side of which bound each row sits on.

var (
	mintKey    = []byte("a-test-key-that-is-32-bytes-long!!") // 32 bytes
	otherKey   = []byte("a-different-key-32-bytes-long!!!!!!") // 32 bytes
	mintAt     = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	service    = New(mintKey)
	otherSvc   = New(otherKey)
	minted     = service.Mint(mintAt)
)

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// mint is the pair under test, and nil means "the pair this key
		// minted at mintAt" — the common case, spelled out only where a
		// test changes it.
		mint Pair
		// key is the service the pair is verified against. nil means
		// "the service that minted it" — again the common case.
		key *Service
		// presentAt is the instant of the verification.
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
			// THE INSTANT SUBMISSION: a bot fills the form and submits in
			// the same breath, so the pair it presents is younger than the
			// floor however fast the request travels.
			name:      "the pair verified the moment it was minted is refused",
			presentAt: mintAt,
			want:      false,
		},
		{
			// A timestamp in the future has a NEGATIVE age, so it fails the
			// floor with the instant submission. One comparison covers both
			// and there is no second clock to ask.
			name:      "a pair from the future is refused",
			mint:      service.Mint(mintAt.Add(time.Hour)),
			presentAt: mintAt,
			want:      false,
		},
		{
			// THE FORGED SIGNATURE: right timestamp, wrong MAC. This is the
			// case the whole package exists for — a bot that knows the
			// timestamp but not the key.
			name: "a forged signature is refused",
			mint: Pair{
				Timestamp: minted.Timestamp,
				Signature: sign(otherKey, minted.Timestamp),
			},
			presentAt: mintAt.Add(30 * time.Second),
			want:      false,
		},
		{
			// A signature minted under a DIFFERENT key, verified against the
			// minting service: the same forgery from the other side.
			name:      "a pair minted under another key is refused",
			mint:      otherSvc.Mint(mintAt),
			presentAt: mintAt.Add(30 * time.Second),
			want:      false,
		},
		{
			// THE TAMPERED TIMESTAMP: a valid signature over a different
			// timestamp, presented with the minted one. The MAC is real and
			// the pair is wrong, and the two must not be tellable apart.
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
			// A truncated signature decodes to fewer bytes than a MAC; the
			// comparison must refuse rather than read past the slice.
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
				// The zero Pair means "the pair this key minted at mintAt" —
				// the common case. A row that sets only one field (the empty
				// signature, the tampered timestamp) is not the zero Pair and
				// is used as written.
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

// TestMintSignsTheCanonicalDecimalForm pins the message, because the whole
// scheme rests on mint and verify agreeing on ONE string for a timestamp.
//
// The signature is over the decimal form — not the raw int64 bytes, not an
// RFC 3339 rendering — so a client that echoes the integer back cannot
// accidentally present a different message than the one that was signed.
func TestMintSignsTheCanonicalDecimalForm(t *testing.T) {
	t.Parallel()

	pair := service.Mint(mintAt)

	if pair.Timestamp != mintAt.Unix() {
		t.Errorf("Timestamp = %d, want %d", pair.Timestamp, mintAt.Unix())
	}
	if pair.Signature == "" {
		t.Fatal("Signature is empty, so the pair carries nothing to verify against")
	}

	// The signature must be exactly the base64url of the HMAC over the
	// decimal string — recomputed here rather than compared against a
	// fixture, so a change to the message form is a change to this line
	// and not a silent drift of the whole scheme.
	want := base64.RawURLEncoding.EncodeToString(mac(mintKey, mintAt.Unix()))
	if pair.Signature != want {
		t.Errorf("Signature = %q, want the HMAC over %q", pair.Signature, strconv.FormatInt(mintAt.Unix(), 10))
	}

	// And it must be the alphabet the service issues everywhere else: no
	// padding, no + or /.
	if strings.ContainsAny(pair.Signature, "+/=") {
		t.Errorf("Signature = %q, want base64url without padding", pair.Signature)
	}
}

// TestMintProducesAFreshPairEachCall is the property the form relies on: two
// mints at the same instant are two pairs, and a pair minted later is not the
// pair minted earlier. A mint that returned a constant would be a credential
// shared by every signup on the platform.
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
