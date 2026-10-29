package httpapi


import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/signup"
)

var mintAt = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func newSignupVerifyHandler(t *testing.T) (*fakeAuth, *fakeSignup, *clock.Fake) {
	t.Helper()

	clk := clock.NewFake(mintAt)
	su := newFakeSignup()
	f := newFakeAuth()
	return f, su, clk
}


func TestMintSignupTimestampIsPublicAndHandsOutOnlyThePair(t *testing.T) {
	t.Parallel()

	clk := clock.NewFake(mintAt)
	su := newFakeSignup()
	h := New(nil, WithSignup(su), WithClock(clk))

	rec := post(t, h, "/v1/signup-timestamp", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if got, want := rec.Header().Get("Content-Type"), "application/json; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	var body struct {
		Timestamp int64  `json:"timestamp"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}
	if body.Timestamp != mintAt.Unix() {
		t.Errorf("timestamp = %d, want the clock's instant %d", body.Timestamp, mintAt.Unix())
	}
	if body.Signature == "" {
		t.Fatal("the signature is empty, so the pair carries nothing to verify against")
	}

	clk.Advance(30 * time.Second)
	if !su.Verify(signup.Pair{Timestamp: body.Timestamp, Signature: body.Signature}, clk.Now()) {
		t.Error("the minted pair does not verify under the same key — the form would submit and be refused")
	}

	if got := su.minted(); len(got) != 1 {
		t.Errorf("the service minted %d pairs, want 1", len(got))
	}
}


func TestRegisterVerifiesTheSignedTimestamp(t *testing.T) {
	t.Parallel()

	otherKey := signup.New([]byte("a-different-key-32-bytes-long!!!!!!"))
	forged := otherKey.Mint(mintAt)

	tests := []struct {
		name string
		pair *signup.Pair
		advance time.Duration
		want    int
	}{
		{
			name:    "a legitimate delayed submission is accepted",
			advance: 30 * time.Second,
			want:    http.StatusCreated,
		},
		{
			name:    "a submission at the floor is accepted",
			advance: signup.MinAge,
			want:    http.StatusCreated,
		},
		{
			name:    "the instant submission is refused",
			advance: 0,
			want:    http.StatusUnprocessableEntity,
		},
		{
			name:    "a submission one second under the floor is refused",
			advance: signup.MinAge - time.Second,
			want:    http.StatusUnprocessableEntity,
		},
		{
			name:    "a submission at the ceiling is accepted",
			advance: signup.MaxAge,
			want:    http.StatusCreated,
		},
		{
			name:    "an expired timestamp is refused",
			advance: signup.MaxAge + time.Second,
			want:    http.StatusUnprocessableEntity,
		},
		{
			name:    "a pair from the future is refused",
			pair:    &signup.Pair{Timestamp: mintAt.Add(time.Hour).Unix(), Signature: "whatever"},
			advance: 0,
			want:    http.StatusUnprocessableEntity,
		},
		{
			name:    "a forged signature is refused",
			pair:    &forged,
			advance: 30 * time.Second,
			want:    http.StatusUnprocessableEntity,
		},
		{
			name:    "a garbage signature is refused",
			pair:    &signup.Pair{Timestamp: mintAt.Unix(), Signature: "not-a-signature"},
			advance: 30 * time.Second,
			want:    http.StatusUnprocessableEntity,
		},
		{
			name:    "a submission with no pair is refused",
			pair:    &signup.Pair{},
			advance: 30 * time.Second,
			want:    http.StatusUnprocessableEntity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f, su, clk := newSignupVerifyHandler(t)
			clk.Set(mintAt)

			pair := tt.pair
			if pair == nil {
				minted := su.Mint(clk.Now())
				pair = &minted
			}

			clk.Advance(tt.advance)

			body := `{"email":"kaka@example.com","password":"correct horse battery",` +
				`"timestamp":` + strconv.FormatInt(pair.Timestamp, 10) + `,` +
				`"signature":"` + pair.Signature + `"}`
			rec := post(t, New(nil, WithAuth(f), WithSignup(su), WithClock(clk)), "/v1/users", body)

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.want, rec.Body)
			}

			if tt.want == http.StatusUnprocessableEntity {
				p := decodeProblem(t, rec)
				if p.Code != CodeValidationFailed {
					t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
				}
				if p.Detail != "the request has an invalid field" {
					t.Errorf("detail = %q, want the generic refusal the honeypot gives", p.Detail)
				}
			}

			if tt.want == http.StatusUnprocessableEntity && f.hasRegistered() {
				t.Error("a refused submission reached the registration service")
			}
			if tt.want == http.StatusCreated && !f.hasRegistered() {
				t.Error("an accepted submission never reached the registration service")
			}

			if got := su.verified(); len(got) != 1 {
				t.Fatalf("the verify was called %d times, want 1", len(got))
			}
			if got := su.verified()[0]; got.pair != *pair {
				t.Errorf("the verify was handed %+v, want the pair the handler was handed %+v", got.pair, *pair)
			}
		})
	}
}

func TestRegisterRefusalsFailWithoutTheVerifyCheck(t *testing.T) {
	t.Parallel()

	otherKey := signup.New([]byte("a-different-key-32-bytes-long!!!!!!"))
	forged := otherKey.Mint(mintAt)

	tests := []struct {
		name    string
		pair    *signup.Pair
		advance time.Duration
	}{
		{name: "a forged signature", pair: &forged, advance: 30 * time.Second},
		{name: "the instant submission", pair: nil, advance: 0},
		{name: "an expired timestamp", pair: nil, advance: signup.MaxAge + time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f, su, clk := newSignupVerifyHandler(t)
			clk.Set(mintAt)

			forced := true
			su.verifyResult = &forced

			pair := tt.pair
			if pair == nil {
				minted := su.Mint(clk.Now())
				pair = &minted
			}

			clk.Advance(tt.advance)

			body := `{"email":"kaka@example.com","password":"correct horse battery",` +
				`"timestamp":` + strconv.FormatInt(pair.Timestamp, 10) + `,` +
				`"signature":"` + pair.Signature + `"}`
			rec := post(t, New(nil, WithAuth(f), WithSignup(su), WithClock(clk)), "/v1/users", body)

			if rec.Code != http.StatusCreated {
				t.Fatalf("with the verify bypassed, status = %d, want 201; body: %s", rec.Code, rec.Body)
			}
			if !f.hasRegistered() {
				t.Error("with the verify bypassed, the registration service was never called")
			}
		})
	}
}
