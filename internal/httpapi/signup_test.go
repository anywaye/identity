package httpapi

// THE SIGNUP TIMESTAMP'S HTTP CONTRACT: THE MINT'S SHAPE AND THE VERIFY'S REFUSALS.
//
// Two surfaces, one package:
//
//	POST /v1/signup-timestamp  →  200 {timestamp, signature}   the mint
//	POST /v1/users             →  422 for a bad pair           the verify
//
// The mint's tests are about the SHAPE: status, JSON, content-type, and the
// fact that it demands nothing. The verify's tests are about the REFUSALS: a
// forged signature, an instant submission, an expired one and a legitimate
// delayed one, each refused or accepted as specified — and each refusal shown
// to fail without its check, which is the evidence that the check is the thing
// doing the refusing.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/signup"
)

// mintAt is the instant the fake clock is parked at, and the instant every
// pair in this file is minted at unless a test says otherwise. Absolute and
// fixed so a reader can see which side of which bound each case sits on.
var mintAt = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// newSignupVerifyHandler is the router the verify tests drive: a fake auth
// (so a 201 is a real registration), a fake signup under a test key (so a
// minted pair is a genuine one), and a fake clock parked at mintAt (so a test
// can move time exactly and assert on the age of the pair it presents).
func newSignupVerifyHandler(t *testing.T) (*fakeAuth, *fakeSignup, *clock.Fake) {
	t.Helper()

	clk := clock.NewFake(mintAt)
	su := newFakeSignup()
	f := newFakeAuth()
	return f, su, clk
}

// ---------------------------------------------------------------------------
// the mint
// ---------------------------------------------------------------------------

// TestMintSignupTimestampIsPublicAndHandsOutOnlyThePair is the mint's shape.
//
// IT DEMANDS NOTHING: no credential, no body, no identifier of any kind. The
// form (parlor) asks for a fresh pair before it renders, and a browser
// arriving at the form holds nothing but the address it was sent to. The
// response carries nothing but the pair — no account, no user, no state —
// which is what makes the endpoint safe to leave open (see the file header's
// rate-limit argument).
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

	// The body is exactly the pair: two fields, a Unix integer and a base64url
	// signature. A third field would be a fact about the minted pair that the
	// form has no use for, and a generated client would carry it into a request
	// that refuses it.
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

	// The pair the endpoint handed out is a GENUINE pair: the same service
	// verifies it. A mint that produced a pair its own verify refused would be
	// a form that could not submit. The clock is advanced past the floor first,
	// because a pair verified at the instant it was minted is refused by the
	// floor — the same instant-submission refusal the verify tests assert.
	clk.Advance(30 * time.Second)
	if !su.Verify(signup.Pair{Timestamp: body.Timestamp, Signature: body.Signature}, clk.Now()) {
		t.Error("the minted pair does not verify under the same key — the form would submit and be refused")
	}

	// And the service was asked to mint exactly once, at the instant the
	// handler claims — the recording is what proves the handler minted rather
	// than returning a constant.
	if got := su.minted(); len(got) != 1 {
		t.Errorf("the service minted %d pairs, want 1", len(got))
	}
}

// ---------------------------------------------------------------------------
// the verify
// ---------------------------------------------------------------------------

// TestRegisterVerifiesTheSignedTimestamp is the verify's contract, as a table
// over the pair presented.
//
// Every refusal is the SAME generic 422 the honeypot gives — a forged
// signature, an instant submission, an expired one and a future one are four
// answers a bot must not be able to tell apart. The legitimate delayed
// submission is the one that must succeed: a person needs seconds to fill a
// form, and the floor is what separates them from a bot.
func TestRegisterVerifiesTheSignedTimestamp(t *testing.T) {
	t.Parallel()

	// A pair minted under a DIFFERENT key: the same forgery a bot would
	// produce by reading the source and hardcoding a key, and the reason the
	// fifth secret exists rather than a reused one.
	otherKey := signup.New([]byte("a-different-key-32-bytes-long!!!!!!"))
	forged := otherKey.Mint(mintAt)

	tests := []struct {
		name string
		// pair is the pair under test. nil means "the pair this key minted at
		// mintAt" — the common case, spelled out only where a test changes it.
		pair *signup.Pair
		// advance is how far the clock moves before the submission. Zero is
		// the instant submission; the floor and the ceiling are measured from
		// it.
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
			// THE INSTANT SUBMISSION: a bot fills the form and submits in the
			// same breath, so the pair it presents is younger than the floor
			// however fast the request travels.
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
			// THE EXPIRED TIMESTAMP: a signed timestamp is a bearer
			// credential, and a bearer credential that never expires is one
			// that can be captured and replayed for as long as the deployment
			// lives.
			name:    "an expired timestamp is refused",
			advance: signup.MaxAge + time.Second,
			want:    http.StatusUnprocessableEntity,
		},
		{
			// A timestamp in the future has a NEGATIVE age, so it fails the
			// floor with the instant submission. One comparison covers both.
			name:    "a pair from the future is refused",
			pair:    &signup.Pair{Timestamp: mintAt.Add(time.Hour).Unix(), Signature: "whatever"},
			advance: 0,
			want:    http.StatusUnprocessableEntity,
		},
		{
			// THE FORGED SIGNATURE: right timestamp, wrong MAC, under a key
			// this deployment never configured. This is the case the whole
			// surface exists for.
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
			// NO PAIR: a submission that carries neither field. The form
			// always sends the pair, so a submission without one is not from
			// the form — and the refusal is the same 422, because a bot must
			// not learn that the pair is the check.
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

			// The refusal is the SAME generic 422 the honeypot gives — a bot
			// must not learn which check caught it. The detail names no field
			// and the code is the validation_failed every other refusal uses.
			if tt.want == http.StatusUnprocessableEntity {
				p := decodeProblem(t, rec)
				if p.Code != CodeValidationFailed {
					t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
				}
				if p.Detail != "the request has an invalid field" {
					t.Errorf("detail = %q, want the generic refusal the honeypot gives", p.Detail)
				}
			}

			// THE ORDER, asserted rather than assumed: a refused submission
			// never reaches the registration service, so no row exists. A bot
			// that gets a row has won, even if the row is later deleted.
			if tt.want == http.StatusUnprocessableEntity && f.hasRegistered() {
				t.Error("a refused submission reached the registration service")
			}
			if tt.want == http.StatusCreated && !f.hasRegistered() {
				t.Error("an accepted submission never reached the registration service")
			}

			// THE CHECK RAN, asserted rather than assumed: the verify was
			// called with the pair the handler was handed. A refusal with no
			// verify call is a refusal that came from somewhere else, and the
			// test would be passing against a handler that does not check.
			if got := su.verified(); len(got) != 1 {
				t.Fatalf("the verify was called %d times, want 1", len(got))
			}
			if got := su.verified()[0]; got.pair != *pair {
				t.Errorf("the verify was handed %+v, want the pair the handler was handed %+v", got.pair, *pair)
			}
		})
	}
}

// TestRegisterRefusalsFailWithoutTheVerifyCheck is the evidence that the verify
// is the thing doing the refusing, and not a coincidence of the fixture.
//
// It forces the verify to PASS — the same effect as commenting the check out,
// which is the fault the honeypot packet's report describes — and shows that
// every refused case is now ACCEPTED. A forged signature, an instant
// submission and an expired one all get a 201 and a user row when the check
// does not run. That is the contrast that makes the table above mean
// something: the 422s there are the verify's, and without the verify they do
// not happen.
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

			// THE FAULT: the verify is forced to pass, which is the check not
			// running. Everything else is the same handler, the same pair, the
			// same instant.
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

			// With the check bypassed, the submission is ACCEPTED — a bot
			// gets a row. This is the red the refusal table above would show
			// if the check were removed, and it is the evidence that the 422s
			// there are the verify's.
			if rec.Code != http.StatusCreated {
				t.Fatalf("with the verify bypassed, status = %d, want 201; body: %s", rec.Code, rec.Body)
			}
			if !f.hasRegistered() {
				t.Error("with the verify bypassed, the registration service was never called")
			}
		})
	}
}
