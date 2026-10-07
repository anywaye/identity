package httpapi

import (
	"sync"
	"time"

	"github.com/cafaye/identity/internal/signup"
)

// fakeSignup is the Signup double. It wraps a REAL signup.Service under a test
// key, so a mint produces a genuine pair and a verify is a genuine verification
// — the same property the other doubles in this package have where the real
// thing is cheap and side-effect-free. What it adds is the ability to FORCE a
// refusal, so a test can prove the handler's 422 without constructing a forged
// pair by hand, and the recordings that prove which values reached the use case.
type fakeSignup struct {
	mu sync.Mutex

	svc *signup.Service

	// verifyResult, when non-nil, is what Verify returns regardless of the
	// pair. It exists so a test can assert the handler's refusal path without
	// building a forged signature — the refusal is the handler's, and the
	// double's answer is the seam that reaches it.
	verifyResult *bool

	// mints records every Mint call, so a test can prove the handler minted at
	// the instant it claims and at no other.
	mints []time.Time
	// verifies records every Verify call's pair and instant, so a test can
	// prove the handler verified the pair it was handed and refused before the
	// registration service was called.
	verifies []fakeVerifyCall
}

// fakeVerifyCall is one Verify call: the pair and the instant.
type fakeVerifyCall struct {
	pair signup.Pair
	at   time.Time
}

// newFakeSignup returns a fakeSignup under a fixed test key. The key is a
// constant rather than a generated value because these tests assert on the
// handler's behaviour, not on the key — and a key that changed per run would
// change nothing about what the handler does with the pair.
func newFakeSignup() *fakeSignup {
	return &fakeSignup{
		svc: signup.New([]byte("a-test-key-that-is-32-bytes-long!!")),
	}
}

// acceptsEveryPair returns a fakeSignup whose Verify always passes.
//
// It exists for the ONE caller whose question is not "did the verify refuse":
// the anonymous enumeration audit, which asks what a route discloses to a
// stranger and would otherwise measure a fixed 422 instead of the 409 and 423
// its rows are about. Mint is still the real one, so a fixture using this still
// exercises the mint route end to end.
func acceptsEveryPair() *fakeSignup {
	f := newFakeSignup()
	pass := true
	f.verifyResult = &pass
	return f
}

// Mint returns a fresh pair for now, recording the instant.
func (f *fakeSignup) Mint(now time.Time) signup.Pair {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mints = append(f.mints, now)
	return f.svc.Mint(now)
}

// Verify reports whether the pair verifies, recording the call. A forced
// verifyResult overrides the real verification.
func (f *fakeSignup) Verify(pair signup.Pair, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifies = append(f.verifies, fakeVerifyCall{pair: pair, at: now})
	if f.verifyResult != nil {
		return *f.verifyResult
	}
	return f.svc.Verify(pair, now)
}

// minted returns the pairs the service minted, in order.
func (f *fakeSignup) minted() []signup.Pair {
	f.mu.Lock()
	defer f.mu.Unlock()
	pairs := make([]signup.Pair, 0, len(f.mints))
	for _, at := range f.mints {
		pairs = append(pairs, f.svc.Mint(at))
	}
	return pairs
}

// verified returns the Verify calls, in order.
func (f *fakeSignup) verified() []fakeVerifyCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeVerifyCall(nil), f.verifies...)
}
