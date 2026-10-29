package httpapi

import (
	"sync"
	"time"

	"github.com/anywaye/identity/internal/signup"
)

type fakeSignup struct {
	mu sync.Mutex

	svc *signup.Service

	verifyResult *bool

	mints []time.Time
	verifies []fakeVerifyCall
}

type fakeVerifyCall struct {
	pair signup.Pair
	at   time.Time
}

func newFakeSignup() *fakeSignup {
	return &fakeSignup{
		svc: signup.New([]byte("a-test-key-that-is-32-bytes-long!!")),
	}
}

func acceptsEveryPair() *fakeSignup {
	f := newFakeSignup()
	pass := true
	f.verifyResult = &pass
	return f
}

func (f *fakeSignup) Mint(now time.Time) signup.Pair {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mints = append(f.mints, now)
	return f.svc.Mint(now)
}

func (f *fakeSignup) Verify(pair signup.Pair, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifies = append(f.verifies, fakeVerifyCall{pair: pair, at: now})
	if f.verifyResult != nil {
		return *f.verifyResult
	}
	return f.svc.Verify(pair, now)
}

func (f *fakeSignup) minted() []signup.Pair {
	f.mu.Lock()
	defer f.mu.Unlock()
	pairs := make([]signup.Pair, 0, len(f.mints))
	for _, at := range f.mints {
		pairs = append(pairs, f.svc.Mint(at))
	}
	return pairs
}

func (f *fakeSignup) verified() []fakeVerifyCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeVerifyCall(nil), f.verifies...)
}
