package httpapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/ratelimit"
)

// THE RATE LIMITER'S TWO PROOFS.
//
// The limiter on the unauthenticated auth surface has two properties that must
// be PROVEN rather than assumed, because both fail in a way that looks like a
// feature:
//
//  1. It must not become an enumeration oracle. A 429 that arrives for one
//     attempted address and not another tells a stranger which addresses are
//     worth trying. The key is the client address and the route, never the
//     account — and TestRateLimitingDoesNotBecomeAnEnumerationOracle proves the
//     refusal is identical for an existing and a non-existing account.
//
//  2. It must actually refuse. A configured number is not the proof:
//     TestRateLimitingRefusesOverTheLimitAndLeavesUnderItUntouched issues more
//     requests than the limit and asserts the refusal, then advances the clock
//     past the window and asserts a request under it is untouched.

// TestRateLimitingDoesNotBecomeAnEnumerationOracle is the enumeration proof.
//
// It is in the same spirit as anonymous_enumeration_test.go: the question is
// "can the response tell 'this account exists' from 'it does not'?" and the
// answer must be "no" for the 429 exactly as it is for the 401.
//
// THE KEY IS THE CLIENT AND THE ROUTE, NEVER THE ACCOUNT. A limiter keyed on
// the address being ATTEMPTED would make the 429 itself the oracle: a client
// that is over the limit for one address and under it for another would learn
// which addresses are worth trying. So the key is the client's source address
// and the route pattern — two facts that say nothing about whether any
// account exists — and this test measures the consequence.
func TestRateLimitingDoesNotBecomeAnEnumerationOracle(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	limiter := ratelimit.New(clk, map[string]ratelimit.Limit{
		"/v1/session": {Max: 2, Window: time.Minute},
	})
	f := newAuditFixture(t, WithRateLimiter(limiter))

	// An existing account and a non-existing one. The existing one is
	// registered through the real route; the non-existing one is an address
	// this service has never heard of.
	existing := dbtest.UniqueEmail(t)
	registerThrough(t, f.handler, existing)
	nonExisting := dbtest.UniqueEmail(t)

	// UNDER THE LIMIT: both get the same 401. The limiter has counted two
	// requests and the window is full, but neither has been refused.
	for _, email := range []string{existing, nonExisting} {
		rec := post(t, f.handler, "/v1/session", `{"email":"`+email+`","password":"not the right password"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("login for %s under the limit = %d, want 401; body: %s", email, rec.Code, rec.Body)
		}
	}

	// OVER THE LIMIT: both get the same 429. The limiter is full, so the
	// refusal is identical for the account that exists and the one that does
	// not — which is the whole of the proof.
	a := post(t, f.handler, "/v1/session", `{"email":"`+existing+`","password":"not the right password"}`)
	b := post(t, f.handler, "/v1/session", `{"email":"`+nonExisting+`","password":"not the right password"}`)
	if a.Code != http.StatusTooManyRequests {
		t.Fatalf("login for the existing address over the limit = %d, want 429; body: %s", a.Code, a.Body)
	}
	if b.Code != http.StatusTooManyRequests {
		t.Fatalf("login for the non-existing address over the limit = %d, want 429; body: %s", b.Code, b.Body)
	}

	// THE TWO 429s ARE ONE DOCUMENT. Compared as whole rendered documents,
	// modulo the trace id, because a 429 that differed between an existing and
	// a non-existing account would be the enumeration oracle this key choice
	// exists to prevent.
	pa, pb := decodeProblem(t, a), decodeProblem(t, b)
	if pa.Code != CodeRateLimited || pb.Code != CodeRateLimited {
		t.Fatalf("over the limit: codes = %q and %q, want %q", pa.Code, pb.Code, CodeRateLimited)
	}
	pa.TraceID, pb.TraceID = "", ""
	if renderedA, renderedB := renderProblem(t, pa), renderProblem(t, pb); renderedA != renderedB {
		t.Errorf("the 429 differs between an existing and a non-existing account:\n  existing:     %s\n  non-existing: %s",
			renderedA, renderedB)
	}
}

// TestRateLimitingRefusesOverTheLimitAndLeavesUnderItUntouched is the
// red-then-green proof.
//
// A configured number is not the proof that a limiter works. This test issues
// more requests than the limit and asserts the refusal, then advances the
// clock past the window and asserts a request under it is untouched — the
// two halves together are what make the limit a fact about the code rather
// than a number in a config file.
func TestRateLimitingRefusesOverTheLimitAndLeavesUnderItUntouched(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	limiter := ratelimit.New(clk, map[string]ratelimit.Limit{
		"/v1/session": {Max: 3, Window: time.Minute},
	})
	f := newAuditFixture(t, WithRateLimiter(limiter))

	body := `{"email":"nobody@example.com","password":"not the right password"}`

	// THREE REQUESTS UNDER THE LIMIT: all 401, none refused.
	for i := 1; i <= 3; i++ {
		rec := post(t, f.handler, "/v1/session", body)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("request %d under the limit = %d, want 401; body: %s", i, rec.Code, rec.Body)
		}
	}

	// THE FOURTH IS OVER THE LIMIT: 429, with the limiter's own code and a
	// sentence that is not the lockout's.
	rec := post(t, f.handler, "/v1/session", body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request 4 over the limit = %d, want 429; body: %s", rec.Code, rec.Body)
	}
	if got := decodeProblem(t, rec).Code; got != CodeRateLimited {
		t.Errorf("request 4 over the limit: code = %q, want %q", got, CodeRateLimited)
	}

	// ADVANCE THE CLOCK PAST THE WINDOW: the next request opens a fresh
	// window and is under the limit again.
	clk.Advance(time.Minute)
	rec = post(t, f.handler, "/v1/session", body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("request after the window = %d, want 401; body: %s", rec.Code, rec.Body)
	}
}

// TestRateLimitingKeysOnTheClientAndNotTheAccount is the structural half of
// the enumeration proof.
//
// It drives the limiter directly: two different "accounts" (which the limiter
// never sees) from the same client share one bucket, and two different
// clients do not. The key is the client address and the route, so the
// limiter's state is a function of those two facts and nothing else.
func TestRateLimitingKeysOnTheClientAndNotTheAccount(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	limiter := ratelimit.New(clk, map[string]ratelimit.Limit{
		"/v1/session": {Max: 1, Window: time.Minute},
	})

	// One client, one route: the first request is allowed, the second is
	// refused. The "account" is never a parameter — Allow takes the route and
	// the client, and the two calls below differ in neither.
	if !limiter.Allow("/v1/session", "192.0.2.1") {
		t.Fatal("the first request from a client was refused; the window should have opened")
	}
	if limiter.Allow("/v1/session", "192.0.2.1") {
		t.Fatal("the second request from the same client was allowed; the limit is 1")
	}

	// A DIFFERENT client has its own bucket: the same route, a different
	// address, and the first request is allowed again.
	if !limiter.Allow("/v1/session", "192.0.2.2") {
		t.Fatal("the first request from a different client was refused; buckets are per client")
	}

	// A ROUTE WITH NO CONFIGURED LIMIT is not limited: the honest answer is
	// "allowed", because a route absent from the table is a route this
	// deployment chose not to limit.
	if !limiter.Allow("/v1/nowhere", "192.0.2.1") {
		t.Fatal("a route with no configured limit was refused; absent means allowed")
	}
}
