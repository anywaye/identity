package httpapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/ratelimit"
)


func TestRateLimitingDoesNotBecomeAnEnumerationOracle(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	limiter := ratelimit.New(clk, map[string]ratelimit.Limit{
		"/v1/session": {Max: 2, Window: time.Minute},
	})
	f := newAuditFixture(t, WithRateLimiter(limiter))

	existing := dbtest.UniqueEmail(t)
	registerThrough(t, f.handler, existing)
	nonExisting := dbtest.UniqueEmail(t)

	for _, email := range []string{existing, nonExisting} {
		rec := post(t, f.handler, "/v1/session", `{"email":"`+email+`","password":"not the right password"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("login for %s under the limit = %d, want 401; body: %s", email, rec.Code, rec.Body)
		}
	}

	a := post(t, f.handler, "/v1/session", `{"email":"`+existing+`","password":"not the right password"}`)
	b := post(t, f.handler, "/v1/session", `{"email":"`+nonExisting+`","password":"not the right password"}`)
	if a.Code != http.StatusTooManyRequests {
		t.Fatalf("login for the existing address over the limit = %d, want 429; body: %s", a.Code, a.Body)
	}
	if b.Code != http.StatusTooManyRequests {
		t.Fatalf("login for the non-existing address over the limit = %d, want 429; body: %s", b.Code, b.Body)
	}

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

func TestRateLimitingRefusesOverTheLimitAndLeavesUnderItUntouched(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	limiter := ratelimit.New(clk, map[string]ratelimit.Limit{
		"/v1/session": {Max: 3, Window: time.Minute},
	})
	f := newAuditFixture(t, WithRateLimiter(limiter))

	body := `{"email":"nobody@example.com","password":"not the right password"}`

	for i := 1; i <= 3; i++ {
		rec := post(t, f.handler, "/v1/session", body)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("request %d under the limit = %d, want 401; body: %s", i, rec.Code, rec.Body)
		}
	}

	rec := post(t, f.handler, "/v1/session", body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request 4 over the limit = %d, want 429; body: %s", rec.Code, rec.Body)
	}
	if got := decodeProblem(t, rec).Code; got != CodeRateLimited {
		t.Errorf("request 4 over the limit: code = %q, want %q", got, CodeRateLimited)
	}

	clk.Advance(time.Minute)
	rec = post(t, f.handler, "/v1/session", body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("request after the window = %d, want 401; body: %s", rec.Code, rec.Body)
	}
}

func TestRateLimitingKeysOnTheClientAndNotTheAccount(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	limiter := ratelimit.New(clk, map[string]ratelimit.Limit{
		"/v1/session": {Max: 1, Window: time.Minute},
	})

	if !limiter.Allow("/v1/session", "192.0.2.1") {
		t.Fatal("the first request from a client was refused; the window should have opened")
	}
	if limiter.Allow("/v1/session", "192.0.2.1") {
		t.Fatal("the second request from the same client was allowed; the limit is 1")
	}

	if !limiter.Allow("/v1/session", "192.0.2.2") {
		t.Fatal("the first request from a different client was refused; buckets are per client")
	}

	if !limiter.Allow("/v1/nowhere", "192.0.2.1") {
		t.Fatal("a route with no configured limit was refused; absent means allowed")
	}
}
