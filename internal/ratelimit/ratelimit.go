// Package ratelimit is the in-process request-rate limiter for the
// unauthenticated auth surface.
//
// # WHY THIS PACKAGE EXISTS, AND WHY IT IS IN-PROCESS
//
// identity rate-limits nothing on its auth surface: signup, signin, the signup
// timestamp mint and the two recovery request routes answer every request a
// stranger sends, and the only defenses are per-account (the login lockout),
// per-address (the recovery cooldown, which is not a rate limiter), and
// bot-shaped (the honeypot and the signed timestamp). None of them bounds what
// one client address can do. A spray of one password across many addresses, a
// loop that triggers signup mail, a hammer of the recovery routes — all of it
// is unbounded, and for a product being sold on its auth that is a launch
// blocker.
//
// The store is in-process for launch. One replica is what the launch has, and
// an in-process counter has no fail-open question: there is no shared store to
// lose, no Redis to fall over, no cluster to keep in step. What a shared store
// would need later is recorded in the packet report, not built now — the
// failure mode of building it early is a limiter that is wrong in a way tests
// cannot see, protecting nothing while looking finished.
//
// # THE KEY IS THE CLIENT AND THE ROUTE, NEVER THE ACCOUNT
//
// A limiter keyed on the address being ATTEMPTED is an enumeration oracle: a
// 429 that arrives for one address and not another tells a stranger which
// addresses are worth trying. So the key is the client address and the route
// pattern — two facts that say nothing about whether any account exists. The
// refusal is identical for every account, existing or not, and
// internal/httpapi's enumeration suite proves it rather than assuming it.
//
// # A FIXED WINDOW, AND WHAT THAT COSTS
//
// The window is fixed, not sliding or token-bucket: a bucket per key, reset
// when its instant arrives. The cost is the boundary burst — a client can send
// twice the limit across a window boundary — and it is accepted because the
// alternative is a more complex state machine for a launch whose traffic does
// not reward the sophistication. The limit is a bound on sustained abuse, not
// a guarantee against a single burst.
package ratelimit

import (
	"sync"
	"time"

	"github.com/cafaye/identity/internal/platform/clock"
)

// Limit is one route's limit: Max requests per Window.
//
// Max is a count and not a rate, because a rate needs a window to mean
// anything and the window is the limiter's to keep. A deployment that wants
// "ten a minute" sets Max=10 and Window=time.Minute; the two variables are
// the operator's to tune per route.
type Limit struct {
	Max    int
	Window time.Duration
}

// maxBuckets bounds the bucket table's growth.
//
// The table is keyed by route and client, so it grows with the number of
// distinct client addresses the service sees. That is bounded by reality for a
// launch-scale deployment, but an attacker who can rotate source addresses can
// grow it without sending a single limited request, and a map that only grows
// is a memory-exhaustion vector on the one service that must not be exhausted.
// So when the table passes this size the expired buckets are swept, which
// bounds the memory at the cost of occasionally resetting a window that had
// already reset on its own.
const maxBuckets = 4096

// Limiter counts requests per route per client in a fixed window.
//
// It is safe for concurrent use. The zero value is not; build one with New.
type Limiter struct {
	mu      sync.Mutex
	clk     clock.Clock
	limits  map[string]Limit
	buckets map[string]*bucket
}

// bucket is one key's window: how many requests it has seen and when the
// window ends.
type bucket struct {
	count int
	end   time.Time
}

// New builds a limiter over the given per-route limits.
//
// limits is keyed by the route PATTERN (the chi template, e.g. "/v1/session"),
// never by a concrete path: a pattern has one value per endpoint and a path
// has one per request, and a bucket table keyed on paths would grow with every
// request a client makes. A route absent from the map is not limited, which is
// how a deployment opts a route out without the limiter having to know why.
func New(clk clock.Clock, limits map[string]Limit) *Limiter {
	return &Limiter{
		clk:     clk,
		limits:  limits,
		buckets: make(map[string]*bucket),
	}
}

// Allow reports whether a request for route from client is within the limit,
// and counts it toward the current window.
//
// The count happens only when the request is allowed, so a refused request
// does not extend the window it was refused by — a client that is over the
// limit is not punished for the attempts it made to get there. The first
// request in a window always succeeds and opens the window; the Max-th
// succeeds and fills it; the (Max+1)-th is refused.
func (l *Limiter) Allow(route, client string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	limit, ok := l.limits[route]
	if !ok {
		// No limit configured for this route. The honest answer is "allowed":
		// a route absent from the table is a route this deployment chose not
		// to limit, and inventing a limit here would be a second answer to a
		// question the operator already answered.
		return true
	}

	now := l.clk.Now()
	key := route + "\x00" + client

	b, ok := l.buckets[key]
	if !ok || !now.Before(b.end) {
		// No bucket, or the window has ended: open a fresh one. This request
		// is the first in it, so it counts and is allowed.
		l.buckets[key] = &bucket{count: 1, end: now.Add(limit.Window)}
		l.sweep(now)
		return true
	}

	if b.count >= limit.Max {
		return false
	}
	b.count++
	return true
}

// sweep deletes the buckets whose window has ended.
//
// It runs when a window opens and the table is past maxBuckets, which is the
// only time the cost is bounded: a table under the threshold is left alone,
// because sweeping it on every request would make every request O(n) in the
// number of clients for a cleanup that reality performs on its own.
func (l *Limiter) sweep(now time.Time) {
	if len(l.buckets) <= maxBuckets {
		return
	}
	for key, b := range l.buckets {
		if !now.Before(b.end) {
			delete(l.buckets, key)
		}
	}
}
