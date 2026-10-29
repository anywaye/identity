package ratelimit

import (
	"sync"
	"time"

	"github.com/anywaye/identity/internal/platform/clock"
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
		return true
	}

	now := l.clk.Now()
	key := route + "\x00" + client

	b, ok := l.buckets[key]
	if !ok || !now.Before(b.end) {
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
