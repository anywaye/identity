package httpapi

import (
	"bytes"
	"net/http"
)

// responseRecorder buffers a handler's response so the rate limiter can
// refuse AFTER the handler has run.
//
// # WHY THE REFUSAL COMES AFTER THE HANDLER, AND THAT IS THE SECURITY PROPERTY
//
// A limiter that refused BEFORE the handler would reintroduce the timing
// signal Login's dummy hash equalizes (internal/auth/service.go:594-599): a
// refused request would return in microseconds while an allowed one pays the
// memory-hard cost, and the difference would be observable by a client
// measuring response times. So the handler always runs — the memory-hard
// work happens, the side effects happen — and the limiter decides after the
// fact whether to replace the response with a 429.
//
// The cost is that a refused request still does the work: a signup creates
// a row, a recovery sends a mail. That is accepted because the limit is a
// bound on SUSTAINED abuse, not a guarantee against a single burst, and the
// alternative — a limiter that short-circuits before the work — is a
// timing oracle. The key is the client address and the route, never the
// account, so the 429 itself discloses nothing about whether any account
// exists; see rateLimit below.
type responseRecorder struct {
	http.ResponseWriter
	status int
	header http.Header
	body   bytes.Buffer
}

func (r *responseRecorder) Header() http.Header { return r.header }

func (r *responseRecorder) WriteHeader(status int) { r.status = status }

func (r *responseRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }

// flush writes the buffered response to the underlying writer.
//
// It is called only when the limiter allows the request. When the limiter
// refuses, the buffered response — including any Set-Cookie header the
// handler set — is discarded and the client sees only the 429.
func (r *responseRecorder) flush() {
	for k, vs := range r.header {
		for _, v := range vs {
			r.ResponseWriter.Header().Add(k, v)
		}
	}
	r.ResponseWriter.WriteHeader(r.status)
	r.ResponseWriter.Write(r.body.Bytes())
}

// rateLimit wraps next with the request-rate limiter for one route.
//
// # THE KEY IS THE CLIENT AND THE ROUTE, NEVER THE ACCOUNT
//
// A limiter keyed on the address being ATTEMPTED is an enumeration oracle: a
// 429 that arrives for one attempted address and not another tells a stranger
// which addresses are worth trying. So the key is the client's source address
// and the route PATTERN — two facts that say nothing about whether any
// account exists. The refusal is identical for every account, existing or
// not, and the enumeration suite in anonymous_enumeration_test.go proves it
// rather than assuming it.
func (o options) rateLimit(route string, next http.HandlerFunc) http.HandlerFunc {
	if o.rateLimiter == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &responseRecorder{ResponseWriter: w, header: make(http.Header), status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if !o.rateLimiter.Allow(route, clientKey(r)) {
			problemFor(w, r, http.StatusTooManyRequests, CodeRateLimited,
				"too many requests; slow down and try again later")
			return
		}
		rec.flush()
	}
}

// clientKey is the limiter's half of the key: the client's source address.
//
// An unparseable address is "unknown" rather than an error, for the reason
// remoteIP gives: failing a request over a malformed address would be a
// denial of service anybody could trigger.
func clientKey(r *http.Request) string {
	addr := remoteIP(r)
	if addr == nil {
		return "unknown"
	}
	return addr.String()
}
