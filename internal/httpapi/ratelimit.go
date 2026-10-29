package httpapi

import (
	"bytes"
	"net/http"
)

type responseRecorder struct {
	http.ResponseWriter
	status int
	header http.Header
	body   bytes.Buffer
}

func (r *responseRecorder) Header() http.Header { return r.header }

func (r *responseRecorder) WriteHeader(status int) { r.status = status }

func (r *responseRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }

func (r *responseRecorder) flush() {
	for k, vs := range r.header {
		for _, v := range vs {
			r.ResponseWriter.Header().Add(k, v)
		}
	}
	r.ResponseWriter.WriteHeader(r.status)
	_, _ = r.ResponseWriter.Write(r.body.Bytes())
}

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

func clientKey(r *http.Request) string {
	addr := remoteIP(r)
	if addr == nil {
		return "unknown"
	}
	return addr.String()
}
