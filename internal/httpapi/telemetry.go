package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/trace"

	"github.com/anywaye/identity/internal/telemetry"
)

var requestSpanName = mustRequestSpanName()

func mustRequestSpanName() string {
	name, err := telemetry.SpanName("request")
	if err != nil {
		panic("httpapi: " + err.Error())
	}
	return name
}

func telemetryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := telemetry.StartServer(r.Context(), r.Header, requestSpanName)

		telemetry.Record(span, map[string]any{"http.request.method": r.Method})

		tracked := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	start := time.Now()
		defer func() {
			telemetry.Record(span, map[string]any{"http.response.status_code": tracked.status})
			RecordRequestFailure(span, tracked.status)
			telemetry.RecordRequest(r.Context(), r.Method, routeTemplate(r), tracked.status, time.Since(start))
			span.End()
		}()

		next.ServeHTTP(tracked, r.WithContext(ctx))
	})
}


type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.written {
		w.status = status
		w.written = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.written = true
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// RecordRequestFailure records the bounded error class for a failed request, and
// nothing for a successful one.
//
// THE BICONDITIONAL, and why both halves happen here. core's traces schema makes
// it a constraint in both directions: a span whose status is `error` must carry
// an `error.type`, and a span that carries one must have failed. That is what
// makes the ABSENCE of `error.type` the load-bearing "this was not an error"
// marker — on a duration histogram the samples carrying the class are the errors
// and every other sample is a success, so a success that carried one would move
// the numerator and make the error rate a number nobody can trust.
//
// So success records no class at all: not `_OTHER`, and not a class a filter has
// to special-case.
//
// WHY 4xx IS NOT HERE, and it is the more interesting half. A 401 on
// `POST /v1/session` is a wrong password and a 404 on
// `GET /v1/accounts/{accountID}` is somebody guessing an id. Both are a caller
// doing something the API answers by refusing, and both are the service working.
// A span marked ERROR for every rejected login is an error rate that is a
// function of how much credential stuffing the platform is absorbing, and an
// alert on it pages somebody to disable the protection that is doing its job.
// The fleet's error view is about the service failing, not about the service
// refusing. A 5xx is the service failing, and that is a span whose status says
// so.
//
// `internal_error` rather than a class derived from the status: the class is a
// grouping key shared with the other five services, and a class invented per
// status code is a class nobody else emits — which is how one place to see all
// errors becomes six places. The status is already on the span as
// `http.response.status_code`, so the pair says everything it can, and `_OTHER`
// is not warranted either, because an unhandled 5xx IS this class. A later
// packet that can tell a dependency failure from a handler bug narrows it
// without changing this call site.
func RecordRequestFailure(span trace.Span, status int) {
	if status < 500 {
		return
	}
	_ = telemetry.RecordFailure(span, "internal_error", "the handler returned a server error")
}

func routeTemplate(r *http.Request) string {
	routeContext := chi.RouteContext(r.Context())
	if routeContext == nil {
		return ""
	}
	return routeContext.RoutePattern()
}

func statusClass(status int) string {
	switch {
	case status >= 100 && status < 200:
		return "1xx"
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	default:
		return ""
	}
}
