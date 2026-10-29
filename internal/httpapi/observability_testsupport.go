package httpapi

import (
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)


var (
	recorderMu sync.Mutex
	recorder   *tracetest.SpanRecorder
)

func installProviderForTest(t *testing.T, provider *sdktrace.TracerProvider) func() {
	t.Helper()
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { otel.SetTracerProvider(previous) })
	return func() { otel.SetTracerProvider(previous) }
}

func installPropagationForTest() func() {
	previous := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	return func() { otel.SetTextMapPropagator(previous) }
}

func setRecorder(r *tracetest.SpanRecorder) {
	recorderMu.Lock()
	defer recorderMu.Unlock()
	recorder = r
}

func currentRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorderMu.Lock()
	defer recorderMu.Unlock()
	if recorder == nil {
		t.Fatal("no span recorder is installed; the test must call recordingRouter first")
	}
	return recorder
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// WithPanickingRouteForTest mounts a ROUTE that panics, rather than replacing the
// router.
//
// The first version of this seam replaced the whole mux, and it was wrong in a
// way the test caught immediately: a replaced router never passes through chi, so
// the request never gets a route template, and the 500 the panic produced was
// recorded against a span with no route on it. That is a test asserting a
// half-built service — the real one has a route, and the real one is what an
// operator will be reading at 3am.
//
// Replacing a route instead keeps everything the production path does: the span
// opens outside, the template is recorded inside, the panic is recovered inside
// that, and the status is read on the way out. The only difference from
// production is which handler the route points at.
func WithPanickingRouteForTest(pattern string) Option {
	return func(o *options) {
		o.panicOnRoute = pattern
	}
}

// WithParameterizedRouteForTest mounts a route whose pattern carries a path
// parameter.
//
// It exists because of the fault injection on tracedRouter, and specifically
// because a suite of fixed requests cannot tell a route template from a concrete
// path: for `GET /healthz` they are the same string, so a service recording
// `r.URL.Path` passed every assertion in the file. A parameterised pattern is the
// only request shape on which the two differ, so it is the only one on which the
// property is testable.
//
// Registered through the traced decorator like every other route, so the test is
// asserting about the production path rather than about a special case.
func WithParameterizedRouteForTest(pattern string) Option {
	return func(o *options) {
		o.parameterizedRoute = pattern
	}
}

func spanAttributes(span sdktrace.ReadOnlySpan) map[string]string {
	attributes := make(map[string]string, len(span.Attributes()))
	for _, kv := range span.Attributes() {
		attributes[string(kv.Key)] = kv.Value.String()
	}
	return attributes
}

// renderSpans is the whole export as one string: every span's name, kind, status
// and every attribute's name and value.
//
// Rendered rather than compared key-by-key, because a key-by-key assertion only
// catches a leak through a key the test already knew to look for. This is the
// whole reason a canary test can catch a leak through an attribute nobody
// predicted.
func renderSpans(r *tracetest.SpanRecorder) string {
	var rendered strings.Builder
	// Sorted by key. A rendered export whose order varies between runs makes a
	// failure message that differs every time, and a failure message that
	// differs every time is one nobody compares against the last one.
	spans := r.Ended()
	sort.Slice(spans, func(i, j int) bool { return spans[i].Name() < spans[j].Name() })
	for _, span := range spans {
		rendered.WriteString("name=")
		rendered.WriteString(span.Name())
		rendered.WriteString(" kind=")
		rendered.WriteString(span.SpanKind().String())
		rendered.WriteString(" status=")
		rendered.WriteString(span.Status().Code.String())
		pairs := append([]attribute.KeyValue(nil), span.Attributes()...)
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].Key < pairs[j].Key })
		for _, kv := range pairs {
			rendered.WriteString(" ")
			rendered.WriteString(string(kv.Key))
			rendered.WriteString("=")
			rendered.WriteString(kv.Value.String())
		}
		rendered.WriteString("\n")
	}
	return rendered.String()
}

func hasAttribute(r *tracetest.SpanRecorder, name, value string) bool {
	for _, span := range r.Ended() {
		for _, kv := range span.Attributes() {
			if string(kv.Key) == name && kv.Value.String() == value {
				return true
			}
		}
	}
	return false
}

func itoa(v int) string { return strconv.Itoa(v) }
