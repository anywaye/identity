package main

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"

	"github.com/anywaye/identity/internal/config"
	"github.com/anywaye/identity/internal/httpapi"
)


type otlpReceiver struct {
	mu       sync.Mutex
	calls    []receivedExport
	server   *httptest.Server
	endpoint string
}

type receivedExport struct {
	method      string
	path        string
	contentType string
	body        string
}

func newOTLPReceiver(t *testing.T) *otlpReceiver {
	t.Helper()
	receiver := &otlpReceiver{}
	receiver.server = httptest.NewServer(http.HandlerFunc(receiver.handle))
	t.Cleanup(receiver.server.Close)
	receiver.endpoint = receiver.server.URL
	return receiver
}

// handle answers 200 with an empty protobuf.
//
// 200 and not 400 is load-bearing: the exporter's own error handling is the thing
// under test elsewhere, and a receiver that rejected the request would make every
// assertion below pass for the wrong reason — "no span arrived" would be true
// because "every export failed" was also true.
func (r *otlpReceiver) handle(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.calls = append(r.calls, receivedExport{
		method:      req.Method,
		path:        req.URL.Path,
		contentType: req.Header.Get("Content-Type"),
		body:        string(body),
	})
	r.mu.Unlock()

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
}

func (r *otlpReceiver) exports() []receivedExport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]receivedExport(nil), r.calls...)
}

// oneExport returns the single export the receiver was sent, failing the test on
// any other count.
//
// "Exactly one" rather than "at least one": a second export for one request means
// the exporter was built twice, which is the shape of a double Install and which a
// `>= 1` assertion would report as success.
func (r *otlpReceiver) oneExport(t *testing.T) receivedExport {
	t.Helper()
	var traces []receivedExport
	for _, c := range r.exports() {
		if c.path == "/v1/traces" {
			traces = append(traces, c)
		}
	}
	if len(traces) != 1 {
		t.Fatalf("the collector received %d trace exports for one request, want 1.\n\n"+
			"Zero means the service is not emitting, or is emitting somewhere nothing is "+
			"listening. More than one means telemetry is installed twice, and the second "+
			"provider's spans are a second, unreconciled copy of every request in the fleet.",
			len(traces))
	}
	return traces[0]
}

// installForTest runs the production install and returns the flush `run` defers.
//
// IT RETURNS THE FLUSH RATHER THAN DEFERRING IT, and that is the whole difference
// between this file proving anything and proving nothing. The SDK's span processor
// is a BATCH processor — kit's pins.md requires it, because one export per span
// makes the collector the bottleneck — and a batch processor exports on a timer or
// on shutdown, not when a span ends.
//
// So a test that serves a request and immediately reads the receiver sees nothing,
// and every assertion below would pass for the wrong reason: zero exports is what
// an UNFLUSHED batch processor looks like whether telemetry is on or off. The first
// draft of this file had exactly that bug, and it is worth writing down because it
// fails in the SAFE direction twice over — the "emits" tests went red and looked
// like a service defect, and the "dials nothing" tests went GREEN and were
// asserting nothing at all.
//
// Every test below therefore flushes before it reads, which makes the no-op tests
// meaningful: they are now the negative control on the positive one. If the kill
// switch stopped working, the tests that want an export would still pass and
// TestTelemetryOffDialsNothing would go red, which is the only arrangement in which
// either result says anything.
//
// The environment is set rather than the Options struct filled in, because
// `installTelemetry` reads the environment and a test that passed it a struct
// literal would assert about a wiring no process ever uses.
func installForTest(t *testing.T) func() {
	t.Helper()

	previous := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(previous) })

	shutdown, err := installTelemetry(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("installTelemetry() error = %v", err)
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			if err := shutdown(context.Background()); err != nil {
				t.Errorf("flushing telemetry: %v", err)
			}
		})
	}
}

func TestARequestProducesAnExportThatCrossesTheWire(t *testing.T) {
	receiver := newOTLPReceiver(t)
	t.Setenv("IDENTITY_OTEL_ENDPOINT", receiver.endpoint)
	t.Setenv("OTEL_SERVICE_VERSION", "0.1.0-test")
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "test")
	flush := installForTest(t)

	a := newDiscardApp(t, probeOnlyConfig())
	rec := httptest.NewRecorder()
	a.srv.Handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", rec.Code)
	}
	flush()

	export := receiver.oneExport(t)

	if export.method != http.MethodPost {
		t.Errorf("the collector was called with %s, want POST. The fleet's receiver is an "+
			"OTLP/HTTP endpoint and a GET is a receiver that will never receive anything.",
			export.method)
	}
	if export.path != "/v1/traces" {
		t.Errorf("the collector was called on %q, want /v1/traces. An export that arrived "+
			"anywhere else arrived nowhere, and a span is not a span until the collector "+
			"has it.", export.path)
	}
	if export.contentType != "application/x-protobuf" {
		t.Errorf("Content-Type = %q, want application/x-protobuf", export.contentType)
	}

	for _, want := range []struct{ what, needle string }{
		{"the span name", "identity.request"},
		{"the route template", "/healthz"},
		{"service.name", "identity"},
		{"deployment.environment", "test"},
	} {
		if !strings.Contains(export.body, want.needle) {
			t.Errorf("the exported bytes carry no %s: %q is not in the body the collector "+
				"received.\n\nA span that arrives with no name has nothing to group by and a "+
				"span that arrives with no resource has no service on it, which in a fleet "+
				"view is a span under no service at all.", want.what, want.needle)
		}
	}
}

// TestATraceparentArrivingOverTheWireIsContinued is the same proof for the
// propagation half, and it is here rather than in internal/httpapi for one reason:
// the tests there prove a RECORDER saw a continued trace id, and this proves the
// bytes on the socket carry the caller's trace.
//
// ONE request goes out carrying a traceparent, and the export must name the
// caller's trace. If the middleware were not extracting, the export would carry a
// freshly generated id and every fleet dashboard would show one-hop traces.
func TestATraceparentArrivingOverTheWireIsContinued(t *testing.T) {
	receiver := newOTLPReceiver(t)
	t.Setenv("IDENTITY_OTEL_ENDPOINT", receiver.endpoint)
	flush := installForTest(t)

	const callersTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	req.Header.Set("traceparent", "00-"+callersTrace+"-00f067aa0ba902b7-01")
	newDiscardApp(t, probeOnlyConfig()).srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", rec.Code)
	}
	flush()

	export := receiver.oneExport(t)
	raw, err := hex.DecodeString(callersTrace)
	if err != nil {
		t.Fatalf("the test's own trace id %q is not hex: %v", callersTrace, err)
	}
	if !strings.Contains(export.body, string(raw)) {
		t.Errorf("the exported bytes do not carry the caller's trace id %s.\n\nA span that "+
			"does not continue its caller's context is a one-hop trace, and four thousand "+
			"one-hop traces are harder to debug than no traces at all.", callersTrace)
	}
}

func TestAMalformedTraceparentOverTheWireIsStillServed(t *testing.T) {
	receiver := newOTLPReceiver(t)
	t.Setenv("IDENTITY_OTEL_ENDPOINT", receiver.endpoint)
	flush := installForTest(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	req.Header.Set("traceparent", "definitely-not-a-traceparent")
	newDiscardApp(t, probeOnlyConfig()).srv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("a malformed traceparent produced %d. Refusing a request because its "+
			"correlation header is untidy is a denial-of-service vector aimed at the "+
			"service's own probe.", rec.Code)
	}
	flush()

	receiver.oneExport(t)
}

func TestAServerErrorCrossesTheWireWithTheFleetsErrorClass(t *testing.T) {
	receiver := newOTLPReceiver(t)
	t.Setenv("IDENTITY_OTEL_ENDPOINT", receiver.endpoint)
	flush := installForTest(t)

	failing := httpapi.Check{
		Name: "always_fails",
		Ping: func(context.Context) error { return errors.New("the dependency is down") },
	}
	handler := httpapi.New([]httpapi.Check{failing}, httpapi.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz = %d, want 503. A readiness probe whose dependency fails "+
			"has to answer 503, or there is nothing here to record.", rec.Code)
	}
	flush()

	export := receiver.oneExport(t)
	for _, want := range []struct{ what, needle string }{
		{"the route template", "/readyz"},
		{"the error class", "internal_error"},
		{"the error attribute name", "error.type"},
	} {
		if !strings.Contains(export.body, want.needle) {
			t.Errorf("the exported bytes carry no %s: %q is not in the body.\n\n"+
				"A 5xx that reaches the collector with no error class is a request an "+
				"operator can see failed and cannot search for by cause, and "+
				"`internal_error` is core's own vocabulary rather than one invented here.",
				want.what, want.needle)
		}
	}
}

func TestTelemetryOffDialsNothing(t *testing.T) {
	receiver := newOTLPReceiver(t)
	t.Setenv("IDENTITY_OTEL_ENDPOINT", receiver.endpoint)
	t.Setenv("OTEL_SDK_DISABLED", "true")
	flush := installForTest(t)

	a := newDiscardApp(t, probeOnlyConfig())
	rec := httptest.NewRecorder()
	a.srv.Handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200. A service that is not exporting telemetry "+
			"is still a service.", rec.Code)
	}
	flush()

	if calls := receiver.exports(); len(calls) != 0 {
		t.Errorf("the collector received %d exports while OTEL_SDK_DISABLED=true, want 0.\n\n"+
			"The no-op is supposed to cost nothing and reach nothing, and this one reaches "+
			"the wire. A switch that does not switch is worse than no switch, because an "+
			"operator who turned it off would be told they had.", len(calls))
	}
}

func TestAPerSignalSwitchOffAlsoDialsNothing(t *testing.T) {
	for _, variable := range []string{"OTEL_TRACES_EXPORTER", "OTEL_METRICS_EXPORTER", "OTEL_LOGS_EXPORTER"} {
		t.Run(variable, func(t *testing.T) {
			receiver := newOTLPReceiver(t)
			t.Setenv("IDENTITY_OTEL_ENDPOINT", receiver.endpoint)
			t.Setenv(variable, "none")
			flush := installForTest(t)

			a := newDiscardApp(t, probeOnlyConfig())
			rec := httptest.NewRecorder()
			a.srv.Handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("GET /healthz = %d, want 200", rec.Code)
			}
			flush()

			if calls := receiver.exports(); len(calls) != 0 {
				t.Errorf("%s=none and the collector still received %d exports. core's "+
					"otel-endpoint schema requires every listed signal to be covered by the "+
					"no-op, because a service that still phones home for a signal it was told "+
					"to stop exporting is discovered by a customer's invoice.", variable, len(calls))
			}
		})
	}
}

func probeOnlyConfig() config.Config {
	const signupKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"
	cfg, err := config.Load(func(key string) (string, bool) {
		if key == "SIGNUP_SIGNING_KEY" {
			return signupKey, true
		}
		return "", false
	})
	if err != nil {
		panic("probeOnlyConfig: " + err.Error())
	}
	return cfg
}
