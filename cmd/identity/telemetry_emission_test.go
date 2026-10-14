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

	"github.com/cafaye/identity/internal/config"
	"github.com/cafaye/identity/internal/httpapi"
)

// The end-to-end emission proof, and the test the fleet's measurement asked for.
//
// WHAT WAS ALREADY HERE, and why this file is not a duplicate of it. The span
// middleware is mounted, the allowlist is a choke point, the exporter builds an
// OTLP/HTTP client and canary_test.go sweeps every field a caller controls for
// canaries. All of that asserts about spans this service CONSTRUCTS, through a
// recorder installed in place of the exporter. Not one of those tests can fail
// because the real path — `installTelemetry` in this file's package, the function
// `run` calls before anything else — builds no provider, or builds one whose
// exporter dials nothing, or dials something that is not a collector.
//
// That gap is not hypothetical. "A service that produces no spans" and "a service
// that produces spans which arrive nowhere" are indistinguishable from a
// dashboard: both show zero. Every test above passes in a process where
// `installTelemetry` returns a shutdown that flushes an empty exporter, which is
// exactly the state the fleet measured on 2026-09-30 and could not tell from
// "identity opens no span".
//
// So this asserts the only thing that can distinguish them: bytes arriving over a
// socket at an address this process was configured with, carrying the span the
// middleware claims to open.
//
// IT IS SUBSTRING ASSERTION ON A PROTOBUF, and that is a deliberate trade rather
// than a shortcut. Decoding it properly needs `go.opentelemetry.io/proto/otlp`,
// which is in the module graph only as an indirect dependency of the exporter —
// importing it makes it a DIRECT requirement of this service, with its version and
// its CVEs, so that a test could parse a message. The bytes a span name and a
// route template are encoded into are the same bytes in the first and second case,
// so "the collector received a request whose body contains the span name and the
// route template" is a real assertion about what crossed the wire. The structured
// reading of the same bytes is what the OTel SDK's own exporter is for.

// otlpReceiver is a collector stand-in: the smallest thing that can answer the
// exporter's request, and the smallest thing that can notice being called.
type otlpReceiver struct {
	mu       sync.Mutex
	calls    []receivedExport
	server   *httptest.Server
	endpoint string
}

// receivedExport is one POST, as the receiver saw it.
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
	calls := r.exports()
	if len(calls) != 1 {
		t.Fatalf("the collector received %d exports for one request, want 1.\n\n"+
			"Zero means the service is not emitting, or is emitting somewhere nothing is "+
			"listening. More than one means telemetry is installed twice, and the second "+
			"provider's spans are a second, unreconciled copy of every request in the fleet.",
			len(calls))
	}
	return calls[0]
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

// TestARequestProducesAnExportThatCrossesTheWire is DONE MEANS 2, asserted
// end-to-end rather than against a recorder: a configured endpoint, a real
// request through the real router, and bytes at the far end of a socket.
//
// THE NUMERIC FACTS ARE NOT ASSERTED AS TEXT HERE, and dropping those two
// assertions is worth writing down. Protobuf encodes a span's `trace_id` as
// sixteen raw bytes and an int64 status code as a varint, so neither appears in
// the payload as the ASCII a reader would type. The first draft of this test
// asserted `"200"` and the caller's trace id in hex; both failed against a
// correctly working exporter, which is the shape of a test that teaches its
// author a falsehood about the wire.
//
// What IS asserted below is everything protobuf carries as a length-prefixed
// string — the span name, the route template, the resource attributes — because
// those are the facts that decide whether a span is usable in HyperDX. The
// numeric ones are asserted where they can be READ as numbers, through the
// recorder, in internal/httpapi's suite.
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

	// The span's own facts, in the bytes that crossed the socket. The span NAME is
	// what core's grammar requires and what a trace view groups by; the ROUTE
	// TEMPLATE is what makes the span usable rather than merely present.
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

	// THE ID IS SEARCHED FOR AS ITS SIXTEEN RAW BYTES, not as hex text, and that is
	// the whole substance of this assertion. Protobuf's `bytes` field carries the
	// trace id exactly as it is — 0x4b 0xf9 0x2f … — so the hexadecimal STRING the
	// caller sent is not in the payload and never was. An earlier draft of this test
	// searched for the hex and failed against a working exporter, which is a test
	// that has learned its author a falsehood about the wire rather than a test that
	// found a defect.
	//
	// So the caller continues this trace if and only if those sixteen bytes are on
	// the socket, which is the property DONE MEANS 3 asks for and the one that makes
	// a fleet's traces join up rather than arriving as one-hop fragments.
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

// TestAMalformedTraceparentOverTheWireIsStillServed is the rule that keeps
// correlation metadata from becoming a denial-of-service vector, asserted on the
// wire: a garbage header is ignored, the request is served, and the span is
// exported under a fresh trace.
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

	// Still exactly one export: the request is traced, just not under the id the
	// header asked for.
	receiver.oneExport(t)
}

// TestAServerErrorCrossesTheWireWithTheFleetsErrorClass is the last unproven half
// of DONE MEANS 2 — `error.type` in core's own vocabulary, on a span that actually
// leaves the process.
//
// The recorder suite already proves a 5xx becomes an error span carrying
// `internal_error`, but "the span carries it" and "the collector receives it" were
// different claims until the path bug, and only one of them was ever tested. So
// this drives a failing readiness probe through `httpapi.New` directly — the same
// constructor `newApp` calls, with the same middleware chain, rather than a
// hand-built one — and asserts the class is in the bytes.
//
// A readiness check that always fails is the cheapest 5xx in this service: no
// database, no fault injection, and a route that genuinely exists, so the span also
// has to carry its route template.
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

// TestTelemetryOffDialsNothing is DONE MEANS 1, and it is the one direction a
// dashboard cannot show. A service that emits nothing and a service that emits
// nothing BECAUSE IT WAS TOLD TO look identical from HyperDX, and the packet's
// requirement is specific: UNSET means a true no-op — nothing dials, nothing
// allocates.
//
// So this points the endpoint at a real, listening, counting receiver and then
// switches telemetry off, and asserts the count is still zero after a request has
// been served. A provider with an exporter that has nowhere to go still allocates a
// span per request, computes attributes nobody reads, and costs a goroutine and a
// batch timer for the life of the process; core's otel-endpoint schema pins
// `startupCost` to `none` and this is the assertion that holds this service to it.
//
// THE RECEIVER IS STILL RUNNING. The alternative — pointing the endpoint at a
// refused port and asserting no error — passes for a service that dials once and
// swallows the failure, which is the shape this is looking for.
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

// TestAPerSignalSwitchOffAlsoDialsNothing is the finer half of the kill switch,
// and it exists because the check that finds it is cheap and the one that misses
// it is somebody's invoice.
//
// All three signals are covered, not only traces: a no-op that only covers traces
// is a service that still phones home for metrics.
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

// probeOnlyConfig is the configuration a process with no DATABASE_URL runs on: the
// probes and nothing else.
//
// No pool and no /v1 routes, so the test needs no database and no migration, and
// what it exercises is the serving path itself — which is the thing under test.
// Every request below is a real request through the real router.
//
// It carries SIGNUP_SIGNING_KEY because a boot without it is a startup failure:
// the lookup answers "" for everything else, which is the "no environment" of a
// process with nothing configured.
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
