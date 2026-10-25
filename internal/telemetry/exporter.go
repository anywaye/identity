package telemetry

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
)

// OTLPExporter is the production Exporter: OTLP over HTTP.
//
// HTTP rather than gRPC, and the reason is that it is the address the fleet
// already agrees on. `<SERVICE>_OTEL_ENDPOINT` defaults to
// `http://otel-collector:4318`, which is the collector's HTTP receiver, and the
// Elixir and Python SDKs this fleet ships both speak OTLP/HTTP. One port, one
// ingestion point, three languages.
//
// WHAT THIS DOES NOT BUY, recorded because a reader would otherwise assume it
// does: it is NOT a way to keep gRPC out of the binary. The HTTP exporter shares
// its configuration package with the gRPC one —
//
//	$ go mod why -m google.golang.org/grpc
//	github.com/anywaye/identity/internal/telemetry
//	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp
//	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp/internal/otlpconfig
//	google.golang.org/grpc
//
// — so `grpc`, `grpc-gateway`, `genproto` and `protobuf` are in the module graph
// either way. The choice is about which port and which wire format, not about
// the dependency count. Measured on this tree rather than assumed; the obvious
// justification was available and would have been wrong.
//
// The endpoint is normalised rather than trusted. `otlptracehttp.WithEndpointURL`
// wants a URL, and every spelling of "where does telemetry go" that an operator
// will actually type is not one: a bare `host:port`, a trailing slash, a path.
// Refusing to start on a shape nobody could have meant is better than exporting
// nowhere with a log line naming a URL that parsed.
func OTLPExporter(ctx context.Context, endpoint string) (Exporter, error) {
	target, err := normaliseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	// No retry and no queue, for the reason kit's collector config states and
	// this repository holds to: a retry loop against a dead collector is a
	// goroutine waking on a timer for the life of the process, invisible in
	// every dashboard because nothing is being recorded, and a queue that
	// accepts spans and holds them is a memory leak with a telemetry-shaped
	// trigger. Losing a span is strictly better than becoming a slow service.
	//
	// The SDK's defaults are `retry_on_failure: enabled` and
	// `sending_queue: enabled`, so BOTH are stated as disabled rather than left
	// to a default that is the opposite of the fleet's rule.
	return otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(target),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}),
		// A bounded export, for the same reason the queue and the retry are off:
		// the collector is a local process on the compose network, and a slow
		// export is a latency bug in development caused by an observability tool.
		otlptracehttp.WithTimeout(5*time.Second),
	)
}

// normaliseEndpoint turns the shapes an operator writes into the one shape the
// exporter takes.
//
// A bare `host:port` is the most likely thing to be typed and the most likely to
// be rejected by a URL parser, because `otel-collector:4318` parses as a scheme
// of `otel-collector` and a path of `4318`. Prefixing a schemeless endpoint with
// `http://` is what makes the documented default work, and it is the difference
// between a service that exports by default and one that fails to boot by
// default.
func normaliseEndpoint(endpoint string) (string, error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return "", fmt.Errorf("telemetry: the OTLP endpoint is empty")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("telemetry: %q is not a usable OTLP endpoint: %w", endpoint, err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("telemetry: %q has no host", endpoint)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("telemetry: %q has scheme %q; an OTLP endpoint is http or https", endpoint, parsed.Scheme)
	}
	// A trailing slash on the path is the difference between a request for `/` and
	// a request for `//v1/traces` once the exporter appends its own path.
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")

	// APPEND THE SIGNAL PATH, and this is a defect that was MEASURED rather than
	// anticipated — it is the whole of why the fleet found this service emitting
	// nothing on 2026-09-30 while every span test in the repository was green.
	//
	// `otlptracehttp.WithEndpointURL` does NOT do this. Its documentation says the
	// default path is not appended, and the SDK carries a test named
	// `TestWithEndpointURLNoPathUsesRootPath` asserting that a pathless endpoint
	// normalises to `/`. That is a defensible reading of "endpoint URL" as a
	// complete address, and it is the wrong reading of what `<SERVICE>_OTEL_ENDPOINT`
	// MEANS in this fleet.
	//
	// The fleet's default is `http://otel-collector:4318` — scheme, host and port,
	// no path — and the collector's OTLP receiver serves `/v1/traces`. So every
	// export went to `http://otel-collector:4318/`, which that receiver answers with
	// 404, and the SDK — with retry disabled and the queue off, both deliberate —
	// dropped every span it had tried to send. The service was constructing spans,
	// building a valid exporter, reaching the collector's port, and recording
	// nothing anywhere. From HyperDX the two states are identical: no data.
	//
	// WHY NOTHING CAUGHT IT, and the reason matters more than the fix. Every
	// observability test in `internal/telemetry` and `internal/httpapi` asserts
	// against a `tracetest.SpanRecorder` — a recorder installed IN PLACE OF the
	// exporter, which never builds a client and never sends a byte. A suite that
	// cannot see the wire cannot see a request to the wrong URL. The collector
	// stand-in in cmd/identity/telemetry_emission_test.go is the first thing in
	// this repository that looks at where the bytes went, and it failed on this
	// line.
	//
	// THE APPEND LIVES HERE, IN NORMALISATION, rather than in a switch to
	// `WithEndpoint(host, port)` plus `WithURLPath`. `path.Join` below is the
	// SDK's own rule — its env-config reader uses exactly
	// `path.Join(u.Path, DefaultTracesPath)` for the environment-variable path — so
	// a self-hoster pointing at `https://otlp.example.com/anywaye` gets
	// `/anywaye/v1/traces`, precisely as they would have from the SDK's own
	// configuration. One implementation of that rule, in the place that already
	// normalises every other spelling.
	//
	// AN OPERATOR WHO NAMED THE SIGNAL PATH IS LEFT ALONE. `otel-collector:4318/v1/traces`
	// is an address somebody chose, and a normalisation layer that appended to it
	// would be the layer making that choice for them.
	if !strings.HasSuffix(parsed.Path, tracesPathSuffix) {
		parsed.Path = path.Join(parsed.Path, defaultTracesPath)
	}
	return parsed.String(), nil
}

// defaultTracesPath and tracesPathSuffix are the OTLP/HTTP traces path, spelled
// once.
//
// The suffix check exists so the append is IDEMPOTENT: an endpoint that already
// names `/v1/traces` must not become `/v1/traces/v1/traces` on a restart with a
// doubled value, and normaliseEndpoint is called once per boot but is also the
// function a reader will call twice while working out what an operator's variable
// means. The SDK's `path.Join` cleans the path but does not know that
// `/v1/traces/v1/traces` was not intended.
const (
	defaultTracesPath = "/v1/traces"
	tracesPathSuffix  = "/v1/traces"
)

// compile-time proof that the OTLP exporter satisfies the seam Install takes, so
// a signature change in the SDK is caught here rather than at the first boot of
// a deployment.
var _ Exporter = (*otlptrace.Exporter)(nil)


// OTLPMetricExporter builds an OTLP/HTTP metric exporter for the given endpoint.
func OTLPMetricExporter(ctx context.Context, endpoint string) (*otlpmetrichttp.Exporter, error) {
	target, err := normaliseMetricEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	return otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpointURL(target))
}

func normaliseMetricEndpoint(endpoint string) (string, error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return "", fmt.Errorf("telemetry: the OTLP endpoint is empty")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("telemetry: %q is not a usable OTLP endpoint: %w", endpoint, err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("telemetry: %q has no host", endpoint)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("telemetry: %q has scheme %q; an OTLP endpoint is http or https", endpoint, parsed.Scheme)
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	if !strings.HasSuffix(parsed.Path, "/v1/metrics") {
		parsed.Path = path.Join(parsed.Path, "/v1/metrics")
	}
	return parsed.String(), nil
}
