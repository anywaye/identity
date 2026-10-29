package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// ServiceName is the emitting service. It is the one value in this file that
// cannot be a default, because it is the prefix every span name carries and the
// label every fleet query partitions by.
const ServiceName = "identity"

// Namespace is what this service groups under in a backend.
const Namespace = "anywaye"

// SpanNamePrefix is the mandatory first segment of every span this package
// names. core's span-naming schema requires the emitting service to be the
// prefix, so a span aggregates fleet-wide without a join.
const SpanNamePrefix = ServiceName

const defaultEndpoint = "http://otel-collector:4318"

// DefaultEndpoint is the address used when `<SERVICE>_OTEL_ENDPOINT` is unset.
// Exported so the compose file and the tests can name one value rather than two.
const DefaultEndpoint = defaultEndpoint

// EndpointVariable is the only contract between identity and an observability
// backend. Set it and telemetry goes there; unset it and nothing is dialed.
const EndpointVariable = "IDENTITY_OTEL_ENDPOINT"

// TenantVariable names the deployment's tenant, which goes on the RESOURCE and
// never on a measurement. See Resource for why that distinction is load-bearing.
const TenantVariable = "IDENTITY_TENANT_ID"

// MaxRouteLength is the longest `http.route` template that may be recorded, and
// it is core's own bound.
//
// There is deliberately no general MaxAttributeLength in this file, and its
// absence is worth stating because an earlier draft had one at 256 and it was
// DEAD CODE. Every allowlisted attribute is already bounded by something tighter:
// the method and the database and the error class are closed enums, the status is
// an integer in a range, and the route template is this. A 256-character ceiling
// on top of a 200-character pattern can never fire, and a truncation branch with
// no test that can reach it is a branch nobody has verified — which is worse than
// no branch, because it reads as a control.
//
// So the bounds are per-attribute, they are the ones core's schema states, and
// each is asserted in telemetry_test.go against a value that exceeds it. A value
// outside its bound is DROPPED, not shortened: a truncated route is a route
// template that matches no real endpoint, and a metric label that reads as
// "no traffic" when it really means "your filter ran first".
const MaxRouteLength = 200

// AllowedSpanAttributes is the complete set of attribute names a anywaye span may
// carry, projected from core's `traces.schema.json`.
//
// Read this list as the security control it is. Every name is a fact about HOW a
// request was served — which method, which route template, which status, which
// class of failure — and none of them is a fact about WHAT the caller said. The
// names are the OpenTelemetry semantic conventions' own, dotted, so a span
// exported to a backend nobody at anywaye has heard of is still readable.
//
// What is absent is the interesting part:
//
//   - `url.path` / `url.full` / `url.query`. A query string is caller text by
//     another name. The route TEMPLATE is the bounded stand-in.
//   - `user.id` / `user.email` / `enduser.id`. The service that mints
//     credentials is the last place to publish them into a searchable store.
//   - `error.message` / `exception.message` / `exception.stacktrace`. Unbounded
//     text, and a stack trace is a path straight to whatever was on the stack.
//   - `http.request.header.*`. A header is a credential in most services. This
//     is one of them: `Authorization` and `Cookie` are the whole of what a
//     caller authenticates with.
var AllowedSpanAttributes = []string{
	"http.request.method",
	"http.response.status_code",
	"http.route",
	"error.type",
	"otel.status_code",
	"db.system",
}

var allowedSpanAttributes = func() map[string]struct{} {
	set := make(map[string]struct{}, len(AllowedSpanAttributes))
	for _, name := range AllowedSpanAttributes {
		set[name] = struct{}{}
	}
	return set
}()

// ErrorTypes is core's closed error-class vocabulary, byte-identical to the
// `enum` in `traces.schema.json` and `metrics.schema.json`.
//
// A class is a GROUPING KEY, and that is why the set is closed rather than a
// pattern. A pattern bounds the SHAPE of a value and not the set of values, so
// `user_42_email_invalid` would validate — snake_case, twenty-two characters,
// and one series per value, which on the metric side is a user id on a
// measurement wearing a different name.
//
// `_OTHER` is the only member outside the snake_case shape and it is the OTel
// well-known fallback. It exists so instrumentation is never FORCED to invent a
// class: a closed enum with no escape hatch gets widened under pressure the
// first time a real failure does not fit, and a widened enum is how `_OTHER`
// becomes a permanent value nobody reads. An alert on `_OTHER` is an alert that
// this service has not classified its own errors.
//
// A class outside this set is refused by RecordFailure and collapses to
// `_OTHER`, rather than being trusted: an invalid one would be dropped by the
// collector anyway, and a silently-missing drill-down is worse than a loud one.
var ErrorTypes = []string{
	"_OTHER",
	// Core's spelling, not a typo: traces.schema.json's closed error.type enum
	// mandates it byte-identical on all three signals, and
	// TestTheErrorVocabularyIsCoreExactly fails on anything else.
	"cancelled", //nolint:misspell
	"circuit_open",
	"conflict",
	"connection_failed",
	"dependency_unavailable",
	"internal_error",
	"invalid_request",
	"policy_denied",
	"provider_auth",
	"provider_rejected",
	"rate_limited",
	"timeout",
}

var errorTypes = func() map[string]struct{} {
	set := make(map[string]struct{}, len(ErrorTypes))
	for _, name := range ErrorTypes {
		set[name] = struct{}{}
	}
	return set
}()

var spanNameSegment = `[a-z][a-z0-9]{0,14}(?:_[a-z0-9]{0,14}){0,2}`

var spanNameSegmentAnchored = regexp.MustCompile(`^` + spanNameSegment + `$`)

var spanName = regexp.MustCompile(`^` + SpanNamePrefix + `(?:\.` + spanNameSegment + `){1,3}$`)

var routeTemplate = regexp.MustCompile(
	fmt.Sprintf(`^/[A-Za-z0-9/_{}.:-]{0,%d}$`, MaxRouteLength-1),
)

var httpMethods = map[string]struct{}{
	"GET": {}, "POST": {}, "PUT": {}, "PATCH": {},
	"DELETE": {}, "HEAD": {}, "OPTIONS": {}, "TRACE": {},
}

var databases = map[string]struct{}{
	"postgresql": {}, "redis": {}, "sqlite": {}, "other": {},
}

// AllowedStatusCode reports whether a status code is one core's schema accepts.
// The schema bounds it to 100..599, and a code outside that range is not a fact
// about an HTTP response — it is a value a handler invented.
func AllowedStatusCode(code int) bool { return code >= 100 && code <= 599 }

// SpanName builds a span name from the service name and one or more operation
// segments, and refuses anything that is not the fleet's grammar.
//
// It returns an error rather than coercing, because the two failure modes are
// different and an operator needs to be able to tell them apart. A name that
// does not match is a CALL SITE that is trying to put a value where an operation
// belongs, and that is a bug worth a loud failure in a test rather than a span
// silently renamed to something an operator can no longer group by.
//
// Every call in this repository passes compile-time constants, so the error is
// unreachable at runtime; the signature exists so that a future call site with a
// computed segment is caught by the compiler's callers and by a test, not by a
// dashboard coming back empty.
func SpanName(operation ...string) (string, error) {
	if len(operation) == 0 || len(operation) > 3 {
		return "", fmt.Errorf("telemetry: a span name carries one to three operation segments, got %d", len(operation))
	}
	for _, segment := range operation {
		if !spanNameSegmentAnchored.MatchString(segment) {
			return "", fmt.Errorf("telemetry: %q is not a span-name segment: lowercase snake_case, at most 15 characters per part", segment)
		}
	}
	name := SpanNamePrefix
	for _, segment := range operation {
		name += "." + segment
	}
	if !spanName.MatchString(name) {
		return "", fmt.Errorf("telemetry: %q does not match the fleet's span-name grammar", name)
	}
	return name, nil
}

// MustSpanName is SpanName for the case the caller cannot do anything about a
// failure, which is a constant operation name. It panics on a constant that does
// not match, which is a programming error and is caught by
// TestSpanNamesAreTheFleetsGrammar at the point it is written rather than by an
// operator looking at an empty dashboard.
func MustSpanName(operation ...string) string {
	name, err := SpanName(operation...)
	if err != nil {
		panic(err)
	}
	return name
}

// Record puts attributes on a span, if they are allowed to be there.
//
// This is the ONLY path from a value to a span in this service. Five filters, in
// order of how much they protect against:
//
//  1. Unknown name — dropped. This is the one that catches a future
//     `identity.email`.
//  2. Unknown VALUE for a known name — dropped. A method outside core's enum, a
//     status outside 100..599, a route that is not a template, an error class
//     outside the closed vocabulary. A name being allowlisted is not a promise
//     that any value under it is shippable.
//  3. A string longer than MaxAttributeLength — truncated, so one absurd value
//     cannot be a memory or cost problem on its own.
//  4. A non-scalar — dropped. An object with a String() is a value that can be
//     anything at all.
//
// Value types are deliberately narrow: string, bool, and the signed and unsigned
// integers. A float64 is refused because nothing in the trace allowlist is a
// measurement — the numeric attributes core defines are integers — and a float
// reaching a trace attribute is nearly always a value that was meant for a
// metric and would carry unbounded precision into a label.
func Record(span trace.Span, attributes map[string]any) {
	if span == nil || !span.IsRecording() {
		return
	}
	for _, name := range sortedKeys(attributes) {
		if _, ok := allowedSpanAttributes[name]; !ok {
			continue
		}
		value, ok := attributeValue(name, attributes[name])
		if !ok {
			continue
		}
		span.SetAttributes(value)
	}
}

// RecordFailure says that a span failed, and what CLASS of failure it was.
//
// Two decisions, and the second is the one people get wrong.
//
//  1. The predicate for "this is an error" is the span's STATUS, not
//     `error.type`. core's traces schema encodes both directions of that as
//     constraints: status `error` obliges an error class, and an error class
//     obliges a failed status. A span whose status is unset is invisible to a
//     `{status=error}` filter however many error attributes it carries, and a
//     span with a class but no failed status is a span two different queries
//     read differently. Both halves are set here so they cannot come apart.
//
//  2. `error.type` is the CLASS, never the message, and `RecordError` is
//     deliberately NOT called: the SDK's RecordError writes
//     `exception.message` and `exception.stacktrace`, which are unbounded, are
//     on nobody's allowlist, and on a service that authenticates people are a
//     path to whatever the failing handler had in hand. A class outside
//     core's closed vocabulary collapses to `_OTHER` and returns an error saying
//     so, so the instrumentation is never silently wrong.
//
// A handled-and-retried failure is not recorded at all. A retry that succeeded is
// not an error, and recording it makes the error rate a lie.
func RecordFailure(span trace.Span, class string, description string) error {
	if span == nil {
		return nil
	}
	resolved := class
	if _, ok := errorTypes[resolved]; !ok {
		resolved = "_OTHER"
	}
	span.SetStatus(codes.Error, description)
	span.SetAttributes(
		attribute.String("error.type", resolved),
		attribute.String("otel.status_code", "ERROR"),
	)
	if resolved != class {
		return fmt.Errorf("telemetry: %q is not in core's error vocabulary; recorded as _OTHER", class)
	}
	return nil
}

func attributeValue(name string, value any) (attribute.KeyValue, bool) {
	switch v := value.(type) {
	case string:
		if v == "" {
			return attribute.KeyValue{}, false
		}
		switch name {
		case "http.request.method":
			if _, ok := httpMethods[v]; !ok {
				return attribute.KeyValue{}, false
			}
		case "http.route":
			if !routeTemplate.MatchString(v) {
				return attribute.KeyValue{}, false
			}
		case "db.system":
			if _, ok := databases[v]; !ok {
				return attribute.KeyValue{}, false
			}
		case "error.type":
			if _, ok := errorTypes[v]; !ok {
				return attribute.KeyValue{}, false
			}
		}
		return attribute.String(name, v), true
	case bool:
		return attribute.Bool(name, v), true
	case int:
		return statusAwareInt64(name, int64(v))
	case int64:
		return statusAwareInt64(name, v)
	case uint8:
		return statusAwareInt64(name, int64(v))
	case int32:
		return statusAwareInt64(name, int64(v))
	case uint32:
		return statusAwareInt64(name, int64(v))
	case int16:
		return statusAwareInt64(name, int64(v))
	case uint16:
		return statusAwareInt64(name, int64(v))
	case int8:
		return statusAwareInt64(name, int64(v))
	case uint:
		return attribute.Int64(name, int64(v)), true
	default:
		return attribute.KeyValue{}, false
	}
}

func statusAwareInt64(name string, value int64) (attribute.KeyValue, bool) {
	if name == "http.response.status_code" && (value < 100 || value > 599) {
		return attribute.KeyValue{}, false
	}
	return attribute.Int64(name, value), true
}

// Resource is the process identity, attached once per process rather than once
// per span.
//
// It is the correct home for `tenant_id` and EXEMPT from OpenTelemetry's
// 2000-attribute-combination metric cap. Put a tenant on a MEASUREMENT instead
// and the moment that stream overflows, every per-tenant breakdown silently
// undercounts while the total stays right — the worst shape a bug can have,
// because the dashboard still renders and looks fine.
func Resource(lookup func(string) string) *resource.Resource {
	attrs := []attribute.KeyValue{semconv.ServiceName(SpanNamePrefix)}
	if version := lookup("OTEL_SERVICE_VERSION"); version != "" {
		attrs = append(attrs, semconv.ServiceVersion(version))
	}
	if environment := lookup("DEPLOYMENT_ENVIRONMENT"); environment != "" {
		attrs = append(attrs, semconv.DeploymentEnvironment(environment))
	}
	if instance := lookup("OTEL_SERVICE_INSTANCE_ID"); instance != "" {
		attrs = append(attrs, semconv.ServiceInstanceID(instance))
	}
	if tenant := lookup(TenantVariable); tenant != "" {
		attrs = append(attrs, attribute.String("tenant_id", tenant))
	}
	return resource.NewWithAttributes(semconv.SchemaURL, attrs...)
}

// Endpoint is the OTLP endpoint, and it is the WHOLE of the contract.
//
//	IDENTITY_OTEL_ENDPOINT set   -> export there. The shipped collector, or
//	                                Datadog, Honeycomb, Grafana Cloud, anything
//	                                speaking OTLP. Bring-your-own is a supported
//	                                deployment, not a degraded mode.
//	unset                          -> the collector that ships with the stack.
//
// `OTEL_EXPORTER_OTLP_ENDPOINT` is honored as a fallback so identity also works
// with generic OTel tooling, and the anywaye name wins when both are set. That
// precedence is written down here rather than discovered later: a contract with
// an undocumented precedence order is a bug report.
func Endpoint(lookup func(string) string) string {
	if value := lookup(EndpointVariable); value != "" {
		return value
	}
	if value := lookup("OTEL_EXPORTER_OTLP_ENDPOINT"); value != "" {
		return value
	}
	return defaultEndpoint
}

var perSignal = []string{"OTEL_TRACES_EXPORTER", "OTEL_METRICS_EXPORTER", "OTEL_LOGS_EXPORTER"}

// Enabled reports whether there is anywhere to export to.
//
// The two switches, in the order the OTel spec means them:
//
//   - `OTEL_SDK_DISABLED` is the spec's OWN kill switch, and it is what core's
//     otel-endpoint schema pins the no-op to. Re-implementing "disabled" in six
//     languages is how six services acquire six different definitions of it, and
//     the difference between them is somebody's production incident.
//   - `<SIGNAL>_EXPORTER=none` is the per-signal half, and all three are
//     checked rather than just the traces one.
func Enabled(lookup func(string) string) bool {
	if strings.EqualFold(strings.TrimSpace(lookup("OTEL_SDK_DISABLED")), "true") {
		return false
	}
	for _, name := range perSignal {
		if strings.EqualFold(strings.TrimSpace(lookup(name)), "none") {
			return false
		}
	}
	return true
}

// NoOpReason is one line for the startup log, and only ever on the DISABLED path.
//
// Silence is the contract there: a service that logs a warning per export
// attempt fills its own log store with the fact that telemetry is off, which is
// how a self-hoster discovers that turning it off is not supported — the
// opposite of the intent. One line at startup is not spam, and it is the
// difference between "telemetry is off" and "telemetry is broken", which look
// identical from outside.
func NoOpReason(lookup func(string) string) string {
	if strings.EqualFold(strings.TrimSpace(lookup("OTEL_SDK_DISABLED")), "true") {
		return "OTEL_SDK_DISABLED=true"
	}
	var off []string
	for _, name := range perSignal {
		if strings.EqualFold(strings.TrimSpace(lookup(name)), "none") {
			off = append(off, name)
		}
	}
	if len(off) == 0 {
		return ""
	}
	return strings.Join(off, ",") + "=none"
}

// Exporter is where finished spans go. Production builds an OTLP exporter; a
// test builds one over an in-memory buffer.
//
// It is a parameter to Install rather than something Install constructs from the
// environment, and that is what makes canary_test.go an assertion about a REAL
// export rather than a claim about one: a test that could only reach the network
// would either be skipped or would make the suite phone an observability backend.
type Exporter interface {
	ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error
	Shutdown(ctx context.Context) error
}

// NewExporter builds the OTLP exporter for an endpoint. The default; a test
// replaces it.
type NewExporter func(ctx context.Context, endpoint string) (Exporter, error)

// Options is everything Install needs. Every field is explicit, because
// Install runs once at boot and a value it read from a global is a value nobody
// can find when a deployment is misconfigured.
type Options struct {
	ServiceName  string
	Version      string
	Endpoint     string
	Disabled     bool
	NewExporter  NewExporter
	LookupEnv    func(string) string
	ShutdownWait time.Duration
}

// Shutdown flushes every signal. Missing it loses the last batch, which is
// usually the batch containing the error you were restarting to look at.
type Shutdown func(context.Context) error

// Install sets the propagator and the tracer provider, and returns one Shutdown.
//
// A NO-OP provider when telemetry is off, never a provider pointed at nothing: a
// provider with an exporter that has nowhere to go still allocates a span per
// request, still computes attributes nobody reads, and still costs a goroutine
// and a batch timer for the life of the process. The no-op is genuinely free,
// which is what core's otel-endpoint schema demands.
//
// The propagator is W3C TraceContext named EXPLICITLY rather than left to the
// default. The default IS W3C today, but several libraries call
// SetTextMapPropagator and may not mean what this service does, and a service
// that depends on a default it never wrote down breaks silently when one of them
// changes it.
func Install(ctx context.Context, opts Options) (Shutdown, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if opts.ServiceName == "" {
		opts.ServiceName = ServiceName
	}
	if opts.LookupEnv == nil {
		opts.LookupEnv = os.Getenv
	}
	if opts.NewExporter == nil {
		opts.NewExporter = OTLPExporter
	}
	if opts.ShutdownWait == 0 {
		opts.ShutdownWait = 5 * time.Second
	}

	if opts.Disabled {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetMeterProvider(metricnoop.NewMeterProvider())
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := opts.NewExporter(ctx, opts.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("building the otlp span exporter for %s: %w", opts.Endpoint, err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithResource(Resource(opts.LookupEnv)),
	)
	otel.SetTracerProvider(provider)

	metricExporter, err := OTLPMetricExporter(ctx, opts.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("building the otlp metric exporter for %s: %w", opts.Endpoint, err)
	}
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
		sdkmetric.WithResource(Resource(opts.LookupEnv)),
	)
	otel.SetMeterProvider(meterProvider)

	return func(shutdownCtx context.Context) error {
		flushCtx, cancel := context.WithTimeout(shutdownCtx, opts.ShutdownWait)
		defer cancel()
		err1 := provider.Shutdown(flushCtx)
		err2 := meterProvider.Shutdown(flushCtx)
		if err1 != nil { return err1 }
		return err2
	}, nil
}

// StartServer begins a span for an inbound request.
//
// The propagator does the extracting and the carrier is the header map the
// framework handed us. On a malformed header this returns the original context
// unchanged and a root span, which is exactly the W3C spec's "ignore the header":
// not an error, and not a 4xx.
func StartServer(ctx context.Context, header http.Header, name string) (context.Context, trace.Span) {
	ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(header))
	tracer := otel.Tracer(SpanNamePrefix)
	return tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindServer))
}

// Inject writes the current trace onto an outbound header map, so a service-to-
// service call continues this trace rather than starting a new one.
//
// A request made without it breaks the trace at that hop, silently and
// permanently, with no error anywhere to grep for.
func Inject(ctx context.Context, header http.Header) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(header))
}

// TraceID is the current trace id, hex-encoded, for a log line or the
// `x-trace-id` response header.
//
// A trace a user cannot quote back to you is a trace you will be asked about and
// cannot find. An invalid context yields "unknown" rather than an error: this is
// called from a logging path, and a 500 on a log-formatting path is worse than a
// missing id.
func TraceID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.HasTraceID() {
		return "unknown"
	}
	return sc.TraceID().String()
}

// SpanID is the current span id, for the same reason as TraceID.
func SpanID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.HasSpanID() {
		return "unknown"
	}
	return sc.SpanID().String()
}

func sortedKeys(attributes map[string]any) []string {
	keys := make([]string, 0, len(attributes))
	for name := range attributes {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return keys
}
