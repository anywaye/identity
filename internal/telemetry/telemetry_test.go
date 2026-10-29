package telemetry

import (
	"context"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func recording(t *testing.T) (*tracetest.SpanRecorder, func()) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	restore := installForTest(t, provider)
	return recorder, restore
}


func TestTheAllowlistCarriesNoNameThatCouldHoldContent(t *testing.T) {
	forbidden := []string{
		"prompt",
		"message",
		"content",
		"text",
		"body",
		"header",
		"query",
		"email",
		"password",
		"secret",
		"token",
		"credential",
		"cookie",
		"authorization",
		"stacktrace",
		"subject",
		"apikey",
		"api_key",
		"detail",
		"user",
		"account",
		"tenant",
	}

	var offending []string
	for _, name := range AllowedSpanAttributes {
		lowered := strings.ToLower(name)
		for _, word := range forbidden {
			if strings.Contains(lowered, word) {
				offending = append(offending, name+" (contains "+word+")")
			}
		}
	}
	if len(offending) > 0 {
		t.Fatalf("the span-attribute allowlist carries names that could hold content: %s\n\n"+
			"Every name on this list is the security control. A name that could carry a "+
			"caller's email, a password, a token or a message body is a value in a "+
			"searchable, retained, widely-readable store — and this is the service that "+
			"mints credentials and reads passwords, so it is the last place to publish them.",
			strings.Join(offending, ", "))
	}
}

func TestTheAllowlistCarriesNoUnboundedIdentifier(t *testing.T) {
	prohibited := []string{
		"tenant_id",
		"user_id",
		"account_id",
		"request_id",
		"trace_id",
		"span_id",
		"session_id",
		"message_id",
		"notification_id",
		"email",
		"error.message",
		"error.stacktrace",
		"url.full",
		"url.path",
	}

	var offending []string
	for _, name := range AllowedSpanAttributes {
		for _, banned := range prohibited {
			if name == banned {
				offending = append(offending, name)
			}
		}
	}
	if len(offending) > 0 {
		t.Fatalf("the span-attribute allowlist carries identifiers core's metrics schema "+
			"prohibits on a measurement: %s. These are unbounded as a dimension, and the "+
			"collector derives the fleet's metrics from these spans.", strings.Join(offending, ", "))
	}
}

func TestTheAllowlistIsTheTransitiveIntersection(t *testing.T) {
	coreAllows := map[string]struct{}{
		"http.request.method":       {},
		"http.response.status_code": {},
		"http.route":                {},
		"db.system":                 {},
		"db.operation":              {},
		"messaging.system":          {},
		"messaging.operation":       {},
		"otel.status_code":          {},
		"error.type":                {},
	}

	var unknown []string
	for _, name := range AllowedSpanAttributes {
		if _, ok := coreAllows[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		t.Fatalf("these attributes are not on core's trace allowlist: %s\n\n"+
			"An attribute core does not name is dropped by the collector, so exporting it "+
			"buys nothing and costs a hole in the one place the boundary can be inspected.",
			strings.Join(unknown, ", "))
	}
}

func TestAnAttributeOutsideTheAllowlistIsDropped(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	Record(span, map[string]any{
		"identity.email":            "someone@example.com",
		"http.request.method":       "POST",
		"user_agent.original":       "curl/8.0",
		"http.response.status_code": 201,
	})
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected one span, got %d", len(spans))
	}
	attributes := map[string]any{}
	for _, kv := range spans[0].Attributes() {
		attributes[string(kv.Key)] = kv.Value.AsInterface()
	}
	if _, present := attributes["identity.email"]; present {
		t.Error("identity.email reached the exported span")
	}
	if _, present := attributes["user_agent.original"]; present {
		t.Error("user_agent.original reached the exported span")
	}
	if got := attributes["http.request.method"]; got != "POST" {
		t.Errorf("http.request.method = %v, want POST — the allowlist must not have dropped the ALLOWED data", got)
	}
	if got := attributes["http.response.status_code"]; got != int64(201) {
		t.Errorf("http.response.status_code = %v, want 201", got)
	}
}

func TestAnAllowedNameWithAnImpossibleValueIsDropped(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	Record(span, map[string]any{
		"http.request.method": "PROPFIND",
		"http.response.status_code": 999,
		"error.type": "user_42_email_invalid",
		"db.system": "postgresql?account_id=acc_01J9",
		"http.route": "/v1/accounts/someone@example.com",
		"http.response.status_code_class": 4.5,
	})
	span.End()

	spans := recorder.Ended()
	attributes := map[string]any{}
	for _, kv := range spans[0].Attributes() {
		attributes[string(kv.Key)] = kv.Value.AsInterface()
	}
	for name := range attributes {
		t.Errorf("%q reached the exported span with a value outside its shape; "+
			"a name allowlist is a promise about names, not about values", name)
	}
}

func TestTheRoutePatternCannotTellATemplateFromAConcretePath(t *testing.T) {
	if !routeTemplate.MatchString("/v1/accounts/acc_01J9Z8QK5M4N7P2R3T6V8W9X0A") {
		t.Fatal("this path stopped matching the route pattern, which means the " +
			"character class changed; re-read the test above before concluding the " +
			"structural guarantee is now the only one left")
	}
}

func TestTheErrorVocabularyIsCoreExactly(t *testing.T) {
	want := []string{
		"_OTHER",
		// Core's spelling — see the note on ErrorTypes. This literal IS the
		// schema's enum, so it carries the same suppression.
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
	if len(ErrorTypes) != len(want) {
		t.Fatalf("ErrorTypes has %d members, core's schema has %d", len(ErrorTypes), len(want))
	}
	for i, class := range want {
		if ErrorTypes[i] != class {
			t.Errorf("ErrorTypes[%d] = %q, core's schema has %q", i, ErrorTypes[i], class)
		}
	}
}

func TestRecordFailureRefusesAnInventedClass(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	err := RecordFailure(span, "password_incorrect", "the caller typed the wrong password")
	span.End()

	if err == nil {
		t.Error("RecordFailure accepted a class outside core's vocabulary without saying so")
	}
	if !strings.Contains(err.Error(), "password_incorrect") {
		t.Errorf("the error names %q, which does not say which class was refused", err)
	}
	spans := recorder.Ended()
	attributes := map[string]any{}
	for _, kv := range spans[0].Attributes() {
		attributes[string(kv.Key)] = kv.Value.AsInterface()
	}
	if got := attributes["error.type"]; got != "_OTHER" {
		t.Errorf("error.type = %v, want _OTHER", got)
	}
	if got := spans[0].Status().Code.String(); got != "Error" {
		t.Errorf("span status = %q, want Error — the class without a failed status is a span two queries read differently", got)
	}
}

func TestRecordFailureSetsBothHalvesOfTheBiconditional(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	if err := RecordFailure(span, "dependency_unavailable", "the database did not answer"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	span.End()

	spans := recorder.Ended()
	if got := spans[0].Status().Code.String(); got != "Error" {
		t.Errorf("status = %q, want Error", got)
	}
	found := map[string]any{}
	for _, kv := range spans[0].Attributes() {
		found[string(kv.Key)] = kv.Value.AsInterface()
	}
	if found["error.type"] != "dependency_unavailable" {
		t.Errorf("error.type = %v, want dependency_unavailable", found["error.type"])
	}
	if found["otel.status_code"] != "ERROR" {
		t.Errorf("otel.status_code = %v, want ERROR — the mirror exists so a log-indexed "+
			"query can filter on it, and it may not disagree with status.code", found["otel.status_code"])
	}
	for _, kv := range spans[0].Attributes() {
		if strings.Contains(string(kv.Key), "exception") {
			t.Errorf("span carries %q; RecordError was deliberately not called, and an "+
				"exception.message on a service that authenticates people is a path to "+
				"whatever the failing handler had in hand", kv.Key)
		}
	}
}

func TestARouteOverTheLengthCeilingIsDroppedNotShortened(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	atLimit := "/" + strings.Repeat("a", MaxRouteLength-1)
	if !routeTemplate.MatchString(atLimit) {
		t.Fatalf("a route of exactly MaxRouteLength (%d) does not match the pattern; the "+
			"bound and the pattern disagree, and every route at the limit is being dropped",
			MaxRouteLength)
	}

	span := startTestSpan(t)
	Record(span, map[string]any{
		"http.route": atLimit,
		"http.route.too.long": "/" + strings.Repeat("a", MaxRouteLength),
		"db.system":           "postgresql?account_id=acc_01J9",
	})
	span.End()

	attributes := map[string]string{}
	for _, kv := range recorder.Ended()[0].Attributes() {
		attributes[string(kv.Key)] = kv.Value.AsString()
	}
	if got, ok := attributes["http.route"]; !ok {
		t.Error("a route of exactly MaxRouteLength was dropped; the bound is off by one")
	} else if got != atLimit {
		t.Errorf("http.route was altered: got %d characters, want %d", len(got), len(atLimit))
	}
	for name := range attributes {
		if name == "http.route" {
			continue
		}
		t.Errorf("%q reached the span; it is not on the allowlist, and the values above are "+
			"the shapes a caller most easily smuggles content through", name)
	}
}


func TestSpanNamesAreTheFleetsGrammar(t *testing.T) {
	if got, err := SpanName("request"); err != nil || got != "identity.request" {
		t.Errorf("SpanName(\"request\") = %q, %v; want identity.request", got, err)
	}
	if got, err := SpanName("provider", "call"); err != nil || got != "identity.provider.call" {
		t.Errorf("SpanName(\"provider\", \"call\") = %q, %v; want identity.provider.call", got, err)
	}

	for _, segments := range [][]string{
		{""},
		{"Request"},
		{"request-id"},
		{"this_segment_is_far_too_long"},
		{"identity.request"},
		{"a", "b", "c", "d"},
		{"/v1/session"},
		{"v1.session"},
		{"usr_01J9Z8QK5M4N7P2R3T6V8W9X0A"},
		{"a b"},
		{"a;b"},
	} {
		if name, err := SpanName(segments...); err == nil {
			t.Errorf("SpanName(%q) = %q with no error; a name that can hold a value is a "+
				"grouping key an operator cannot filter out of", segments, name)
		}
	}

	if _, err := SpanName(); err == nil {
		t.Error("SpanName() with no operation succeeded; a span name with no operation says nothing")
	}
}

func TestMustSpanNamePanicsOnAConstantThatCannotBeRight(t *testing.T) {
	if got := MustSpanName("request"); got != "identity.request" {
		t.Errorf("MustSpanName(\"request\") = %q, want identity.request", got)
	}
	defer func() {
		if recover() == nil {
			t.Error("MustSpanName did not panic on a segment that is not a legal operation")
		}
	}()
	MustSpanName("Not A Segment")
}


func TestTheEndpointContractIsOneVariable(t *testing.T) {
	table := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "unset falls back to the collector that ships with the stack",
			env:  map[string]string{},
			want: DefaultEndpoint,
		},
		{
			name: "the anywaye variable wins over the standard one",
			env: map[string]string{
				EndpointVariable:              "https://otlp.example.com:4318",
				"OTEL_EXPORTER_OTLP_ENDPOINT": "https://other.example.com:4318",
			},
			want: "https://otlp.example.com:4318",
		},
		{
			name: "the standard variable works for generic tooling",
			env:  map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "https://other.example.com:4318"},
			want: "https://other.example.com:4318",
		},
		{
			name: "an empty value is a missing value",
			env:  map[string]string{EndpointVariable: ""},
			want: DefaultEndpoint,
		},
	}
	for _, tc := range table {
		t.Run(tc.name, func(t *testing.T) {
			if got := Endpoint(lookupFrom(tc.env)); got != tc.want {
				t.Errorf("Endpoint = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTheKillSwitchIsTheSpecsOwn(t *testing.T) {
	for _, value := range []string{"true", "TRUE", "True"} {
		if Enabled(lookupFrom(map[string]string{"OTEL_SDK_DISABLED": value})) {
			t.Errorf("Enabled() = true with OTEL_SDK_DISABLED=%s", value)
		}
	}

	for _, name := range []string{"OTEL_TRACES_EXPORTER", "OTEL_METRICS_EXPORTER", "OTEL_LOGS_EXPORTER"} {
		for _, value := range []string{"none", "NONE", "None"} {
			if Enabled(lookupFrom(map[string]string{name: value})) {
				t.Errorf("Enabled() = true with %s=%s", name, value)
			}
			if reason := NoOpReason(lookupFrom(map[string]string{name: value})); reason != name+"=none" {
				t.Errorf("NoOpReason = %q, want %q", reason, name+"=none")
			}
		}
	}

	if !Enabled(lookupFrom(map[string]string{"OTEL_SDK_DISABLED": "nottrue"})) {
		t.Error(`Enabled() = false with OTEL_SDK_DISABLED=nottrue; a value that merely ` +
			`CONTAINS "true" is not the spec's switch`)
	}
	if !Enabled(lookupFrom(map[string]string{"OTEL_SDK_DISABLED": "false"})) {
		t.Error(`Enabled() = false with OTEL_SDK_DISABLED=false`)
	}
	if reason := NoOpReason(lookupFrom(map[string]string{})); reason != "" {
		t.Errorf("NoOpReason = %q on the ENABLED path; the line is only ever for the disabled one", reason)
	}
}

// TestNoOpReasonNamesWhatSwitchedItOff is what makes "telemetry is off" and
// "telemetry is broken" tellable apart from outside the process.
//
// One line at startup, and only on the disabled path. Silence is the contract
// there: a warning per export attempt fills the service's own log store with the
// fact that telemetry is off, which is how a self-hoster discovers that turning
// it off is not supported — the opposite of the intent.
func TestNoOpReasonNamesWhatSwitchedItOff(t *testing.T) {
	if got := NoOpReason(lookupFrom(map[string]string{"OTEL_SDK_DISABLED": "true"})); got != "OTEL_SDK_DISABLED=true" {
		t.Errorf("NoOpReason = %q, want OTEL_SDK_DISABLED=true", got)
	}
	got := NoOpReason(lookupFrom(map[string]string{
		"OTEL_TRACES_EXPORTER": "none",
		"OTEL_LOGS_EXPORTER":   "none",
	}))
	if got != "OTEL_TRACES_EXPORTER,OTEL_LOGS_EXPORTER=none" {
		t.Errorf("NoOpReason = %q; both switches must be named, or an operator turns off the "+
			"one they thought was responsible", got)
	}
}

func TestTheDisabledPathStartsNoExporter(t *testing.T) {
	called := false
	shutdown, err := Install(context.Background(), Options{
		Disabled: true,
		NewExporter: func(context.Context, string) (Exporter, error) {
			called = true
			return nil, assertNever("the disabled path built an exporter")
		},
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if called {
		t.Error("Install built an exporter while telemetry is off")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("the no-op shutdown returned %v; it must be free", err)
	}
	span := startTestSpan(t)
	span.End()
}

func TestAMisconfiguredEndpointIsABootFailure(t *testing.T) {
	_, err := Install(context.Background(), Options{
		Endpoint: "://not a url",
		NewExporter: func(context.Context, string) (Exporter, error) {
			return nil, assertNever("a malformed endpoint reached the exporter constructor")
		},
	})
	if err == nil {
		t.Fatal("Install succeeded with a malformed endpoint; a service that exports nowhere " +
			"while looking healthy is the failure this is here to prevent")
	}
	if !strings.Contains(err.Error(), "not a url") {
		t.Errorf("the error does not quote the endpoint it refused: %v", err)
	}
}


func TestTheExporterAcceptsEveryShapeAnOperatorTypes(t *testing.T) {
	for _, endpoint := range []string{
		"http://otel-collector:4318",
		"otel-collector:4318",
		"https://otlp.example.com",
		"http://otel-collector:4318/",
		"  http://otel-collector:4318  ",
	} {
		if _, err := OTLPExporter(context.Background(), endpoint); err != nil {
			t.Errorf("OTLPExporter(%q) = %v; this is a shape an operator will type", endpoint, err)
		}
	}
}

func TestTheNormalisedEndpointNamesTheSignalPath(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		want     string
	}{
		{"http://otel-collector:4318", "http://otel-collector:4318/v1/traces"},
		{"otel-collector:4318", "http://otel-collector:4318/v1/traces"},
		{"http://otel-collector:4318/", "http://otel-collector:4318/v1/traces"},
		{"https://otlp.example.com", "https://otlp.example.com/v1/traces"},
		{"https://otlp.example.com/anywaye", "https://otlp.example.com/anywaye/v1/traces"},
		{"http://otel-collector:4318/v1/traces", "http://otel-collector:4318/v1/traces"},
		{"https://otlp.example.com/anywaye/v1/traces", "https://otlp.example.com/anywaye/v1/traces"},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			got, err := normaliseEndpoint(tc.endpoint)
			if err != nil {
				t.Fatalf("normaliseEndpoint(%q) error = %v", tc.endpoint, err)
			}
			if got != tc.want {
				t.Errorf("normaliseEndpoint(%q) = %q, want %q.\n\nAn endpoint with no signal "+
					"path makes every export a request the collector does not serve, and a "+
					"span that is never received is indistinguishable from a span that was "+
					"never created.", tc.endpoint, got, tc.want)
			}
		})
	}
}

func TestTheSignalPathAppendIsIdempotent(t *testing.T) {
	const endpoint = "http://otel-collector:4318"

	once, err := normaliseEndpoint(endpoint)
	if err != nil {
		t.Fatalf("normaliseEndpoint(%q) error = %v", endpoint, err)
	}
	twice, err := normaliseEndpoint(once)
	if err != nil {
		t.Fatalf("normaliseEndpoint(%q) error = %v", once, err)
	}
	if once != twice {
		t.Errorf("normalising twice is not stable: %q then %q", once, twice)
	}
}

func TestTheExporterRefusesWhatNobodyCouldHaveMeant(t *testing.T) {
	for _, endpoint := range []string{
		"",
		"   ",
		"://missing-scheme",
		"ftp://otel-collector:4318",
		"http://",
	} {
		if _, err := OTLPExporter(context.Background(), endpoint); err == nil {
			t.Errorf("OTLPExporter(%q) succeeded; a transport that accepts this exports nowhere "+
				"and says nothing", endpoint)
		}
	}
}


func TestTheTenantGoesOnTheResourceAndNowhereElse(t *testing.T) {
	resource := Resource(lookupFrom(map[string]string{
		TenantVariable:             "tenant-abc",
		"DEPLOYMENT_ENVIRONMENT":   "development",
		"OTEL_SERVICE_VERSION":     "0.1.0",
		"OTEL_SERVICE_INSTANCE_ID": "identity-7d9f",
	}))

	got := map[string]string{}
	for _, kv := range resource.Attributes() {
		got[string(kv.Key)] = kv.Value.String()
	}
	for name, want := range map[string]string{
		"service.name":           "identity",
		"service.version":        "0.1.0",
		"service.instance.id":    "identity-7d9f",
		"deployment.environment": "development",
		"tenant_id":              "tenant-abc",
	} {
		if got[name] != want {
			t.Errorf("resource %s = %q, want %q", name, got[name], want)
		}
	}

	if _, onASpan := allowedSpanAttributes["tenant_id"]; onASpan {
		t.Error("tenant_id is on the span-attribute allowlist; core's metrics schema " +
			"prohibits it on a measurement and the collector's spanmetrics connector " +
			"derives this fleet's metrics from these spans")
	}
}

func TestAnUnsetResourceVariableIsAbsentRatherThanEmpty(t *testing.T) {
	for _, kv := range Resource(lookupFrom(map[string]string{})).Attributes() {
		if value := kv.Value.String(); value == "" {
			t.Errorf("resource %s is an empty string; absent is not the same as empty", kv.Key)
		}
	}
}
