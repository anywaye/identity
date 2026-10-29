package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/anywaye/identity/internal/telemetry"
)


const (
	canaryEmail = "canary-7b3e@example.com"
	canaryAccount = "acc_01J9Z8QK5M4N7P2R3T6V8W9X0A"
	canaryToken = "sess_01J9Z8QK5M4N7P2R3T6V8W9X0A"
)

func recordingRouter(t *testing.T, opts ...Option) (http.Handler, *tracetest.SpanRecorder) {
	t.Helper()

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	installProviderForTest(t, provider)
	installPropagationForTest()
	setRecorder(recorder)

	return New(nil, append([]Option{WithLogger(discardLogger())}, opts...)...), recorder
}

func serve(t *testing.T, handler http.Handler, method, target string, header http.Header) *tracetest.SpanRecorder {
	t.Helper()

	fresh := tracetest.NewSpanRecorder()
	installProviderForTest(t, sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(fresh)))
	installPropagationForTest()

	req := httptest.NewRequestWithContext(context.Background(), method, target, nil)
	for name, values := range header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	handler.ServeHTTP(httptest.NewRecorder(), req)
	return fresh
}

func TestAParameterisedRouteRecordsItsTemplateNotThePath(t *testing.T) {
	const parameterised = "/v1/test/accounts/{accountID}"
	handler, _ := recordingRouter(t, WithParameterizedRouteForTest(parameterised))

	patterns := recordedRouteTable()

	var sawTemplate bool
	for _, pattern := range patterns {
		if pattern == parameterised {
			sawTemplate = true
		}
	}
	if !sawTemplate {
		t.Fatalf("the route table is %v, which does not contain %q. Every assertion below "+
			"assumes the route really is parameterised, and a literal route would satisfy "+
			"them while proving nothing.", patterns, parameterised)
	}

	recorder := serve(t, handler, http.MethodGet,
		strings.Replace(parameterised, "{accountID}", canaryAccount, 1), nil)
	first := spanAttributes(onlySpan(t, recorder))
	if got := first["http.route"]; got != parameterised {
		t.Errorf("http.route = %q, want the TEMPLATE %q.\n\n"+
			"A route template has one value per endpoint. A concrete path has one per "+
			"request, and the collector's spanmetrics connector mints a metric series for "+
			"every distinct value of it — so at a thousand accounts this is a thousand "+
			"series, and at a hundred thousand it is a bill.\n\n"+
			"Nothing downstream can tell the two apart: both are on core's allowlist and "+
			"both pass the redaction processor unchanged. This is a service-side choice, "+
			"which is why it is tested here and not left to the collector.",
			got, parameterised)
	}
	if rendered := renderSpans(recorder); strings.Contains(rendered, canaryAccount) {
		t.Errorf("the account id reached the span:\n%s", rendered)
	}

	recorder = serve(t, handler, http.MethodGet,
		strings.Replace(parameterised, "{accountID}", "acc_01DIFFERENT00000000000000", 1), nil)
	second := spanAttributes(onlySpan(t, recorder))
	if second["http.route"] != first["http.route"] {
		t.Errorf("two requests to one endpoint recorded two routes (%q and %q). That is the "+
			"cardinality bomb: the collector mints a series per distinct value, so an "+
			"endpoint's request count stops being a single number.",
			first["http.route"], second["http.route"])
	}
}

func TestTheStatusIsRecordedExactlyOnce(t *testing.T) {
	handler, _ := recordingRouter(t)

	for _, tc := range []struct {
		target string
		status int
	}{
		{"/healthz", 200},
		{"/v1/nope", 404},
	} {
		recorder := serve(t, handler, http.MethodGet, tc.target, nil)
		span := onlySpan(t, recorder)

		attributes := spanAttributes(span)
		if got, want := attributes["http.response.status_code"], itoa(tc.status); got != want {
			t.Errorf("%s: http.response.status_code = %v, want %s. The status has to be "+
				"read from the writer on the way OUT: read earlier it is always 200, and a "+
				"500 recorded as a 200 is a failure invisible in every error view in the "+
				"fleet.", tc.target, got, want)
		}

		failed := span.Status().Code.String() == "Error"
		_, hasClass := attributes["error.type"]
		if failed != hasClass {
			t.Errorf("%s: status=Error is %v but error.type is present=%v. core's schema "+
				"makes those two a biconditional, and it is what makes the ABSENCE of "+
				"error.type the load-bearing not-an-error marker on a duration histogram.",
				tc.target, failed, hasClass)
		}
	}
}

func onlySpan(t *testing.T, recorder *tracetest.SpanRecorder) sdktrace.ReadOnlySpan {
	t.Helper()
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("%d spans were exported, want 1", len(spans))
	}
	return spans[0]
}

func TestTheRouteOnASpanIsTheTemplateAndNotThePath(t *testing.T) {
	handler, _ := recordingRouter(t)

	recorder := serve(t, handler, http.MethodGet, "/v1/accounts/"+canaryAccount, nil)
	for _, span := range recorder.Ended() {
		for _, kv := range span.Attributes() {
			if string(kv.Key) != "http.route" {
				continue
			}
			got := kv.Value.String()
			if strings.Contains(got, canaryAccount) {
				t.Errorf("the span carries the CONCRETE PATH %q as its route.\n\n"+
					"A route template is one value per endpoint; a concrete path is one per "+
					"request, and the collector's spanmetrics connector mints a metric series "+
					"for every distinct value of it. Nothing downstream can tell the two apart: "+
					"both are on core's allowlist and both pass the redaction processor. This "+
					"is a cardinality bomb that costs money at volume while every static check "+
					"stays green — which is why it is tested on a real request and not on the "+
					"allowlist.", got)
			}
		}
	}

	recorder = serve(t, handler, http.MethodGet, "/healthz", nil)
	if !hasAttribute(recorder, "http.route", "/healthz") {
		t.Error("a matched route recorded no http.route template. Every absence assertion " +
			"in this file is only meaningful if the positive case works — check that " +
			"requestAttributes is still being called before believing a green run.")
	}
}

func TestTheSpanCarriesTheStatusAndTheMethod(t *testing.T) {
	handler, _ := recordingRouter(t)

	for _, tc := range []struct {
		method string
		target string
		status int
	}{
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/readyz", http.StatusOK},
		{http.MethodGet, "/v1/does-not-exist", http.StatusNotFound},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
	} {
		recorder := serve(t, handler, tc.method, tc.target, nil)
		spans := recorder.Ended()
		if len(spans) != 1 {
			t.Errorf("%s %s produced %d spans, want 1. A middleware registered twice "+
				"produces two spans for one request, which doubles every request count in "+
				"the fleet and is invisible in a trace view.", tc.method, tc.target, len(spans))
			continue
		}
		attributes := spanAttributes(spans[0])
		if got := attributes["http.request.method"]; got != tc.method {
			t.Errorf("%s %s: http.request.method = %v, want %s. A 404 and a 405 never reach "+
				"a route handler, so the method has to be recorded outside the router or it "+
				"is missing from exactly the requests where knowing what was asked for "+
				"matters most.", tc.method, tc.target, got, tc.method)
		}
		if got := attributes["http.response.status_code"]; got != itoa(tc.status) {
			t.Errorf("%s %s: http.response.status_code = %v, want %d", tc.method, tc.target, got, tc.status)
		}
		if spans[0].Name() != "identity.request" {
			t.Errorf("%s %s: span name = %q, want identity.request. A name is the grouping "+
				"key in every trace UI, so a name carrying the route is a grouping an "+
				"operator cannot break apart by endpoint.", tc.method, tc.target, spans[0].Name())
		}
	}
}

func TestAnUnmatchedRequestCarriesNoRoute(t *testing.T) {
	handler, _ := recordingRouter(t)

	for _, target := range []string{
		"/v1/does-not-exist",
		"/v1/accounts/" + canaryAccount,
		"/v1/session?email=" + canaryEmail,
		"/../../etc/passwd",
	} {
		recorder := serve(t, handler, http.MethodGet, target, nil)
		spans := recorder.Ended()
		if len(spans) != 1 {
			t.Fatalf("%s produced %d spans, want 1", target, len(spans))
		}
		if got, present := spanAttributes(spans[0])["http.route"]; present {
			t.Errorf("%s produced a span with http.route = %q.\n\n"+
				"An unmatched path is caller-controlled text, and the collector's "+
				"spanmetrics connector mints a metric series for every distinct value of "+
				"http.route. Recording it is a cardinality bomb and a content leak in the "+
				"same move; the 404 status is the answer.", target, got)
		}
		if got := spanAttributes(spans[0])["http.response.status_code"]; got != "404" {
			t.Errorf("%s: status = %v, want 404 — without a route, the status is the only "+
				"thing that says what happened", target, got)
		}
		if rendered := renderSpans(recorder); strings.Contains(rendered, canaryEmail) ||
			strings.Contains(rendered, canaryAccount) {
			t.Errorf("caller-supplied text reached the span for %s:\n%s", target, rendered)
		}
	}
}

func TestA5xxIsAnErrorSpanAndA4xxIsNot(t *testing.T) {
	handler, _ := recordingRouter(t)

	recorder := serve(t, handler, http.MethodGet, "/v1/nope", nil)
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected one span, got %d", len(spans))
	}
	if got := spans[0].Status().Code.String(); got == "Error" {
		t.Error("a 404 produced an ERROR span. A 404 is the service refusing a request, " +
			"which is the service working; an error rate that counts it is a function of " +
			"how much guessing the platform absorbs, and an alert on it pages somebody to " +
			"turn off the protection.")
	}
	if _, present := spanAttributes(spans[0])["error.type"]; present {
		t.Error("a 404 carried error.type. core's schema makes the class present if and " +
			"only if the span failed, so a class on a success makes the error rate wrong.")
	}

	const panicking = "/v1/test/panics"
	panickingRouter, _ := recordingRouter(t, WithPanickingRouteForTest(panicking))
	recorder = serve(t, panickingRouter, http.MethodGet, panicking, nil)
	spans = recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("the panicking handler produced %d spans, want 1", len(spans))
	}
	if got := spans[0].Status().Code.String(); got != "Error" {
		t.Errorf("a panic produced a %s span, want Error. A request that 500s with nothing "+
			"in the trace view saying so is the one request an operator most wants to find.",
			got)
	}
	attributes := spanAttributes(spans[0])
	if attributes["error.type"] != "internal_error" {
		t.Errorf("error.type = %v, want internal_error", attributes["error.type"])
	}
	rendered := renderSpans(recorder)
	for name, canary := range map[string]string{
		"the email":   canaryEmail,
		"the token":   canaryToken,
		"the account": canaryAccount,
	} {
		if strings.Contains(rendered, canary) {
			t.Errorf("%s reached an exported span.\n\nA recovered panic carries whatever was "+
				"on the stack, and in an auth handler that routinely means a decoded request "+
				"struct. The span gets the CLASS; the message stays in the log, where an "+
				"operator reads it and where the log pipeline can apply its own rules.\n\n%s",
				name, rendered)
		}
	}
	if got := attributes["http.response.status_code"]; got != "500" {
		t.Errorf("http.response.status_code = %v, want 500", got)
	}
	if got := attributes["http.route"]; got != panicking {
		t.Errorf("http.route = %v, want %q. A 500 whose span carries no route is a failure "+
			"an operator can see but not place, and a test seam that dropped the route would "+
			"have made this test pass against a service that is not the one that ships.",
			got, panicking)
	}
}

func TestAnInboundTraceparentIsContinued(t *testing.T) {
	handler, _ := recordingRouter(t)

	const inbound = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

	recorder := serve(t, handler, http.MethodGet, "/healthz", http.Header{
		"traceparent": []string{inbound},
	})
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected one span, got %d", len(spans))
	}
	if got := spans[0].SpanContext().TraceID().String(); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trace id = %s, want the caller's 4bf92f3577b34da6a3ce929d0e0e4736.\n\n"+
			"A span that does not continue the caller's context is a one-hop trace, and four "+
			"thousand one-hop traces are harder to debug than no traces at all.", got)
	}
	if got := spans[0].Parent().SpanID().String(); got != "00f067aa0ba902b7" {
		t.Errorf("parent span id = %s, want the caller's 00f067aa0ba902b7", got)
	}
}

func TestAMalformedTraceparentStartsANewTraceAndIsNeverA4xx(t *testing.T) {
	for _, value := range []string{
		"not-a-traceparent",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-" + canaryEmail + "-" + canaryToken + "-01",
	} {
		t.Run(value[:min(len(value), 24)], func(t *testing.T) {
			router, _ := recordingRouter(t)

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
			req.Header.Set("traceparent", value)
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("traceparent %q produced a %d. A malformed correlation header is an "+
					"observability affordance failing, not a request failing; refusing it is a "+
					"denial-of-service vector aimed at the service's own probe.", value, rec.Code)
			}
			spans := currentRecorder(t).Ended()
			if len(spans) != 1 {
				t.Fatalf("traceparent %q produced %d spans, want 1; the request should still "+
					"be traced, just under a new trace id", value, len(spans))
			}
			if got := spans[0].SpanContext().TraceID().String(); got == "00000000000000000000000000000000" {
				t.Errorf("traceparent %q produced an all-zero trace id, which the spec reserves "+
					"and which correlates every such request in the system into one trace", value)
			}
			if rendered := renderSpans(currentRecorder(t)); strings.Contains(rendered, canaryEmail) ||
				strings.Contains(rendered, canaryToken) {
				t.Errorf("a fragment of the refused traceparent reached the span:\n%s", rendered)
			}
		})
	}
}

func TestTelemetryIsNeverInTheReadinessPath(t *testing.T) {
	handler, _ := recordingRouter(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz returned %d with no checks configured, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"otel", "telemetry", "collector", "4317", "4318"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("/readyz mentions %q: %s. A readiness probe that consults telemetry "+
				"fails when telemetry fails, and an orchestrator that takes a service out "+
				"of rotation because a collector restarted is a service that stopped serving "+
				"traffic for a reason nobody can see.", forbidden, body)
		}
	}
}

func TestTheProbesAreTracedLikeEverythingElse(t *testing.T) {
	handler, _ := recordingRouter(t)

	for _, probe := range []string{"/healthz", "/readyz"} {
		recorder := serve(t, handler, http.MethodGet, probe, nil)
		if len(recorder.Ended()) != 1 {
			t.Errorf("%s produced %d spans, want 1", probe, len(recorder.Ended()))
		}
	}
}

func TestTheSpanNameIsTheFleetsGrammar(t *testing.T) {
	if requestSpanName != "identity.request" {
		t.Errorf("requestSpanName = %q, want identity.request. The span name is the grouping "+
			"key in every trace view in the fleet; changing it breaks every one of them, "+
			"and the collector's spanmetrics namespace is derived from it.", requestSpanName)
	}
	if !strings.HasPrefix(requestSpanName, telemetry.SpanNamePrefix+".") {
		t.Errorf("requestSpanName = %q does not start with the service prefix %q",
			requestSpanName, telemetry.SpanNamePrefix)
	}
}

func TestTheStatusClassLadderIsTheOnesTheCollectorApplies(t *testing.T) {
	for status, want := range map[int]string{
		100: "1xx", 199: "1xx",
		200: "2xx", 299: "2xx",
		301: "3xx", 399: "3xx",
		400: "4xx", 499: "4xx",
		500: "5xx", 599: "5xx",
		0: "", 99: "", 600: "", -1: "",
	} {
		if got := statusClass(status); got != want {
			t.Errorf("statusClass(%d) = %q, want %q", status, got, want)
		}
	}
}
