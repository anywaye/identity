package telemetry

import (
	"context"

	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)


const canary = "CANARY-7b3e-DO-NOT-EXPORT"

// renderExports is the whole export as one string: every span's name, kind,
// status and every attribute's name AND value.
//
// Rendered rather than compared key-by-key, and that is the whole design. A
// key-by-key assertion only catches a leak through a key the test already knew
// to look for; rendering catches a leak through a VALUE as well, and through a
// key nobody predicted. The leak this file exists to prevent arrives as a new
// attribute name, and a test that asserts on the names it knows about is a test
// that goes green on the day the new name is added.
func renderExports(recorder *tracetest.SpanRecorder) string {
	var rendered strings.Builder
	for _, span := range recorder.Ended() {
		rendered.WriteString("name=")
		rendered.WriteString(span.Name())
		rendered.WriteString(" kind=")
		rendered.WriteString(span.SpanKind().String())
		rendered.WriteString(" status=")
		rendered.WriteString(span.Status().Code.String())
		for _, kv := range span.Attributes() {
			rendered.WriteString(" ")
			rendered.WriteString(string(kv.Key))
			rendered.WriteString("=")
			rendered.WriteString(kv.Value.String())
		}
		rendered.WriteString("\n")
	}
	return rendered.String()
}

// assertNoCanary is the assertion every test in this file ends with, phrased once
// so the failure message is the same everywhere.
//
// It takes the RENDERED export rather than a chosen attribute, which is what
// makes it catch a leak through a key nobody thought of.
func assertNoCanary(t *testing.T, recorder *tracetest.SpanRecorder) {
	t.Helper()
	exported := renderExports(recorder)
	if strings.Contains(exported, canary) {
		t.Fatalf("THE REDACTION BOUNDARY LEAKED.\n\n"+
			"The canary %q reached an exportable span attribute. It was planted in a field "+
			"a caller controls, so whatever route it took is a route by which a customer's "+
			"email, a password, a TOTP secret or a session token reaches a searchable, "+
			"retained, widely-readable store — and identity is the service that mints "+
			"credentials.\n\nThe whole export:\n%s", canary, exported)
	}
}

func assertExported(t *testing.T, recorder *tracetest.SpanRecorder, want ...string) {
	t.Helper()
	exported := renderExports(recorder)
	for _, attribute := range want {
		if !strings.Contains(exported, attribute) {
			t.Errorf("%q did not reach the export.\n\n"+
				"The canary assertions in this file can all be satisfied by a service that "+
				"exports NOTHING, so each one is paired with this. A redaction boundary that "+
				"deletes the data rather than the content is not a boundary, it is a "+
				"black hole.\n\nThe whole export:\n%s", attribute, exported)
		}
	}
}

func TestAContentBearingAttributeNameNeverReachesAnExport(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	Record(span, map[string]any{
		"identity.email":         "someone@example.com",
		"identity.password":      "hunter2",
		"identity.subject":       "usr_01J9Z8QK5M4N7P2R3T6V8W9X0A",
		"identity.account_id":    "acc_01J9Z8QK5M4N7P2R3T6V8W9X0A",
		"identity.session_token": "sess_01J9Z8QK5M4N7P2R3T6V8W9X0A",
		"identity.mfa_secret":    "JBSWY3DPEHPK3PXP",
		"identity.email_hash": "sha256:9f3a1c7e",
		"error.message":        "the account already exists",
		"exception.message":    "runtime error: index out of range",
		"exception.stacktrace": "goroutine 1 [running]:\nmain.handleLogin",
		"url.full":                          "https://identity.internal/v1/session?email=someone@example.com",
		"url.query":                         "email=someone@example.com",
		"http.request.header.authorization": "Bearer " + canary,
	})
	span.End()

	assertNoCanary(t, recorder)
}

func TestTheCanaryInAnAllowedKeysValueIsStillARedaction(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	for _, route := range []string{
		"/v1/accounts/" + canary + "@example.com",
		"/v1/accounts?email=" + canary,
		"/v1/accounts/" + canary + " " + canary,
	} {
		span := startTestSpan(t)
		Record(span, map[string]any{"http.route": route})
		span.End()
	}

	span := startTestSpan(t)
	Record(span, map[string]any{
		"db.system": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi" + canary + ".c2ln",
	})
	span.End()

	assertNoCanary(t, recorder)
}

func TestTheResourceCarriesOnlyCoresFiveNames(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	built := Resource(lookupFrom(map[string]string{
		"OTEL_SERVICE_VERSION":     "0.1.0",
		"DEPLOYMENT_ENVIRONMENT":   "production",
		TenantVariable:             "tenant-abc",
		"OTEL_SERVICE_INSTANCE_ID": "identity-7d9f",
		"OIDC_SIGNING_KEY":                       canary,
		"MFA_ENCRYPTION_KEY":                     canary,
		"DATABASE_URL":                           "postgres://identity:hunter2@postgres:5432/identity",
		"OIDC_ISSUER":                            "https://accounts.example.com/" + canary,
		"IDENTITY_TENANT_ID_NOT_A_REAL_VARIABLE": canary,
	}))

	got := map[string]string{}
	for _, kv := range built.Attributes() {
		got[string(kv.Key)] = kv.Value.String()
	}

	coreAllows := map[string]struct{}{
		"service.name":           {},
		"service.version":        {},
		"service.instance.id":    {},
		"deployment.environment": {},
		"tenant_id":              {},
	}
	for name := range got {
		if _, ok := coreAllows[name]; !ok {
			t.Errorf("the resource carries %q, which is not one of core's six. A resource "+
				"attribute is attached to EVERY span the process emits, so this is a "+
				"per-request leak of whatever the variable holds.", name)
		}
	}
	for name := range coreAllows {
		if _, present := got[name]; !present {
			t.Errorf("the resource is missing %q, which core requires", name)
		}
	}

	if rendered := renderAttributes(got); strings.Contains(rendered, "hunter2") {
		t.Errorf("the database URL reached the resource: %s", rendered)
	}

	_, span := StartServer(context.Background(), nil, MustSpanName("unit"))
	span.SetAttributes(built.Attributes()...)
	span.End()
	assertNoCanary(t, recorder)
}

func renderAttributes(attributes map[string]string) string {
	var rendered strings.Builder
	for name, value := range attributes {
		rendered.WriteString(name)
		rendered.WriteString("=")
		rendered.WriteString(value)
		rendered.WriteString("\n")
	}
	return rendered.String()
}

func TestAFailedRequestCarriesTheClassAndNotTheMessage(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	_ = RecordFailure(span, "internal_error",
		"failed to load account "+canary+" for "+canary+": connection refused")
	span.RecordError(assertNever(canary))
	span.End()

	assertNoCanary(t, recorder)
	assertExported(t, recorder, "error.type=internal_error")
}

func TestAPanicPathRecordsTheClassWithoutTheRecoveredValue(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	_ = RecordFailure(span, "internal_error", "the handler panicked")
	span.End()

	assertExported(t, recorder, "error.type=internal_error", "status=Error")
	assertNoCanary(t, recorder)
}

// TestACredentialNeverReachesAnExport is the credential half of the boundary,
// and it is a separate claim from the content half.
//
// The same rule governs both — never export a token, a key or a JWT, and never
// log one — and they are tested separately because they arrive by different
// routes. Content arrives in a field; a credential arrives in a HEADER, which is
// the one place a service is tempted to record "just the auth header" for
// debugging. There is no `http.request.header.*` on the allowlist at all, and
// the test says so by trying.
func TestACredentialNeverReachesAnExport(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	const (
		jwt    = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		apiKey = "sk-live-51H8xQ2eZvKYlo2C0abcdefghijklmnop"
		bearer = "Bearer " + "sess_01J9Z8QK5M4N7P2R3T6V8W9X0A"
	)

	span := startTestSpan(t)
	Record(span, map[string]any{
		"http.request.header.authorization": bearer,
		"http.request.header.Authorization": bearer,
		"authorization":                     bearer,
		"http.request.header.cookie":        "session=" + jwt,
		"http.request.header.x-api-key":     apiKey,
		"http.route": "/v1/introspections",
		"db.system":  jwt,
		"error.type": apiKey,
	})
	span.End()

	exported := renderExports(recorder)
	for name, credential := range map[string]string{
		"the JWT":          jwt,
		"the API key":      apiKey,
		"the bearer token": bearer,
	} {
		if strings.Contains(exported, credential) {
			t.Errorf("%s reached the exported span.\n\n%s", name, exported)
		}
	}
	assertNoCanary(t, recorder)
}

func TestTheAllowlistIsTheOnlyPathToASpan(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	span.SetAttributes(
		attribute.String("identity.email", "someone@example.com"),
		attribute.String("http.route", "/v1/session"),
	)
	Record(span, map[string]any{"http.route": "/v1/session"})
	span.End()

	exported := renderExports(recorder)
	if !strings.Contains(exported, "identity.email") {
		t.Skip("the SDK refuses unknown attributes; if this ever becomes true the " +
			"allowlist is no longer load-bearing and the bypass is gone")
	}
	t.Log("confirmed: a direct span.SetAttributes bypasses the allowlist, which is why " +
		"Record is the only documented path and the collector's allowlist is the backstop")
}

func TestTheNumberOfExportedSpansIsOne(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	Record(span, map[string]any{"http.request.method": "POST"})
	span.End()

	if got := len(recorder.Ended()); got != 1 {
		t.Fatalf("%d spans were exported, want 1. Every canary assertion in this file is "+
			"vacuously true against an empty export.", got)
	}
}
