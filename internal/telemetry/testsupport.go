package telemetry

import (
	"context"
	"fmt"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)


func installForTest(t *testing.T, provider *sdktrace.TracerProvider) func() {
	t.Helper()
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	return func() { otel.SetTracerProvider(previous) }
}

func startTestSpan(t *testing.T) trace.Span {
	t.Helper()
	_, span := StartServer(context.Background(), nil, MustSpanName("unit"))
	return span
}

func lookupFrom(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}

func assertNever(what string) error { return fmt.Errorf("telemetry: %s", what) }
