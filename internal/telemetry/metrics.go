package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	idRequestCount metric.Int64Counter
	idRequestDur   metric.Float64Histogram
	idMetricsInit  bool
)

func initIdentityMetrics() {
	if idMetricsInit {
		return
	}
	meter := otel.Meter(ServiceName)
	c, _ := meter.Int64Counter("http.server.request.count")
	h, _ := meter.Float64Histogram("http.server.request.duration", metric.WithUnit("s"))
	idRequestCount = c
	idRequestDur = h
	idMetricsInit = true
}

func RecordRequest(ctx context.Context, method, route string, status int, dur time.Duration) {
	initIdentityMetrics()
	attrs := []attribute.KeyValue{
		attribute.String("http.request.method", method),
		attribute.String("http.route", route),
		attribute.Int("http.response.status_code", status),
	}
	if idRequestCount != nil {
		idRequestCount.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	if idRequestDur != nil {
		idRequestDur.Record(ctx, dur.Seconds(), metric.WithAttributes(attrs...))
	}
}
