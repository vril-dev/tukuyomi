package observability

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

type TracingConfig struct {
	Enabled      bool
	ServiceName  string
	OTLPEndpoint string
	Insecure     bool
	SampleRatio  float64
}

var tracingEnabled atomic.Bool

func SetupTracing(ctx context.Context, cfg TracingConfig) (func(context.Context) error, error) {
	tracingEnabled.Store(false)
	if !cfg.Enabled {
		return func(context.Context) error { return nil }, nil
	}
	endpoint, insecure := normalizeOTLPEndpoint(cfg.OTLPEndpoint, cfg.Insecure)
	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(endpoint)}
	if insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create otlp trace exporter: %w", err)
	}
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(strings.TrimSpace(cfg.ServiceName)),
	)
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(normalizeSampleRatio(cfg.SampleRatio)))),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	tracingEnabled.Store(true)
	return func(ctx context.Context) error {
		defer tracingEnabled.Store(false)
		return tp.Shutdown(ctx)
	}, nil
}

func TracingEnabled() bool {
	return tracingEnabled.Load()
}

func TraceIDFromContext(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

func normalizeSampleRatio(v float64) float64 {
	switch {
	case v <= 0:
		return 1
	case v > 1:
		return 1
	default:
		return v
	}
}

func normalizeOTLPEndpoint(raw string, insecure bool) (string, bool) {
	endpoint := strings.TrimSpace(raw)
	if endpoint == "" {
		return "127.0.0.1:4317", true
	}
	if !strings.Contains(endpoint, "://") {
		return endpoint, insecure
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || strings.TrimSpace(parsed.Host) == "" {
		return endpoint, insecure
	}
	return parsed.Host, parsed.Scheme == "http" || insecure
}
