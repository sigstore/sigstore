package otelinstr

import (
	"context"
	"os"
	"time"

	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"

	errors "github.com/zgalor/weberr"
)

type Logger interface {
	Info(string, ...any)
	Error(error, ...any)
}

// ConfigureOpenTelemetryTracer configures the global OpenTelemetry trace
// provider and propagator for baggages and trace context.
//
// The function uses the following environment variables for the tracer
// configuration:
//   - `OTEL_TRACES_EXPORTER`, either `otlp` to send traces to an OTLP endpoint or `console`.
//   - `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`, either `grpc` or `http`.
//   - `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, endpoint where to send the OTLP
//     traces (e.g. `https://localhost:4318/v1/traces`).
//
// See
// https://pkg.go.dev/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp
// for the list of all supported variables.
//
// An error is returned if an environment value is set to an unhandled value.
//
// If no environment variable are set, a no-op tracer is setup.
func ConfigureOpenTelemetryTracer(ctx context.Context, logger Logger, resourceAttrs ...attribute.KeyValue) (func(context.Context) error, error) {
	if v, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"); !ok || v == "" {
		logger.Info("skipping OpenTelemetry SDK initialization...")
		return func(context.Context) error { return nil }, nil
	}

	logger.Info("initializing OpenTelemetry SDK...")

	exp, err := autoexport.NewSpanExporter(ctx, autoexport.WithFallbackSpanExporter(newNoopFactory))
	if err != nil {
		return nil, errors.Errorf("failed to create OTEL exporter: %s", err)
	}

	var isNoop bool
	if _, isNoop = exp.(*noopSpanExporter); !isNoop || autoexport.IsNoneSpanExporter(exp) {
		isNoop = true
	}
	logger.Info("initializing OpenTelemetry tracer:", "isNoop", isNoop)

	opts := []resource.Option{resource.WithHost()}
	if len(resourceAttrs) > 0 {
		opts = append(opts, resource.WithAttributes(resourceAttrs...))
	}
	resources, err := resource.New(ctx, opts...)
	if err != nil {
		return nil, errors.Errorf("failed to initialize trace resources: %s", err)
	}

	tp := tracesdk.NewTracerProvider(
		tracesdk.WithBatcher(exp),
		tracesdk.WithResource(resources),
	)
	otel.SetTracerProvider(tp)

	shutdown := func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return tp.Shutdown(ctx)
	}

	propagator := propagation.NewCompositeTextMapPropagator(propagation.Baggage{}, propagation.TraceContext{})
	otel.SetTextMapPropagator(propagator)

	otel.SetErrorHandler(otelErrorHandlerFunc(func(err error) {
		logger.Error(err, "OpenTelemetry.ErrorHandler: %v", err.Error())
	}))

	return shutdown, nil
}

type otelErrorHandlerFunc func(error)

// Handle implements otel.ErrorHandler
func (f otelErrorHandlerFunc) Handle(err error) {
	f(err)
}

func newNoopFactory(_ context.Context) (tracesdk.SpanExporter, error) {
	return &noopSpanExporter{}, nil
}

var _ tracesdk.SpanExporter = noopSpanExporter{}

// noopSpanExporter is an implementation of trace.SpanExporter that performs no operations.
type noopSpanExporter struct{}

// ExportSpans is part of trace.SpanExporter interface.
func (e noopSpanExporter) ExportSpans(ctx context.Context, spans []tracesdk.ReadOnlySpan) error {
	return nil
}

// Shutdown is part of trace.SpanExporter interface.
func (e noopSpanExporter) Shutdown(ctx context.Context) error {
	return nil
}
