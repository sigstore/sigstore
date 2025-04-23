# OpenTelemetry Initialization for Sigstore Projects

This package provides a standardized method to initialize the OpenTelemetry SDK across Sigstore projects, with a focus on **trace export**.

## Trace Export Configuration

Trace exporting is configured using the following environment variables:

- `OTEL_TRACES_EXPORTER`: Defines the exporter type.
  - Must be configured for a tracer to be initialised.
  - Supported values:
    - `otlp` – sends traces to an OTLP endpoint.
    - `console` – prints traces to the console.
- `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`: Sets the OTLP protocol.
  - Supported values:
    - `grpc`
    - `http`
- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`: Specifies the OTLP endpoint (e.g. `https://localhost:4318/v1/traces`).

If these environment variable `OTEL_TRACES_EXPORTER` is not set, **no** tracer will is initialized.

> See the [OTLP HTTP Exporter documentation](https://pkg.go.dev/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp) for all supported configuration options.

## Propagators

The default propagator is a composite propagator that uses the W3C Trace Context format:

```go
propagation.NewCompositeTextMapPropagator(propagation.TraceContext{})
```

This enables trace context propagation across service boundaries in a standard-compliant way.

## Resource Attributes

Resource attributes allow you to associate metadata with traces, such as:

- Service name
- Environment (e.g. staging, production)
- Version

They can be provided in code as arguments when calling the function for OTEL SD initialization:

```go
resourceAttrs := []attribute.KeyValue{
    semconv.ServiceNameKey.String("fulcio"),
    semconv.ServiceVersionKey.String("1.7.0"),
    attribute.String("foo", "bar")
}
```

Or using enviorment variables:
```go
OTEL_SERVICE_NAME="fulcio"
OTEL_RESOURCE_ATTRIBUTES="service.version=1.7.0-1-hotfix,foo=bar"
```

This package’s configuration function accepts any number of resource attributes as `attribute.KeyValue` arguments.

There are no default attributes set by this package. More details can be found on the [OpenTelemetry Resource SDK documentation](https://opentelemetry.io/docs/languages/go/resources/)
