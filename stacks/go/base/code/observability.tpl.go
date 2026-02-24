// File: observability.tpl.go
// Purpose: OpenTelemetry tracing setup for Go
// Generated for: {{PROJECT_NAME}}

package observability

import (
	"context"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

func SetupTracing(ctx context.Context, serviceName, otlpEndpoint string) (func(context.Context) error, error) {
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(otlpEndpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}

func GetTracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

// WithSpan is a helper for manual tracing
func WithSpan(ctx context.Context, name string, fn func(ctx context.Context) error, attrs ...attribute.KeyValue) error {
	tracer := GetTracer("default")
	ctx, span := tracer.Start(ctx, name)
	defer span.End()

	span.SetAttributes(attrs...)

	if err := fn(ctx); err != nil {
		span.RecordError(err)
		return err
	}

	return nil
}

// Example usage
func ExampleUsage() {
	ctx := context.Background()
	shutdown, err := SetupTracing(ctx, "my-service", "localhost:4317")
	if err != nil {
		log.Fatal(err)
	}
	defer shutdown(ctx)

	tracer := GetTracer("my-service")
	ctx, span := tracer.Start(ctx, "operation")
	defer span.End()

	span.SetAttributes(attribute.String("user.id", "123"))
}
