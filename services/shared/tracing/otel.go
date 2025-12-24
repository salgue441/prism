// Package tracing provides OpenTelemetry instrumentation for distributed tracing.
package tracing

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Config holds tracing configuration.
type Config struct {
	ServiceName    string  `mapstructure:"service_name"`
	ServiceVersion string  `mapstructure:"service_version"`
	Environment    string  `mapstructure:"environment"`
	Endpoint       string  `mapstructure:"endpoint"`
	Insecure       bool    `mapstructure:"insecure"`
	SampleRate     float64 `mapstructure:"sample_rate"`
	Enabled        bool    `mapstructure:"enabled"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		ServiceName:    "prism",
		ServiceVersion: "dev",
		Environment:    "development",
		Endpoint:       "localhost:4317",
		Insecure:       true,
		SampleRate:     1.0,
		Enabled:        true,
	}
}

// Provider wraps the OpenTelemetry tracer provider.
type Provider struct {
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
	config   Config
}

// Init initializes the tracing provider and returns a cleanup function.
func Init(cfg Config) (*Provider, func(context.Context) error, error) {
	if !cfg.Enabled {
		// Return a no-op provider
		return &Provider{
			tracer: otel.Tracer(cfg.ServiceName),
			config: cfg,
		}, func(context.Context) error { return nil }, nil
	}

	ctx := context.Background()

	// Create OTLP exporter
	var opts []otlptracegrpc.Option
	opts = append(opts, otlptracegrpc.WithEndpoint(cfg.Endpoint))

	if cfg.Insecure {
		opts = append(opts, otlptracegrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	exporter, err := otlptrace.New(ctx, otlptracegrpc.NewClient(opts...))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create resource with service information
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			semconv.DeploymentEnvironment(cfg.Environment),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create sampler
	var sampler sdktrace.Sampler
	if cfg.SampleRate >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if cfg.SampleRate <= 0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(cfg.SampleRate)
	}

	// Create tracer provider
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Set global provider
	otel.SetTracerProvider(provider)

	// Set global propagator for context propagation
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	p := &Provider{
		provider: provider,
		tracer:   provider.Tracer(cfg.ServiceName),
		config:   cfg,
	}

	cleanup := func(ctx context.Context) error {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return provider.Shutdown(shutdownCtx)
	}

	return p, cleanup, nil
}

// Tracer returns the tracer.
func (p *Provider) Tracer() trace.Tracer {
	return p.tracer
}

// Provider returns the underlying provider.
func (p *Provider) Provider() *sdktrace.TracerProvider {
	return p.provider
}

// --- Span Helpers ---

// StartSpan starts a new span with the given name.
func (p *Provider) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return p.tracer.Start(ctx, name, opts...)
}

// SpanFromContext returns the current span from context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// TraceIDFromContext extracts the trace ID from context.
func TraceIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().HasTraceID() {
		return span.SpanContext().TraceID().String()
	}
	return ""
}

// SpanIDFromContext extracts the span ID from context.
func SpanIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().HasSpanID() {
		return span.SpanContext().SpanID().String()
	}
	return ""
}

// --- Attribute Helpers ---

// WithHTTPAttributes adds common HTTP attributes to a span.
func WithHTTPAttributes(span trace.Span, method, path string, statusCode int) {
	span.SetAttributes(
		semconv.HTTPRequestMethodKey.String(method),
		semconv.URLPath(path),
		semconv.HTTPResponseStatusCode(statusCode),
	)
}

// WithGRPCAttributes adds common gRPC attributes to a span.
func WithGRPCAttributes(span trace.Span, method string, statusCode int) {
	span.SetAttributes(
		semconv.RPCMethod(method),
		semconv.RPCSystemGRPC,
		attribute.Int("rpc.grpc.status_code", statusCode),
	)
}

// WithDatabaseAttributes adds common database attributes to a span.
func WithDatabaseAttributes(span trace.Span, dbSystem, dbName, operation string) {
	span.SetAttributes(
		semconv.DBSystemKey.String(dbSystem),
		attribute.String("db.name", dbName),
		attribute.String("db.operation", operation),
	)
}

// WithError records an error on a span.
func WithError(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}

// WithSuccess marks a span as successful.
func WithSuccess(span trace.Span) {
	span.SetStatus(codes.Ok, "")
}

// --- Common Span Types ---

// SpanKind represents the type of span.
type SpanKind = trace.SpanKind

const (
	SpanKindServer   = trace.SpanKindServer
	SpanKindClient   = trace.SpanKindClient
	SpanKindProducer = trace.SpanKindProducer
	SpanKindConsumer = trace.SpanKindConsumer
	SpanKindInternal = trace.SpanKindInternal
)

// StartServerSpan starts a new server span.
func (p *Provider) StartServerSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return p.tracer.Start(ctx, name, trace.WithSpanKind(SpanKindServer))
}

// StartClientSpan starts a new client span.
func (p *Provider) StartClientSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return p.tracer.Start(ctx, name, trace.WithSpanKind(SpanKindClient))
}

// StartInternalSpan starts a new internal span.
func (p *Provider) StartInternalSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return p.tracer.Start(ctx, name, trace.WithSpanKind(SpanKindInternal))
}

// --- Context Propagation ---

// InjectContext injects tracing context into a carrier (e.g., HTTP headers).
func InjectContext(ctx context.Context, carrier propagation.TextMapCarrier) {
	otel.GetTextMapPropagator().Inject(ctx, carrier)
}

// ExtractContext extracts tracing context from a carrier.
func ExtractContext(ctx context.Context, carrier propagation.TextMapCarrier) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, carrier)
}

// HeaderCarrier is a simple map-based carrier for headers.
type HeaderCarrier map[string]string

func (c HeaderCarrier) Get(key string) string {
	return c[key]
}

func (c HeaderCarrier) Set(key, value string) {
	c[key] = value
}

func (c HeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	return keys
}

// --- Middleware Helpers ---

// HTTPSpanName generates a span name for HTTP requests.
func HTTPSpanName(method, path string) string {
	return fmt.Sprintf("%s %s", method, path)
}

// GRPCSpanName generates a span name for gRPC methods.
func GRPCSpanName(fullMethod string) string {
	return fullMethod
}

// --- Global Provider ---

var globalProvider *Provider

// InitGlobal initializes the global tracing provider.
func InitGlobal(cfg Config) (func(context.Context) error, error) {
	provider, cleanup, err := Init(cfg)
	if err != nil {
		return nil, err
	}
	globalProvider = provider
	return cleanup, nil
}

// Default returns the global tracing provider.
func Default() *Provider {
	return globalProvider
}

// Tracer returns the global tracer.
func Tracer() trace.Tracer {
	if globalProvider != nil {
		return globalProvider.tracer
	}
	return otel.Tracer("prism")
}

// StartSpan starts a new span using the global tracer.
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return Tracer().Start(ctx, name, opts...)
}
