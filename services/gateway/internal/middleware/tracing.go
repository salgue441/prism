// Package middleware provides HTTP tracing middleware.
package middleware

import (
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// TracingConfig holds tracing middleware configuration.
type TracingConfig struct {
	ServiceName string
	SkipPaths   []string
}

// Tracing returns middleware that adds distributed tracing to requests.
func Tracing(cfg TracingConfig) func(http.Handler) http.Handler {
	tracer := otel.Tracer(cfg.ServiceName)

	skipPaths := make(map[string]bool)
	for _, p := range cfg.SkipPaths {
		skipPaths[p] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip tracing for certain paths
			if skipPaths[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			// Extract parent context from incoming request headers
			ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			// Start span
			spanName := r.Method + " " + r.URL.Path
			ctx, span := tracer.Start(ctx, spanName,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					semconv.HTTPRequestMethodKey.String(r.Method),
					semconv.URLPath(r.URL.Path),
					semconv.URLScheme(scheme(r)),
					semconv.ServerAddress(r.Host),
					attribute.String("http.user_agent", r.UserAgent()),
					attribute.String("http.remote_addr", r.RemoteAddr),
				),
			)
			defer span.End()

			// Add request ID if available
			if reqID := GetRequestID(ctx); reqID != "" {
				span.SetAttributes(attribute.String("request.id", reqID))
			}

			// Wrap response writer to capture status code
			rw := &tracingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Process request with traced context
			next.ServeHTTP(rw, r.WithContext(ctx))

			// Record response attributes
			span.SetAttributes(
				semconv.HTTPResponseStatusCode(rw.statusCode),
			)

			// Set span status based on HTTP status code
			if rw.statusCode >= 400 {
				span.SetAttributes(attribute.Bool("error", true))
			}
		})
	}
}

// tracingResponseWriter wraps ResponseWriter to capture status code.
type tracingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *tracingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// scheme returns the request scheme (http/https).
func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}
