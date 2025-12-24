// Package logger provides structured logging with slog optimized for Loki ingestion.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"runtime"
	"time"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// RequestIDKey is the context key for request ID.
	RequestIDKey contextKey = "request_id"
	// UserIDKey is the context key for user ID.
	UserIDKey contextKey = "user_id"
	// TraceIDKey is the context key for trace ID.
	TraceIDKey contextKey = "trace_id"
)

// Config holds logger configuration.
type Config struct {
	Level       string `mapstructure:"level"`
	Format      string `mapstructure:"format"` // json or text
	ServiceName string `mapstructure:"service_name"`
	Environment string `mapstructure:"environment"`
	Output      io.Writer
}

// Logger wraps slog.Logger with additional functionality.
type Logger struct {
	*slog.Logger
	serviceName string
	environment string
}

// defaultLogger is the package-level logger instance.
var defaultLogger *Logger

// New creates a new Logger instance with the given configuration.
func New(cfg Config) *Logger {
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	output := cfg.Output
	if output == nil {
		output = os.Stdout
	}

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Rename time to timestamp for Loki compatibility
			if a.Key == slog.TimeKey {
				a.Key = "timestamp"
				a.Value = slog.StringValue(a.Value.Time().Format(time.RFC3339Nano))
			}
			// Rename msg to message for consistency
			if a.Key == slog.MessageKey {
				a.Key = "message"
			}
			return a
		},
	}

	var handler slog.Handler
	if cfg.Format == "text" {
		handler = slog.NewTextHandler(output, opts)
	} else {
		handler = slog.NewJSONHandler(output, opts)
	}

	// Wrap handler to add default fields
	handler = &contextHandler{
		Handler:     handler,
		serviceName: cfg.ServiceName,
		environment: cfg.Environment,
	}

	logger := &Logger{
		Logger:      slog.New(handler),
		serviceName: cfg.ServiceName,
		environment: cfg.Environment,
	}

	return logger
}

// Init initializes the default logger with the given configuration.
func Init(cfg Config) {
	defaultLogger = New(cfg)
	slog.SetDefault(defaultLogger.Logger)
}

// Default returns the default logger instance.
func Default() *Logger {
	if defaultLogger == nil {
		Init(Config{
			Level:       "info",
			Format:      "json",
			ServiceName: "prism",
			Environment: "development",
		})
	}
	return defaultLogger
}

// contextHandler wraps an slog.Handler to add context-based attributes.
type contextHandler struct {
	slog.Handler
	serviceName string
	environment string
}

// Handle adds context attributes to the log record.
func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	// Add service metadata
	r.AddAttrs(
		slog.String("service", h.serviceName),
		slog.String("environment", h.environment),
	)

	// Add context values if present
	if requestID, ok := ctx.Value(RequestIDKey).(string); ok && requestID != "" {
		r.AddAttrs(slog.String("request_id", requestID))
	}
	if userID, ok := ctx.Value(UserIDKey).(string); ok && userID != "" {
		r.AddAttrs(slog.String("user_id", userID))
	}
	if traceID, ok := ctx.Value(TraceIDKey).(string); ok && traceID != "" {
		r.AddAttrs(slog.String("trace_id", traceID))
	}

	return h.Handler.Handle(ctx, r)
}

// WithAttrs returns a new handler with additional attributes.
func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{
		Handler:     h.Handler.WithAttrs(attrs),
		serviceName: h.serviceName,
		environment: h.environment,
	}
}

// WithGroup returns a new handler with a group name.
func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{
		Handler:     h.Handler.WithGroup(name),
		serviceName: h.serviceName,
		environment: h.environment,
	}
}

// WithContext returns a new Logger that includes context values in logs.
func (l *Logger) WithContext(ctx context.Context) *Logger {
	attrs := make([]slog.Attr, 0, 3)

	if requestID, ok := ctx.Value(RequestIDKey).(string); ok && requestID != "" {
		attrs = append(attrs, slog.String("request_id", requestID))
	}
	if userID, ok := ctx.Value(UserIDKey).(string); ok && userID != "" {
		attrs = append(attrs, slog.String("user_id", userID))
	}
	if traceID, ok := ctx.Value(TraceIDKey).(string); ok && traceID != "" {
		attrs = append(attrs, slog.String("trace_id", traceID))
	}

	if len(attrs) == 0 {
		return l
	}

	args := make([]any, len(attrs))
	for i, attr := range attrs {
		args[i] = attr
	}

	return &Logger{
		Logger:      l.Logger.With(args...),
		serviceName: l.serviceName,
		environment: l.environment,
	}
}

// With returns a new Logger with additional attributes.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{
		Logger:      l.Logger.With(args...),
		serviceName: l.serviceName,
		environment: l.environment,
	}
}

// WithError returns a new Logger with an error attribute.
func (l *Logger) WithError(err error) *Logger {
	return l.With("error", err.Error())
}

// WithRequestID returns a new Logger with a request ID attribute.
func (l *Logger) WithRequestID(requestID string) *Logger {
	return l.With("request_id", requestID)
}

// WithUserID returns a new Logger with a user ID attribute.
func (l *Logger) WithUserID(userID string) *Logger {
	return l.With("user_id", userID)
}

// WithComponent returns a new Logger with a component attribute.
func (l *Logger) WithComponent(component string) *Logger {
	return l.With("component", component)
}

// LogHTTPRequest logs an HTTP request with standard fields.
func (l *Logger) LogHTTPRequest(ctx context.Context, method, path string, statusCode int, duration time.Duration, bytesWritten int64) {
	l.WithContext(ctx).Info("http request",
		slog.String("method", method),
		slog.String("path", path),
		slog.Int("status", statusCode),
		slog.Duration("duration", duration),
		slog.Int64("bytes_written", bytesWritten),
	)
}

// LogGRPCRequest logs a gRPC request with standard fields.
func (l *Logger) LogGRPCRequest(ctx context.Context, method string, duration time.Duration, err error) {
	attrs := []any{
		slog.String("grpc_method", method),
		slog.Duration("duration", duration),
	}

	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
		l.WithContext(ctx).Error("grpc request failed", attrs...)
		return
	}

	l.WithContext(ctx).Info("grpc request", attrs...)
}

// LogPanic logs a panic with stack trace.
func (l *Logger) LogPanic(ctx context.Context, recovered any) {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	stackTrace := string(buf[:n])

	l.WithContext(ctx).Error("panic recovered",
		slog.Any("panic", recovered),
		slog.String("stack_trace", stackTrace),
	)
}

// Package-level convenience functions

// Debug logs at debug level.
func Debug(msg string, args ...any) {
	Default().Debug(msg, args...)
}

// Info logs at info level.
func Info(msg string, args ...any) {
	Default().Info(msg, args...)
}

// Warn logs at warn level.
func Warn(msg string, args ...any) {
	Default().Warn(msg, args...)
}

// Error logs at error level.
func Error(msg string, args ...any) {
	Default().Error(msg, args...)
}

// DebugContext logs at debug level with context.
func DebugContext(ctx context.Context, msg string, args ...any) {
	Default().DebugContext(ctx, msg, args...)
}

// InfoContext logs at info level with context.
func InfoContext(ctx context.Context, msg string, args ...any) {
	Default().InfoContext(ctx, msg, args...)
}

// WarnContext logs at warn level with context.
func WarnContext(ctx context.Context, msg string, args ...any) {
	Default().WarnContext(ctx, msg, args...)
}

// ErrorContext logs at error level with context.
func ErrorContext(ctx context.Context, msg string, args ...any) {
	Default().ErrorContext(ctx, msg, args...)
}
