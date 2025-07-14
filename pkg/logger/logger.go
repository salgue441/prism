// Package logger provides a structured logging interface with
// multiple backend implementations.
//
// This package offers a unified logging interface that can be backed by
// different logging libraries (slog, zap, logrus) while maintaining consistent
// behavior and performance characteristics across the application.
//
// Basic usage:
//
//	logger := logger.New(logger.Config{
//	  Level: "info",
//	  Format: "json",
//	  Output: "stdout",
//	})
//
// The logger automatically handles structured fields and provides
// zero-allocation logging for hot paths when possible.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Logger defines the logging interface used throughout the application.
// It provides structured logging with context support and performance
// optimizations.
type Logger interface {
	// Debug logs a debug message with optional key-value pairs.
	// Debug messages are only logged when the log level is set to debug.
	Debug(msg string, keysAndValues ...any)

	// DebugContext logs a debug message with context and optional key-value
	// pairs. The context can be used for tracing and request correlation.
	DebugContext(ctx context.Context, msg string, keysAndValues ...any)

	// Info logs an info message with optional key-value pairs.
	// This is the recommended level for general application information.
	Info(msg string, keysAndValues ...any)

	// InfoContext logs an info message with context and optional key-value pairs.
	InfoContext(ctx context.Context, msg string, keysAndValues ...any)

	// Warn logs a warning message with optional key-value pairs.
	// Use for recoverable errors or unexpected but non-fatal conditions.
	Warn(msg string, keysAndValues ...any)

	// WarnContext logs a warning message with context and optional key-value
	// pairs.
	WarnContext(ctx context.Context, msg string, keysAndValues ...any)

	// Error logs an error message with optional key-value pairs.
	// Use for errors that need attention but don't require immediate action.
	Error(msg string, keysAndValues ...any)

	// ErrorContext logs an error message with context and optional key-value
	// pairs.
	ErrorContext(ctx context.Context, msg string, keysAndValues ...any)

	// Fatal logs a fatal message and terminates the application.
	// Use sparingly, only for unrecoverable errors.
	Fatal(msg string, keysAndValues ...any)

	// With returns a new logger instance with the given key-value pairs
	// permanently attached to all future log messages.
	With(keysAndValues ...any) Logger

	// WithGroup returns a new logger instance that groups all future
	// log messages under the given group name.
	WithGroup(name string) Logger
}

// Config holds the configuration for logger initialization.
type Config struct {
	// Level sets the minimum log level. Valid values: debug, info, warn, error.
	// Default: info
	Level string `yaml:"level" json:"level"`

	// Format sets the log output format. Valid values: json, text.
	// Default: json
	Format string `yaml:"format" json:"format"`

	// Output sets the log output destination. Valid values: stdout, stderr, or
	// file path. Default: stdout
	Output string `yaml:"output" json:"output"`

	// AddSource adds source code position to log records.
	// This has a performance impact and should be disabled in production.
	// Default: false
	AddSource bool `yaml:"add_source" json:"add_source"`

	// TimeFormat sets the time format for text output.
	// Default: RFC3339
	TimeFormat string `yaml:"time_format" json:"time_format"`
}

// slogLogger implements the Logger interface using the standard library's slog
// package.
type slogLogger struct {
	logger *slog.Logger
}

// New creates a new Logger instance with the given configuration.
// It returns an error if the configuration is invalid.
//
// The logger is optimized for performance and uses the standard library's
// slog package by default, which provides zero-allocation logging for
// many common use cases.
func New(cfg Config) (Logger, error) {
	if cfg.Level == "" {
		cfg.Level = "Info"
	}

	if cfg.Format == "" {
		cfg.Format = "json"
	}

	if cfg.Output == "" {
		cfg.Output = "stdout"
	}

	if cfg.TimeFormat == "" {
		cfg.TimeFormat = time.RFC3339
	}

	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	var writer io.Writer
	switch cfg.Output {
	case "stdout":
		writer = os.Stdout

	case "stderr":
		writer = os.Stderr

	default:
		file, err := os.OpenFile(cfg.Output,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)

		if err != nil {
			return nil, err
		}

		writer = file
	}

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.AddSource,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && cfg.Format == "text" {
				return slog.String(slog.TimeKey, a.Value.Time().Format(cfg.TimeFormat))
			}

			return a
		},
	}

	var handler slog.Handler
	switch cfg.Format {
	case "json":
		handler = slog.NewJSONHandler(writer, opts)

	case "text":
		handler = slog.NewTextHandler(writer, opts)

	default:
		return nil, &ConfigError{
			Field:       "format",
			Value:       cfg.Format,
			ValidValues: []string{"json", "text"},
		}
	}

	return &slogLogger{
		logger: slog.New(handler),
	}, nil
}

// ConfigError represents a configuration validation error.
type ConfigError struct {
	Field       string
	Value       string
	ValidValues []string
}

func (e *ConfigError) Error() string {
	return "invalid " + e.Field + " '" + e.Value +
		"', valid values: " + strings.Join(e.ValidValues, ", ")
}

// parseLevel converts a string level to slog.Level.
func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil

	case "info":
		return slog.LevelInfo, nil

	case "warn", "warning":
		return slog.LevelWarn, nil

	case "error":
		return slog.LevelError, nil

	default:
		return slog.LevelInfo, &ConfigError{
			Field:       "level",
			Value:       level,
			ValidValues: []string{"debug", "info", "warn", "error"},
		}
	}
}

// Implementation of Logger interface for slogLogger

// Debug logs a debug message with optional key-value pairs.
func (l *slogLogger) Debug(msg string, keysAndValues ...any) {
	l.logger.Debug(msg, keysAndValues...)
}

// DebugContext logs a debug message with context and optional key-value pairs.
func (l *slogLogger) DebugContext(ctx context.Context,
	msg string, keysAndValues ...any) {
	l.logger.DebugContext(ctx, msg, keysAndValues...)
}

// Info logs an info message with optional key-value pairs.
func (l *slogLogger) Info(msg string, keysAndValues ...any) {
	l.logger.Info(msg, keysAndValues...)
}

// InfoContext logs an info message with context and optional key-value pairs.
func (l *slogLogger) InfoContext(ctx context.Context,
	msg string, keysAndValues ...any) {
	l.logger.InfoContext(ctx, msg, keysAndValues...)
}

// Warn logs a warning message with optional key-value pairs.
func (l *slogLogger) Warn(msg string, keysAndValues ...any) {
	l.logger.Warn(msg, keysAndValues...)
}

// WarnContext logs a warning message with context and optional key-value pairs.
func (l *slogLogger) WarnContext(ctx context.Context,
	msg string, keysAndValues ...any) {
	l.logger.WarnContext(ctx, msg, keysAndValues...)
}

// Error logs an error message with optional key-value pairs.
func (l *slogLogger) Error(msg string, keysAndValues ...any) {
	l.logger.Error(msg, keysAndValues...)
}

// ErrorContext logs an error message with context and optional key-value pairs.
func (l *slogLogger) ErrorContext(ctx context.Context,
	msg string, keysAndValues ...any) {
	l.logger.ErrorContext(ctx, msg, keysAndValues...)
}

// Fatal logs a fatal message and terminates the application.
func (l *slogLogger) Fatal(msg string, keysAndValues ...any) {
	l.logger.Error(msg, keysAndValues...)
	os.Exit(1)
}

// With returns a new logger instance with the given key-value pairs
// permanently attached to all future log messages.
func (l *slogLogger) With(keysAndValues ...any) Logger {
	return &slogLogger{
		logger: l.logger.With(keysAndValues...),
	}
}

// WithGroup returns a new logger instance that groups all future
// log messages under the given group name.
func (l *slogLogger) WithGroup(name string) Logger {
	return &slogLogger{
		logger: l.logger.WithGroup(name),
	}
}
