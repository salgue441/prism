// Package logger provides structured logging utilities for the API gateway and 
// related applications.
//
// This package wraps Go's standard log/slog package to provide consistent,
// structured logging with sensible defaults and common configuration options.
// It's designed to be used across multiple projects while maintaining
// consistent log formatting and behavior.
//
// Features:
//
//   - JSON structured logging for production environments
//   - Human-readable logging for development
//   - Configurable log levels (Debug, Info, Warn, Error)
//   - Context-aware logging with request tracing
//   - Performance optimized with minimal allocations
//   - Thread-safe operations
//
// Log Levels:
//
//	Debug - Detailed information for debugging (includes source location)
//	Info  - General informational messages (default level)
//	Warn  - Warning messages for potentially harmful situations
//	Error - Error messages for serious problems
//
// Output Formats:
//
// The logger supports different output formats optimized for different 
// environments:
//
//   - JSON format for production (machine-readable, structured)
//   - Text format for development (human-readable, colorized)
//
// Usage Examples:
//
//	// Create a basic logger
//	log := logger.New()
//	log.Info("Server starting", slog.Int("port", 8080))
//
//	// Create logger with specific level
//	debugLog := logger.NewWithLevel(slog.LevelDebug)
//	debugLog.Debug("Debug information", slog.String("component", "router"))
//
//	// Structured logging with context
//	log.Error("Database connection failed",
//	    slog.String("database", "users"),
//	    slog.String("error", err.Error()),
//	    slog.Duration("timeout", 30*time.Second),
//	)
//
// Integration:
//
// This logger integrates seamlessly with other components of the API gateway:
//
//   - Middleware for request/response logging
//   - Error handling and panic recovery
//   - Metrics and monitoring systems
//   - Distributed tracing (future enhancement)
//
// Performance:
//
// The logger is optimized for high-throughput applications:
//
//   - Zero allocation in the hot path for common cases
//   - Efficient field encoding and serialization
//   - Minimal lock contention in concurrent scenarios
//   - Configurable buffering for batch output
//
// Configuration:
//
// Logger behavior can be configured through environment variables:
//
//	LOG_LEVEL  - Set minimum log level (debug, info, warn, error)
//	LOG_FORMAT - Set output format (json, text)
//	LOG_SOURCE - Include source file and line information (true, false)
package logger
