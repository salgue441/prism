// Package logger provides a high-performance, structured logging interface
// with multiple backend implementations for Go applications.
//
// # Overview
//
// This package offers a unified logging interface that abstracts away the
// underlying logging implementation, allowing applications to switch between
// different logging backends without changing application code.
//
// The logger is designed with performance in mind, using the standard
// library's slog package by default, which provides zero-allocation logging
// for many common use cases.
//
// # Key Features
//
//   - Structured logging with key-value pairs
//   - Context-aware logging for request tracing
//   - Multiple output formats (JSON, text)
//   - Configurable log levels and outputs
//   - High performance with minimal allocations
//   - Thread-safe operations
//   - Persistent field attachment
//   - Log grouping for better organization
//
// # Basic Usage
//
//	// Create a logger with default configuration
//	logger, err := logger.New(logger.Config{
//	  Level: "info",
//	  Format: "json",
//	  Output: "stdout",
//	})
//
//	if err != nil {
//	  log.Fatal(err)
//	}
//
//	// Simple logging
//	logger.Info("application started")
//
//	// Structured logging with fields
//	logger.Info("user logged in",
//	  "user_id", 12345,
//	  "email", "user@example.com",
//	  "ip", "192.168.1.1")
//
//	// Context-aware logging
//	ctx := context.WithValue(context.Backgound(), "request_id", "req-123")
//	logger.InfoContext(ctx, "processing request")
//
// # Advanced Usage
//
//	// Create logger with persistent fields
//	serviceLogger := logger.With(
//	  "service", "api-gateway",
//	  "version", "1.2.3",
//	)
//
//	// Group related fields
//	httpLogger := serviceLogger.WithGroup("http")
//	httpLogger.Info("request received",
//	  "method", "GET",
//	  "path", "/api/users",
//	  "status", 200,
//	)
//
// # Configuration
//
// The logger supports various coniguration options:
//
//   - Level: debug, info, warn, error
//   - Format: json, text
//   - Output: stdout, stderr, or file path
//   - AddSource: Include source code location (development only)
//   - TimeFormat: Custom time format for text output
//
// # Performance Considerations
//
// The logger is optimized for performance:
//
//   - Uses slog's zero-allocation APIs where possible
//   - Lazy evaluation of expensive operations
//   - Efficient JSON encoding
//   - Minimal memory allocations for hot paths
//
// For maximum performance in production:
//
//   - Set level to "info" or higher
//   - Use JSON format for better parsing performance
//   - Disable AddSource (has significant overhead)
//   - Use persistent loggers with With() for repeated fields
//
// # Error Handling
//
// The package defines custom error types for better error handling:
//
//	logger, err := logger.New(invalidConfig)
//	if err != nil {
//	  var configErr *logger.ConfigError
//	  if errors.As(err, &configErr) {
//	    fmt.Printf("Invalid %s: %s\n", configErr.Field, configErr.Value)
//	  }
//	}
//
// # Best Practices
//
//   - Use structured logging with key-value pairs instead of formatted strings
//   - Include relevant context in log messages (user_id, request_id, etc.)
//   - Use appropriate log levels (debug for debugging, info for general info, etc.)
//   - Create service-specific loggers with persistent fields
//   - Use context-aware logging for request tracing
//   - Avoid logging sensitive information (passwords, tokens, etc.)
//   - Use log grouping to organize related fields
//
// # Thread Safety
//
// All logger implementations are thread-safe and can be used concurrently
// from multiple goroutines without additional synchronization.
package logger
