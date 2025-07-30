// Package config provides thread-safe configuration management for the Prism
// API Gateway.
//
// This package implements secure configuration loading, validation, and
// management with support for multiple configuration sources including files,
// environment variables, and secure defaults. All configuration access is
// thread-safe and optimized for high-performance concurrent operations.
//
// # Configuration Sources
//
// The configuration system supports multiple sources in order of precedence:
//  1. Command line flags (highest priority)
//  2. Environment variables with PRISM_ prefix
//  3. Configuration files (YAML format)
//  4. Secure defaults (lowest priority)
//
// # Security Features
//
//   - Path traversal protection for configuration files
//   - Input validation and sanitization
//   - Secure default values that follow security best practices
//   - TLS configuration validation
//   - IP address and network validation
//   - File permission and accessibility checks
//
// # Thread Safety
//
// All configuration operations are thread-safe using read-write mutexes.
// The configuration can be safely accessed from multiple goroutines without
// additional synchronization.
//
// # Performance Optimizations
//
//   - Minimal memory allocations during access
//   - Efficient validation using compile-time checks where possible
//   - Lazy loading of non-critical configuration sections
//   - Connection pooling and timeout configurations optimized for high throughput
//
// # Usage Example
//
//	cfg, err := config.Load("/etc/prism/config.yaml")
//	if err != nil {
//		log.Fatal("Failed to load configuration:", err)
//	}
//
//	// Thread-safe access
//	address := cfg.GetAddress()
//	tlsEnabled := cfg.IsTLSEnabled()
//
//	// Use configuration for server setup
//	server := http.Server{
//		Addr:         address,
//		ReadTimeout:  cfg.Server.ReadTimeout,
//		WriteTimeout: cfg.Server.WriteTimeout,
//	}
//
// # Configuration Validation
//
// The package provides comprehensive validation including:
//   - Network address validation
//   - Port conflict detection
//   - File accessibility checks
//   - TLS certificate validation
//   - Security policy enforcement
//   - Performance parameter bounds checking
//
// # Environment Variables
//
// All configuration values can be overridden using environment variables
// with the PRISM_ prefix. Nested configuration keys use underscores:
//
//	PRISM_SERVER_PORT=8080
//	PRISM_SERVER_HOST=0.0.0.0
//	PRISM_LOGGING_LEVEL=debug
//	PRISM_SECURITY_RATE_LIMITING_ENABLED=true
//
// # Hot Reloading
//
// When enabled in development mode, the configuration system supports
// hot reloading of configuration files without requiring application restart.
// This feature is automatically disabled in production for security.
package config
