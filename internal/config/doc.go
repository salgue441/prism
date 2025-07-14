// Package config provides comprehensive configuration management for the
// reverse API gateway.
//
// # Overview
//
// The config package handles loading, validation, and management of
// application configuration from multiple sources including configuration
// files, environment variables, and defaults.
//
// It provides a type-safe, validated configuration structure that can be used
// throughout the application.
//
// # Key Features
//
//   - Multiple configuration sources with precedence handling
//   - Comprehensive validation with detailed error messages
//   - Environment variable override support
//   - Type-safe configuration structures
//   - Performance optimized loading and validation
//   - Production-ready default values
//
// # Configuration Sources
//
// Configuration is loaded from multiple sources in the following order of
// precedence (highest to lowest):
//
//  1. Environment variables (prefixed with PRISM_)
//  2. Configuration file (YAML format)
//  3. Default values
//
// # Basic Usage
//
//	// Load configuration with defaults and environment overrides
//	config, err := config.Load()
//	if err != nil {
//		log.Fatal("Failed to load configuration:", err)
//	}
//
//	// Access configuration sections
//	fmt.Printf("Server listening on %s\n", config.Server.ServerAddr())
//	fmt.Printf("Redis connection: %s\n", config.Redis.RedisAddr())
//
// # Environment Variables
//
// All configuration options can be overridden using environment variables with
// the PRISM_ prefix. Nested configuration keys use underscores for separation.
//
// Examples:
//
//	PRISM_SERVER_PORT=9090                 # server.port
//	PRISM_SERVER_HOST=127.0.0.1            # server.host
//	PRISM_REDIS_HOST=redis.example.com     # redis.host
//	PRISM_REDIS_PORT=6380                  # redis.port
//	PRISM_LOGGING_LEVEL=debug              # logging.level
//	PRISM_MONITORING_METRICS_ENABLED=false # monitoring.metrics_enabled
//
// # Configuration Structure
//
// The configuration is organized into logical sections:
//
//   - Server: HTTP server configuration (host, port, timeouts)
//   - Redis: Redis connection and pool configuration
//   - Logging: Log level, format, and output configuration
//   - Monitoring: Health check and metrics configuration
//
// # Validation
//
// All configuration values are validated during loading to ensure:
//
//   - Ports are within valid range (1-65535)
//   - Timeouts are positive durations
//   - Required fields are not empty
//   - Enum values are from valid sets
//   - Cross-field validation (e.g., min_idle_conns ≤ pool_size)
//
// # Error Handling
//
// The package provides detailed error information for configuration issues:
//
//		config, err := config.Load()
//		if err != nil {
//			var validationErr *config.ValidationError
//			if errors.As(err, &validationErr) {
//				fmt.Printf("Invalid %s: %s\n",
//	       validationErr.Field, validationErr.Message)
//			}
//		}
//
// # Configuration File Format
//
// Configuration files use YAML format and support all configuration options:
//
//	server:
//	  host: "0.0.0.0"
//	  port: 8080
//	  read_timeout: "30s"
//	  write_timeout: "30s"
//	  idle_timeout: "60s"
//	  graceful_timeout: "10s"
//
//	redis:
//	  host: "localhost"
//	  port: 6379
//	  password: ""
//	  db: 0
//	  pool_size: 10
//	  min_idle_conns: 5
//	  connect_timeout: "5s"
//	  read_timeout: "3s"
//	  write_timeout: "3s"
//
//	logging:
//	  level: "info"           # debug, info, warn, error
//	  format: "json"          # json, text
//	  output: "stdout"        # stdout, stderr, or file path
//	  add_source: false       # include source location (dev only)
//
//	monitoring:
//	  metrics_enabled: true
//	  metrics_path: "/metrics"
//	  health_check_path: "/health"
//
// # Default Values
//
// The package provides sensible defaults for all configuration options:
//
//   - Server: Listens on 0.0.0.0:8080 with 30s timeouts
//   - Redis: Connects to localhost:6379 with 10 connection pool
//   - Logging: Info level, JSON format to stdout
//   - Monitoring: Metrics enabled on /metrics, health on /health
//
// # Performance Considerations
//
// Configuration loading is optimized for performance:
//
//   - Validation is performed once during load
//   - Configuration is immutable after loading
//   - No reflection or dynamic type conversion during runtime
//   - Efficient string parsing for durations and enums
//
// For high-performance applications, load configuration once at startup
// and pass the Config struct to components that need it.
//
// # Production Usage
//
// For production deployments:
//
//   - Use environment variables for sensitive values (Redis password)
//   - Set appropriate timeouts for your infrastructure
//   - Disable logging.add_source for performance
//   - Use JSON logging format for log aggregation
//   - Configure appropriate connection pool sizes
//
// # Thread Safety
//
// The Config struct and all its fields are read-only after loading,
// making them safe for concurrent access across goroutines without
// additional synchronization.
//
// # Extending Configuration
//
// To add new configuration sections:
//
//  1. Define a new struct with appropriate tags
//  2. Add it to the Config struct
//  3. Implement a Validate() method
//  4. Add default values in setDefaults()
//  5. Add validation to Config.Validate()
//
// Example:
//
//	type JWTConfig struct {
//		Secret     string        `mapstructure:"secret" json:"secret" yaml:"secret"`
//		Expiration time.Duration `mapstructure:"expiration" json:"expiration" yaml:"expiration"`
//	}
//
//	func (jc *JWTConfig) Validate() error {
//		if jc.Secret == "" {
//			return &ValidationError{Field: "secret", Message: "cannot be empty"}
//		}
//		return nil
//	}
package config
