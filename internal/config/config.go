// Package config provides application configuration management with
// environment variable overrides and validation.
//
// This package handles loading configuration from multiple sources
// (files, environment variables) and provides a validated configuration
// structure for the entire application.

package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config represents the complete application configuration.
// It aggregates all configuration sections and provides validation.
type Config struct {
	Server     ServerConfig     `mapstructure:"server" json:"server" yaml:"server"`
	Redis      RedisConfig      `mapstructure:"redis" json:"redis" yaml:"redis"`
	Logging    LoggingConfig    `mapstructure:"logging" json:"logging" yaml:"logging"`
	Monitoring MonitoringConfig `mapstructure:"monitoring" json:"monitoring" yaml:"monitoring"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	// Host is the interface to bind the server to.
	// Use "0.0.0.0" to bind to all interfaces.
	Host string `mapstructure:"host" json:"host" yaml:"host"`

	// Port is the TCP port number to listen on.
	Port int `mapstructure:"port" json:"port" yaml:"port"`

	// ReadTimeout is the maximum duration for reading the entire request.
	ReadTimeout time.Duration `mapstructure:"read_timeout" json:"read_timeout" yaml:"read_timeout"`

	// WriteTimeout is the maximum duration before timing out writes.
	WriteTimeout time.Duration `mapstructure:"write_timeout" json:"write_timeout" yaml:"write_timeout"`

	// IdleTimeout is the maximum amount of time to wait for the next request.
	IdleTimeout time.Duration `mapstructure:"idle_timeout" json:"idle_timeout" yaml:"idle_timeout"`

	// GracefulTimeout is the maximum time to wait for graceful shutdown.
	GracefulTimeout time.Duration `mapstructure:"graceful_timeout" json:"graceful_timeout" yaml:"graceful_timeout"`
}

// RedisConfig holds Redis connection configuration.
type RedisConfig struct {
	// Host is the Redis server hostname or IP address.
	Host string `mapstructure:"host" json:"host" yaml:"host"`

	// Port is the Redis server port number.
	Port int `mapstructure:"port" json:"port" yaml:"port"`

	// Password for Redis authentication. Leave empty if no auth required.
	Password string `mapstructure:"password" json:"password,omitempty" yaml:"password,omitempty"`

	// DB is the Redis database number to select.
	DB int `mapstructure:"db" json:"db" yaml:"db"`

	// PoolSize is the maximum number of socket connections.
	PoolSize int `mapstructure:"pool_size" json:"pool_size" yaml:"pool_size"`

	// MinIdleConns is the minimum number of idle connections.
	MinIdleConns int `mapstructure:"min_idle_conns" json:"min_idle_conns" yaml:"min_idle_conns"`

	// ConnectTimeout is the timeout for connecting to Redis.
	ConnectTimeout time.Duration `mapstructure:"connect_timeout" json:"connect_timeout" yaml:"connect_timeout"`

	// ReadTimeout is the timeout for reading from Redis.
	ReadTimeout time.Duration `mapstructure:"read_timeout" json:"read_timeout" yaml:"read_timeout"`

	// WriteTimeout is the timeout for writing to Redis.
	WriteTimeout time.Duration `mapstructure:"write_timeout" json:"write_timeout" yaml:"write_timeout"`
}

// LoggingConfig holds logging configuration.
type LoggingConfig struct {
	// Level sets the minimum log level (debug, info, warn, error).
	Level string `mapstructure:"level" json:"level" yaml:"level"`

	// Format sets the log output format (json, text).
	Format string `mapstructure:"format" json:"format" yaml:"format"`

	// Output sets the log output destination (stdout, stderr, file path).
	Output string `mapstructure:"output" json:"output" yaml:"output"`

	// AddSource adds source code location to log entries.
	// This has performance overhead and should be disabled in production.
	AddSource bool `mapstructure:"add_source" json:"add_source" yaml:"add_source"`
}

// MonitoringConfig holds monitoring and observability configuration.
type MonitoringConfig struct {
	// MetricsEnabled enables Prometheus metrics collection.
	MetricsEnabled bool `mapstructure:"metrics_enabled" json:"metrics_enabled" yaml:"metrics_enabled"`

	// MetricsPath is the HTTP path for metrics endpoint.
	MetricsPath string `mapstructure:"metrics_path" json:"metrics_path" yaml:"metrics_path"`

	// HealthCheckPath is the HTTP path for health check endpoint.
	HealthCheckPath string `mapstructure:"health_check_path" json:"health_check_path" yaml:"health_check_path"`
}

// Load reads configuration from file and environment variables.
// It returns a validated Config struct or an error if the configuration is
// invalid.
//
// Configuration loading precedence (highest to lowest):
//  1. Environment variables (prefixed with GATEWAY_)
//  2. Configuration file
//  3. Default values
//
// Example usage:
//
//	config, err := config.Load()
//	if err != nil {
//		log.Fatal("Failed to load configuration:", err)
//	}
func Load() (*Config, error) {
	v := viper.New()

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./configs")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/gateway")
	v.SetEnvPrefix("GATEWAY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	setDefaults(v)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// setDefaults configures default values for all configuration options.
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("server.idle_timeout", "60s")
	v.SetDefault("server.graceful_timeout", "10s")

	// Redis defaults
	v.SetDefault("redis.host", "localhost")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.pool_size", 10)
	v.SetDefault("redis.min_idle_conns", 5)
	v.SetDefault("redis.connect_timeout", "5s")
	v.SetDefault("redis.read_timeout", "3s")
	v.SetDefault("redis.write_timeout", "3s")

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")
	v.SetDefault("logging.add_source", false)

	// Monitoring defaults
	v.SetDefault("monitoring.metrics_enabled", true)
	v.SetDefault("monitoring.metrics_path", "/metrics")
	v.SetDefault("monitoring.health_check_path", "/health")
}

// Validate performs comprehensive validation of the configuration.
// It returns an error if any configuration value is invalid.
func (c *Config) Validate() error {
	if err := c.Server.Validate(); err != nil {
		return fmt.Errorf("server config: %w", err)
	}

	if err := c.Redis.Validate(); err != nil {
		return fmt.Errorf("redis config: %w", err)
	}

	if err := c.Logging.Validate(); err != nil {
		return fmt.Errorf("logging config: %w", err)
	}

	if err := c.Monitoring.Validate(); err != nil {
		return fmt.Errorf("monitoring config: %w", err)
	}

	return nil
}

// Validate validates server configuration.
func (sc *ServerConfig) Validate() error {
	if sc.Port < 1 || sc.Port > 65535 {
		return &ValidationError{
			Field:   "port",
			Value:   fmt.Sprintf("%d", sc.Port),
			Message: "must be between 1 and 65535",
		}
	}

	if sc.ReadTimeout <= 0 {
		return &ValidationError{
			Field:   "read_timeout",
			Value:   sc.ReadTimeout.String(),
			Message: "must be positive",
		}
	}

	if sc.WriteTimeout <= 0 {
		return &ValidationError{
			Field:   "write_timeout",
			Value:   sc.WriteTimeout.String(),
			Message: "must be positive",
		}
	}

	if sc.IdleTimeout <= 0 {
		return &ValidationError{
			Field:   "idle_timeout",
			Value:   sc.IdleTimeout.String(),
			Message: "must be positive",
		}
	}

	if sc.GracefulTimeout <= 0 {
		return &ValidationError{
			Field:   "graceful_timeout",
			Value:   sc.GracefulTimeout.String(),
			Message: "must be positive",
		}
	}

	return nil
}

// Validate validates Redis configuration.
func (rc *RedisConfig) Validate() error {
	if rc.Host == "" {
		return &ValidationError{
			Field:   "host",
			Value:   rc.Host,
			Message: "cannot be empty",
		}
	}

	if rc.Port < 1 || rc.Port > 65535 {
		return &ValidationError{
			Field:   "port",
			Value:   fmt.Sprintf("%d", rc.Port),
			Message: "must be between 1 and 65535",
		}
	}

	if rc.DB < 0 || rc.DB > 15 {
		return &ValidationError{
			Field:   "db",
			Value:   fmt.Sprintf("%d", rc.DB),
			Message: "must be between 0 and 15",
		}
	}

	if rc.PoolSize < 1 {
		return &ValidationError{
			Field:   "pool_size",
			Value:   fmt.Sprintf("%d", rc.PoolSize),
			Message: "must be at least 1",
		}
	}

	if rc.MinIdleConns < 0 {
		return &ValidationError{
			Field:   "min_idle_conns",
			Value:   fmt.Sprintf("%d", rc.MinIdleConns),
			Message: "cannot be negative",
		}
	}

	if rc.MinIdleConns > rc.PoolSize {
		return &ValidationError{
			Field:   "min_idle_conns",
			Value:   fmt.Sprintf("%d", rc.MinIdleConns),
			Message: "cannot be greater than pool_size",
		}
	}

	if rc.ConnectTimeout <= 0 {
		return &ValidationError{
			Field:   "connect_timeout",
			Value:   rc.ConnectTimeout.String(),
			Message: "must be positive",
		}
	}

	if rc.ReadTimeout <= 0 {
		return &ValidationError{
			Field:   "read_timeout",
			Value:   rc.ReadTimeout.String(),
			Message: "must be positive",
		}
	}

	if rc.WriteTimeout <= 0 {
		return &ValidationError{
			Field:   "write_timeout",
			Value:   rc.WriteTimeout.String(),
			Message: "must be positive",
		}
	}

	return nil
}

// Validate validates logging configuration.
func (lc *LoggingConfig) Validate() error {
	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}

	if !validLevels[strings.ToLower(lc.Level)] {
		return &ValidationError{
			Field:   "level",
			Value:   lc.Level,
			Message: "must be one of: debug, info, warn, error",
		}
	}

	validFormats := map[string]bool{
		"json": true,
		"text": true,
	}

	if !validFormats[strings.ToLower(lc.Format)] {
		return &ValidationError{
			Field:   "format",
			Value:   lc.Format,
			Message: "must be one of: json, text",
		}
	}

	if lc.Output == "" {
		return &ValidationError{
			Field:   "output",
			Value:   lc.Output,
			Message: "cannot be empty",
		}
	}

	return nil
}

// Validate validates monitoring configuration.
func (mc *MonitoringConfig) Validate() error {
	if mc.MetricsPath == "" {
		return &ValidationError{
			Field:   "metrics_path",
			Value:   mc.MetricsPath,
			Message: "cannot be empty",
		}
	}

	if mc.HealthCheckPath == "" {
		return &ValidationError{
			Field:   "health_check_path",
			Value:   mc.HealthCheckPath,
			Message: "cannot be empty",
		}
	}

	if mc.MetricsPath == mc.HealthCheckPath {
		return &ValidationError{
			Field:   "metrics_path",
			Value:   mc.MetricsPath,
			Message: "cannot be the same as health_check_path",
		}
	}

	return nil
}

// ValidationError represents a configuration validation error.
type ValidationError struct {
	Field   string
	Value   string
	Message string
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid %s '%s': %s", e.Field, e.Value, e.Message)
}

// RedisAddr returns the Redis address in host:port format.
func (rc *RedisConfig) RedisAddr() string {
	return fmt.Sprintf("%s:%d", rc.Host, rc.Port)
}

// ServerAddr returns the server address in host:port format.
func (sc *ServerConfig) ServerAddr() string {
	return fmt.Sprintf("%s:%d", sc.Host, sc.Port)
}
