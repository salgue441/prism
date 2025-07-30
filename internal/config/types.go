package config

import (
	"errors"
	"sync"
	"time"
)

// Configuration errors for precise error handling and debugging.
var (
	// ErrInvalidPort indicates an invalid port number was provided.
	ErrInvalidPort = errors.New("port must be between 1 and 65535")

	// ErrEmptyHost indicates an empty host was provided.
	ErrEmptyHost = errors.New("host cannot be empty")

	// ErrInvalidLogLevel indicates an invalid log level was provided.
	ErrInvalidLogLevel = errors.New("invalid log level")

	// ErrInvalidLogFormat indicates an invalid log format was provided.
	ErrInvalidLogFormat = errors.New("invalid log format")

	// ErrTLSConfigIncomplete indicates incomplete TLS configuration.
	ErrTLSConfigIncomplete = errors.New("TLS enabled but certificate or key file missing")

	// ErrPortConflict indicates a port conflict between services.
	ErrPortConflict = errors.New("port conflict detected")

	// ErrInvalidIPAddress indicates an invalid IP address format.
	ErrInvalidIPAddress = errors.New("invalid IP address format")

	// ErrInvalidCIDR indicates an invalid CIDR range format.
	ErrInvalidCIDR = errors.New("invalid CIDR range format")

	// ErrFileNotAccessible indicates a configuration file is not accessible.
	ErrFileNotAccessible = errors.New("configuration file not accessible")

	// ErrInvalidTimeout indicates an invalid timeout duration.
	ErrInvalidTimeout = errors.New("invalid timeout duration")

	// ErrInvalidRateLimit indicates invalid rate limiting configuration.
	ErrInvalidRateLimit = errors.New("invalid rate limiting configuration")
)

// Config represents the complete application configuration with thread-safe
// access. All fields are validated during load and safe for concurrent read
// access.
type Config struct {
	// mu protects concurrent access to configuration fields
	mu sync.RWMutex

	// Core service configurations
	Server      ServerConfig      `mapstructure:"server" json:"server" validate:"required"`
	Logging     LoggingConfig     `mapstructure:"logging" json:"logging" validate:"required"`
	Health      HealthConfig      `mapstructure:"health" json:"health" validate:"required"`
	Metrics     MetricsConfig     `mapstructure:"metrics" json:"metrics" validate:"required"`
	CORS        CORSConfig        `mapstructure:"cors" json:"cors" validate:"required"`
	Security    SecurityConfig    `mapstructure:"security" json:"security" validate:"required"`
	Development DevelopmentConfig `mapstructure:"development" json:"development" validate:"required"`

	// Runtime metadata (not serialized)
	loadTime   time.Time `json:"-"`
	configPath string    `json:"-"`
	version    string    `json:"-"`
}

// ServerConfig holds server-specific configuration with performance optimizations.
// These settings directly impact connection handling and request processing performance.
type ServerConfig struct {
	// Network binding configuration
	Host string `mapstructure:"host" json:"host" validate:"required"`
	Port int    `mapstructure:"port" json:"port" validate:"required,min=1,max=65535"`

	// Connection timeout configurations optimized for high-throughput
	ReadTimeout       time.Duration `mapstructure:"read_timeout" json:"read_timeout" validate:"required,min=1s"`
	WriteTimeout      time.Duration `mapstructure:"write_timeout" json:"write_timeout" validate:"required,min=1s"`
	IdleTimeout       time.Duration `mapstructure:"idle_timeout" json:"idle_timeout" validate:"required,min=1s"`
	ReadHeaderTimeout time.Duration `mapstructure:"read_header_timeout" json:"read_header_timeout" validate:"min=1s"`

	// Request size and connection limits for security and performance
	MaxHeaderBytes     int  `mapstructure:"max_header_bytes" json:"max_header_bytes" validate:"required,min=1024"`
	MaxRequestBodySize int  `mapstructure:"max_request_body_size" json:"max_request_body_size" validate:"min=1024"`
	KeepAlivesEnabled  bool `mapstructure:"keep_alives_enabled" json:"keep_alives_enabled"`

	// HTTP/2 specific configurations for modern protocols
	MaxConcurrentStreams uint32 `mapstructure:"max_concurrent_streams" json:"max_concurrent_streams" validate:"min=1"`
	MaxReadFrameSize     uint32 `mapstructure:"max_read_frame_size" json:"max_read_frame_size" validate:"min=16384"`

	// Connection pool settings for backend services
	MaxIdleConns        int           `mapstructure:"max_idle_conns" json:"max_idle_conns" validate:"min=1"`
	MaxIdleConnsPerHost int           `mapstructure:"max_idle_conns_per_host" json:"max_idle_conns_per_host" validate:"min=1"`
	IdleConnTimeout     time.Duration `mapstructure:"idle_conn_timeout" json:"idle_conn_timeout" validate:"min=1s"`

	// TLS configuration for secure connections
	TLS TLSConfig `mapstructure:"tls" json:"tls" validate:"required"`

	// Graceful shutdown configuration
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout" json:"shutdown_timeout" validate:"min=1s"`
}

// TLSConfig holds TLS/SSL configuration with security validations.
// Implements security best practices and modern cipher suite preferences.
type TLSConfig struct {
	// Basic TLS enablement
	Enabled bool `mapstructure:"enabled" json:"enabled"`

	// Certificate and key file paths with validation
	CertFile string `mapstructure:"cert_file" json:"cert_file"`
	KeyFile  string `mapstructure:"key_file" json:"key_file"`

	// TLS version control for security compliance
	MinVersion string `mapstructure:"min_version" json:"min_version" validate:"oneof=1.2 1.3"`
	MaxVersion string `mapstructure:"max_version" json:"max_version" validate:"oneof=1.2 1.3"`

	// Cipher suite configuration for TLS < 1.3
	CipherSuites []string `mapstructure:"cipher_suites" json:"cipher_suites"`

	// Client certificate authentication modes
	ClientAuth string `mapstructure:"client_auth" json:"client_auth" validate:"oneof=NoClientCert RequestClientCert RequireAnyClientCert VerifyClientCertIfGiven RequireAndVerifyClientCert"`

	// Certificate authority for client cert verification
	ClientCAFile string `mapstructure:"client_ca_file" json:"client_ca_file"`

	// OCSP and certificate transparency
	EnableOCSPStapling bool `mapstructure:"enable_ocsp_stapling" json:"enable_ocsp_stapling"`

	// Session resumption and performance
	SessionTicketKey string        `mapstructure:"session_ticket_key" json:"session_ticket_key"`
	SessionTimeout   time.Duration `mapstructure:"session_timeout" json:"session_timeout"`
}

// LoggingConfig holds logging configuration with structured output support.
// Optimized for high-volume logging with sampling and performance controls.
type LoggingConfig struct {
	// Basic logging configuration
	Level  string `mapstructure:"level" json:"level" validate:"required,oneof=trace debug info warn error fatal panic"`
	Format string `mapstructure:"format" json:"format" validate:"required,oneof=json text"`
	Output string `mapstructure:"output" json:"output" validate:"required"`

	// File rotation configuration for file-based logging
	MaxSize    int  `mapstructure:"max_size" json:"max_size" validate:"min=1"`
	MaxBackups int  `mapstructure:"max_backups" json:"max_backups" validate:"min=0"`
	MaxAge     int  `mapstructure:"max_age" json:"max_age" validate:"min=1"`
	Compress   bool `mapstructure:"compress" json:"compress"`

	// Performance and sampling configuration
	SamplingRate  float64       `mapstructure:"sampling_rate" json:"sampling_rate" validate:"min=0,max=1"`
	BufferSize    int           `mapstructure:"buffer_size" json:"buffer_size" validate:"min=0"`
	FlushInterval time.Duration `mapstructure:"flush_interval" json:"flush_interval" validate:"min=100ms"`

	// Security and privacy settings
	SanitizeFields bool     `mapstructure:"sanitize_fields" json:"sanitize_fields"`
	RedactedFields []string `mapstructure:"redacted_fields" json:"redacted_fields"`
	MaxFieldSize   int      `mapstructure:"max_field_size" json:"max_field_size" validate:"min=0"`

	// Structured logging enhancements
	EnableCaller     bool `mapstructure:"enable_caller" json:"enable_caller"`
	EnableStackTrace bool `mapstructure:"enable_stack_trace" json:"enable_stack_trace"`
}

// HealthConfig holds health check endpoint configuration.
// Supports both simple liveness checks and detailed readiness probes.
type HealthConfig struct {
	// Basic health check configuration
	Enabled bool   `mapstructure:"enabled" json:"enabled"`
	Path    string `mapstructure:"path" json:"path" validate:"required,startswith=/"`

	// Health check timing configuration
	Timeout  time.Duration `mapstructure:"timeout" json:"timeout" validate:"min=100ms"`
	Interval time.Duration `mapstructure:"interval" json:"interval" validate:"min=1s"`

	// Detailed health checking
	EnableDetailedChecks bool     `mapstructure:"enable_detailed_checks" json:"enable_detailed_checks"`
	CheckedServices      []string `mapstructure:"checked_services" json:"checked_services"`

	// Readiness vs liveness probe configuration
	ReadinessPath    string        `mapstructure:"readiness_path" json:"readiness_path"`
	ReadinessTimeout time.Duration `mapstructure:"readiness_timeout" json:"readiness_timeout"`

	// Health check caching for performance
	CacheTimeout time.Duration `mapstructure:"cache_timeout" json:"cache_timeout"`
}

// MetricsConfig holds Prometheus metrics configuration.
// Optimized for high-cardinality metrics collection with performance controls.
type MetricsConfig struct {
	// Basic metrics configuration
	Enabled bool   `mapstructure:"enabled" json:"enabled"`
	Path    string `mapstructure:"path" json:"path" validate:"required,startswith=/"`
	Port    int    `mapstructure:"port" json:"port" validate:"min=0,max=65535"`

	// Metrics organization and naming
	Namespace string `mapstructure:"namespace" json:"namespace" validate:"required"`
	Subsystem string `mapstructure:"subsystem" json:"subsystem"`

	// Performance and cardinality controls
	EnableHighCardinalityMetrics bool          `mapstructure:"enable_high_cardinality_metrics" json:"enable_high_cardinality_metrics"`
	MetricsTTL                   time.Duration `mapstructure:"metrics_ttl" json:"metrics_ttl"`
	MaxMetricsAge                time.Duration `mapstructure:"max_metrics_age" json:"max_metrics_age"`

	// Collection intervals and batching
	CollectionInterval time.Duration `mapstructure:"collection_interval" json:"collection_interval"`
	BatchSize          int           `mapstructure:"batch_size" json:"batch_size" validate:"min=1"`

	// Security configuration for metrics endpoint
	EnableAuth      bool     `mapstructure:"enable_auth" json:"enable_auth"`
	AllowedIPs      []string `mapstructure:"allowed_ips" json:"allowed_ips"`
	SecureTransport bool     `mapstructure:"secure_transport" json:"secure_transport"`
}

// CORSConfig holds Cross-Origin Resource Sharing configuration.
// Implements security-first CORS policy with fine-grained control.
type CORSConfig struct {
	// Basic CORS enablement
	Enabled bool `mapstructure:"enabled" json:"enabled"`

	// Origin control with wildcard and specific domain support
	AllowedOrigins  []string `mapstructure:"allowed_origins" json:"allowed_origins"`
	AllowOriginFunc string   `mapstructure:"allow_origin_func" json:"allow_origin_func"`

	// HTTP method and header control
	AllowedMethods []string `mapstructure:"allowed_methods" json:"allowed_methods"`
	AllowedHeaders []string `mapstructure:"allowed_headers" json:"allowed_headers"`
	ExposedHeaders []string `mapstructure:"exposed_headers" json:"exposed_headers"`

	// Credential and caching configuration
	AllowCredentials bool          `mapstructure:"allow_credentials" json:"allow_credentials"`
	MaxAge           time.Duration `mapstructure:"max_age" json:"max_age" validate:"min=0"`

	// Advanced CORS security features
	AllowPrivateNetwork bool `mapstructure:"allow_private_network" json:"allow_private_network"`
	VaryHeader          bool `mapstructure:"vary_header" json:"vary_header"`
	OptionsPassthrough  bool `mapstructure:"options_passthrough" json:"options_passthrough"`
	AllowWebSockets     bool `mapstructure:"allow_websockets" json:"allow_websockets"`

	// Debug and development features
	Debug bool `mapstructure:"debug" json:"debug"`
}

// SecurityConfig holds comprehensive security-related configuration.
// Implements defense-in-depth security controls and threat mitigation.
type SecurityConfig struct {
	// Rate limiting configuration
	RateLimiting RateLimitConfig `mapstructure:"rate_limiting" json:"rate_limiting"`

	// Request size and validation limits
	MaxRequestSize int64         `mapstructure:"max_request_size" json:"max_request_size" validate:"min=1024"`
	MaxURILength   int           `mapstructure:"max_uri_length" json:"max_uri_length" validate:"min=1"`
	MaxQueryParams int           `mapstructure:"max_query_params" json:"max_query_params" validate:"min=1"`
	RequestTimeout time.Duration `mapstructure:"request_timeout" json:"request_timeout" validate:"min=1s"`

	// Network access controls
	TrustedProxies []string `mapstructure:"trusted_proxies" json:"trusted_proxies"`
	IPWhitelist    []string `mapstructure:"ip_whitelist" json:"ip_whitelist"`
	IPBlacklist    []string `mapstructure:"ip_blacklist" json:"ip_blacklist"`

	// HTTP security headers
	EnableHSTS     bool `mapstructure:"enable_hsts" json:"enable_hsts"`
	HSTSMaxAge     int  `mapstructure:"hsts_max_age" json:"hsts_max_age" validate:"min=0"`
	HSTSSubdomains bool `mapstructure:"hsts_subdomains" json:"hsts_subdomains"`
	HSTSPreload    bool `mapstructure:"hsts_preload" json:"hsts_preload"`

	EnableCSP     bool   `mapstructure:"enable_csp" json:"enable_csp"`
	CSPDirectives string `mapstructure:"csp_directives" json:"csp_directives"`
	CSPReportOnly bool   `mapstructure:"csp_report_only" json:"csp_report_only"`
	CSPReportURI  string `mapstructure:"csp_report_uri" json:"csp_report_uri"`

	EnableFrameDeny          bool   `mapstructure:"enable_frame_deny" json:"enable_frame_deny"`
	EnableContentTypeNoSniff bool   `mapstructure:"enable_content_type_nosniff" json:"enable_content_type_nosniff"`
	EnableXSSProtection      bool   `mapstructure:"enable_xss_protection" json:"enable_xss_protection"`
	EnableReferrerPolicy     bool   `mapstructure:"enable_referrer_policy" json:"enable_referrer_policy"`
	ReferrerPolicy           string `mapstructure:"referrer_policy" json:"referrer_policy"`

	// Authentication and authorization
	RequireAuth      bool          `mapstructure:"require_auth" json:"require_auth"`
	AuthExcludePaths []string      `mapstructure:"auth_exclude_paths" json:"auth_exclude_paths"`
	SessionTimeout   time.Duration `mapstructure:"session_timeout" json:"session_timeout"`

	// Input validation and sanitization
	EnableInputValidation bool     `mapstructure:"enable_input_validation" json:"enable_input_validation"`
	SanitizeInput         bool     `mapstructure:"sanitize_input" json:"sanitize_input"`
	BlockedPatterns       []string `mapstructure:"blocked_patterns" json:"blocked_patterns"`
	AllowedFileTypes      []string `mapstructure:"allowed_file_types" json:"allowed_file_types"`
}

// RateLimitConfig holds rate limiting configuration with multiple algorithms.
// Supports various rate limiting strategies optimized for different use cases.
type RateLimitConfig struct {
	// Basic rate limiting configuration
	Enabled   bool   `mapstructure:"enabled" json:"enabled"`
	Algorithm string `mapstructure:"algorithm" json:"algorithm" validate:"oneof=token_bucket sliding_window fixed_window leaky_bucket"`

	// Rate limits and burst configuration
	RequestsPerSecond int `mapstructure:"requests_per_second" json:"requests_per_second" validate:"min=1"`
	BurstSize         int `mapstructure:"burst_size" json:"burst_size" validate:"min=1"`

	// Time window configuration for window-based algorithms
	WindowSize    time.Duration `mapstructure:"window_size" json:"window_size" validate:"min=1s"`
	SlidingWindow bool          `mapstructure:"sliding_window" json:"sliding_window"`

	// Rate limit key generation strategies
	KeyGenerators []string `mapstructure:"key_generators" json:"key_generators"`
	CustomKeyFunc string   `mapstructure:"custom_key_func" json:"custom_key_func"`

	// Conditional rate limiting
	SkipSuccessfulRequests bool     `mapstructure:"skip_successful_requests" json:"skip_successful_requests"`
	SkipFailedRequests     bool     `mapstructure:"skip_failed_requests" json:"skip_failed_requests"`
	ExcludedPaths          []string `mapstructure:"excluded_paths" json:"excluded_paths"`
	ExcludedMethods        []string `mapstructure:"excluded_methods" json:"excluded_methods"`
	ExcludedUserAgents     []string `mapstructure:"excluded_user_agents" json:"excluded_user_agents"`

	// Distributed rate limiting
	EnableDistributed bool   `mapstructure:"enable_distributed" json:"enable_distributed"`
	RedisURL          string `mapstructure:"redis_url" json:"redis_url"`
	RedisKeyPrefix    string `mapstructure:"redis_key_prefix" json:"redis_key_prefix"`

	// Rate limit response configuration
	Headers          map[string]string `mapstructure:"headers" json:"headers"`
	RetryAfterHeader bool              `mapstructure:"retry_after_header" json:"retry_after_header"`
	CustomMessage    string            `mapstructure:"custom_message" json:"custom_message"`

	// Performance and cleanup configuration
	CleanupInterval time.Duration `mapstructure:"cleanup_interval" json:"cleanup_interval"`
	MaxKeys         int           `mapstructure:"max_keys" json:"max_keys" validate:"min=1"`
}

// DevelopmentConfig holds development-specific configuration.
// These settings are automatically disabled in production for security.
type DevelopmentConfig struct {
	// Basic development features
	Debug       bool `mapstructure:"debug" json:"debug"`
	LogRequests bool `mapstructure:"log_requests" json:"log_requests"`

	// Profiling and debugging tools
	PProf     bool `mapstructure:"pprof" json:"pprof"`
	PprofPort int  `mapstructure:"pprof_port" json:"pprof_port" validate:"min=0,max=65535"`

	// Configuration management
	HotReload   bool `mapstructure:"hot_reload" json:"hot_reload"`
	ConfigWatch bool `mapstructure:"config_watch" json:"config_watch"`

	// Testing and simulation features
	MockMode        bool          `mapstructure:"mock_mode" json:"mock_mode"`
	SimulateLatency time.Duration `mapstructure:"simulate_latency" json:"simulate_latency"`
	SimulateErrors  float64       `mapstructure:"simulate_errors" json:"simulate_errors" validate:"min=0,max=1"`

	// Development server features
	EnableCORS       bool `mapstructure:"enable_cors" json:"enable_cors"`
	VerboseLogging   bool `mapstructure:"verbose_logging" json:"verbose_logging"`
	EnableStackTrace bool `mapstructure:"enable_stack_trace" json:"enable_stack_trace"`

	// API documentation and testing
	EnableSwagger    bool   `mapstructure:"enable_swagger" json:"enable_swagger"`
	SwaggerPath      string `mapstructure:"swagger_path" json:"swagger_path"`
	EnablePlayground bool   `mapstructure:"enable_playground" json:"enable_playground"`
	PlaygroundPath   string `mapstructure:"playground_path" json:"playground_path"`
}
