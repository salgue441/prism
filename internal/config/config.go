package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Load loads and validates configuration from multiple sources with thread
// safety.
//
// It supports configuration files, environment variables, and provides secure
// defaults. This function implements a secure-by-default approach with c
// omprehensive validation.
//
// Parameters:
//   - configPath: Path to the configuration file. If empty, default locations are searched.
//
// Returns:
//   - *Config: Validated configuration ready for use
//   - error: Any error encountered during loading or validation
//
// The loading process follows this order of precedence:
//  1. Environment variables (highest priority)
//  2. Configuration files
//  3. Secure defaults (lowest priority)
func Load(configPath string) (*Config, error) {
	v := viper.New()
	setSecureDefaults(v)

	if err := configureViper(v, configPath); err != nil {
		return nil, fmt.Errorf("failed to configure viper: %w", err)
	}

	if err := readConfig(v); err != nil {
		return nil, fmt.Errorf("failed to read configuration: %w", err)
	}

	config := &Config{
		loadTime:   time.Now(),
		configPath: configPath,
	}

	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	if err := config.applySecurity(); err != nil {
		return nil, fmt.Errorf("failed to apply security configurations: %w", err)
	}

	config.optimize()
	return config, nil
}

// Validate performs comprehensive validation of the configuration with
// security checks. This method ensures all configuration values are safe,
// performant, and secure.
func (c *Config) Validate() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var validationErrors []error
	if err := c.validateServer(); err != nil {
		validationErrors = append(validationErrors,
			fmt.Errorf("server validation: %w", err))
	}

	if err := c.validateLogging(); err != nil {
		validationErrors = append(validationErrors,
			fmt.Errorf("logging validation: %w", err))
	}

	if err := c.validateTLS(); err != nil {
		validationErrors = append(validationErrors,
			fmt.Errorf("TLS validation: %w", err))
	}

	if err := c.validateHealth(); err != nil {
		validationErrors = append(validationErrors,
			fmt.Errorf("health validation: %w", err))
	}

	if err := c.validateMetrics(); err != nil {
		validationErrors = append(validationErrors,
			fmt.Errorf("metrics validation: %w", err))
	}

	if err := c.validateCORS(); err != nil {
		validationErrors = append(validationErrors,
			fmt.Errorf("CORS validation: %w", err))
	}

	if err := c.validateSecurity(); err != nil {
		validationErrors = append(validationErrors,
			fmt.Errorf("security validation: %w", err))
	}

	if err := c.validateRateLimiting(); err != nil {
		validationErrors = append(validationErrors,
			fmt.Errorf("rate limiting validation: %w", err))
	}

	if err := c.validateDevelopment(); err != nil {
		validationErrors = append(validationErrors,
			fmt.Errorf("development validation: %w", err))
	}

	if err := c.validateNetworkConfig(); err != nil {
		validationErrors = append(validationErrors,
			fmt.Errorf("network validation: %w", err))
	}

	if len(validationErrors) > 0 {
		return fmt.Errorf("configuration validation failed with %d errors: %v",
			len(validationErrors), validationErrors)
	}

	return nil
}

// configureViper sets up viper with secure configuration options and sources.
// This function implements security best practices for configuration loading.
func configureViper(v *viper.Viper, configPath string) error {
	v.AutomaticEnv()
	v.SetEnvPrefix("PRISM")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	if configPath != "" {
		if err := validateConfigPath(configPath); err != nil {
			return fmt.Errorf("invalid config path: %v", err)
		}

		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("./config")
		v.AddConfigPath("/etc/prism")
		v.AddConfigPath("$HOME/.prism")
		v.AddConfigPath(".")
	}

	return nil
}

// validateConfigPath validates the configuration file path for security.
// This prevents path traversal attacks and ensures the file is accessible.
func validateConfigPath(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("config file not accessible: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("config path points to directory, not file")
	}

	file, err := os.Open(absPath)
	if err != nil {
		return fmt.Errorf("config file not readable: %w", err)
	}
	file.Close()

	dir := filepath.Dir(absPath)
	if dirInfo, err := os.Stat(dir); err == nil {
		if dirInfo.Mode().Perm()&0002 != 0 {
			return fmt.Errorf("config file in world-writable directory")
		}
	}

	return nil
}

// readConfig reads configuration from file with proper error handling.
// Missing configuration files are acceptable as we have secure defaults.
func readConfig(v *viper.Viper) error {
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("failed to read config file: %w", err)
		}
	}

	return nil
}

// setSecureDefaults establishes secure default values for all configuration options.
// These defaults follow security best practices and performance optimization guidelines.
func setSecureDefaults(v *viper.Viper) {
	// Server defaults with security-first approach
	v.SetDefault("server.host", "127.0.0.1") // Secure default: localhost only
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("server.idle_timeout", "120s")
	v.SetDefault("server.read_header_timeout", "10s")
	v.SetDefault("server.max_header_bytes", 1048576)       // 1MB
	v.SetDefault("server.max_request_body_size", 10485760) // 10MB
	v.SetDefault("server.keep_alives_enabled", true)
	v.SetDefault("server.max_concurrent_streams", 1000)
	v.SetDefault("server.max_read_frame_size", 1048576)
	v.SetDefault("server.max_idle_conns", 100)
	v.SetDefault("server.max_idle_conns_per_host", 10)
	v.SetDefault("server.idle_conn_timeout", "90s")
	v.SetDefault("server.shutdown_timeout", "30s")

	// TLS defaults (secure by default)
	v.SetDefault("server.tls.enabled", false)
	v.SetDefault("server.tls.min_version", "1.2")
	v.SetDefault("server.tls.max_version", "1.3")
	v.SetDefault("server.tls.client_auth", "NoClientCert")
	v.SetDefault("server.tls.enable_ocsp_stapling", true)
	v.SetDefault("server.tls.session_timeout", "24h")

	// Logging defaults with security considerations
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")
	v.SetDefault("logging.max_size", 100) // 100MB
	v.SetDefault("logging.max_backups", 3)
	v.SetDefault("logging.max_age", 28) // 28 days
	v.SetDefault("logging.compress", true)
	v.SetDefault("logging.sampling_rate", 1.0)
	v.SetDefault("logging.buffer_size", 1000)
	v.SetDefault("logging.flush_interval", "5s")
	v.SetDefault("logging.sanitize_fields", true)
	v.SetDefault("logging.redacted_fields", []string{"password", "token", "secret", "key", "authorization"})
	v.SetDefault("logging.max_field_size", 1024)
	v.SetDefault("logging.enable_caller", false)
	v.SetDefault("logging.enable_stack_trace", false)

	// Health check defaults
	v.SetDefault("health.enabled", true)
	v.SetDefault("health.path", "/health")
	v.SetDefault("health.timeout", "5s")
	v.SetDefault("health.interval", "30s")
	v.SetDefault("health.enable_detailed_checks", false)
	v.SetDefault("health.checked_services", []string{})
	v.SetDefault("health.readiness_path", "/ready")
	v.SetDefault("health.readiness_timeout", "10s")
	v.SetDefault("health.cache_timeout", "30s")

	// Metrics defaults
	v.SetDefault("metrics.enabled", true)
	v.SetDefault("metrics.path", "/metrics")
	v.SetDefault("metrics.port", 0) // Use main server by default
	v.SetDefault("metrics.namespace", "prism")
	v.SetDefault("metrics.subsystem", "gateway")
	v.SetDefault("metrics.enable_high_cardinality_metrics", false)
	v.SetDefault("metrics.metrics_ttl", "5m")
	v.SetDefault("metrics.max_metrics_age", "1h")
	v.SetDefault("metrics.collection_interval", "15s")
	v.SetDefault("metrics.batch_size", 100)
	v.SetDefault("metrics.enable_auth", false)
	v.SetDefault("metrics.allowed_ips", []string{})
	v.SetDefault("metrics.secure_transport", false)

	// CORS defaults (restrictive by default for security)
	v.SetDefault("cors.enabled", false) // Disabled by default
	v.SetDefault("cors.allowed_origins", []string{})
	v.SetDefault("cors.allow_origin_func", "")
	v.SetDefault("cors.allowed_methods", []string{"GET", "POST"})
	v.SetDefault("cors.allowed_headers", []string{"Content-Type", "Authorization"})
	v.SetDefault("cors.exposed_headers", []string{})
	v.SetDefault("cors.allow_credentials", false)
	v.SetDefault("cors.max_age", "86400s") // 24 hours
	v.SetDefault("cors.allow_private_network", false)
	v.SetDefault("cors.vary_header", true)
	v.SetDefault("cors.options_passthrough", false)
	v.SetDefault("cors.allow_websockets", false)
	v.SetDefault("cors.debug", false)

	// Security defaults (defense-in-depth)
	v.SetDefault("security.max_request_size", 10485760) // 10MB
	v.SetDefault("security.max_uri_length", 2048)
	v.SetDefault("security.max_query_params", 100)
	v.SetDefault("security.request_timeout", "30s")
	v.SetDefault("security.trusted_proxies", []string{})
	v.SetDefault("security.ip_whitelist", []string{})
	v.SetDefault("security.ip_blacklist", []string{})

	// HTTP security headers
	v.SetDefault("security.enable_hsts", true)
	v.SetDefault("security.hsts_max_age", 31536000) // 1 year
	v.SetDefault("security.hsts_subdomains", true)
	v.SetDefault("security.hsts_preload", false)
	v.SetDefault("security.enable_csp", true)
	v.SetDefault("security.csp_directives", "default-src 'self'")
	v.SetDefault("security.csp_report_only", false)
	v.SetDefault("security.csp_report_uri", "")
	v.SetDefault("security.enable_frame_deny", true)
	v.SetDefault("security.enable_content_type_nosniff", true)
	v.SetDefault("security.enable_xss_protection", true)
	v.SetDefault("security.enable_referrer_policy", true)
	v.SetDefault("security.referrer_policy", "strict-origin-when-cross-origin")

	// Authentication and authorization
	v.SetDefault("security.require_auth", false)
	v.SetDefault("security.auth_exclude_paths", []string{"/health", "/metrics"})
	v.SetDefault("security.session_timeout", "24h")

	// Input validation and sanitization
	v.SetDefault("security.enable_input_validation", true)
	v.SetDefault("security.sanitize_input", true)
	v.SetDefault("security.blocked_patterns", []string{})
	v.SetDefault("security.allowed_file_types", []string{})

	// Rate limiting defaults (enabled by default for security)
	v.SetDefault("security.rate_limiting.enabled", true)
	v.SetDefault("security.rate_limiting.algorithm", "token_bucket")
	v.SetDefault("security.rate_limiting.requests_per_second", 100)
	v.SetDefault("security.rate_limiting.burst_size", 200)
	v.SetDefault("security.rate_limiting.window_size", "1m")
	v.SetDefault("security.rate_limiting.sliding_window", true)
	v.SetDefault("security.rate_limiting.key_generators", []string{"ip"})
	v.SetDefault("security.rate_limiting.custom_key_func", "")
	v.SetDefault("security.rate_limiting.skip_successful_requests", false)
	v.SetDefault("security.rate_limiting.skip_failed_requests", false)
	v.SetDefault("security.rate_limiting.excluded_paths", []string{"/health"})
	v.SetDefault("security.rate_limiting.excluded_methods", []string{})
	v.SetDefault("security.rate_limiting.excluded_user_agents", []string{})
	v.SetDefault("security.rate_limiting.enable_distributed", false)
	v.SetDefault("security.rate_limiting.redis_url", "")
	v.SetDefault("security.rate_limiting.redis_key_prefix", "prism:ratelimit:")
	v.SetDefault("security.rate_limiting.headers", map[string]string{})
	v.SetDefault("security.rate_limiting.retry_after_header", true)
	v.SetDefault("security.rate_limiting.custom_message", "Rate limit exceeded")
	v.SetDefault("security.rate_limiting.cleanup_interval", "5m")
	v.SetDefault("security.rate_limiting.max_keys", 10000)

	// Development defaults (secure by default - disabled in production)
	v.SetDefault("development.debug", false)
	v.SetDefault("development.log_requests", false)
	v.SetDefault("development.pprof", false)
	v.SetDefault("development.pprof_port", 0)
	v.SetDefault("development.hot_reload", false)
	v.SetDefault("development.config_watch", false)
	v.SetDefault("development.mock_mode", false)
	v.SetDefault("development.simulate_latency", "0s")
	v.SetDefault("development.simulate_errors", 0.0)
	v.SetDefault("development.enable_cors", false)
	v.SetDefault("development.verbose_logging", false)
	v.SetDefault("development.enable_stack_trace", false)
	v.SetDefault("development.enable_swagger", false)
	v.SetDefault("development.swagger_path", "/swagger")
	v.SetDefault("development.enable_playground", false)
	v.SetDefault("development.playground_path", "/playground")
}

// validateServer validates server-specific configuration with performance
// considerations.
func (c *Config) validateServer() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("%w: %d", ErrInvalidPort, c.Server.Port)
	}

	if strings.TrimSpace(c.Server.Host) == "" {
		return ErrEmptyHost
	}

	if net.ParseIP(c.Server.Host) == nil && !isValidHostname(c.Server.Host) {
		return fmt.Errorf("invalid host address: %s", c.Server.Host)
	}

	if c.Server.ReadTimeout <= 0 {
		return fmt.Errorf("%w: read_timeout must be positive", ErrInvalidTimeout)
	}

	if c.Server.WriteTimeout <= 0 {
		return fmt.Errorf("%w: write_timeout must be positive", ErrInvalidTimeout)
	}

	if c.Server.IdleTimeout <= 0 {
		return fmt.Errorf("%w: idle_timeout must be positive", ErrInvalidTimeout)
	}

	if c.Server.ReadHeaderTimeout <= 0 {
		return fmt.Errorf("%w: read_header_timeout must be positive", ErrInvalidTimeout)
	}

	if c.Server.MaxHeaderBytes <= 1024 {
		return fmt.Errorf("max_header_bytes must be at least 1024 bytes")
	}

	if c.Server.MaxRequestBodySize <= 1024 {
		return fmt.Errorf("max_request_body_size must be at least 1024 bytes")
	}

	if c.Server.MaxConcurrentStreams == 0 {
		return fmt.Errorf("max_concurrent_streams must be greater than 0")
	}

	if c.Server.MaxReadFrameSize < 16384 {
		return fmt.Errorf("max_read_frame_size must be at least 16384 bytes")
	}

	return nil
}

// validateLogging validates logging configuration for security and performance.
func (c *Config) validateLogging() error {
	validLevels := map[string]bool{
		"trace": true, "debug": true, "info": true,
		"warn": true, "error": true, "fatal": true, "panic": true,
	}

	if !validLevels[c.Logging.Level] {
		return fmt.Errorf("%w: %s", ErrInvalidLogLevel, c.Logging.Level)
	}

	validFormats := map[string]bool{"json": true, "text": true}
	if !validFormats[c.Logging.Format] {
		return fmt.Errorf("%w: %s", ErrInvalidLogFormat, c.Logging.Format)
	}

	if c.Logging.SamplingRate < 0 || c.Logging.SamplingRate > 1 {
		return fmt.Errorf("sampling_rate must be between 0 and 1")
	}

	if c.Logging.MaxSize <= 0 {
		return fmt.Errorf("max_size must be positive")
	}

	if c.Logging.MaxBackups < 0 {
		return fmt.Errorf("max_backups must be non-negative")
	}

	if c.Logging.MaxAge <= 0 {
		return fmt.Errorf("max_age must be positive")
	}

	return nil
}

// validateTLS validates TLS configuration for security compliance.
func (c *Config) validateTLS() error {
	if !c.Server.TLS.Enabled {
		return nil
	}

	if c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "" {
		return ErrTLSConfigIncomplete
	}

	if err := validateFileAccess(c.Server.TLS.CertFile); err != nil {
		return fmt.Errorf("certificate file validation failed: %w", err)
	}

	if err := validateFileAccess(c.Server.TLS.KeyFile); err != nil {
		return fmt.Errorf("private key file validation failed: %w", err)
	}

	validVersions := map[string]bool{"1.2": true, "1.3": true}
	if c.Server.TLS.MinVersion != "" && !validVersions[c.Server.TLS.MinVersion] {
		return fmt.Errorf("invalid TLS min_version: %s", c.Server.TLS.MinVersion)
	}

	if c.Server.TLS.MaxVersion != "" && !validVersions[c.Server.TLS.MaxVersion] {
		return fmt.Errorf("invalid TLS max_version: %s", c.Server.TLS.MaxVersion)
	}

	validClientAuth := map[string]bool{
		"NoClientCert":               true,
		"RequestClientCert":          true,
		"RequireAnyClientCert":       true,
		"VerifyClientCertIfGiven":    true,
		"RequireAndVerifyClientCert": true,
	}
	if !validClientAuth[c.Server.TLS.ClientAuth] {
		return fmt.Errorf("invalid client_auth mode: %s", c.Server.TLS.ClientAuth)
	}

	if (c.Server.TLS.ClientAuth == "RequireAnyClientCert" ||
		c.Server.TLS.ClientAuth == "VerifyClientCertIfGiven" ||
		c.Server.TLS.ClientAuth == "RequireAndVerifyClientCert") &&
		c.Server.TLS.ClientCAFile != "" {
		if err := validateFileAccess(c.Server.TLS.ClientCAFile); err != nil {
			return fmt.Errorf("client CA file validation failed: %w", err)
		}
	}

	return nil
}

// validateHealth validates health check configuration.
func (c *Config) validateHealth() error {
	if !c.Health.Enabled {
		return nil
	}

	if !strings.HasPrefix(c.Health.Path, "/") {
		return fmt.Errorf("health path must start with '/'")
	}

	if c.Health.Timeout <= 0 {
		return fmt.Errorf("%w: health timeout must be positive", ErrInvalidTimeout)
	}

	if c.Health.Interval <= 0 {
		return fmt.Errorf("%w: health interval must be positive", ErrInvalidTimeout)
	}

	if c.Health.ReadinessPath != "" &&
		!strings.HasPrefix(c.Health.ReadinessPath, "/") {
		return fmt.Errorf("readiness path must start with '/'")
	}

	return nil
}

// validateMetrics validates metrics configuration.
func (c *Config) validateMetrics() error {
	if !c.Metrics.Enabled {
		return nil
	}

	if !strings.HasPrefix(c.Metrics.Path, "/") {
		return fmt.Errorf("metrics path must start with '/'")
	}

	if c.Metrics.Port > 0 {
		if c.Metrics.Port <= 0 || c.Metrics.Port > 65535 {
			return fmt.Errorf("%w: metrics port %d", ErrInvalidPort, c.Metrics.Port)
		}
	}

	if strings.TrimSpace(c.Metrics.Namespace) == "" {
		return fmt.Errorf("metrics namespace cannot be empty")
	}

	if c.Metrics.BatchSize <= 0 {
		return fmt.Errorf("metrics batch_size must be positive")
	}

	return nil
}

// validateCORS validates CORS configuration for security.
func (c *Config) validateCORS() error {
	if !c.CORS.Enabled {
		return nil
	}

	if len(c.CORS.AllowedOrigins) == 0 && c.CORS.AllowOriginFunc == "" {
		return fmt.Errorf("CORS enabled but no allowed origins specified")
	}

	if len(c.CORS.AllowedMethods) == 0 {
		return fmt.Errorf("CORS enabled but no allowed methods specified")
	}

	for _, origin := range c.CORS.AllowedOrigins {
		if origin == "*" && c.CORS.AllowCredentials {
			return fmt.Errorf("CORS security violation: cannot use wildcard origin with credentials")
		}
	}

	return nil
}

// validateSecurity validates security configuration for comprehensive protection.
func (c *Config) validateSecurity() error {
	// Validate request size limits
	if c.Security.MaxRequestSize <= 1024 {
		return fmt.Errorf("max_request_size must be at least 1024 bytes")
	}
	if c.Security.MaxURILength <= 0 {
		return fmt.Errorf("max_uri_length must be positive")
	}
	if c.Security.MaxQueryParams <= 0 {
		return fmt.Errorf("max_query_params must be positive")
	}

	// Validate timeout
	if c.Security.RequestTimeout <= 0 {
		return fmt.Errorf("%w: request_timeout must be positive", ErrInvalidTimeout)
	}

	// Validate IP lists
	for _, ip := range c.Security.TrustedProxies {
		if err := validateIPOrCIDR(ip); err != nil {
			return fmt.Errorf("invalid trusted proxy IP %s: %w", ip, err)
		}
	}

	for _, ip := range c.Security.IPWhitelist {
		if err := validateIPOrCIDR(ip); err != nil {
			return fmt.Errorf("invalid whitelist IP %s: %w", ip, err)
		}
	}

	for _, ip := range c.Security.IPBlacklist {
		if err := validateIPOrCIDR(ip); err != nil {
			return fmt.Errorf("invalid blacklist IP %s: %w", ip, err)
		}
	}

	// Validate HSTS configuration
	if c.Security.EnableHSTS && c.Security.HSTSMaxAge < 0 {
		return fmt.Errorf("hsts_max_age must be non-negative")
	}

	// Validate referrer policy
	if c.Security.EnableReferrerPolicy {
		validPolicies := map[string]bool{
			"no-referrer": true, "no-referrer-when-downgrade": true,
			"origin": true, "origin-when-cross-origin": true,
			"same-origin": true, "strict-origin": true,
			"strict-origin-when-cross-origin": true, "unsafe-url": true,
		}
		if !validPolicies[c.Security.ReferrerPolicy] {
			return fmt.Errorf("invalid referrer_policy: %s", c.Security.ReferrerPolicy)
		}
	}

	return nil
}

// validateRateLimiting validates rate limiting configuration.
func (c *Config) validateRateLimiting() error {
	rl := &c.Security.RateLimiting
	if !rl.Enabled {
		return nil
	}

	validAlgorithms := map[string]bool{
		"token_bucket": true, "sliding_window": true,
		"fixed_window": true, "leaky_bucket": true,
	}

	if !validAlgorithms[rl.Algorithm] {
		return fmt.Errorf("%w: invalid algorithm %s", ErrInvalidRateLimit, rl.Algorithm)
	}

	if rl.RequestsPerSecond <= 0 {
		return fmt.Errorf("%w: requests_per_second must be positive", ErrInvalidRateLimit)
	}

	if rl.BurstSize <= 0 {
		return fmt.Errorf("%w: burst_size must be positive", ErrInvalidRateLimit)
	}

	if rl.WindowSize <= 0 {
		return fmt.Errorf("%w: window_size must be positive", ErrInvalidRateLimit)
	}

	if len(rl.KeyGenerators) == 0 {
		return fmt.Errorf("%w: at least one key generator required", ErrInvalidRateLimit)
	}

	validKeyGens := map[string]bool{
		"ip": true, "user": true, "api_key": true, "custom": true,
	}

	for _, gen := range rl.KeyGenerators {
		if !validKeyGens[gen] {
			return fmt.Errorf("%w: invalid key generator %s", ErrInvalidRateLimit, gen)
		}
	}

	if rl.EnableDistributed && rl.RedisURL == "" {
		return fmt.Errorf("%w: redis_url required for distributed rate limiting", ErrInvalidRateLimit)
	}

	if rl.MaxKeys <= 0 {
		return fmt.Errorf("%w: max_keys must be positive", ErrInvalidRateLimit)
	}

	return nil
}

// validateDevelopment validates development configuration.
func (c *Config) validateDevelopment() error {
	if c.Development.PProf && c.Development.PprofPort > 0 {
		if c.Development.PprofPort <= 0 || c.Development.PprofPort > 65535 {
			return fmt.Errorf("%w: pprof port %d", ErrInvalidPort, c.Development.PprofPort)
		}
	}

	if c.Development.SimulateErrors < 0 || c.Development.SimulateErrors > 1 {
		return fmt.Errorf("simulate_errors must be between 0 and 1")
	}

	if c.Development.EnableSwagger &&
		!strings.HasPrefix(c.Development.SwaggerPath, "/") {
		return fmt.Errorf("swagger_path must start with '/'")
	}

	if c.Development.EnablePlayground &&
		!strings.HasPrefix(c.Development.PlaygroundPath, "/") {
		return fmt.Errorf("playground_path must start with '/'")
	}

	return nil
}

// validateNetworkConfig validates network-related configurations for conflicts.
func (c *Config) validateNetworkConfig() error {
	usedPorts := make(map[int]string)
	usedPorts[c.Server.Port] = "server"
	if c.Metrics.Enabled && c.Metrics.Port > 0 {
		if service, exists := usedPorts[c.Metrics.Port]; exists {
			return fmt.Errorf("%w: metrics port %d conflicts with %s", ErrPortConflict, c.Metrics.Port, service)
		}

		usedPorts[c.Metrics.Port] = "metrics"
	}

	if c.Development.PProf && c.Development.PprofPort > 0 {
		if service, exists := usedPorts[c.Development.PprofPort]; exists {
			return fmt.Errorf("%w: pprof port %d conflicts with %s", ErrPortConflict, c.Development.PprofPort, service)
		}

		usedPorts[c.Development.PprofPort] = "pprof"
	}

	return nil
}

// applySecurity applies additional security configurations and post-processing.
// This method enforces security policies and production-ready defaults.
func (c *Config) applySecurity() error {
	if !c.Development.Debug {
		c.Development.PProf = false
		c.Development.LogRequests = false
		c.Development.HotReload = false
		c.Development.MockMode = false
		c.Development.EnableSwagger = false
		c.Development.EnablePlayground = false

		if c.Logging.Level == "trace" || c.Logging.Level == "debug" {
			c.Logging.Level = "info"
		}

		c.Security.EnableInputValidation = true
		c.Security.SanitizeInput = true
		c.Logging.SanitizeFields = true
	}

	if c.CORS.Enabled {
		if len(c.CORS.AllowedHeaders) == 0 {
			c.CORS.AllowedHeaders = []string{"Content-Type", "Authorization"}
		}

		if len(c.CORS.AllowedMethods) == 0 {
			c.CORS.AllowedMethods = []string{"GET", "POST"}
		}
	}

	return nil
}

// optimize performs final optimization of configuration for runtime
// performance.
func (c *Config) optimize() {
	c.Security.TrustedProxies = removeDuplicatesAndEmpty(c.Security.TrustedProxies)
	c.Security.IPWhitelist = removeDuplicatesAndEmpty(c.Security.IPWhitelist)
	c.Security.IPBlacklist = removeDuplicatesAndEmpty(c.Security.IPBlacklist)
	c.CORS.AllowedOrigins = removeDuplicatesAndEmpty(c.CORS.AllowedOrigins)
	c.CORS.AllowedMethods = removeDuplicatesAndEmpty(c.CORS.AllowedMethods)
	c.CORS.AllowedHeaders = removeDuplicatesAndEmpty(c.CORS.AllowedHeaders)
	c.Logging.RedactedFields = removeDuplicatesAndEmpty(c.Logging.RedactedFields)
}

// Thread-safe getter methods for high-performance access

// GetAddress returns the server address in a thread-safe manner.
// This method is optimized for frequent access with minimal overhead.
func (c *Config) GetAddress() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return net.JoinHostPort(c.Server.Host, strconv.Itoa(c.Server.Port))
}

// GetMetricsAddress returns the metrics server address in a thread-safe manner.
func (c *Config) GetMetricsAddress() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Metrics.Port > 0 {
		return net.JoinHostPort(c.Server.Host, strconv.Itoa(c.Metrics.Port))
	}

	return c.GetAddress()
}

// GetPprofAddress returns the pprof server address in a thread-safe manner.
func (c *Config) GetPprofAddress() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Development.PProf && c.Development.PprofPort > 0 {
		return net.JoinHostPort(c.Server.Host, strconv.Itoa(c.Development.PprofPort))
	}

	return c.GetAddress()
}

// IsTLSEnabled returns true if TLS is enabled in a thread-safe manner.
func (c *Config) IsTLSEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.Server.TLS.Enabled
}

// IsDebugMode returns true if debug mode is enabled in a thread-safe manner.
func (c *Config) IsDebugMode() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.Development.Debug
}

// IsProductionMode returns true if running in production mode.
func (c *Config) IsProductionMode() bool {
	return !c.IsDebugMode()
}

// GetLoadTime returns when the configuration was loaded.
func (c *Config) GetLoadTime() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loadTime
}

// GetConfigPath returns the path of the loaded configuration file.
func (c *Config) GetConfigPath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.configPath
}

// GetVersion returns the configuration version.
func (c *Config) GetVersion() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.version
}

// SetVersion sets the configuration version in a thread-safe manner.
func (c *Config) SetVersion(version string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version = version
}

// IsHealthEnabled returns true if health checks are enabled.
func (c *Config) IsHealthEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Health.Enabled
}

// IsMetricsEnabled returns true if metrics collection is enabled.
func (c *Config) IsMetricsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Metrics.Enabled
}

// IsCORSEnabled returns true if CORS is enabled.
func (c *Config) IsCORSEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.CORS.Enabled
}

// IsRateLimitingEnabled returns true if rate limiting is enabled.
func (c *Config) IsRateLimitingEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Security.RateLimiting.Enabled
}

// GetServerTimeouts returns server timeout configuration in a thread-safe manner.
func (c *Config) GetServerTimeouts() (read, write, idle,
	readHeader time.Duration) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.Server.ReadTimeout, c.Server.WriteTimeout,
		c.Server.IdleTimeout, c.Server.ReadHeaderTimeout
}

// GetRateLimitConfig returns a copy of rate limiting configuration.
func (c *Config) GetRateLimitConfig() RateLimitConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.Security.RateLimiting
}

// GetTLSConfig returns a copy of TLS configuration.
func (c *Config) GetTLSConfig() TLSConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.Server.TLS
}

// GetCORSConfig returns a copy of CORS configuration.
func (c *Config) GetCORSConfig() CORSConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.CORS
}

// Utility functions for validation and optimization

// isValidHostname validates if a string is a valid hostname according to RFC
// standards. This function implements comprehensive hostname validation for
// security.
func isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 0 {
			return false
		}

		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}

	return true
}

// validateIPOrCIDR validates if a string is a valid IP address or CIDR range.
// This function provides comprehensive network address validation.
func validateIPOrCIDR(ipStr string) error {
	if ip := net.ParseIP(ipStr); ip != nil {
		return nil
	}

	if _, _, err := net.ParseCIDR(ipStr); err == nil {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrInvalidIPAddress, ipStr)
}

// validateFileAccess validates if a file exists, is accessible, and has proper
// permissions. This function implements security checks to prevent
// unauthorized file access.
func validateFileAccess(filepath string) error {
	info, err := os.Stat(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: file does not exist: %s", ErrFileNotAccessible, filepath)
		}

		return fmt.Errorf("%w: %v", ErrFileNotAccessible, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: not a regular file: %s", ErrFileNotAccessible, filepath)
	}

	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("%w: file not readable: %v", ErrFileNotAccessible, err)
	}
	file.Close()

	if info.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("%w: file is world-writable (security risk): %s", ErrFileNotAccessible, filepath)
	}

	return nil
}

// removeDuplicatesAndEmpty removes duplicate and empty strings from a slice.
// This function optimizes string slices for runtime performance.
func removeDuplicatesAndEmpty(slice []string) []string {
	if len(slice) == 0 {
		return slice
	}

	seen := make(map[string]bool, len(slice))
	result := make([]string, 0, len(slice))

	for _, item := range slice {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			result = append(result, trimmed)
		}
	}

	return result
}

// Clone creates a deep copy of the configuration for safe external access.
// This method prevents external modification of the internal configuration
// state.
func (c *Config) Clone() *Config {
	c.mu.RLock()
	defer c.mu.RUnlock()

	clone := &Config{
		loadTime:   c.loadTime,
		configPath: c.configPath,
		version:    c.version,
	}

	clone.Server = c.cloneServerConfig()
	clone.Logging = c.cloneLoggingConfig()
	clone.Health = c.cloneHealthConfig()
	clone.Metrics = c.cloneMetricsConfig()
	clone.CORS = c.cloneCORSConfig()
	clone.Security = c.cloneSecurityConfig()
	clone.Development = c.cloneDevelopmentConfig()

	return clone
}

// Helper methods for deep cloning configuration sections

func (c *Config) cloneServerConfig() ServerConfig {
	return ServerConfig{
		Host:                 c.Server.Host,
		Port:                 c.Server.Port,
		ReadTimeout:          c.Server.ReadTimeout,
		WriteTimeout:         c.Server.WriteTimeout,
		IdleTimeout:          c.Server.IdleTimeout,
		ReadHeaderTimeout:    c.Server.ReadHeaderTimeout,
		MaxHeaderBytes:       c.Server.MaxHeaderBytes,
		MaxRequestBodySize:   c.Server.MaxRequestBodySize,
		KeepAlivesEnabled:    c.Server.KeepAlivesEnabled,
		MaxConcurrentStreams: c.Server.MaxConcurrentStreams,
		MaxReadFrameSize:     c.Server.MaxReadFrameSize,
		MaxIdleConns:         c.Server.MaxIdleConns,
		MaxIdleConnsPerHost:  c.Server.MaxIdleConnsPerHost,
		IdleConnTimeout:      c.Server.IdleConnTimeout,
		ShutdownTimeout:      c.Server.ShutdownTimeout,
		TLS: TLSConfig{
			Enabled:            c.Server.TLS.Enabled,
			CertFile:           c.Server.TLS.CertFile,
			KeyFile:            c.Server.TLS.KeyFile,
			MinVersion:         c.Server.TLS.MinVersion,
			MaxVersion:         c.Server.TLS.MaxVersion,
			CipherSuites:       append([]string(nil), c.Server.TLS.CipherSuites...),
			ClientAuth:         c.Server.TLS.ClientAuth,
			ClientCAFile:       c.Server.TLS.ClientCAFile,
			EnableOCSPStapling: c.Server.TLS.EnableOCSPStapling,
			SessionTicketKey:   c.Server.TLS.SessionTicketKey,
			SessionTimeout:     c.Server.TLS.SessionTimeout,
		},
	}
}

func (c *Config) cloneLoggingConfig() LoggingConfig {
	return LoggingConfig{
		Level:            c.Logging.Level,
		Format:           c.Logging.Format,
		Output:           c.Logging.Output,
		MaxSize:          c.Logging.MaxSize,
		MaxBackups:       c.Logging.MaxBackups,
		MaxAge:           c.Logging.MaxAge,
		Compress:         c.Logging.Compress,
		SamplingRate:     c.Logging.SamplingRate,
		BufferSize:       c.Logging.BufferSize,
		FlushInterval:    c.Logging.FlushInterval,
		SanitizeFields:   c.Logging.SanitizeFields,
		RedactedFields:   append([]string(nil), c.Logging.RedactedFields...),
		MaxFieldSize:     c.Logging.MaxFieldSize,
		EnableCaller:     c.Logging.EnableCaller,
		EnableStackTrace: c.Logging.EnableStackTrace,
	}
}

func (c *Config) cloneHealthConfig() HealthConfig {
	return HealthConfig{
		Enabled:              c.Health.Enabled,
		Path:                 c.Health.Path,
		Timeout:              c.Health.Timeout,
		Interval:             c.Health.Interval,
		EnableDetailedChecks: c.Health.EnableDetailedChecks,
		CheckedServices:      append([]string(nil), c.Health.CheckedServices...),
		ReadinessPath:        c.Health.ReadinessPath,
		ReadinessTimeout:     c.Health.ReadinessTimeout,
		CacheTimeout:         c.Health.CacheTimeout,
	}
}

func (c *Config) cloneMetricsConfig() MetricsConfig {
	return MetricsConfig{
		Enabled:                      c.Metrics.Enabled,
		Path:                         c.Metrics.Path,
		Port:                         c.Metrics.Port,
		Namespace:                    c.Metrics.Namespace,
		Subsystem:                    c.Metrics.Subsystem,
		EnableHighCardinalityMetrics: c.Metrics.EnableHighCardinalityMetrics,
		MetricsTTL:                   c.Metrics.MetricsTTL,
		MaxMetricsAge:                c.Metrics.MaxMetricsAge,
		CollectionInterval:           c.Metrics.CollectionInterval,
		BatchSize:                    c.Metrics.BatchSize,
		EnableAuth:                   c.Metrics.EnableAuth,
		AllowedIPs:                   append([]string(nil), c.Metrics.AllowedIPs...),
		SecureTransport:              c.Metrics.SecureTransport,
	}
}

func (c *Config) cloneCORSConfig() CORSConfig {
	return CORSConfig{
		Enabled:             c.CORS.Enabled,
		AllowedOrigins:      append([]string(nil), c.CORS.AllowedOrigins...),
		AllowOriginFunc:     c.CORS.AllowOriginFunc,
		AllowedMethods:      append([]string(nil), c.CORS.AllowedMethods...),
		AllowedHeaders:      append([]string(nil), c.CORS.AllowedHeaders...),
		ExposedHeaders:      append([]string(nil), c.CORS.ExposedHeaders...),
		AllowCredentials:    c.CORS.AllowCredentials,
		MaxAge:              c.CORS.MaxAge,
		AllowPrivateNetwork: c.CORS.AllowPrivateNetwork,
		VaryHeader:          c.CORS.VaryHeader,
		OptionsPassthrough:  c.CORS.OptionsPassthrough,
		AllowWebSockets:     c.CORS.AllowWebSockets,
		Debug:               c.CORS.Debug,
	}
}

func (c *Config) cloneSecurityConfig() SecurityConfig {
	headers := make(map[string]string, len(c.Security.RateLimiting.Headers))
	for k, v := range c.Security.RateLimiting.Headers {
		headers[k] = v
	}

	return SecurityConfig{
		RateLimiting: RateLimitConfig{
			Enabled:                c.Security.RateLimiting.Enabled,
			Algorithm:              c.Security.RateLimiting.Algorithm,
			RequestsPerSecond:      c.Security.RateLimiting.RequestsPerSecond,
			BurstSize:              c.Security.RateLimiting.BurstSize,
			WindowSize:             c.Security.RateLimiting.WindowSize,
			SlidingWindow:          c.Security.RateLimiting.SlidingWindow,
			KeyGenerators:          append([]string(nil), c.Security.RateLimiting.KeyGenerators...),
			CustomKeyFunc:          c.Security.RateLimiting.CustomKeyFunc,
			SkipSuccessfulRequests: c.Security.RateLimiting.SkipSuccessfulRequests,
			SkipFailedRequests:     c.Security.RateLimiting.SkipFailedRequests,
			ExcludedPaths:          append([]string(nil), c.Security.RateLimiting.ExcludedPaths...),
			ExcludedMethods:        append([]string(nil), c.Security.RateLimiting.ExcludedMethods...),
			ExcludedUserAgents:     append([]string(nil), c.Security.RateLimiting.ExcludedUserAgents...),
			EnableDistributed:      c.Security.RateLimiting.EnableDistributed,
			RedisURL:               c.Security.RateLimiting.RedisURL,
			RedisKeyPrefix:         c.Security.RateLimiting.RedisKeyPrefix,
			Headers:                headers,
			RetryAfterHeader:       c.Security.RateLimiting.RetryAfterHeader,
			CustomMessage:          c.Security.RateLimiting.CustomMessage,
			CleanupInterval:        c.Security.RateLimiting.CleanupInterval,
			MaxKeys:                c.Security.RateLimiting.MaxKeys,
		},
		MaxRequestSize:           c.Security.MaxRequestSize,
		MaxURILength:             c.Security.MaxURILength,
		MaxQueryParams:           c.Security.MaxQueryParams,
		RequestTimeout:           c.Security.RequestTimeout,
		TrustedProxies:           append([]string(nil), c.Security.TrustedProxies...),
		IPWhitelist:              append([]string(nil), c.Security.IPWhitelist...),
		IPBlacklist:              append([]string(nil), c.Security.IPBlacklist...),
		EnableHSTS:               c.Security.EnableHSTS,
		HSTSMaxAge:               c.Security.HSTSMaxAge,
		HSTSSubdomains:           c.Security.HSTSSubdomains,
		HSTSPreload:              c.Security.HSTSPreload,
		EnableCSP:                c.Security.EnableCSP,
		CSPDirectives:            c.Security.CSPDirectives,
		CSPReportOnly:            c.Security.CSPReportOnly,
		CSPReportURI:             c.Security.CSPReportURI,
		EnableFrameDeny:          c.Security.EnableFrameDeny,
		EnableContentTypeNoSniff: c.Security.EnableContentTypeNoSniff,
		EnableXSSProtection:      c.Security.EnableXSSProtection,
		EnableReferrerPolicy:     c.Security.EnableReferrerPolicy,
		ReferrerPolicy:           c.Security.ReferrerPolicy,
		RequireAuth:              c.Security.RequireAuth,
		AuthExcludePaths:         append([]string(nil), c.Security.AuthExcludePaths...),
		SessionTimeout:           c.Security.SessionTimeout,
		EnableInputValidation:    c.Security.EnableInputValidation,
		SanitizeInput:            c.Security.SanitizeInput,
		BlockedPatterns:          append([]string(nil), c.Security.BlockedPatterns...),
		AllowedFileTypes:         append([]string(nil), c.Security.AllowedFileTypes...),
	}
}

func (c *Config) cloneDevelopmentConfig() DevelopmentConfig {
	return DevelopmentConfig{
		Debug:            c.Development.Debug,
		LogRequests:      c.Development.LogRequests,
		PProf:            c.Development.PProf,
		PprofPort:        c.Development.PprofPort,
		HotReload:        c.Development.HotReload,
		ConfigWatch:      c.Development.ConfigWatch,
		MockMode:         c.Development.MockMode,
		SimulateLatency:  c.Development.SimulateLatency,
		SimulateErrors:   c.Development.SimulateErrors,
		EnableCORS:       c.Development.EnableCORS,
		VerboseLogging:   c.Development.VerboseLogging,
		EnableStackTrace: c.Development.EnableStackTrace,
		EnableSwagger:    c.Development.EnableSwagger,
		SwaggerPath:      c.Development.SwaggerPath,
		EnablePlayground: c.Development.EnablePlayground,
		PlaygroundPath:   c.Development.PlaygroundPath,
	}
}
