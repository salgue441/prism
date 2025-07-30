package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Rate limiting errors for precise error handling and debugging.
var (
	// ErrStorageUnavailable indicates the storage backend is unavailable.
	ErrStorageUnavailable = errors.New("rate limit storage backend unavailable")

	// ErrInvalidKey indicates an invalid rate limit key was provided.
	ErrInvalidKey = errors.New("invalid rate limit key")

	// ErrInvalidAlgorithm indicates an unsupported algorithm was specified.
	ErrInvalidAlgorithm = errors.New("invalid or unsupported rate limiting algorithm")

	// ErrInvalidConfiguration indicates invalid configuration parameters.
	ErrInvalidConfiguration = errors.New("invalid rate limiter configuration")

	// ErrLimiterClosed indicates the rate limiter has been closed.
	ErrLimiterClosed = errors.New("rate limiter has been closed")

	// ErrKeyGenerationFailed indicates key generation failed.
	ErrKeyGenerationFailed = errors.New("failed to generate rate limit key")

	// ErrQuotaExceeded indicates the rate limit quota has been exceeded.
	ErrQuotaExceeded = errors.New("rate limit quota exceeded")

	// ErrBlacklisted indicates the key is blacklisted.
	ErrBlacklisted = errors.New("key is blacklisted")
)

// Limiter interface defines the core rate limiting operations.
// All rate limiting algorithms must implement this interface.
type Limiter interface {
	// Allow checks if a request with the given key is allowed.
	// Returns: allowed, remaining, resetTime, error
	Allow(key string) (bool, int64, time.Time, error)

	// AllowN checks if N requests with the given key are allowed.
	AllowN(key string, n int64) (bool, int64, time.Time, error)

	// Reset resets the rate limit for the given key.
	Reset(key string) error

	// GetLimit returns the current limit configuration.
	GetLimit() int64

	// GetRemaining returns the remaining requests for the given key.
	GetRemaining(key string) (int64, error)

	// GetResetTime returns the next reset time for the given key.
	GetResetTime(key string) (time.Time, error)

	// Close gracefully closes the rate limiter and cleans up resources.
	Close() error

	// GetMetrics returns current performance metrics.
	GetMetrics() *Metrics
}

// Storage interface defines the storage backend operations.
type Storage interface {
	// Get retrieves a value from storage.
	Get(ctx context.Context, key string) (*StorageValue, error)

	// Set stores a value in storage with TTL.
	Set(ctx context.Context, key string, value *StorageValue, ttl time.Duration) error

	// Increment atomically increments a counter.
	Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error)

	// Delete removes a key from storage.
	Delete(ctx context.Context, key string) error

	// Exists checks if a key exists in storage.
	Exists(ctx context.Context, key string) (bool, error)

	// BatchGet retrieves multiple values efficiently.
	BatchGet(ctx context.Context, keys []string) (map[string]*StorageValue, error)

	// BatchSet stores multiple values efficiently.
	BatchSet(ctx context.Context, values map[string]*StorageValue, ttl time.Duration) error

	// Close closes the storage backend.
	Close() error

	// Ping checks if the storage backend is available.
	Ping(ctx context.Context) error
}

// KeyGenerator interface defines key generation strategies.
type KeyGenerator interface {
	// GenerateKey generates a rate limit key from an HTTP request.
	GenerateKey(req *http.Request) (string, error)

	// GetName returns the name of the key generator.
	GetName() string
}

// Algorithm represents different rate limiting algorithms.
type Algorithm string

// Supported rate limiting algorithms.
const (
	TokenBucket   Algorithm = "token_bucket"
	SlidingWindow Algorithm = "sliding_window"
	FixedWindow   Algorithm = "fixed_window"
	LeakyBucket   Algorithm = "leaky_bucket"
)

// StorageType represents different storage backend types.
type StorageType string

// Supported storage backend types.
const (
	MemoryStorage StorageType = "memory"
	RedisStorage  StorageType = "redis"
	HybridStorage StorageType = "hybrid"
)

// KeyGeneratorType represents different key generation strategies.
type KeyGeneratorType string

// Supported key generation strategies.
const (
	IPKeyGenerator        KeyGeneratorType = "ip"
	UserKeyGenerator      KeyGeneratorType = "user"
	APIKeyGenerator       KeyGeneratorType = "api_key"
	CustomKeyGenerator    KeyGeneratorType = "custom"
	CompositeKeyGenerator KeyGeneratorType = "composite"
)

// Config holds comprehensive configuration for rate limiting.
type Config struct {
	// Algorithm configuration
	Algorithm         Algorithm     `json:"algorithm" yaml:"algorithm" validate:"required,oneof=token_bucket sliding_window fixed_window leaky_bucket"`
	RequestsPerSecond int64         `json:"requests_per_second" yaml:"requests_per_second" validate:"required,min=1"`
	BurstSize         int64         `json:"burst_size" yaml:"burst_size" validate:"min=1"`
	WindowSize        time.Duration `json:"window_size" yaml:"window_size" validate:"min=1s"`

	// Storage configuration
	Storage   StorageType   `json:"storage" yaml:"storage" validate:"required,oneof=memory redis hybrid"`
	RedisURL  string        `json:"redis_url" yaml:"redis_url"`
	RedisPool int           `json:"redis_pool" yaml:"redis_pool" validate:"min=1"`
	KeyPrefix string        `json:"key_prefix" yaml:"key_prefix"`
	TTL       time.Duration `json:"ttl" yaml:"ttl" validate:"min=1s"`

	// Key generation configuration
	KeyGenerator  KeyGeneratorType           `json:"key_generator" yaml:"key_generator" validate:"required"`
	KeyGenerators []KeyGeneratorType         `json:"key_generators" yaml:"key_generators"`
	CustomKeyFunc func(*http.Request) string `json:"-" yaml:"-"`

	// Security configuration
	EnableBlacklist    bool          `json:"enable_blacklist" yaml:"enable_blacklist"`
	BlacklistThreshold int64         `json:"blacklist_threshold" yaml:"blacklist_threshold" validate:"min=1"`
	BlacklistDuration  time.Duration `json:"blacklist_duration" yaml:"blacklist_duration" validate:"min=1m"`
	TrustedIPs         []string      `json:"trusted_ips" yaml:"trusted_ips"`
	TrustedUsers       []string      `json:"trusted_users" yaml:"trusted_users"`

	// Performance configuration
	CleanupInterval time.Duration `json:"cleanup_interval" yaml:"cleanup_interval" validate:"min=1m"`
	MaxKeys         int           `json:"max_keys" yaml:"max_keys" validate:"min=1"`
	BatchSize       int           `json:"batch_size" yaml:"batch_size" validate:"min=1"`
	EnableAsync     bool          `json:"enable_async" yaml:"enable_async"`

	// Response configuration
	Headers          map[string]string `json:"headers" yaml:"headers"`
	RetryAfterHeader bool              `json:"retry_after_header" yaml:"retry_after_header"`
	CustomMessage    string            `json:"custom_message" yaml:"custom_message"`
	SkipSuccessful   bool              `json:"skip_successful" yaml:"skip_successful"`
	SkipFailed       bool              `json:"skip_failed" yaml:"skip_failed"`

	// Monitoring configuration
	EnableMetrics    bool   `json:"enable_metrics" yaml:"enable_metrics"`
	MetricsNamespace string `json:"metrics_namespace" yaml:"metrics_namespace"`
}

// Result represents the result of a rate limit check.
type Result struct {
	// Allowed indicates whether the request is allowed.
	Allowed bool `json:"allowed"`

	// Remaining indicates the number of remaining requests.
	Remaining int64 `json:"remaining"`

	// ResetTime indicates when the rate limit resets.
	ResetTime time.Time `json:"reset_time"`

	// RetryAfter indicates how long to wait before retrying (if blocked).
	RetryAfter time.Duration `json:"retry_after,omitempty"`

	// Key is the rate limit key used for this check.
	Key string `json:"key"`

	// Algorithm is the algorithm used for this check.
	Algorithm Algorithm `json:"algorithm"`

	// Limit is the configured rate limit.
	Limit int64 `json:"limit"`

	// WindowStart is the start of the current window (for window-based algorithms).
	WindowStart time.Time `json:"window_start,omitempty"`

	// Blacklisted indicates if the key is blacklisted.
	Blacklisted bool `json:"blacklisted,omitempty"`
}

// StorageValue represents a value stored in the rate limit storage.
type StorageValue struct {
	// Count is the current request count.
	Count int64 `json:"count"`

	// LastRefill is the last time tokens were refilled (for token bucket).
	LastRefill time.Time `json:"last_refill,omitempty"`

	// WindowStart is the start of the current window.
	WindowStart time.Time `json:"window_start,omitempty"`

	// Tokens is the current token count (for token bucket).
	Tokens float64 `json:"tokens,omitempty"`

	// Requests is a list of request timestamps (for sliding window).
	Requests []time.Time `json:"requests,omitempty"`

	// Blacklisted indicates if this key is blacklisted.
	Blacklisted bool `json:"blacklisted,omitempty"`

	// BlacklistedUntil indicates when the blacklist expires.
	BlacklistedUntil time.Time `json:"blacklisted_until,omitempty"`

	// Metadata holds additional algorithm-specific data.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Metrics holds performance and operational metrics for rate limiters.
type Metrics struct {
	// Request metrics
	TotalRequests   int64   `json:"total_requests"`
	AllowedRequests int64   `json:"allowed_requests"`
	BlockedRequests int64   `json:"blocked_requests"`
	HitRate         float64 `json:"hit_rate"`

	// Performance metrics
	AvgResponseTime time.Duration `json:"avg_response_time"`
	P95ResponseTime time.Duration `json:"p95_response_time"`
	P99ResponseTime time.Duration `json:"p99_response_time"`

	// Storage metrics
	StorageHits    int64         `json:"storage_hits"`
	StorageMisses  int64         `json:"storage_misses"`
	StorageErrors  int64         `json:"storage_errors"`
	StorageLatency time.Duration `json:"storage_latency"`

	// Key metrics
	ActiveKeys      int64 `json:"active_keys"`
	BlacklistedKeys int64 `json:"blacklisted_keys"`
	ExpiredKeys     int64 `json:"expired_keys"`
	CleanupRuns     int64 `json:"cleanup_runs"`

	// Algorithm-specific metrics
	TokensRefilled int64 `json:"tokens_refilled,omitempty"`
	WindowsRotated int64 `json:"windows_rotated,omitempty"`

	// Error metrics
	KeyGenerationErrors int64 `json:"key_generation_errors"`
	ConfigurationErrors int64 `json:"configuration_errors"`

	// Timing metrics
	StartTime       time.Time     `json:"start_time"`
	LastResetTime   time.Time     `json:"last_reset_time"`
	LastCleanupTime time.Time     `json:"last_cleanup_time"`
	Uptime          time.Duration `json:"uptime"`
}

// MiddlewareConfig holds configuration for rate limiting middleware.
type MiddlewareConfig struct {
	// Limiters is a list of rate limiters to apply.
	Limiters []Limiter `json:"-"`

	// SkipPaths contains paths to skip rate limiting.
	SkipPaths []string `json:"skip_paths"`

	// SkipMethods contains HTTP methods to skip rate limiting.
	SkipMethods []string `json:"skip_methods"`

	// OnBlocked is called when a request is blocked.
	OnBlocked func(http.ResponseWriter, *http.Request, *Result) `json:"-"`

	// OnError is called when an error occurs.
	OnError func(http.ResponseWriter, *http.Request, error) `json:"-"`

	// ErrorResponse is the response sent when rate limited.
	ErrorResponse any `json:"error_response"`

	// IncludeHeaders determines which headers to include in responses.
	IncludeHeaders []string `json:"include_headers"`

	// TrustForwardedHeaders trusts X-Forwarded-For and similar headers.
	TrustForwardedHeaders bool `json:"trust_forwarded_headers"`
}

// Context keys for request data.
type ContextKey string

const (
	// RateLimitResultKey holds the rate limit result in request context.
	RateLimitResultKey ContextKey = "rate_limit_result"

	// RateLimitKeyKey holds the rate limit key in request context.
	RateLimitKeyKey ContextKey = "rate_limit_key"

	// RateLimitSkippedKey indicates if rate limiting was skipped.
	RateLimitSkippedKey ContextKey = "rate_limit_skipped"
)

// Default configuration values.
const (
	DefaultRequestsPerSecond  = 100
	DefaultBurstSize          = 200
	DefaultWindowSize         = time.Minute
	DefaultTTL                = time.Hour
	DefaultCleanupInterval    = 5 * time.Minute
	DefaultMaxKeys            = 10000
	DefaultBatchSize          = 100
	DefaultRedisPool          = 10
	DefaultKeyPrefix          = "prism:ratelimit:"
	DefaultBlacklistThreshold = 1000
	DefaultBlacklistDuration  = time.Hour
)

// HTTP headers for rate limiting information.
const (
	HeaderRateLimitLimit      = "X-RateLimit-Limit"
	HeaderRateLimitRemaining  = "X-RateLimit-Remaining"
	HeaderRateLimitReset      = "X-RateLimit-Reset"
	HeaderRateLimitRetryAfter = "Retry-After"
	HeaderRateLimitPolicy     = "X-RateLimit-Policy"
)

// Performance constants for optimization.
const (
	MaxBatchSize          = 1000
	MaxKeys               = 100000
	MinCleanupInterval    = time.Minute
	MaxCleanupInterval    = time.Hour
	DefaultStorageTimeout = 5 * time.Second
	MaxConcurrentRequests = 10000
)

// TokenBucketState represents the state of a token bucket.
type TokenBucketState struct {
	Tokens     float64   `json:"tokens"`
	LastRefill time.Time `json:"last_refill"`
	mu         sync.RWMutex
}

// SlidingWindowState represents the state of a sliding window.
type SlidingWindowState struct {
	Requests []time.Time `json:"requests"`
	mu       sync.RWMutex
}

// FixedWindowState represents the state of a fixed window.
type FixedWindowState struct {
	Count       int64     `json:"count"`
	WindowStart time.Time `json:"window_start"`
	mu          sync.RWMutex
}

// LeakyBucketState represents the state of a leaky bucket.
type LeakyBucketState struct {
	Volume   float64   `json:"volume"`
	LastLeak time.Time `json:"last_leak"`
	mu       sync.RWMutex
}

// BlacklistEntry represents a blacklisted key.
type BlacklistEntry struct {
	Key       string    `json:"key"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason"`
	Count     int64     `json:"count"`
}

// RateLimitError represents a rate limiting error with additional context.
type RateLimitError struct {
	Err       error                  `json:"error"`
	Key       string                 `json:"key"`
	Algorithm Algorithm              `json:"algorithm"`
	Timestamp time.Time              `json:"timestamp"`
	Context   map[string]any `json:"context,omitempty"`
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limit error for key %s: %v", e.Key, e.Err)
}

func (e *RateLimitError) Unwrap() error {
	return e.Err
}
