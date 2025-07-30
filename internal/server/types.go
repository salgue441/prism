package server

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"prism/internal/config"
	"prism/pkg/logger"
)

// Server errors for precise error handling and debugging.
var (
	// ErrServerAlreadyStarted indicates the server is already running.
	ErrServerAlreadyStarted = errors.New("server is already started")

	// ErrServerNotStarted indicates the server is not running.
	ErrServerNotStarted = errors.New("server is not started")

	// ErrServerClosed indicates the server has been closed.
	ErrServerClosed = errors.New("server has been closed")

	// ErrInvalidHandler indicates an invalid handler was provided.
	ErrInvalidHandler = errors.New("invalid handler provided")

	// ErrShutdownTimeout indicates the shutdown process timed out.
	ErrShutdownTimeout = errors.New("server shutdown timed out")

	// ErrTLSConfigRequired indicates TLS configuration is required but missing.
	ErrTLSConfigRequired = errors.New("TLS configuration required")

	// ErrInvalidMiddleware indicates invalid middleware was provided.
	ErrInvalidMiddleware = errors.New("invalid middleware provided")
)

// Server represents a high-performance HTTP server with comprehensive
// security, observability, and lifecycle management features.
type Server struct {
	// Configuration and dependencies
	config *config.Config
	logger *logger.Logger

	// HTTP server instances
	httpServer    *http.Server
	metricsServer *http.Server
	pprofServer   *http.Server

	// Gin router and middleware
	router     *gin.Engine
	middleware []gin.HandlerFunc

	// Server state management (thread-safe)
	mu      sync.RWMutex
	started int32 // Atomic flag for started state
	closed  int32 // Atomic flag for closed state

	// Lifecycle management
	startTime    time.Time
	shutdownChan chan struct{}
	doneChan     chan struct{}

	// Performance metrics (atomic counters)
	requestCount int64
	errorCount   int64
	activeConns  int64
	totalConns   int64

	// Connection management
	connTracker *ConnectionTracker

	// Graceful shutdown
	shutdownTimeout time.Duration

	// Health check state
	healthStatus *HealthStatus

	// Custom error handlers
	errorHandlers map[int]gin.HandlerFunc

	// Route groups for organization
	apiGroup    *gin.RouterGroup
	adminGroup  *gin.RouterGroup
	healthGroup *gin.RouterGroup
}

// ConnectionTracker manages active HTTP connections for graceful shutdown.
type ConnectionTracker struct {
	mu    sync.RWMutex
	conns map[*http.Server]map[*http.Request]*ConnectionState
}

// ConnectionState tracks the state of an individual HTTP connection.
type ConnectionState struct {
	StartTime  time.Time
	RemoteAddr string
	UserAgent  string
	RequestID  string
}

// HealthStatus represents the current health status of the server.
type HealthStatus struct {
	mu           sync.RWMutex
	status       HealthState
	lastCheck    time.Time
	checkCount   int64
	dependencies map[string]*DependencyHealth
	startTime    time.Time
}

// HealthState represents the overall health state.
type HealthState string

// Health state constants.
const (
	HealthStateHealthy   HealthState = "healthy"
	HealthStateDegraded  HealthState = "degraded"
	HealthStateUnhealthy HealthState = "unhealthy"
	HealthStateStarting  HealthState = "starting"
	HealthStateStopping  HealthState = "stopping"
	HealthStateStopped   HealthState = "stopped"
)

// DependencyHealth represents the health status of a dependency.
type DependencyHealth struct {
	Name         string         `json:"name"`
	Status       HealthState    `json:"status"`
	LastCheck    time.Time      `json:"last_check"`
	ResponseTime time.Duration  `json:"response_time"`
	Error        string         `json:"error,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// HealthCheckResult represents the result of a health check.
type HealthCheckResult struct {
	Status       HealthState                  `json:"status"`
	Timestamp    time.Time                    `json:"timestamp"`
	Uptime       time.Duration                `json:"uptime"`
	Version      string                       `json:"version,omitempty"`
	Dependencies map[string]*DependencyHealth `json:"dependencies,omitempty"`
	Metrics      *ServerMetrics               `json:"metrics,omitempty"`
}

// ServerMetrics contains real-time server performance metrics.
type ServerMetrics struct {
	// Request metrics
	RequestCount int64   `json:"request_count"`
	ErrorCount   int64   `json:"error_count"`
	RequestRate  float64 `json:"request_rate"` // Requests per second
	ErrorRate    float64 `json:"error_rate"`   // Errors per second

	// Connection metrics
	ActiveConnections int64 `json:"active_connections"`
	TotalConnections  int64 `json:"total_connections"`

	// Response time metrics
	AvgResponseTime time.Duration `json:"avg_response_time"`
	P95ResponseTime time.Duration `json:"p95_response_time"`
	P99ResponseTime time.Duration `json:"p99_response_time"`

	// System metrics
	MemoryUsage    uint64  `json:"memory_usage"` // Bytes
	CPUUsage       float64 `json:"cpu_usage"`    // Percentage
	GoroutineCount int     `json:"goroutine_count"`

	// Server status
	Uptime    time.Duration `json:"uptime"`
	StartTime time.Time     `json:"start_time"`

	// Custom metrics
	CustomMetrics map[string]float64 `json:"custom_metrics,omitempty"`
}

// Route represents a registered HTTP route with metadata.
type Route struct {
	Method       string         `json:"method"`
	Path         string         `json:"path"`
	Handler      string         `json:"handler"`
	Middleware   []string       `json:"middleware,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	RegisteredAt time.Time      `json:"registered_at"`
}

// Middleware represents registered middleware with metadata.
type Middleware struct {
	Name         string          `json:"name"`
	Handler      gin.HandlerFunc `json:"-"` // Not serialized
	Order        int             `json:"order"`
	Metadata     map[string]any  `json:"metadata,omitempty"`
	RegisteredAt time.Time       `json:"registered_at"`
}

// RequestContext contains enhanced request context information.
type RequestContext struct {
	RequestID   string            `json:"request_id"`
	TraceID     string            `json:"trace_id,omitempty"`
	UserID      string            `json:"user_id,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
	StartTime   time.Time         `json:"start_time"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	RemoteAddr  string            `json:"remote_addr"`
	UserAgent   string            `json:"user_agent"`
	Headers     map[string]string `json:"headers,omitempty"`
	QueryParams map[string]string `json:"query_params,omitempty"`
	Metadata    map[string]any    `json:"metadata,omitempty"`
}

// ResponseContext contains response context information for logging.
type ResponseContext struct {
	StatusCode   int               `json:"status_code"`
	ResponseSize int64             `json:"response_size"`
	Duration     time.Duration     `json:"duration"`
	Headers      map[string]string `json:"headers,omitempty"`
	Error        string            `json:"error,omitempty"`
	CacheHit     bool              `json:"cache_hit,omitempty"`
	CacheKey     string            `json:"cache_key,omitempty"`
}

// SecurityContext contains security-related request information.
type SecurityContext struct {
	ClientIP      string   `json:"client_ip"`
	ForwardedFor  string   `json:"forwarded_for,omitempty"`
	TrustedProxy  bool     `json:"trusted_proxy"`
	TLSEnabled    bool     `json:"tls_enabled"`
	TLSVersion    string   `json:"tls_version,omitempty"`
	CipherSuite   string   `json:"cipher_suite,omitempty"`
	Certificate   string   `json:"certificate,omitempty"`
	RateLimited   bool     `json:"rate_limited"`
	RateLimitKey  string   `json:"rate_limit_key,omitempty"`
	Authenticated bool     `json:"authenticated"`
	AuthMethod    string   `json:"auth_method,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	Permissions   []string `json:"permissions,omitempty"`
}

// HandlerFunc represents an enhanced HTTP handler with context.
type HandlerFunc func(*Context)

// Context represents an enhanced Gin context with additional functionality.
type Context struct {
	*gin.Context

	// Enhanced context
	RequestCtx  *RequestContext
	ResponseCtx *ResponseContext
	SecurityCtx *SecurityContext
	Logger      *logger.Entry

	// Server reference
	server *Server

	// Request processing state
	startTime   time.Time
	aborted     bool
	skipLogging bool

	// Custom data storage
	data map[string]any
	mu   sync.RWMutex
}

// ServerOptions contains optional configuration for server creation.
type ServerOptions struct {
	// Custom router configuration
	RouterMode     string   `json:"router_mode,omitempty"`
	TrustedProxies []string `json:"trusted_proxies,omitempty"`

	// Performance tuning
	MaxHeaderBytes  int `json:"max_header_bytes,omitempty"`
	ReadBufferSize  int `json:"read_buffer_size,omitempty"`
	WriteBufferSize int `json:"write_buffer_size,omitempty"`

	// Custom handlers
	NotFoundHandler  gin.HandlerFunc  `json:"-"`
	MethodNotAllowed gin.HandlerFunc  `json:"-"`
	PanicHandler     gin.RecoveryFunc `json:"-"`

	// Middleware configuration
	DisableDefaultMiddleware bool              `json:"disable_default_middleware"`
	CustomMiddleware         []gin.HandlerFunc `json:"-"`

	// Monitoring configuration
	EnableMetrics bool `json:"enable_metrics"`
	EnablePprof   bool `json:"enable_pprof"`
	EnableTracing bool `json:"enable_tracing"`

	// Health check configuration
	HealthCheckers map[string]HealthChecker `json:"-"`

	// Custom error handlers
	ErrorHandlers map[int]gin.HandlerFunc `json:"-"`
}

// HealthChecker interface for custom health checks.
type HealthChecker interface {
	// Name returns the name of the health checker.
	Name() string

	// Check performs the health check and returns the result.
	Check(ctx context.Context) *DependencyHealth

	// Timeout returns the maximum time allowed for the health check.
	Timeout() time.Duration
}

// Middleware configuration constants.
const (
	// Default middleware execution order
	MiddlewareOrderRecovery    = 100
	MiddlewareOrderLogger      = 200
	MiddlewareOrderCORS        = 300
	MiddlewareOrderSecurity    = 400
	MiddlewareOrderRateLimit   = 500
	MiddlewareOrderAuth        = 600
	MiddlewareOrderValidation  = 700
	MiddlewareOrderCompression = 800
	MiddlewareOrderMetrics     = 900
	MiddlewareOrderTracing     = 950
	MiddlewareOrderApplication = 1000
)

// HTTP method constants for type safety.
const (
	MethodGET     = "GET"
	MethodPOST    = "POST"
	MethodPUT     = "PUT"
	MethodPATCH   = "PATCH"
	MethodDELETE  = "DELETE"
	MethodHEAD    = "HEAD"
	MethodOPTIONS = "OPTIONS"
	MethodTRACE   = "TRACE"
	MethodCONNECT = "CONNECT"
)

// Context keys for request data.
type ContextKey string

const (
	RequestIDKey   ContextKey = "request_id"
	TraceIDKey     ContextKey = "trace_id"
	UserIDKey      ContextKey = "user_id"
	SessionIDKey   ContextKey = "session_id"
	StartTimeKey   ContextKey = "start_time"
	SecurityCtxKey ContextKey = "security_context"
	LoggerKey      ContextKey = "logger"
)

// Server state constants.
const (
	ServerStateIdle     = "idle"
	ServerStateStarting = "starting"
	ServerStateRunning  = "running"
	ServerStateStopping = "stopping"
	ServerStateStopped  = "stopped"
	ServerStateError    = "error"
)

// Default configuration values.
const (
	DefaultShutdownTimeout     = 30 * time.Second
	DefaultReadTimeout         = 30 * time.Second
	DefaultWriteTimeout        = 30 * time.Second
	DefaultIdleTimeout         = 120 * time.Second
	DefaultMaxHeaderBytes      = 1 << 20 // 1MB
	DefaultRequestTimeout      = 30 * time.Second
	DefaultHealthCheckInterval = 30 * time.Second
	DefaultMetricsInterval     = 15 * time.Second
)

// Performance monitoring constants.
const (
	MetricsBufferSize      = 1000
	ConnectionTrackingSize = 10000
	MaxConcurrentRequests  = 10000
	RequestTimeoutDefault  = 30 * time.Second
)

// Security constants.
const (
	MaxRequestBodySize    = 10 << 20 // 10MB
	MaxFormMemory         = 32 << 20 // 32MB
	MaxMultipartMemory    = 32 << 20 // 32MB
	DefaultRateLimitRPS   = 1000
	DefaultRateLimitBurst = 2000
)

// Header constants for enhanced functionality.
const (
	HeaderRequestID      = "X-Request-ID"
	HeaderTraceID        = "X-Trace-ID"
	HeaderForwardedFor   = "X-Forwarded-For"
	HeaderRealIP         = "X-Real-IP"
	HeaderUserAgent      = "User-Agent"
	HeaderContentType    = "Content-Type"
	HeaderContentLength  = "Content-Length"
	HeaderAcceptEncoding = "Accept-Encoding"
	HeaderCacheControl   = "Cache-Control"
	HeaderAuthorization  = "Authorization"
)

// Response header constants for security and performance.
const (
	HeaderServer                  = "Server"
	HeaderXFrameOptions           = "X-Frame-Options"
	HeaderXContentTypeOptions     = "X-Content-Type-Options"
	HeaderXXSSProtection          = "X-XSS-Protection"
	HeaderStrictTransportSecurity = "Strict-Transport-Security"
	HeaderContentSecurityPolicy   = "Content-Security-Policy"
	HeaderReferrerPolicy          = "Referrer-Policy"
	HeaderPermissionsPolicy       = "Permissions-Policy"
)

// Error response templates for consistent error handling.
type ErrorResponse struct {
	Error     string         `json:"error"`
	Message   string         `json:"message"`
	Code      string         `json:"code,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

// SuccessResponse template for consistent success responses.
type SuccessResponse struct {
	Success   bool           `json:"success"`
	Message   string         `json:"message,omitempty"`
	Data      any            `json:"data,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}
