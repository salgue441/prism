package logger

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Logger errors for precise error handling and debugging.
var (
	// ErrInvalidLogLevel indicates an invalid log level was provided.
	ErrInvalidLogLevel = errors.New("invalid log level")

	// ErrInvalidLogFormat indicates an invalid log format was provided.
	ErrInvalidLogFormat = errors.New("invalid log format")

	// ErrInvalidOutput indicates an invalid log output was provided.
	ErrInvalidOutput = errors.New("invalid log output destination")

	// ErrInvalidSamplingRate indicates an invalid sampling rate was provided.
	ErrInvalidSamplingRate = errors.New("sampling rate must be between 0.0 and 1.0")

	// ErrBufferSizeInvalid indicates an invalid buffer size was provided.
	ErrBufferSizeInvalid = errors.New("buffer size must be non-negative")

	// ErrFlushIntervalInvalid indicates an invalid flush interval was provided.
	ErrFlushIntervalInvalid = errors.New("flush interval must be positive")

	// ErrMaxFieldSizeInvalid indicates an invalid max field size was provided.
	ErrMaxFieldSizeInvalid = errors.New("max field size must be positive")

	// ErrLoggerClosed indicates the logger has been closed and cannot be used.
	ErrLoggerClosed = errors.New("logger has been closed")
)

// Logger provides thread-safe, high-performance structured logging.
// It implements sampling, field sanitization, and performance optimizations
// for concurrent use.
type Logger struct {
	// Embedded logrus logger for core functionality
	*logrus.Logger

	// Atomic counters for performance metrics (lock-free access)
	logCount     int64 // Total number of log entries processed
	errorCount   int64 // Number of error-level log entries
	warnCount    int64 // Number of warning-level log entries
	sampledCount int64 // Number of log entries that were sampled (dropped)
	flushCount   int64 // Number of buffer flushes performed

	// Thread-safe configuration (protected by mutex)
	mu        sync.RWMutex
	config    *Config
	component string
	closed    int32 // Atomic flag indicating if logger is closed

	// Performance optimization: object pooling
	entryPool  sync.Pool
	bufferPool sync.Pool

	// Buffering and batching for performance
	buffer     []LogEntry
	bufferMu   sync.Mutex
	flushTimer *time.Timer
	flushDone  chan struct{}

	// Security: field sanitization
	sanitizer *FieldSanitizer

	// Output management
	outputs  []io.Writer
	outputMu sync.RWMutex
}

// Config holds configuration for creating a new logger instance.
// All fields are validated during logger creation for security and performance.
type Config struct {
	// Basic logging configuration
	Level  string `json:"level" validate:"required,oneof=trace debug info warn error fatal panic"`
	Format string `json:"format" validate:"required,oneof=json text"`
	Output string `json:"output" validate:"required"`

	// Performance and sampling configuration
	SamplingRate  float64       `json:"sampling_rate" validate:"min=0,max=1"`
	BufferSize    int           `json:"buffer_size" validate:"min=0"`
	FlushInterval time.Duration `json:"flush_interval" validate:"min=100ms"`

	// Security and privacy settings
	SanitizeFields bool     `json:"sanitize_fields"`
	RedactedFields []string `json:"redacted_fields"`
	MaxFieldSize   int      `json:"max_field_size" validate:"min=1"`

	// Advanced logging features
	EnableCaller     bool   `json:"enable_caller"`
	EnableStackTrace bool   `json:"enable_stack_trace"`
	ComponentName    string `json:"component_name"`

	// File rotation settings (when output is a file)
	MaxFileSize   int  `json:"max_file_size" validate:"min=1"` // MB
	MaxBackups    int  `json:"max_backups" validate:"min=0"`
	MaxAge        int  `json:"max_age" validate:"min=1"` // Days
	CompressFiles bool `json:"compress_files"`

	// Development and debugging
	PrettyPrint bool `json:"pretty_print"`
	ColorOutput bool `json:"color_output"`
}

// LogEntry represents a buffered log entry for high-performance batch processing.
type LogEntry struct {
	Level     logrus.Level   `json:"level"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields"`
	Timestamp time.Time      `json:"timestamp"`
	Component string         `json:"component,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
	TraceID   string         `json:"trace_id,omitempty"`

	// Caller information (when enabled)
	Caller *CallerInfo `json:"caller,omitempty"`

	// Stack trace (when enabled and level >= error)
	StackTrace string `json:"stack_trace,omitempty"`
}

// CallerInfo holds information about the code location that generated the log entry.
type CallerInfo struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function"`
}

// FieldSanitizer provides security-focused field sanitization and validation.
type FieldSanitizer struct {
	// Configuration
	maxFieldSize   int
	redactedFields map[string]bool
	enabled        bool

	// Performance optimization
	stringPool sync.Pool
}

// SanitizedField represents a field that has been processed for security.
type SanitizedField struct {
	Key       string `json:"key"`
	Value     any    `json:"value"`
	Redacted  bool   `json:"redacted,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Original  string `json:"original,omitempty"` // Hash of original for debugging
}

// LogMetrics provides performance and operational metrics for the logger.
type LogMetrics struct {
	// Message counters
	TotalMessages   int64 `json:"total_messages"`
	ErrorMessages   int64 `json:"error_messages"`
	WarnMessages    int64 `json:"warn_messages"`
	SampledMessages int64 `json:"sampled_messages"`

	// Performance metrics
	FlushCount        int64         `json:"flush_count"`
	BufferUtilization float64       `json:"buffer_utilization"`
	LastFlushLatency  time.Duration `json:"last_flush_latency"`

	// Error tracking
	FlushErrors  int64 `json:"flush_errors"`
	WriteErrors  int64 `json:"write_errors"`
	FormatErrors int64 `json:"format_errors"`

	// Timing information
	LastFlushTime time.Time `json:"last_flush_time"`
	StartTime     time.Time `json:"start_time"`
}

// Entry represents an enhanced log entry with additional context and security features.
// It extends the base logrus.Entry with Prism-specific functionality.
type Entry struct {
	*logrus.Entry
	logger    *Logger
	component string
	requestID string
	traceID   string
	startTime time.Time
}

// HTTPRequestLogFields contains fields for HTTP request logging.
type HTTPRequestLogFields struct {
	Method       string        `json:"method"`
	Path         string        `json:"path"`
	UserAgent    string        `json:"user_agent"`
	ClientIP     string        `json:"client_ip"`
	StatusCode   int           `json:"status_code"`
	Duration     time.Duration `json:"duration"`
	RequestSize  int64         `json:"request_size,omitempty"`
	ResponseSize int64         `json:"response_size,omitempty"`
	RequestID    string        `json:"request_id,omitempty"`
	TraceID      string        `json:"trace_id,omitempty"`
}

// ErrorLogFields contains fields for error logging with context.
type ErrorLogFields struct {
	Error      error          `json:"error"`
	ErrorType  string         `json:"error_type,omitempty"`
	ErrorCode  string         `json:"error_code,omitempty"`
	Component  string         `json:"component"`
	Operation  string         `json:"operation,omitempty"`
	Context    map[string]any `json:"context,omitempty"`
	RequestID  string         `json:"request_id,omitempty"`
	TraceID    string         `json:"trace_id,omitempty"`
	StackTrace string         `json:"stack_trace,omitempty"`
}

// StartupLogFields contains fields for application startup logging.
type StartupLogFields struct {
	Component string         `json:"component"`
	Version   string         `json:"version"`
	Address   string         `json:"address"`
	Config    map[string]any `json:"config,omitempty"`
	StartTime time.Time      `json:"start_time"`
}

// ShutdownLogFields contains fields for application shutdown logging.
type ShutdownLogFields struct {
	Component string        `json:"component"`
	Reason    string        `json:"reason"`
	Uptime    time.Duration `json:"uptime"`
	Graceful  bool          `json:"graceful"`
}

// SecurityEventFields contains fields for security event logging.
type SecurityEventFields struct {
	EventType string         `json:"event_type"`
	Severity  string         `json:"severity"`
	Source    string         `json:"source"`
	Target    string         `json:"target,omitempty"`
	Action    string         `json:"action"`
	Result    string         `json:"result"`
	Reason    string         `json:"reason,omitempty"`
	ClientIP  string         `json:"client_ip,omitempty"`
	UserAgent string         `json:"user_agent,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// PerformanceLogFields contains fields for performance monitoring.
type PerformanceLogFields struct {
	Operation     string             `json:"operation"`
	Component     string             `json:"component"`
	Duration      time.Duration      `json:"duration"`
	Success       bool               `json:"success"`
	Metrics       map[string]float64 `json:"metrics,omitempty"`
	Thresholds    map[string]float64 `json:"thresholds,omitempty"`
	ResourceUsage map[string]any     `json:"resource_usage,omitempty"`
	RequestID     string             `json:"request_id,omitempty"`
}

// AuditLogFields contains fields for audit trail logging.
type AuditLogFields struct {
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	ResourceID string         `json:"resource_id,omitempty"`
	Actor      string         `json:"actor"`
	ActorType  string         `json:"actor_type"`
	Result     string         `json:"result"`
	Changes    map[string]any `json:"changes,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	ClientIP   string         `json:"client_ip,omitempty"`
	UserAgent  string         `json:"user_agent,omitempty"`
	RequestID  string         `json:"request_id,omitempty"`
	SessionID  string         `json:"session_id,omitempty"`
	Timestamp  time.Time      `json:"timestamp"`
}

// LogLevel represents the severity level of a log entry.
type LogLevel int

// Log level constants matching logrus levels for type safety.
const (
	TraceLevel LogLevel = iota
	DebugLevel
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
	PanicLevel
)

// String returns the string representation of the log level.
func (l LogLevel) String() string {
	switch l {
	case TraceLevel:
		return "trace"

	case DebugLevel:
		return "debug"

	case InfoLevel:
		return "info"

	case WarnLevel:
		return "warn"

	case ErrorLevel:
		return "error"

	case FatalLevel:
		return "fatal"

	case PanicLevel:
		return "panic"

	default:
		return "unknown"
	}
}

// ParseLogLevel parses a string representation into a LogLevel.
func ParseLogLevel(level string) (LogLevel, error) {
	switch level {
	case "trace":
		return TraceLevel, nil

	case "debug":
		return DebugLevel, nil

	case "info":
		return InfoLevel, nil

	case "warn", "warning":
		return WarnLevel, nil

	case "error":
		return ErrorLevel, nil

	case "fatal":
		return FatalLevel, nil

	case "panic":
		return PanicLevel, nil

	default:
		return InfoLevel, ErrInvalidLogLevel
	}
}

// LogFormat represents the output format for log entries.
type LogFormat int

// Log format constants for type safety.
const (
	JSONFormat LogFormat = iota
	TextFormat
)

// String returns the string representation of the log format.
func (f LogFormat) String() string {
	switch f {
	case JSONFormat:
		return "json"
	case TextFormat:
		return "text"
	default:
		return "json"
	}
}

// ParseLogFormat parses a string representation into a LogFormat.
func ParseLogFormat(format string) (LogFormat, error) {
	switch format {
	case "json":
		return JSONFormat, nil

	case "text":
		return TextFormat, nil

	default:
		return JSONFormat, ErrInvalidLogFormat
	}
}

// SamplingStrategy defines how log sampling should be performed.
type SamplingStrategy int

// Sampling strategy constants.
const (
	UniformSampling  SamplingStrategy = iota // Random uniform sampling
	PrioritySampling                         // Priority-based sampling (always log errors)
	BurstSampling                            // Allow bursts, then sample
	AdaptiveSampling                         // Adaptive based on system load
)

// String returns the string representation of the sampling strategy.
func (s SamplingStrategy) String() string {
	switch s {
	case UniformSampling:
		return "uniform"

	case PrioritySampling:
		return "priority"

	case BurstSampling:
		return "burst"

	case AdaptiveSampling:
		return "adaptive"

	default:
		return "uniform"
	}
}

// BufferConfig holds configuration for log buffering and batching.
type BufferConfig struct {
	Size          int           `json:"size" validate:"min=0"`
	FlushInterval time.Duration `json:"flush_interval" validate:"min=100ms"`
	FlushOnLevel  LogLevel      `json:"flush_on_level"` // Flush immediately on this level or higher
	MaxBatchSize  int           `json:"max_batch_size" validate:"min=1"`
}

// SecurityConfig holds security-related logging configuration.
type SecurityConfig struct {
	SanitizeFields bool     `json:"sanitize_fields"`
	RedactedFields []string `json:"redacted_fields"`
	MaxFieldSize   int      `json:"max_field_size" validate:"min=1"`
	HashPII        bool     `json:"hash_pii"`   // Hash PII instead of redacting
	AuditMode      bool     `json:"audit_mode"` // Enable audit trail features
}

// OutputConfig holds configuration for log output destinations.
type OutputConfig struct {
	Type   string         `json:"type" validate:"required,oneof=stdout stderr file syslog"`
	Target string         `json:"target,omitempty"`
	Config map[string]any `json:"config,omitempty"`
}

// Formatter interface for custom log formatters.
type Formatter interface {
	Format(entry *LogEntry) ([]byte, error)
}

// Hook interface for custom log hooks.
type Hook interface {
	Levels() []logrus.Level
	Fire(entry *logrus.Entry) error
}

// Filter interface for custom log filtering.
type Filter interface {
	ShouldLog(entry *LogEntry) bool
}

// Writer interface for custom log writers with enhanced capabilities.
type Writer interface {
	io.Writer
	Flush() error
	Close() error
}

// ContextKey type for context keys to avoid collisions.
type ContextKey string

// Context keys for request correlation.
const (
	RequestIDKey ContextKey = "request_id"
	TraceIDKey   ContextKey = "trace_id"
	ComponentKey ContextKey = "component"
	StartTimeKey ContextKey = "start_time"
)
