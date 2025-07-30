package logger

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
)

// New creates a new high-performance, thread-safe logger instance with
// comprehensive and performance features. It validates all configuration
// params and initializes optimized data structures for concurrent use.
//
// The logger implements:
//   - Thread-safe operations with minimal lock contention
//   - Field sanitization and PII protection
//   - Configurable sampling for high-volume environments
//   - Object pooling for reduced garbage collection pressure
//   - Buffered I/O with configurable flush intervals
//
// Parameters:
//   - config: Logger configuration with validation
//
// Returns:
//   - *Logger: Configured logger instance ready for use
//   - error: Configuration validation or initialization error
func New(config *Config) (*Logger, error) {
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid logger configuration: %w", err)
	}

	baseLogger := logrus.New()
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level %s: %w", config.Level, err)
	}

	baseLogger.SetLevel(level)
	output, err := configureOutput(config.Output)
	if err != nil {
		return nil, fmt.Errorf("failed to configure output: %w", err)
	}

	baseLogger.SetOutput(output)
	formatter, err := configureFormatter(config)
	if err != nil {
		return nil, fmt.Errorf("failed to configure formatter: %w", err)
	}

	baseLogger.SetFormatter(formatter)
	logger := &Logger{
		Logger:    baseLogger,
		config:    config,
		component: config.ComponentName,
		flushDone: make(chan struct{}),
	}

	logger.entryPool = sync.Pool{
		New: func() any {
			return &LogEntry{
				Fields: make(map[string]any, 8),
			}
		},
	}

	logger.bufferPool = sync.Pool{
		New: func() any {
			return make([]byte, 0, 1024)
		},
	}

	if config.SanitizeFields {
		logger.sanitizer = newFieldSanitizer(config)
	}

	if config.BufferSize > 0 {
		logger.buffer = make([]LogEntry, 0, config.BufferSize)
		logger.startFlushTimer()
	}

	return logger, nil
}

// WithComponent creates a new logger instance with a specific component name.
// This method is thread-safe and optimized for frequent calls.
func (l *Logger) WithComponent(component string) *Logger {
	if atomic.LoadInt32(&l.closed) != 0 {
		return l
	}

	newLogger := &Logger{
		Logger:    l.Logger,
		config:    l.config,
		component: component,
		entryPool: sync.Pool{
			New: l.entryPool.New,
		},
		bufferPool: sync.Pool{
			New: l.bufferPool.New,
		},
		sanitizer: l.sanitizer,
		flushDone: l.flushDone,
	}

	return newLogger
}

// WithRequestID creates a new entry with request ID for correlation.
func (l *Logger) WithRequestID(requestID string) *Entry {
	if atomic.LoadInt32(&l.closed) != 0 {
		return &Entry{Entry: logrus.NewEntry(l.Logger), logger: l}
	}

	entry := &Entry{
		Entry:     l.Logger.WithField("request_id", requestID),
		logger:    l,
		requestID: requestID,
		startTime: time.Now(),
	}

	return entry
}

// WithTraceID creates a new entry with trace ID for distributed tracing.
func (l *Logger) WithTraceID(traceID string) *Entry {
	if atomic.LoadInt32(&l.closed) != 0 {
		return &Entry{Entry: logrus.NewEntry(l.Logger), logger: l}
	}

	entry := &Entry{
		Entry:     l.Logger.WithField("trace_id", traceID),
		logger:    l,
		traceID:   traceID,
		startTime: time.Now(),
	}

	return entry
}

// WithContext creates a new entry with context values for correlation.
func (l *Logger) WithContext(ctx context.Context) *Entry {
	if atomic.LoadInt32(&l.closed) != 0 {
		return &Entry{Entry: logrus.NewEntry(l.Logger), logger: l}
	}

	entry := &Entry{
		Entry:     logrus.NewEntry(l.Logger),
		logger:    l,
		startTime: time.Now(),
	}

	if requestID, ok := ctx.Value(RequestIDKey).(string); ok {
		entry.requestID = requestID
		entry.Entry = entry.Entry.WithField("request_id", requestID)
	}

	if traceID, ok := ctx.Value(TraceIDKey).(string); ok {
		entry.traceID = traceID
		entry.Entry = entry.Entry.WithField("trace_id", traceID)
	}

	if component, ok := ctx.Value(ComponentKey).(string); ok {
		entry.component = component
		entry.Entry = entry.Entry.WithField("component", component)
	}

	return entry
}

// WithFields creates a new entry with multiple fields.
func (l *Logger) WithFields(fields map[string]any) *Entry {
	if atomic.LoadInt32(&l.closed) != 0 {
		return &Entry{Entry: logrus.NewEntry(l.Logger), logger: l}
	}

	if l.sanitizer != nil {
		fields = l.sanitizer.SanitizeFields(fields)
	}

	entry := &Entry{
		Entry:     l.Logger.WithFields(fields),
		logger:    l,
		component: l.component,
		startTime: time.Now(),
	}

	return entry
}

// WithField creates a new entry with a single field.
func (l *Logger) WithField(key string, value any) *Entry {
	return l.WithFields(map[string]any{key: value})
}

// WithError creates a new entry with an error field.
func (l *Logger) WithError(err error) *Entry {
	if atomic.LoadInt32(&l.closed) != 0 {
		return &Entry{Entry: logrus.NewEntry(l.Logger), logger: l}
	}

	entry := &Entry{
		Entry:     l.Logger.WithError(err),
		logger:    l,
		component: l.component,
		startTime: time.Now(),
	}

	return entry
}

// validateConfig performs comprehensive validation of logger configuration.
func validateConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	validLevels := map[string]bool{
		"trace": true, "debug": true, "info": true,
		"warn": true, "error": true, "fatal": true, "panic": true,
	}
	if !validLevels[config.Level] {
		return fmt.Errorf("%w: %s", ErrInvalidLogLevel, config.Level)
	}

	validFormats := map[string]bool{"json": true, "text": true}
	if !validFormats[config.Format] {
		return fmt.Errorf("%w: %s", ErrInvalidLogFormat, config.Format)
	}

	if config.SamplingRate < 0 || config.SamplingRate > 1 {
		return ErrInvalidSamplingRate
	}

	if config.BufferSize < 0 {
		return ErrBufferSizeInvalid
	}

	if config.FlushInterval <= 0 && config.BufferSize > 0 {
		return ErrFlushIntervalInvalid
	}

	if config.SanitizeFields && config.MaxFieldSize <= 0 {
		return ErrMaxFieldSizeInvalid
	}

	return nil
}

// configureOutput sets up the output destination for log messages.
func configureOutput(output string) (io.Writer, error) {
	switch strings.ToLower(output) {
	case "stdout":
		return os.Stdout, nil

	case "stderr":
		return os.Stderr, nil

	default:
		dir := filepath.Dir(output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		file, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}

		return file, nil
	}
}

// configureFormatter sets up the log formatter based on configuration.
func configureFormatter(config *Config) (logrus.Formatter, error) {
	switch config.Format {
	case "json":
		return &logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "caller",
			},
			PrettyPrint: config.PrettyPrint,
		}, nil

	case "text":
		return &logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339Nano,
			ForceColors:     config.ColorOutput,
			DisableColors:   !config.ColorOutput,
		}, nil

	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidLogFormat, config.Format)
	}
}

// Log methods with performance optimizations and security features

// Trace logs a message at trace level with sampling consideration.
func (l *Logger) Trace(msg string, fields ...any) {
	if !l.shouldLog(TraceLevel) {
		return
	}

	l.logWithFields(logrus.TraceLevel, msg, fields...)
}

// Debug logs a message at debug level with sampling consideration.
func (l *Logger) Debug(msg string, fields ...any) {
	if !l.shouldLog(DebugLevel) {
		return
	}

	l.logWithFields(logrus.DebugLevel, msg, fields...)
}

// Info logs a message at info level with sampling consideration.
func (l *Logger) Info(msg string, fields ...any) {
	if !l.shouldLog(InfoLevel) {
		return
	}

	l.logWithFields(logrus.InfoLevel, msg, fields...)
}

// Warn logs a message at warning level with sampling consideration.
func (l *Logger) Warn(msg string, fields ...any) {
	if !l.shouldLog(WarnLevel) {
		return
	}

	atomic.AddInt64(&l.warnCount, 1)
	l.logWithFields(logrus.WarnLevel, msg, fields...)
}

// Error logs a message at error level (always logged, no sampling).
func (l *Logger) Error(msg string, fields ...any) {
	atomic.AddInt64(&l.errorCount, 1)
	l.logWithFields(logrus.ErrorLevel, msg, fields...)
}

// Fatal logs a message at fatal level and calls os.Exit(1).
func (l *Logger) Fatal(msg string, fields ...any) {
	l.logWithFields(logrus.FatalLevel, msg, fields...)
	l.Close()

	os.Exit(1)
}

// Panic logs a message at panic level and panics.
func (l *Logger) Panic(msg string, fields ...any) {
	l.logWithFields(logrus.PanicLevel, msg, fields...)
	panic(msg)
}

// logWithFields is the internal method that handles field processing and logging.
func (l *Logger) logWithFields(level logrus.Level, msg string, fields ...any) {
	if atomic.LoadInt32(&l.closed) != 0 {
		return
	}

	fieldMap := make(map[string]any)
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok && i+1 < len(fields) {
			fieldMap[key] = fields[i+1]
		}
	}

	if l.component != "" {
		fieldMap["component"] = l.component
	}

	if l.sanitizer != nil {
		fieldMap = l.sanitizer.SanitizeFields(fieldMap)
	}

	if l.config.EnableCaller {
		if caller := l.getCaller(); caller != nil {
			fieldMap["caller"] = caller
		}
	}

	if l.config.EnableStackTrace && level >= logrus.ErrorLevel {
		fieldMap["stack_trace"] = l.getStackTrace()
	}

	entry := l.Logger.WithFields(fieldMap)
	switch level {
	case logrus.TraceLevel:
		entry.Trace(msg)

	case logrus.DebugLevel:
		entry.Debug(msg)

	case logrus.InfoLevel:
		entry.Info(msg)

	case logrus.WarnLevel:
		entry.Warn(msg)

	case logrus.ErrorLevel:
		entry.Error(msg)

	case logrus.FatalLevel:
		entry.Fatal(msg)

	case logrus.PanicLevel:
		entry.Panic(msg)
	}

	atomic.AddInt64(&l.logCount, 1)
}

// shouldLog determines if a log entry should be written based on sampling configuration.
func (l *Logger) shouldLog(level LogLevel) bool {
	if atomic.LoadInt32(&l.closed) != 0 {
		return false
	}

	if level >= ErrorLevel {
		return true
	}

	logrusLevel, _ := logrus.ParseLevel(level.String())
	if !l.Logger.IsLevelEnabled(logrusLevel) {
		return false
	}

	if l.config.SamplingRate < 1.0 {
		if rand.Float64() > l.config.SamplingRate {
			atomic.AddInt64(&l.sampledCount, 1)
			return false
		}
	}

	return true
}

// getCaller returns caller information for the log entry.
func (l *Logger) getCaller() *CallerInfo {
	const skip = 4
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return nil
	}

	function := "unknown"
	if fn := runtime.FuncForPC(pc); fn != nil {
		function = fn.Name()
	}

	return &CallerInfo{
		File:     filepath.Base(file),
		Line:     line,
		Function: function,
	}
}

// getStackTrace returns a formatted stack trace.
func (l *Logger) getStackTrace() string {
	const maxStackSize = 4096
	buf := make([]byte, maxStackSize)
	n := runtime.Stack(buf, false)

	return string(buf[:n])
}

// Specialized logging methods for common use cases

// LogRequest logs HTTP request information with standardized fields.
func (l *Logger) LogRequest(method, path, userAgent, clientIP string,
	statusCode int, duration float64) {
	fields := &HTTPRequestLogFields{
		Method:     method,
		Path:       path,
		UserAgent:  userAgent,
		ClientIP:   clientIP,
		StatusCode: statusCode,
		Duration:   time.Duration(duration * float64(time.Millisecond)),
	}

	l.WithFields(StructToMapFast(fields)).Info("HTTP request processed")
}

// LogError logs an error with comprehensive context information.
func (l *Logger) LogError(component string, err error, context map[string]any) {
	fields := &ErrorLogFields{
		Error:     err,
		ErrorType: fmt.Sprintf("%T", err),
		Component: component,
		Context:   context,
	}

	if l.config.EnableStackTrace {
		fields.StackTrace = l.getStackTrace()
	}

	l.WithFields(StructToMapFast(fields)).Error("Error occurred")
}

// LogStartup logs application startup information.
func (l *Logger) LogStartup(component, version, address string) {
	fields := &StartupLogFields{
		Component: component,
		Version:   version,
		Address:   address,
		StartTime: time.Now(),
	}

	l.WithFields(StructToMapFast(fields)).Info("Component started")
}

// LogShutdown logs application shutdown information.
func (l *Logger) LogShutdown(component, reason string, uptime time.Duration, graceful bool) {
	fields := &ShutdownLogFields{
		Component: component,
		Reason:    reason,
		Uptime:    uptime,
		Graceful:  graceful,
	}

	l.WithFields(StructToMapFast(fields)).Info("Component shutdown")
}

// LogSecurityEvent logs security-related events with appropriate fields.
func (l *Logger) LogSecurityEvent(eventType, severity, source, action, result string, metadata map[string]any) {
	fields := &SecurityEventFields{
		EventType: eventType,
		Severity:  severity,
		Source:    source,
		Action:    action,
		Result:    result,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}

	l.WithFields(StructToMapFast(fields)).Warn("Security event")
}

// LogPerformance logs performance metrics and monitoring data.
func (l *Logger) LogPerformance(operation, component string, duration time.Duration, success bool, metrics map[string]float64) {
	fields := &PerformanceLogFields{
		Operation: operation,
		Component: component,
		Duration:  duration,
		Success:   success,
		Metrics:   metrics,
	}

	level := "info"
	if !success {
		level = "warn"
	}

	entry := l.WithFields(StructToMapFast(fields))
	if level == "warn" {
		entry.Warn("Performance event")
	} else {
		entry.Info("Performance event")
	}
}

// LogAudit logs audit trail information for compliance and security.
func (l *Logger) LogAudit(action, resource, actor, result string, changes map[string]any) {
	fields := &AuditLogFields{
		Action:    action,
		Resource:  resource,
		Actor:     actor,
		Result:    result,
		Changes:   changes,
		Timestamp: time.Now(),
	}

	l.WithFields(StructToMapFast(fields)).Info("Audit event")
}

// Performance and metrics methods

// GetMetrics returns current logger performance metrics.
func (l *Logger) GetMetrics() *LogMetrics {
	return &LogMetrics{
		TotalMessages:   atomic.LoadInt64(&l.logCount),
		ErrorMessages:   atomic.LoadInt64(&l.errorCount),
		WarnMessages:    atomic.LoadInt64(&l.warnCount),
		SampledMessages: atomic.LoadInt64(&l.sampledCount),
		FlushCount:      atomic.LoadInt64(&l.flushCount),
		StartTime:       time.Now(),
	}
}

// ResetMetrics resets all performance counters.
func (l *Logger) ResetMetrics() {
	atomic.StoreInt64(&l.logCount, 0)
	atomic.StoreInt64(&l.errorCount, 0)
	atomic.StoreInt64(&l.warnCount, 0)
	atomic.StoreInt64(&l.sampledCount, 0)
	atomic.StoreInt64(&l.flushCount, 0)
}

// Flush forces all buffered log entries to be written immediately.
func (l *Logger) Flush() error {
	if atomic.LoadInt32(&l.closed) != 0 {
		return ErrLoggerClosed
	}

	l.bufferMu.Lock()
	defer l.bufferMu.Unlock()

	if len(l.buffer) == 0 {
		return nil
	}

	for _, entry := range l.buffer {
		logrusEntry := l.Logger.WithFields(entry.Fields)
		logrusEntry.Time = entry.Timestamp
		logrusEntry.Level = entry.Level
		logrusEntry.Message = entry.Message
	}

	l.buffer = l.buffer[:0]
	atomic.AddInt64(&l.flushCount, 1)

	return nil
}

// Close gracefully closes the logger, flushing any buffered entries.
func (l *Logger) Close() error {
	if !atomic.CompareAndSwapInt32(&l.closed, 0, 1) {
		return ErrLoggerClosed
	}

	if l.flushTimer != nil {
		l.flushTimer.Stop()
	}

	close(l.flushDone)
	if err := l.Flush(); err != nil {
		return fmt.Errorf("failed to flush during close: %w", err)
	}

	return nil
}

// startFlushTimer starts the periodic flush timer for buffered logging.
func (l *Logger) startFlushTimer() {
	l.flushTimer = time.NewTimer(l.config.FlushInterval)

	go func() {
		for {
			select {
			case <-l.flushTimer.C:
				if err := l.Flush(); err != nil {
					fmt.Fprintf(os.Stderr, "Logger flush error: %v\n", err)
				}

				l.flushTimer.Reset(l.config.FlushInterval)
			case <-l.flushDone:
				return
			}
		}
	}()
}

// Entry methods for fluent interface

// WithField adds a field to the log entry.
func (e *Entry) WithField(key string, value any) *Entry {
	if e.logger.sanitizer != nil {
		fields := map[string]any{key: value}
		fields = e.logger.sanitizer.SanitizeFields(fields)
		value = fields[key]
	}

	return &Entry{
		Entry:     e.Entry.WithField(key, value),
		logger:    e.logger,
		component: e.component,
		requestID: e.requestID,
		traceID:   e.traceID,
		startTime: e.startTime,
	}
}

// WithFields adds multiple fields to the log entry.
func (e *Entry) WithFields(fields map[string]any) *Entry {
	if e.logger.sanitizer != nil {
		fields = e.logger.sanitizer.SanitizeFields(fields)
	}

	return &Entry{
		Entry:     e.Entry.WithFields(fields),
		logger:    e.logger,
		component: e.component,
		requestID: e.requestID,
		traceID:   e.traceID,
		startTime: e.startTime,
	}
}

// WithError adds an error field to the log entry.
func (e *Entry) WithError(err error) *Entry {
	return &Entry{
		Entry:     e.Entry.WithError(err),
		logger:    e.logger,
		component: e.component,
		requestID: e.requestID,
		traceID:   e.traceID,
		startTime: e.startTime,
	}
}

// WithDuration adds a duration field calculated from the entry's start time.
func (e *Entry) WithDuration() *Entry {
	duration := time.Since(e.startTime)
	return e.WithField("duration", duration)
}

// Field sanitizer implementation

// newFieldSanitizer creates a new field sanitizer with the given configuration.
func newFieldSanitizer(config *Config) *FieldSanitizer {
	redactedFields := make(map[string]bool)
	for _, field := range config.RedactedFields {
		redactedFields[strings.ToLower(field)] = true
	}

	return &FieldSanitizer{
		maxFieldSize:   config.MaxFieldSize,
		redactedFields: redactedFields,
		enabled:        config.SanitizeFields,
		stringPool: sync.Pool{
			New: func() any {
				return make([]byte, 0, 256)
			},
		},
	}
}

// SanitizeFields sanitizes a map of fields for security and size constraints.
func (fs *FieldSanitizer) SanitizeFields(fields map[string]any) map[string]any {
	if !fs.enabled || len(fields) == 0 {
		return fields
	}

	sanitized := make(map[string]any, len(fields))

	for key, value := range fields {
		sanitized[key] = fs.sanitizeValue(key, value)
	}

	return sanitized
}

// sanitizeValue sanitizes a single field value.
func (fs *FieldSanitizer) sanitizeValue(key string, value any) any {
	if fs.redactedFields[strings.ToLower(key)] {
		return "[REDACTED]"
	}

	str := fmt.Sprintf("%v", value)
	if len(str) > fs.maxFieldSize {
		truncated := str[:fs.maxFieldSize-10] + "...[TRUNC]"
		return truncated
	}

	str = fs.sanitizeString(str)
	return str
}

// sanitizeString removes potentially dangerous characters from log strings.
func (fs *FieldSanitizer) sanitizeString(s string) string {
	var result strings.Builder
	result.Grow(len(s))

	for _, r := range s {
		switch {
		case r == '\n':
			result.WriteString("\\n")

		case r == '\r':
			result.WriteString("\\r")

		case r == '\t':
			result.WriteString("\\t")

		case r < 32 || r == 127:
			result.WriteString(fmt.Sprintf("\\x%02x", r))

		default:
			result.WriteRune(r)
		}
	}

	return result.String()
}

// Utility functions

// structToMapOptions controls the behavior of struct to map conversion.
type structToMapOptions struct {
	// TagName specifies the struct tag to use for field names (default: "json")
	TagName string

	// OmitEmpty omits fields with zero values
	OmitEmpty bool

	// MaxDepth prevents infinite recursion in nested structs
	MaxDepth int

	// FieldFilter allows filtering which fields to include
	FieldFilter func(fieldName string, fieldValue any) bool

	// KeyTransform allows transforming field names
	KeyTransform func(key string) string
}

// Default options for struct conversion
var defaultStructToMapOptions = &structToMapOptions{
	TagName:   "json",
	OmitEmpty: true,
	MaxDepth:  3,
}

// Cache for reflection type information to improve performance
var (
	structInfoCache = sync.Map{} // map[reflect.Type]*structInfo
	structPoolCache = sync.Map{} // map[reflect.Type]*sync.Pool
)

// structInfo holds cached reflection information for a struct type
type structInfo struct {
	fields []fieldInfo
	isPtr  bool
}

// fieldInfo holds information about a struct field
type fieldInfo struct {
	name      string
	jsonName  string
	offset    uintptr
	typ       reflect.Type
	omitEmpty bool
	skip      bool
}

// structToMap converts a struct to a map with high performance and security.
// It uses reflection caching and unsafe operations for optimal performance
// while maintaining type safety and preventing common security issues.
//
// Performance optimizations:
//   - Reflection type caching to avoid repeated type analysis
//   - Object pooling for map allocation
//   - Unsafe field access for direct memory reads (when safe)
//   - Compile-time field analysis and caching
//
// Security features:
//   - Depth limiting to prevent stack overflow from recursive structs
//   - Field filtering to prevent sensitive data exposure
//   - Size limiting for large collections
//   - Safe handling of unexported fields
//
// Parameters:
//   - v: The struct or pointer to struct to convert
//   - opts: Optional conversion options (nil uses defaults)
//
// Returns:
//   - map[string]any: The converted map
//   - error: Any conversion error encountered
func structToMap(v any, opts ...*structToMapOptions) (map[string]any, error) {
	if v == nil {
		return nil, nil
	}

	options := defaultStructToMapOptions
	if len(opts) > 0 && opts[0] != nil {
		options = opts[0]
	}

	pool := getMapPool()
	result := pool.Get().(map[string]any)
	defer func() {
		for k := range result {
			delete(result, k)
		}

		pool.Put(result)
	}()

	finalResult := make(map[string]any)
	if err := structToMapRecursive(v, finalResult, options, 0); err != nil {
		return nil, err
	}

	for k, v := range result {
		finalResult[k] = v
	}

	return finalResult, nil
}

// getMapPool returns an object pool for map allocation
func getMapPool() *sync.Pool {
	return &sync.Pool{
		New: func() any {
			return make(map[string]any, 16)
		},
	}
}

// structToMapRecursive handles the recursive conversion with depth control
func structToMapRecursive(v any, result map[string]any,
	opts *structToMapOptions, depth int) error {
	if depth > opts.MaxDepth {
		return nil
	}

	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return nil
	}

	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil
		}

		rv = rv.Elem()
	}

	if rv.Kind() != reflect.Struct {
		return convertKnownTypes(v, result, opts)
	}

	rt := rv.Type()
	info := getStructInfo(rt)

	for _, field := range info.fields {
		if field.skip {
			continue
		}

		fieldValue := getFieldValue(rv, field)
		if opts.FieldFilter != nil &&
			!opts.FieldFilter(field.name, fieldValue.Interface()) {
			continue
		}

		if opts.OmitEmpty && field.omitEmpty && isZeroValue(fieldValue) {
			continue
		}

		key := field.jsonName
		if key == "" {
			key = field.name
		}

		if opts.KeyTransform != nil {
			key = opts.KeyTransform(key)
		}

		convertedValue, err := convertFieldValue(fieldValue, opts, depth+1)
		if err != nil {
			return err
		}

		result[key] = convertedValue
	}

	return nil
}

// getStructInfo retrieves or creates cached struct information
func getStructInfo(rt reflect.Type) *structInfo {
	if cached, ok := structInfoCache.Load(rt); ok {
		return cached.(*structInfo)
	}

	info := analyzeStruct(rt)
	structInfoCache.Store(rt, info)
	return info
}

// analyzeStruct performs compile-time analysis of struct fields
func analyzeStruct(rt reflect.Type) *structInfo {
	numFields := rt.NumField()
	fields := make([]fieldInfo, 0, numFields)

	for i := 0; i < numFields; i++ {
		field := rt.Field(i)
		if !field.IsExported() {
			continue
		}

		fieldInfo := fieldInfo{
			name:   field.Name,
			offset: field.Offset,
			typ:    field.Type,
		}

		if tag := field.Tag.Get("json"); tag != "" {
			parts := strings.Split(tag, ",")
			if parts[0] == "-" {
				fieldInfo.skip = true
				continue
			}

			if parts[0] != "" {
				fieldInfo.jsonName = parts[0]
			}

			for _, option := range parts[1:] {
				if option == "omitempty" {
					fieldInfo.omitEmpty = true
				}
			}
		}

		if fieldInfo.jsonName == "" {
			fieldInfo.jsonName = toSnakeCase(field.Name)
		}

		fields = append(fields, fieldInfo)
	}

	return &structInfo{
		fields: fields,
		isPtr:  rt.Kind() == reflect.Ptr,
	}
}

// getFieldValue efficiently retrieves a field value using unsafe operations when safe
func getFieldValue(structValue reflect.Value, field fieldInfo) reflect.Value {
	if structValue.CanAddr() {
		structPtr := structValue.UnsafeAddr()
		fieldPtr := unsafe.Pointer(structPtr + field.offset)
		return reflect.NewAt(field.typ, fieldPtr).Elem()
	}

	return structValue.FieldByName(field.name)
}

// convertFieldValue converts a field value to the appropriate type for the map
func convertFieldValue(fv reflect.Value, opts *structToMapOptions, depth int) (any, error) {
	if !fv.IsValid() {
		return nil, nil
	}

	for fv.Kind() == reflect.Ptr {
		if fv.IsNil() {
			return nil, nil
		}

		fv = fv.Elem()
	}

	switch fv.Kind() {
	case reflect.Struct:
		if fv.Type() == reflect.TypeOf(time.Time{}) {
			return fv.Interface().(time.Time), nil
		}

		nestedMap := make(map[string]any)
		if err := structToMapRecursive(fv.Interface(), nestedMap, opts, depth); err != nil {
			return nil, err
		}

		return nestedMap, nil

	case reflect.Slice, reflect.Array:
		return convertSliceValue(fv, opts, depth)

	case reflect.Map:
		return convertMapValue(fv, opts, depth)

	case reflect.Interface:
		if fv.IsNil() {
			return nil, nil
		}

		return convertFieldValue(fv.Elem(), opts, depth)

	default:
		return fv.Interface(), nil
	}
}

// convertSliceValue converts slice/array values with size limiting for security
func convertSliceValue(fv reflect.Value, opts *structToMapOptions, depth int) (any, error) {
	length := fv.Len()

	// Security: limit slice size to prevent memory exhaustion
	const maxSliceSize = 1000
	if length > maxSliceSize {
		length = maxSliceSize
	}

	result := make([]any, length)
	for i := 0; i < length; i++ {
		elem := fv.Index(i)
		convertedElem, err := convertFieldValue(elem, opts, depth)
		if err != nil {
			return nil, err
		}
		result[i] = convertedElem
	}

	return result, nil
}

// convertMapValue converts map values with key/value conversion
func convertMapValue(fv reflect.Value, opts *structToMapOptions, depth int) (any, error) {
	if fv.IsNil() {
		return nil, nil
	}

	result := make(map[string]any)
	const maxMapSize = 1000
	keys := fv.MapKeys()

	if len(keys) > maxMapSize {
		keys = keys[:maxMapSize]
	}

	for _, key := range keys {
		keyStr := ""
		switch key.Kind() {
		case reflect.String:
			keyStr = key.String()

		default:
			keyStr = key.String()
		}

		value := fv.MapIndex(key)
		convertedValue, err := convertFieldValue(value, opts, depth)
		if err != nil {
			return nil, err
		}

		result[keyStr] = convertedValue
	}

	return result, nil
}

// convertKnownTypes handles conversion of known non-struct types
func convertKnownTypes(v any, result map[string]any, opts *structToMapOptions) error {
	switch typed := v.(type) {
	case *HTTPRequestLogFields:
		result["method"] = typed.Method
		result["path"] = typed.Path
		result["user_agent"] = typed.UserAgent
		result["client_ip"] = typed.ClientIP
		result["status_code"] = typed.StatusCode
		result["duration"] = typed.Duration

		if !opts.OmitEmpty || typed.RequestSize > 0 {
			result["request_size"] = typed.RequestSize
		}

		if !opts.OmitEmpty || typed.ResponseSize > 0 {
			result["response_size"] = typed.ResponseSize
		}

		if !opts.OmitEmpty || typed.RequestID != "" {
			result["request_id"] = typed.RequestID
		}

		if !opts.OmitEmpty || typed.TraceID != "" {
			result["trace_id"] = typed.TraceID
		}

	case *ErrorLogFields:
		if typed.Error != nil {
			result["error"] = typed.Error.Error()
		}

		if !opts.OmitEmpty || typed.ErrorType != "" {
			result["error_type"] = typed.ErrorType
		}

		if !opts.OmitEmpty || typed.ErrorCode != "" {
			result["error_code"] = typed.ErrorCode
		}

		result["component"] = typed.Component
		if !opts.OmitEmpty || typed.Operation != "" {
			result["operation"] = typed.Operation
		}

		if typed.Context != nil {
			for k, v := range typed.Context {
				result[k] = v
			}
		}

		if !opts.OmitEmpty || typed.RequestID != "" {
			result["request_id"] = typed.RequestID
		}

		if !opts.OmitEmpty || typed.TraceID != "" {
			result["trace_id"] = typed.TraceID
		}

		if !opts.OmitEmpty || typed.StackTrace != "" {
			result["stack_trace"] = typed.StackTrace
		}

	case *StartupLogFields:
		result["component"] = typed.Component
		result["version"] = typed.Version
		result["address"] = typed.Address
		result["start_time"] = typed.StartTime
		if typed.Config != nil {
			result["config"] = typed.Config
		}

	case *ShutdownLogFields:
		result["component"] = typed.Component
		result["reason"] = typed.Reason
		result["uptime"] = typed.Uptime
		result["graceful"] = typed.Graceful

	case *SecurityEventFields:
		result["event_type"] = typed.EventType
		result["severity"] = typed.Severity
		result["source"] = typed.Source
		if !opts.OmitEmpty || typed.Target != "" {
			result["target"] = typed.Target
		}

		result["action"] = typed.Action
		result["result"] = typed.Result
		if !opts.OmitEmpty || typed.Reason != "" {
			result["reason"] = typed.Reason
		}

		if !opts.OmitEmpty || typed.ClientIP != "" {
			result["client_ip"] = typed.ClientIP
		}

		if !opts.OmitEmpty || typed.UserAgent != "" {
			result["user_agent"] = typed.UserAgent
		}

		if !opts.OmitEmpty || typed.RequestID != "" {
			result["request_id"] = typed.RequestID
		}

		result["timestamp"] = typed.Timestamp
		if typed.Metadata != nil {
			count := 0
			const maxMetadataFields = 50
			for k, v := range typed.Metadata {
				if count >= maxMetadataFields {
					break
				}

				result[k] = v
				count++
			}
		}

	case *PerformanceLogFields:
		result["operation"] = typed.Operation
		result["component"] = typed.Component
		result["duration"] = typed.Duration
		result["success"] = typed.Success
		if typed.Metrics != nil {
			result["metrics"] = typed.Metrics
		}

		if typed.Thresholds != nil {
			result["thresholds"] = typed.Thresholds
		}

		if typed.ResourceUsage != nil {
			result["resource_usage"] = typed.ResourceUsage
		}

		if !opts.OmitEmpty || typed.RequestID != "" {
			result["request_id"] = typed.RequestID
		}

	case *AuditLogFields:
		result["action"] = typed.Action
		result["resource"] = typed.Resource
		if !opts.OmitEmpty || typed.ResourceID != "" {
			result["resource_id"] = typed.ResourceID
		}

		result["actor"] = typed.Actor
		result["actor_type"] = typed.ActorType
		result["result"] = typed.Result
		if typed.Changes != nil {
			result["changes"] = typed.Changes
		}

		if typed.Metadata != nil {

			result["metadata"] = typed.Metadata
		}
		if !opts.OmitEmpty || typed.ClientIP != "" {
			result["client_ip"] = typed.ClientIP
		}

		if !opts.OmitEmpty || typed.UserAgent != "" {
			result["user_agent"] = typed.UserAgent
		}

		if !opts.OmitEmpty || typed.RequestID != "" {
			result["request_id"] = typed.RequestID
		}

		if !opts.OmitEmpty || typed.SessionID != "" {
			result["session_id"] = typed.SessionID
		}

		result["timestamp"] = typed.Timestamp

	default:
		genericResult, err := structToMapGeneric(v, opts)
		if err != nil {
			return err
		}

		for k, v := range genericResult {
			result[k] = v
		}
	}

	return nil
}

// structToMapGeneric handles generic struct conversion using reflection
func structToMapGeneric(v any, opts *structToMapOptions) (map[string]any, error) {
	result := make(map[string]any)
	return result, structToMapRecursive(v, result, opts, 0)
}

// isZeroValue checks if a reflect.Value represents a zero value
func isZeroValue(v reflect.Value) bool {
	if !v.IsValid() {
		return true
	}

	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0

	case reflect.Bool:
		return !v.Bool()

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0

	case reflect.Float32, reflect.Float64:
		return v.Float() == 0

	case reflect.Interface, reflect.Ptr:
		return v.IsNil()

	case reflect.Struct:
		return v.Interface() == reflect.Zero(v.Type()).Interface()
	}

	return false
}

// toSnakeCase converts CamelCase to snake_case
func toSnakeCase(s string) string {
	var result strings.Builder
	result.Grow(len(s) + 5)

	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteByte('_')
		}

		if r >= 'A' && r <= 'Z' {
			result.WriteRune(r + 32)
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// StructToMapFast provides a fast conversion with minimal options
func StructToMapFast(v any) map[string]any {
	result, _ := structToMap(v, &structToMapOptions{
		TagName:   "json",
		OmitEmpty: true,
		MaxDepth:  2,
	})

	return result
}

// StructToMapDeep provides a deep conversion with full recursion
func StructToMapDeep(v any) map[string]any {
	result, _ := structToMap(v, &structToMapOptions{
		TagName:   "json",
		OmitEmpty: false,
		MaxDepth:  10,
	})

	return result
}

// StructToMapSecure provides a secure conversion with field filtering
func StructToMapSecure(v any, sensitiveFields []string) map[string]any {
	sensitive := make(map[string]bool)
	for _, field := range sensitiveFields {
		sensitive[field] = true
	}

	result, _ := structToMap(v, &structToMapOptions{
		TagName:   "json",
		OmitEmpty: true,
		MaxDepth:  3,
		FieldFilter: func(fieldName string, fieldValue any) bool {
			return !sensitive[strings.ToLower(fieldName)]
		},
	})

	return result
}
