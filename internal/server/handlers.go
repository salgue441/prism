package server

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// Default route handlers

// handleRoot handles the root endpoint.
func (s *Server) handleRoot(c *gin.Context) {
	requestID := c.GetHeader(HeaderRequestID)
	if requestID == "" {
		requestID = generateRequestID()
		c.Header(HeaderRequestID, requestID)
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Prism API Gateway",
		Data: map[string]interface{}{
			"version": "1.0.0",
			"status":  "running",
			"uptime":  time.Since(s.startTime).String(),
		},
		RequestID: requestID,
		Timestamp: time.Now(),
	})
}

// handleHealthCheck handles health check requests.
func (s *Server) handleHealthCheck(c *gin.Context) {
	status := s.GetHealthStatus()

	var httpStatus int
	switch status.Status {
	case HealthStateHealthy:
		httpStatus = http.StatusOK

	case HealthStateDegraded:
		httpStatus = http.StatusOK

	case HealthStateUnhealthy:
		httpStatus = http.StatusServiceUnavailable

	case HealthStateStarting:
		httpStatus = http.StatusServiceUnavailable

	case HealthStateStopping:
		httpStatus = http.StatusServiceUnavailable

	default:
		httpStatus = http.StatusInternalServerError
	}

	c.JSON(httpStatus, status)
}

// handleReadinessCheck handles readiness probe requests.
func (s *Server) handleReadinessCheck(c *gin.Context) {
	status := s.GetHealthStatus()
	var httpStatus int
	if status.Status == HealthStateHealthy {
		httpStatus = http.StatusOK
	} else {
		httpStatus = http.StatusServiceUnavailable
	}

	c.JSON(httpStatus, map[string]any{
		"ready":     status.Status == HealthStateHealthy,
		"status":    status.Status,
		"timestamp": time.Now(),
	})
}

// handleNotFound handles 404 errors.
func (s *Server) handleNotFound(c *gin.Context) {
	s.handleError(c, http.StatusNotFound,
		"Not Found", "The requested resource was not found")
}

// handleMethodNotAllowed handles 405 errors.
func (s *Server) handleMethodNotAllowed(c *gin.Context) {
	s.handleError(c, http.StatusMethodNotAllowed,
		"Method Not Allowed", "The request method is not allowed for this resource")
}

// handleError sends a standardized error response.
func (s *Server) handleError(c *gin.Context, statusCode int, error, message string) {
	requestID := c.GetHeader(HeaderRequestID)
	if requestID == "" {
		requestID = generateRequestID()
	}

	response := ErrorResponse{
		Error:     error,
		Message:   message,
		RequestID: requestID,
		Timestamp: time.Now(),
	}

	if s.config.IsDebugMode() {
		response.Details = map[string]any{
			"method": c.Request.Method,
			"path":   c.Request.URL.Path,
			"query":  c.Request.URL.RawQuery,
		}
	}

	c.JSON(statusCode, response)
}

// Middleware creators

// createRecoveryHandler creates a custom recovery handler.
func (s *Server) createRecoveryHandler() gin.RecoveryFunc {
	return func(c *gin.Context, err any) {
		requestID := c.GetHeader(HeaderRequestID)
		if requestID == "" {
			requestID = generateRequestID()
			c.Header(HeaderRequestID, requestID)
		}

		s.logger.Error("Panic recovered",
			"error", err,
			"request_id", requestID,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"client_ip", c.ClientIP())

		s.incrementErrorCount()
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:     "Internal Server Error",
			Message:   "An unexpected error occurred",
			RequestID: requestID,
			Timestamp: time.Now(),
		})

		c.Abort()
	}
}

// createRequestIDMiddleware creates middleware for request ID generation.
func (s *Server) createRequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader(HeaderRequestID)
		if requestID == "" {
			requestID = generateRequestID()
			c.Header(HeaderRequestID, requestID)
		}

		c.Set(string(RequestIDKey), requestID)
		c.Next()
	}
}

// createLoggingMiddleware creates a structured logging middleware.
func (s *Server) createLoggingMiddleware(component string) gin.HandlerFunc {
	return gin.LoggerWithConfig(gin.LoggerConfig{
		Formatter: func(param gin.LogFormatterParams) string {
			fields := map[string]any{
				"component":    component,
				"method":       param.Method,
				"path":         param.Path,
				"status":       param.StatusCode,
				"latency":      param.Latency.String(),
				"client_ip":    param.ClientIP,
				"user_agent":   param.Request.UserAgent(),
				"request_size": param.Request.ContentLength,
			}

			if requestID := param.Request.Header.Get(HeaderRequestID); requestID != "" {
				fields["request_id"] = requestID
			}

			if param.StatusCode >= 500 {
				s.logger.WithFields(fields).Error("HTTP request")
			} else if param.StatusCode >= 400 {
				s.logger.WithFields(fields).Warn("HTTP request")
			} else {
				s.logger.WithFields(fields).Info("HTTP request")
			}

			return ""
		},
		Output: s.logger.Logger.Out,
	})
}

// createSecurityHeadersMiddleware creates middleware for security headers.
func (s *Server) createSecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.config.Security.EnableFrameDeny {
			c.Header(HeaderXFrameOptions, "DENY")
		}

		if s.config.Security.EnableContentTypeNoSniff {
			c.Header(HeaderXContentTypeOptions, "nosniff")
		}

		if s.config.Security.EnableXSSProtection {
			c.Header(HeaderXXSSProtection, "1; mode=block")
		}

		if s.config.Security.EnableReferrerPolicy {
			c.Header(HeaderReferrerPolicy, s.config.Security.ReferrerPolicy)
		}

		if s.config.IsTLSEnabled() && s.config.Security.EnableHSTS {
			hstsValue := fmt.Sprintf("max-age=%d", s.config.Security.HSTSMaxAge)
			if s.config.Security.HSTSSubdomains {
				hstsValue += "; includeSubDomains"
			}

			if s.config.Security.HSTSPreload {
				hstsValue += "; preload"
			}

			c.Header(HeaderStrictTransportSecurity, hstsValue)
		}

		if s.config.Security.EnableCSP {
			if s.config.Security.CSPReportOnly {
				c.Header("Content-Security-Policy-Report-Only", s.config.Security.CSPDirectives)
			} else {
				c.Header(HeaderContentSecurityPolicy, s.config.Security.CSPDirectives)
			}
		}

		c.Header(HeaderServer, "Prism/1.0.0")
		c.Next()
	}
}

// createCORSMiddleware creates CORS middleware based on configuration.
func (s *Server) createCORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if s.isOriginAllowed(origin) {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Methods",
			strings.Join(s.config.CORS.AllowedMethods, ", "))
		c.Header("Access-Control-Allow-Headers",
			strings.Join(s.config.CORS.AllowedHeaders, ", "))

		if len(s.config.CORS.ExposedHeaders) > 0 {
			c.Header("Access-Control-Expose-Headers", strings.Join(s.config.CORS.ExposedHeaders, ", "))
		}

		if s.config.CORS.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		if s.config.CORS.MaxAge > 0 {
			c.Header("Access-Control-Max-Age", strconv.Itoa(int(s.config.CORS.MaxAge.Seconds())))
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// createRateLimitMiddleware creates rate limiting middleware.
func (s *Server) createRateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement rate limiting logic
		// For now, just continue
		c.Next()
	}
}

// createMetricsMiddleware creates metrics collection middleware.
func (s *Server) createMetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		s.incrementRequestCount()
		c.Next()

		duration := time.Since(start)
		status := c.Writer.Status()
		if status >= 400 {
			s.incrementErrorCount()
		}

		// TODO: Record metrics to Prometheus
		_ = duration // Placeholder to avoid unused variable
	}
}

// createCompressionMiddleware creates response compression middleware.
func (s *Server) createCompressionMiddleware() gin.HandlerFunc {
	// This is a placeholder - in production, you'd use a proper compression library
	return func(c *gin.Context) {
		// TODO: Implement compression logic
		c.Next()
	}
}

// createAdminAuthMiddleware creates authentication middleware for admin routes.
func (s *Server) createAdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement admin authentication
		// For now, just continue (in development mode)
		if !s.config.IsDebugMode() {
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:     "Unauthorized",
				Message:   "Admin authentication required",
				RequestID: c.GetHeader(HeaderRequestID),
				Timestamp: time.Now(),
			})

			c.Abort()
			return
		}

		c.Next()
	}
}

// registerPprofRoutes registers pprof endpoints for development profiling.
func (s *Server) registerPprofRoutes(router *gin.Engine) {
	pprofGroup := router.Group("/debug/pprof")

	pprofGroup.GET("/", gin.WrapF(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/debug/pprof/", http.StatusMovedPermanently)
	}))

	pprofGroup.GET("/cmdline", gin.WrapH(http.HandlerFunc(pprof.Cmdline)))
	pprofGroup.GET("/profile", gin.WrapH(http.HandlerFunc(pprof.Profile)))
	pprofGroup.GET("/symbol", gin.WrapH(http.HandlerFunc(pprof.Symbol)))
	pprofGroup.GET("/trace", gin.WrapH(http.HandlerFunc(pprof.Trace)))
	pprofGroup.GET("/allocs", gin.WrapH(pprof.Handler("allocs")))
	pprofGroup.GET("/block", gin.WrapH(pprof.Handler("block")))
	pprofGroup.GET("/goroutine", gin.WrapH(pprof.Handler("goroutine")))
	pprofGroup.GET("/heap", gin.WrapH(pprof.Handler("heap")))
	pprofGroup.GET("/mutex", gin.WrapH(pprof.Handler("mutex")))
	pprofGroup.GET("/threadcreate", gin.WrapH(pprof.Handler("threadcreate")))
}

// Enhanced Context methods

// JSON sends a JSON response with automatic metrics tracking.
func (ctx *Context) JSON(code int, obj any) {
	ctx.updateResponseContext(code, 0)
	ctx.Context.JSON(code, obj)
}

// String sends a plain text response.
func (ctx *Context) String(code int, format string, values ...any) {
	ctx.updateResponseContext(code, int64(len(fmt.Sprintf(format, values...))))
	ctx.Context.String(code, format, values...)
}

// Data sends raw data response.
func (ctx *Context) Data(code int, contentType string, data []byte) {
	ctx.updateResponseContext(code, int64(len(data)))
	ctx.Context.Data(code, contentType, data)
}

// HTML sends an HTML response.
func (ctx *Context) HTML(code int, name string, obj any) {
	ctx.updateResponseContext(code, 0)
	ctx.Context.HTML(code, name, obj)
}

// Redirect sends a redirect response.
func (ctx *Context) Redirect(code int, location string) {
	ctx.updateResponseContext(code, 0)
	ctx.Context.Redirect(code, location)
}

// Error sends an error response with consistent formatting.
func (ctx *Context) Error(code int, err error, message ...string) {
	msg := err.Error()
	if len(message) > 0 {
		msg = message[0]
	}

	ctx.updateResponseContext(code, 0)
	ctx.ResponseCtx.Error = err.Error()

	response := ErrorResponse{
		Error:     http.StatusText(code),
		Message:   msg,
		RequestID: ctx.RequestCtx.RequestID,
		Timestamp: time.Now(),
	}

	if ctx.server.config.IsDebugMode() {
		response.Details = map[string]any{
			"error_type": fmt.Sprintf("%T", err),
			"stack":      getStackTrace(),
		}
	}

	ctx.Context.JSON(code, response)
}

// Success sends a success response with consistent formatting.
func (ctx *Context) Success(data any, message ...string) {
	msg := "Success"
	if len(message) > 0 {
		msg = message[0]
	}

	ctx.updateResponseContext(http.StatusOK, 0)
	response := SuccessResponse{
		Success:   true,
		Message:   msg,
		Data:      data,
		RequestID: ctx.RequestCtx.RequestID,
		Timestamp: time.Now(),
	}

	ctx.Context.JSON(http.StatusOK, response)
}

// Set stores a key-value pair in the context.
func (ctx *Context) Set(key string, value any) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.data[key] = value
}

// Get retrieves a value from the context.
func (ctx *Context) Get(key string) (any, bool) {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	value, exists := ctx.data[key]

	return value, exists
}

// MustGet retrieves a value from the context or panics if not found.
func (ctx *Context) MustGet(key string) any {
	if value, exists := ctx.Get(key); exists {
		return value
	}

	panic("Key \"" + key + "\" does not exist")
}

// GetString retrieves a string value from the context.
func (ctx *Context) GetString(key string) string {
	if value, exists := ctx.Get(key); exists {
		if str, ok := value.(string); ok {
			return str
		}
	}

	return ""
}

// GetInt retrieves an integer value from the context.
func (ctx *Context) GetInt(key string) int {
	if value, exists := ctx.Get(key); exists {
		if i, ok := value.(int); ok {
			return i
		}
	}
	return 0
}

// GetBool retrieves a boolean value from the context.
func (ctx *Context) GetBool(key string) bool {
	if value, exists := ctx.Get(key); exists {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return false
}

// updateResponseContext updates the response context with status and size.
func (ctx *Context) updateResponseContext(statusCode int, responseSize int64) {
	ctx.ResponseCtx.StatusCode = statusCode
	ctx.ResponseCtx.ResponseSize = responseSize
	ctx.ResponseCtx.Duration = time.Since(ctx.startTime)
}

// handleAutoResponse handles automatic response for handlers that don't send
// one.
func (ctx *Context) handleAutoResponse() {
	if !ctx.Context.Writer.Written() {
		ctx.Success(nil, "Request processed successfully")
	}
}

// Utility functions

// generateRequestID generates a unique request ID.
func generateRequestID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("req_%d", time.Now().UnixNano())
	}

	return "req_" + hex.EncodeToString(bytes)
}

// extractHeaders extracts important headers from HTTP request.
func extractHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	importantHeaders := []string{
		"Authorization", "Content-Type", "Accept", "User-Agent",
		"X-Forwarded-For", "X-Real-IP", "X-Request-ID", "X-Trace-ID",
	}

	for _, header := range importantHeaders {
		if value := headers.Get(header); value != "" {
			result[header] = value
		}
	}

	return result
}

// extractQueryParams extracts query parameters from URL.
func extractQueryParams(values url.Values) map[string]string {
	result := make(map[string]string)

	for key, vals := range values {
		if len(vals) > 0 {
			result[key] = vals[0]
		}
	}

	return result
}

// getTLSVersion returns a string representation of the TLS version.
func getTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"

	case tls.VersionTLS11:
		return "TLS 1.1"

	case tls.VersionTLS12:
		return "TLS 1.2"

	case tls.VersionTLS13:
		return "TLS 1.3"

	default:
		return "Unknown"
	}
}

// getCipherSuite returns a string representation of the cipher suite.
func getCipherSuite(suite uint16) string {
	switch suite {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"

	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"

	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"

	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"

	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"

	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"

	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"

	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"

	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"

	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"

	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"

	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"

	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"

	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"

	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"

	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"

	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"

	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"

	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"

	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"

	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"

	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", suite)
	}
}

// isOriginAllowed checks if the given origin is allowed for CORS.
func (s *Server) isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}

	for _, allowed := range s.config.CORS.AllowedOrigins {
		if allowed == "*" {
			return true
		}
		if allowed == origin {
			return true
		}

		// TODO: Add pattern matching for wildcards like *.example.com
	}

	return false
}

// incrementRequestCount increments the request counter atomically.
func (s *Server) incrementRequestCount() {
	atomic.AddInt64(&s.requestCount, 1)
}

// incrementErrorCount increments the error counter atomically.
func (s *Server) incrementErrorCount() {
	atomic.AddInt64(&s.errorCount, 1)
}

// getStackTrace returns a formatted stack trace for debugging.
func getStackTrace() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)

	return string(buf[:n])
}

// Admin route handlers

// handleAdminStatus returns detailed server status for admin interface.
func (s *Server) handleAdminStatus(ctx *Context) {
	status := map[string]any{
		"server": map[string]any{
			"status":     "running",
			"start_time": s.startTime,
			"uptime":     time.Since(s.startTime).String(),
			"version":    "1.0.0",
		},
		"health":  s.GetHealthStatus(),
		"metrics": s.GetMetrics(),
		"config": map[string]any{
			"debug_mode":      s.config.IsDebugMode(),
			"tls_enabled":     s.config.IsTLSEnabled(),
			"cors_enabled":    s.config.IsCORSEnabled(),
			"metrics_enabled": s.config.IsMetricsEnabled(),
		},
	}

	ctx.Success(status, "Server status retrieved")
}

// handleAdminRoutes returns all registered routes.
func (s *Server) handleAdminRoutes(ctx *Context) {
	routes := s.router.Routes()

	routeInfo := make([]map[string]any, len(routes))
	for i, route := range routes {
		routeInfo[i] = map[string]any{
			"method": route.Method,
			"path":   route.Path,
		}
	}

	ctx.Success(routeInfo, "Routes retrieved")
}

// handleAdminConfig returns server configuration (sanitized).
func (s *Server) handleAdminConfig(ctx *Context) {
	configInfo := map[string]any{
		"server": map[string]any{
			"host":        s.config.Server.Host,
			"port":        s.config.Server.Port,
			"tls_enabled": s.config.IsTLSEnabled(),
		},
		"logging": map[string]any{
			"level":  s.config.Logging.Level,
			"format": s.config.Logging.Format,
		},
		"metrics": map[string]any{
			"enabled": s.config.IsMetricsEnabled(),
			"path":    s.config.Metrics.Path,
		},
		"health": map[string]any{
			"enabled": s.config.IsHealthEnabled(),
			"path":    s.config.Health.Path,
		},
	}

	ctx.Success(configInfo, "Configuration retrieved")
}
