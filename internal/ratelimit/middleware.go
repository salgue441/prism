package ratelimit

import (
	"encoding/json"
	"net"
	"net/http"
	"prism/pkg/logger"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// GinMiddleware creates a Gin middleware for rate limiting.
func GinMiddleware(limiter Limiter) gin.HandlerFunc {
	return GinMiddlewareWithConfig(limiter, &MiddlewareConfig{})
}

// GinMiddlewareWithConfig creates a Gin middleware with custom configuration.
func GinMiddlewareWithConfig(limiter Limiter, config *MiddlewareConfig) gin.HandlerFunc {
	if config == nil {
		config = &MiddlewareConfig{}
	}

	if config.OnBlocked == nil {
		config.OnBlocked = defaultOnBlocked
	}

	if config.OnError == nil {
		config.OnError = defaultOnError
	}

	return func(c *gin.Context) {
		if shouldSkipPath(c.Request.URL.Path, config.SkipPaths) {
			c.Set(string(RateLimitSkippedKey), true)
			c.Next()
			return
		}

		if shouldSkipMethod(c.Request.Method, config.SkipMethods) {
			c.Set(string(RateLimitSkippedKey), true)
			c.Next()
			return
		}

		key, err := generateKey(c.Request, config.TrustForwardedHeaders)
		if err != nil {
			config.OnError(c.Writer, c.Request, err)

			c.Abort()
			return
		}

		allowed, remaining, resetTime, err := limiter.Allow(key)
		if err != nil {
			config.OnError(c.Writer, c.Request, err)

			c.Next()
			return
		}

		result := &Result{
			Allowed:   allowed,
			Remaining: remaining,
			ResetTime: resetTime,
			Key:       key,
			Limit:     limiter.GetLimit(),
		}

		c.Set(string(RateLimitResultKey), result)
		c.Set(string(RateLimitKeyKey), key)

		addRateLimitHeaders(c.Writer, result, config.IncludeHeaders)
		if !allowed {
			result.RetryAfter = time.Until(resetTime)
			config.OnBlocked(c.Writer, c.Request, result)

			c.Abort()
			return
		}

		c.Next()
	}
}

// HTTPMiddleware creates a standard HTTP middleware for rate limiting.
func HTTPMiddleware(limiter Limiter) func(http.Handler) http.Handler {
	return HTTPMiddlewareWithConfig(limiter, &MiddlewareConfig{})
}

// HTTPMiddlewareWithConfig creates an HTTP middleware with custom configuration.
func HTTPMiddlewareWithConfig(limiter Limiter, config *MiddlewareConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = &MiddlewareConfig{}
	}

	if config.OnBlocked == nil {
		config.OnBlocked = defaultOnBlocked
	}

	if config.OnError == nil {
		config.OnError = defaultOnError
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if shouldSkipPath(r.URL.Path, config.SkipPaths) {
				next.ServeHTTP(w, r)
				return
			}

			if shouldSkipMethod(r.Method, config.SkipMethods) {
				next.ServeHTTP(w, r)
				return
			}

			key, err := generateKey(r, config.TrustForwardedHeaders)
			if err != nil {
				config.OnError(w, r, err)
				return
			}

			allowed, remaining, resetTime, err := limiter.Allow(key)
			if err != nil {
				config.OnError(w, r, err)
				return
			}

			result := &Result{
				Allowed:   allowed,
				Remaining: remaining,
				ResetTime: resetTime,
				Key:       key,
				Limit:     limiter.GetLimit(),
			}

			addRateLimitHeaders(w, result, config.IncludeHeaders)
			if !allowed {
				result.RetryAfter = time.Until(resetTime)
				config.OnBlocked(w, r, result)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// MultiLimiterMiddleware creates middleware that applies multiple rate limiters.
func MultiLimiterMiddleware(limiters []Limiter) gin.HandlerFunc {
	return MultiLimiterMiddlewareWithConfig(limiters, &MiddlewareConfig{})
}

// MultiLimiterMiddlewareWithConfig creates multi-limiter middleware with config.
func MultiLimiterMiddlewareWithConfig(limiters []Limiter, config *MiddlewareConfig) gin.HandlerFunc {
	if config == nil {
		config = &MiddlewareConfig{}
	}

	if config.OnBlocked == nil {
		config.OnBlocked = defaultOnBlocked
	}

	if config.OnError == nil {
		config.OnError = defaultOnError
	}

	return func(c *gin.Context) {
		if shouldSkipPath(c.Request.URL.Path, config.SkipPaths) ||
			shouldSkipMethod(c.Request.Method, config.SkipMethods) {
			c.Set(string(RateLimitSkippedKey), true)
			c.Next()
			return
		}

		key, err := generateKey(c.Request, config.TrustForwardedHeaders)
		if err != nil {
			config.OnError(c.Writer, c.Request, err)
			c.Abort()
			return
		}

		var results []*Result
		allAllowed := true

		for _, limiter := range limiters {
			allowed, remaining, resetTime, err := limiter.Allow(key)
			if err != nil {
				config.OnError(c.Writer, c.Request, err)
				c.Abort()
				return
			}

			result := &Result{
				Allowed:   allowed,
				Remaining: remaining,
				ResetTime: resetTime,
				Key:       key,
				Algorithm: Algorithm("unknown"),
				Limit:     limiter.GetLimit(),
			}
			results = append(results, result)

			if !allowed {
				allAllowed = false
				result.RetryAfter = time.Until(resetTime)
			}
		}

		mostRestrictive := getMostRestrictiveResult(results)
		c.Set(string(RateLimitResultKey), mostRestrictive)
		c.Set(string(RateLimitKeyKey), key)

		addRateLimitHeaders(c.Writer, mostRestrictive, config.IncludeHeaders)
		if !allAllowed {
			config.OnBlocked(c.Writer, c.Request, mostRestrictive)
			c.Abort()
			return
		}

		c.Next()
	}
}

// Helper functions

// shouldSkipPath checks if a path should skip rate limiting.
func shouldSkipPath(path string, skipPaths []string) bool {
	for _, skipPath := range skipPaths {
		if matchPath(path, skipPath) {
			return true
		}
	}

	return false
}

// shouldSkipMethod checks if a method should skip rate limiting.
func shouldSkipMethod(method string, skipMethods []string) bool {
	for _, skipMethod := range skipMethods {
		if strings.EqualFold(method, skipMethod) {
			return true
		}
	}

	return false
}

// matchPath checks if a path matches a pattern (supports wildcards).
func matchPath(path, pattern string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(path, prefix)
	}

	return path == pattern
}

// generateKey generates a rate limiting key from the request.
func generateKey(r *http.Request, trustForwardedHeaders bool) (string, error) {
	clientIP := getClientIP(r, trustForwardedHeaders)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	// For now, use IP-based key generation
	// In a production system, you might want pluggable key generators
	return "ip:" + clientIP, nil
}

// getClientIP extracts the real client IP from the request.
func getClientIP(r *http.Request, trustForwardedHeaders bool) string {
	if !trustForwardedHeaders {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			return host
		}

		return r.RemoteAddr
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if isValidIP(ip) {
				return ip
			}
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if isValidIP(ip) {
			return ip
		}
	}

	if xf := r.Header.Get("X-Forwarded"); xf != "" {
		ip := strings.TrimSpace(xf)
		if isValidIP(ip) {
			return ip
		}
	}

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}

	return r.RemoteAddr
}

// isValidIP checks if a string is a valid IP address.
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// addRateLimitHeaders adds standard rate limiting headers to the response.
func addRateLimitHeaders(w http.ResponseWriter, result *Result,
	includeHeaders []string) {
	headers := map[string]string{
		HeaderRateLimitLimit:     strconv.FormatInt(result.Limit, 10),
		HeaderRateLimitRemaining: strconv.FormatInt(result.Remaining, 10),
		HeaderRateLimitReset:     strconv.FormatInt(result.ResetTime.Unix(), 10),
		HeaderRateLimitPolicy:    string(result.Algorithm),
	}

	if !result.Allowed && result.RetryAfter > 0 {
		headers[HeaderRateLimitRetryAfter] = strconv.FormatInt(int64(result.RetryAfter.Seconds()), 10)
	}

	if len(includeHeaders) == 0 {
		for header, value := range headers {
			w.Header().Set(header, value)
		}
	} else {
		for _, header := range includeHeaders {
			if value, exists := headers[header]; exists {
				w.Header().Set(header, value)
			}
		}
	}
}

// getMostRestrictiveResult returns the most restrictive result from multiple limiters.
func getMostRestrictiveResult(results []*Result) *Result {
	if len(results) == 0 {
		return nil
	}

	mostRestrictive := results[0]
	for _, result := range results[1:] {
		if !result.Allowed {
			mostRestrictive = result
			break
		}

		if result.Remaining < mostRestrictive.Remaining {
			mostRestrictive = result
		}
	}

	return mostRestrictive
}

// Default error handlers

// defaultOnBlocked is the default handler for blocked requests.
func defaultOnBlocked(w http.ResponseWriter, r *http.Request, result *Result) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)

	response := map[string]any{
		"error":      "Rate limit exceeded",
		"message":    "Too many requests",
		"limit":      result.Limit,
		"remaining":  result.Remaining,
		"reset_time": result.ResetTime.Unix(),
	}

	if result.RetryAfter > 0 {
		response["retry_after"] = int64(result.RetryAfter.Seconds())
	}

	json.NewEncoder(w).Encode(response)
}

// defaultOnError is the default handler for rate limiting errors.
func defaultOnError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)

	response := map[string]any{
		"error":   "Rate limiting error",
		"message": "Internal server error",
	}

	json.NewEncoder(w).Encode(response)
}

// Advanced middleware patterns

// ConditionalMiddleware applies rate limiting based on conditions.
func ConditionalMiddleware(limiter Limiter, condition func(*http.Request) bool) gin.HandlerFunc {
	middleware := GinMiddleware(limiter)

	return func(c *gin.Context) {
		if condition(c.Request) {
			middleware(c)
		} else {
			c.Set(string(RateLimitSkippedKey), true)
			c.Next()
		}
	}
}

// UserBasedMiddleware applies different rate limits based on user type.
func UserBasedMiddleware(limiters map[string]Limiter, getUserType func(*http.Request) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userType := getUserType(c.Request)
		limiter, exists := limiters[userType]

		if !exists {
			c.Set(string(RateLimitSkippedKey), true)
			c.Next()
			return
		}

		middleware := GinMiddleware(limiter)
		middleware(c)
	}
}

// GeographicMiddleware applies rate limiting based on geographic location.
func GeographicMiddleware(limiters map[string]Limiter,
	getCountry func(*http.Request) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		country := getCountry(c.Request)
		limiter, exists := limiters[country]

		if !exists {
			if defaultLimiter, hasDefault := limiters["default"]; hasDefault {
				limiter = defaultLimiter
			} else {
				c.Set(string(RateLimitSkippedKey), true)
				c.Next()
				return
			}
		}

		middleware := GinMiddleware(limiter)
		middleware(c)
	}
}

// TimeBasedMiddleware applies different rate limits based on time of day.
func TimeBasedMiddleware(limiters map[string]Limiter,
	getTimeSlot func(time.Time) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		timeSlot := getTimeSlot(time.Now())
		limiter, exists := limiters[timeSlot]

		if !exists {
			if defaultLimiter, hasDefault := limiters["default"]; hasDefault {
				limiter = defaultLimiter
			} else {
				c.Set(string(RateLimitSkippedKey), true)
				c.Next()
				return
			}
		}

		middleware := GinMiddleware(limiter)
		middleware(c)
	}
}

// Monitoring and observability middleware

// MetricsMiddleware wraps rate limiting with metrics collection.
func MetricsMiddleware(limiter Limiter, metricsCollector interface{}) gin.HandlerFunc {
	middleware := GinMiddleware(limiter)

	return func(c *gin.Context) {
		start := time.Now()
		middleware(c)

		duration := time.Since(start)

		if result, exists := c.Get(string(RateLimitResultKey)); exists {
			if r, ok := result.(*Result); ok {
				recordRateLimitMetrics(metricsCollector, r, duration)
			}
		}
	}
}

// LoggingMiddleware wraps rate limiting with detailed logging.
func LoggingMiddleware(limiter Limiter, logger *logger.Logger) gin.HandlerFunc {
	middleware := GinMiddleware(limiter)

	return func(c *gin.Context) {
		start := time.Now()
		clientIP := getClientIP(c.Request, true)

		middleware(c)

		duration := time.Since(start)
		if result, exists := c.Get(string(RateLimitResultKey)); exists {
			if r, ok := result.(*Result); ok {
				if r.Allowed {
					logger.Debug("Rate limit allowed",
						"client_ip", clientIP,
						"key", r.Key,
						"remaining", r.Remaining,
						"limit", r.Limit,
						"duration", duration)
				} else {
					logger.Warn("Rate limit exceeded",
						"client_ip", clientIP,
						"key", r.Key,
						"remaining", r.Remaining,
						"limit", r.Limit,
						"retry_after", r.RetryAfter,
						"duration", duration)
				}
			}
		}

		if skipped, exists := c.Get(string(RateLimitSkippedKey)); exists && skipped.(bool) {
			logger.Debug("Rate limiting skipped",
				"client_ip", clientIP,
				"path", c.Request.URL.Path,
				"method", c.Request.Method)
		}
	}
}

// Circuit breaker middleware

// CircuitBreakerMiddleware applies circuit breaker pattern to rate limiting.
func CircuitBreakerMiddleware(limiter Limiter, maxFailures int, timeout time.Duration) gin.HandlerFunc {
	var (
		failures    int64
		lastFailure time.Time
		circuitOpen bool
		mu          sync.RWMutex
	)

	return func(c *gin.Context) {
		mu.RLock()
		isOpen := circuitOpen
		lastFail := lastFailure
		mu.RUnlock()

		if isOpen && time.Since(lastFail) > timeout {
			mu.Lock()
			circuitOpen = false
			failures = 0
			mu.Unlock()
			isOpen = false
		}

		if isOpen {
			c.Set(string(RateLimitSkippedKey), true)
			c.Next()
			return
		}

		key, err := generateKey(c.Request, true)
		if err != nil {
			mu.Lock()
			failures++
			lastFailure = time.Now()
			if failures >= int64(maxFailures) {
				circuitOpen = true
			}

			mu.Unlock()
			c.Set(string(RateLimitSkippedKey), true)
			c.Next()

			return
		}

		allowed, remaining, resetTime, err := limiter.Allow(key)
		if err != nil {
			mu.Lock()
			failures++
			lastFailure = time.Now()
			if failures >= int64(maxFailures) {
				circuitOpen = true
			}

			mu.Unlock()

			c.Set(string(RateLimitSkippedKey), true)
			c.Next()
			return
		}

		mu.Lock()
		failures = 0
		mu.Unlock()

		result := &Result{
			Allowed:   allowed,
			Remaining: remaining,
			ResetTime: resetTime,
			Key:       key,
			Limit:     limiter.GetLimit(),
		}

		c.Set(string(RateLimitResultKey), result)
		c.Set(string(RateLimitKeyKey), key)

		addRateLimitHeaders(c.Writer, result, nil)
		if !allowed {
			result.RetryAfter = time.Until(resetTime)
			defaultOnBlocked(c.Writer, c.Request, result)

			c.Abort()
			return
		}

		c.Next()
	}
}

// Utility functions for middleware

// recordRateLimitMetrics records metrics (placeholder implementation).
func recordRateLimitMetrics(collector any, result *Result, duration time.Duration) {
	// Implementation would depend on your metrics system (Prometheus, etc.)
	// This is a placeholder showing the interface
}

// GetRateLimitResult extracts the rate limit result from Gin context.
func GetRateLimitResult(c *gin.Context) (*Result, bool) {
	if result, exists := c.Get(string(RateLimitResultKey)); exists {
		if r, ok := result.(*Result); ok {
			return r, true
		}
	}

	return nil, false
}

// GetRateLimitKey extracts the rate limit key from Gin context.
func GetRateLimitKey(c *gin.Context) (string, bool) {
	if key, exists := c.Get(string(RateLimitKeyKey)); exists {
		if k, ok := key.(string); ok {
			return k, true
		}
	}

	return "", false
}

// IsRateLimitSkipped checks if rate limiting was skipped for this request.
func IsRateLimitSkipped(c *gin.Context) bool {
	if skipped, exists := c.Get(string(RateLimitSkippedKey)); exists {
		if s, ok := skipped.(bool); ok {
			return s
		}
	}

	return false
}

// Custom key generators for middleware

// IPKeyGenerator generates keys based on IP address.
type IPKeyGeneratorMiddleware struct {
	TrustForwardedHeaders bool
}

func (g *IPKeyGeneratorMiddleware) GenerateKey(r *http.Request) (string, error) {
	ip := getClientIP(r, g.TrustForwardedHeaders)
	if ip == "" {
		return "", ErrKeyGenerationFailed
	}
	
	return "ip:" + ip, nil
}

func (g *IPKeyGeneratorMiddleware) GetName() string {
	return "ip"
}

// HeaderKeyGenerator generates keys based on header values.
type HeaderKeyGenerator struct {
	HeaderName string
	Prefix     string
}

func (g *HeaderKeyGenerator) GenerateKey(r *http.Request) (string, error) {
	value := r.Header.Get(g.HeaderName)
	if value == "" {
		return "", ErrKeyGenerationFailed
	}

	prefix := g.Prefix
	if prefix == "" {
		prefix = strings.ToLower(g.HeaderName) + ":"
	}

	return prefix + value, nil
}

func (g *HeaderKeyGenerator) GetName() string {
	return "header:" + g.HeaderName
}
