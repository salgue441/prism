// Package middleware provides rate limiting middleware for the gateway.
package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/carlossalguero/prism/services/shared/errors"
	"github.com/carlossalguero/prism/services/shared/metrics"
)

// RateLimiter implements a token bucket rate limiter.
type RateLimiter struct {
	mu           sync.RWMutex
	limiters     map[string]*clientLimiter
	rate         rate.Limit
	burst        int
	cleanupEvery time.Duration
	stopCleanup  chan struct{}
	metrics      *metrics.Metrics
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(requestsPerSecond float64, burstSize int) *RateLimiter {
	rl := &RateLimiter{
		limiters:     make(map[string]*clientLimiter),
		rate:         rate.Limit(requestsPerSecond),
		burst:        burstSize,
		cleanupEvery: time.Minute,
		stopCleanup:  make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a request should be allowed for the given key.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	limiter, exists := rl.limiters[key]
	if !exists {
		limiter = &clientLimiter{
			limiter:  rate.NewLimiter(rl.rate, rl.burst),
			lastSeen: time.Now(),
		}
		rl.limiters[key] = limiter
	}
	limiter.lastSeen = time.Now()
	rl.mu.Unlock()

	return limiter.limiter.Allow()
}

// Wait blocks until the request is allowed or the context is cancelled.
func (rl *RateLimiter) Wait(key string) error {
	rl.mu.Lock()
	limiter, exists := rl.limiters[key]
	if !exists {
		limiter = &clientLimiter{
			limiter:  rate.NewLimiter(rl.rate, rl.burst),
			lastSeen: time.Now(),
		}
		rl.limiters[key] = limiter
	}
	limiter.lastSeen = time.Now()
	rl.mu.Unlock()

	return limiter.limiter.Wait(nil)
}

// cleanup removes stale limiters.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cleanupEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			for key, limiter := range rl.limiters {
				if time.Since(limiter.lastSeen) > 3*time.Minute {
					delete(rl.limiters, key)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCleanup:
			return
		}
	}
}

// Stop stops the cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCleanup)
}

// SetMetrics sets the metrics instance for recording rate limit statistics.
func (rl *RateLimiter) SetMetrics(m *metrics.Metrics) {
	rl.metrics = m
}

// Middleware returns HTTP middleware that rate limits requests.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client identifier (IP address by default)
		key := getClientIP(r)

		// Record rate limit check
		if rl.metrics != nil {
			rl.metrics.RecordRateLimitHit(r.URL.Path)
		}

		// Check rate limit
		if !rl.Allow(key) {
			if rl.metrics != nil {
				rl.metrics.RecordRateLimitDrop(r.URL.Path)
			}
			writeRateLimitError(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// MiddlewareByUser returns middleware that rate limits by user ID.
func (rl *RateLimiter) MiddlewareByUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user ID from context or fall back to IP
		key := getClientIP(r)
		if userInfo := GetUserInfo(r.Context()); userInfo != nil {
			key = "user:" + userInfo.ID
		}

		if !rl.Allow(key) {
			writeRateLimitError(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// MultiKeyRateLimiter supports rate limiting by multiple keys.
type MultiKeyRateLimiter struct {
	limiters map[string]*RateLimiter
	mu       sync.RWMutex
}

// NewMultiKeyRateLimiter creates a new multi-key rate limiter.
func NewMultiKeyRateLimiter() *MultiKeyRateLimiter {
	return &MultiKeyRateLimiter{
		limiters: make(map[string]*RateLimiter),
	}
}

// AddLimiter adds a rate limiter for a specific route or pattern.
func (m *MultiKeyRateLimiter) AddLimiter(pattern string, requestsPerSecond float64, burstSize int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.limiters[pattern] = NewRateLimiter(requestsPerSecond, burstSize)
}

// GetLimiter returns the rate limiter for a pattern.
func (m *MultiKeyRateLimiter) GetLimiter(pattern string) *RateLimiter {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.limiters[pattern]
}

// Stop stops all limiters.
func (m *MultiKeyRateLimiter) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, limiter := range m.limiters {
		limiter.Stop()
	}
}

// SlidingWindowLimiter implements a sliding window rate limiter.
type SlidingWindowLimiter struct {
	mu         sync.RWMutex
	windows    map[string]*slidingWindow
	limit      int
	windowSize time.Duration
}

type slidingWindow struct {
	timestamps []time.Time
	mu         sync.Mutex
}

// NewSlidingWindowLimiter creates a new sliding window rate limiter.
func NewSlidingWindowLimiter(limit int, windowSize time.Duration) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{
		windows:    make(map[string]*slidingWindow),
		limit:      limit,
		windowSize: windowSize,
	}
}

// Allow checks if a request should be allowed.
func (s *SlidingWindowLimiter) Allow(key string) bool {
	s.mu.Lock()
	window, exists := s.windows[key]
	if !exists {
		window = &slidingWindow{timestamps: make([]time.Time, 0, s.limit)}
		s.windows[key] = window
	}
	s.mu.Unlock()

	window.mu.Lock()
	defer window.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-s.windowSize)

	// Remove old timestamps
	valid := make([]time.Time, 0, len(window.timestamps))
	for _, ts := range window.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	window.timestamps = valid

	// Check limit
	if len(window.timestamps) >= s.limit {
		return false
	}

	// Add new timestamp
	window.timestamps = append(window.timestamps, now)
	return true
}

// Middleware returns HTTP middleware.
func (s *SlidingWindowLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := getClientIP(r)

		if !s.Allow(key) {
			writeRateLimitError(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Helper functions

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		ips := splitByComma(xff)
		if len(ips) > 0 {
			return trimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func splitByComma(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && s[start] == ' ' {
		start++
	}
	for end > start && s[end-1] == ' ' {
		end--
	}
	return s[start:end]
}

func writeRateLimitError(w http.ResponseWriter) {
	err := errors.RateLimited("too many requests")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(err.HTTPStatusCode())

	response := `{"error":"` + err.Message + `","code":"` + string(err.Code) + `"}`
	w.Write([]byte(response))
}
