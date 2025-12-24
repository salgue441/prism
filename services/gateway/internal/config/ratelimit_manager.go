// Package config provides configuration management for the gateway.
package config

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/carlossalguero/prism/services/shared/errors"
	"github.com/carlossalguero/prism/services/shared/logger"
	"github.com/carlossalguero/prism/services/shared/metrics"
)

// RateLimitManager manages dynamic rate limit rules.
type RateLimitManager struct {
	mu           sync.RWMutex
	rules        map[string]*RateLimitConfig // rule ID -> config
	limiters     map[string]*dynamicLimiter  // "ruleID:clientKey" -> limiter
	cleanupEvery time.Duration
	stopCleanup  chan struct{}
	logger       *logger.Logger
	metrics      *metrics.Metrics
}

type dynamicLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
	ruleID   string
}

// NewRateLimitManager creates a new rate limit manager.
func NewRateLimitManager(log *logger.Logger) *RateLimitManager {
	m := &RateLimitManager{
		rules:        make(map[string]*RateLimitConfig),
		limiters:     make(map[string]*dynamicLimiter),
		cleanupEvery: time.Minute,
		stopCleanup:  make(chan struct{}),
		logger:       log,
	}

	go m.cleanup()

	return m
}

// SetMetrics sets the metrics instance.
func (m *RateLimitManager) SetMetrics(met *metrics.Metrics) {
	m.metrics = met
}

// AddRule adds or updates a rate limit rule.
func (m *RateLimitManager) AddRule(config *RateLimitConfig) {
	if config == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	oldRule, exists := m.rules[config.ID]
	m.rules[config.ID] = config

	// If rule parameters changed, clear existing limiters for this rule
	if exists && (oldRule.RequestsPerSecond != config.RequestsPerSecond ||
		oldRule.BurstSize != config.BurstSize) {
		m.clearLimitersForRule(config.ID)
	}

	m.logger.Info("rate limit rule added/updated",
		"rule_id", config.ID,
		"name", config.Name,
		"rps", config.RequestsPerSecond,
		"burst", config.BurstSize,
		"scope", config.Scope,
	)
}

// RemoveRule removes a rate limit rule.
func (m *RateLimitManager) RemoveRule(ruleID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.rules[ruleID]; exists {
		delete(m.rules, ruleID)
		m.clearLimitersForRule(ruleID)
		m.logger.Info("rate limit rule removed", "rule_id", ruleID)
	}
}

// GetRule returns a rate limit rule by ID.
func (m *RateLimitManager) GetRule(ruleID string) *RateLimitConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rules[ruleID]
}

// ReplaceAllRules atomically replaces all rate limit rules.
func (m *RateLimitManager) ReplaceAllRules(rules []*RateLimitConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear all existing rules and limiters
	m.rules = make(map[string]*RateLimitConfig)
	m.limiters = make(map[string]*dynamicLimiter)

	// Add new rules
	for _, rule := range rules {
		if rule != nil {
			m.rules[rule.ID] = rule
		}
	}

	m.logger.Info("replaced all rate limit rules", "count", len(rules))
}

// Allow checks if a request should be allowed for the given rule and request.
func (m *RateLimitManager) Allow(ruleID string, r *http.Request, userID string) bool {
	m.mu.RLock()
	rule, exists := m.rules[ruleID]
	if !exists {
		m.mu.RUnlock()
		return true // No rule means allow
	}
	m.mu.RUnlock()

	// Generate client key based on scope
	clientKey := m.getClientKey(rule.Scope, r, userID)
	limiterKey := ruleID + ":" + clientKey

	m.mu.Lock()
	limiter, exists := m.limiters[limiterKey]
	if !exists {
		limiter = &dynamicLimiter{
			limiter:  rate.NewLimiter(rate.Limit(rule.RequestsPerSecond), rule.BurstSize),
			lastSeen: time.Now(),
			ruleID:   ruleID,
		}
		m.limiters[limiterKey] = limiter
	}
	limiter.lastSeen = time.Now()
	m.mu.Unlock()

	allowed := limiter.limiter.Allow()

	if m.metrics != nil {
		m.metrics.RecordRateLimitHit(r.URL.Path)
		if !allowed {
			m.metrics.RecordRateLimitDrop(r.URL.Path)
		}
	}

	return allowed
}

// UserInfoGetter is a function that returns user ID from request context.
type UserInfoGetter func(*http.Request) string

// Middleware returns HTTP middleware that checks rate limits dynamically.
// The getRuleID function returns the rate limit rule ID for the request.
// The getUserID function extracts user ID from request context.
func (m *RateLimitManager) Middleware(getRuleID func(*http.Request) string, getUserID UserInfoGetter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ruleID := getRuleID(r)
			if ruleID == "" {
				// No rate limit rule for this request
				next.ServeHTTP(w, r)
				return
			}

			// Get user ID from context if available
			var userID string
			if getUserID != nil {
				userID = getUserID(r)
			}

			if !m.Allow(ruleID, r, userID) {
				m.writeRateLimitError(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Stop stops the cleanup goroutine.
func (m *RateLimitManager) Stop() {
	close(m.stopCleanup)
}

// RuleCount returns the number of active rules.
func (m *RateLimitManager) RuleCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.rules)
}

func (m *RateLimitManager) cleanup() {
	ticker := time.NewTicker(m.cleanupEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			for key, limiter := range m.limiters {
				if time.Since(limiter.lastSeen) > 3*time.Minute {
					delete(m.limiters, key)
				}
			}
			m.mu.Unlock()
		case <-m.stopCleanup:
			return
		}
	}
}

func (m *RateLimitManager) clearLimitersForRule(ruleID string) {
	// Called with lock held
	for key, limiter := range m.limiters {
		if limiter.ruleID == ruleID {
			delete(m.limiters, key)
		}
	}
}

func (m *RateLimitManager) getClientKey(scope string, r *http.Request, userID string) string {
	switch scope {
	case "global":
		return "global"
	case "user":
		if userID != "" {
			return "user:" + userID
		}
		return "ip:" + getClientIPFromRequest(r)
	case "api_key":
		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			return "apikey:" + apiKey
		}
		return "ip:" + getClientIPFromRequest(r)
	case "ip":
		fallthrough
	default:
		return "ip:" + getClientIPFromRequest(r)
	}
}

func (m *RateLimitManager) writeRateLimitError(w http.ResponseWriter) {
	err := errors.RateLimited("too many requests")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(err.HTTPStatusCode())

	response := `{"error":"` + err.Message + `","code":"` + string(err.Code) + `"}`
	w.Write([]byte(response))
}

func getClientIPFromRequest(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return trimSpaces(xff[:i])
			}
		}
		return trimSpaces(xff)
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

func trimSpaces(s string) string {
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
