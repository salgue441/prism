// Package dashboard provides REST API endpoints for the health dashboard.
package dashboard

// OverviewResponse represents the overall system status.
type OverviewResponse struct {
	Status          string                 `json:"status"`
	UptimeSeconds   int64                  `json:"uptime_seconds"`
	Version         string                 `json:"version"`
	RoutesCount     int                    `json:"routes_count"`
	UpstreamsCount  int                    `json:"upstreams_count"`
	CircuitBreakers CircuitBreakersSummary `json:"circuit_breakers"`
}

// CircuitBreakersSummary summarizes circuit breaker states.
type CircuitBreakersSummary struct {
	Open     int `json:"open"`
	HalfOpen int `json:"half_open"`
	Closed   int `json:"closed"`
}

// RoutesResponse represents the routes list.
type RoutesResponse struct {
	Routes []RouteInfo `json:"routes"`
}

// RouteInfo represents a single route's information.
type RouteInfo struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Paths          []string          `json:"paths"`
	Hosts          []string          `json:"hosts,omitempty"`
	Methods        []string          `json:"methods,omitempty"`
	UpstreamID     string            `json:"upstream_id,omitempty"`
	Enabled        bool              `json:"enabled"`
	AuthRequired   bool              `json:"auth_required"`
	RequiredRoles  []string          `json:"required_roles,omitempty"`
	RequiredScopes []string          `json:"required_scopes,omitempty"`
	RateLimitKey   string            `json:"rate_limit_key,omitempty"`
	StripPath      bool              `json:"strip_path"`
	PathRewrite    string            `json:"path_rewrite,omitempty"`
	MirrorEnabled  bool              `json:"mirror_enabled"`
	Priority       int               `json:"priority"`
	Headers        map[string]string `json:"headers,omitempty"`
}

// UpstreamsResponse represents the upstreams list.
type UpstreamsResponse struct {
	Upstreams []UpstreamInfo `json:"upstreams"`
}

// UpstreamInfo represents a single upstream's information.
type UpstreamInfo struct {
	ID                  string       `json:"id"`
	Name                string       `json:"name"`
	Targets             []TargetInfo `json:"targets"`
	CircuitBreakerState string       `json:"circuit_breaker_state,omitempty"`
}

// TargetInfo represents an upstream target.
type TargetInfo struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// MetricsResponse represents key metrics summary.
type MetricsResponse struct {
	HTTP            HTTPMetrics            `json:"http"`
	RateLimiting    RateLimitingMetrics    `json:"rate_limiting"`
	CircuitBreakers CircuitBreakerMetrics  `json:"circuit_breakers"`
	Mirror          MirrorMetrics          `json:"mirror"`
}

// HTTPMetrics represents HTTP-related metrics.
type HTTPMetrics struct {
	RequestsInFlight int64 `json:"requests_in_flight"`
}

// RateLimitingMetrics represents rate limiting metrics.
type RateLimitingMetrics struct {
	// Placeholder for future metrics from Prometheus
}

// CircuitBreakerMetrics represents circuit breaker metrics.
type CircuitBreakerMetrics struct {
	// Placeholder for future metrics from Prometheus
}

// MirrorMetrics represents traffic mirroring metrics.
type MirrorMetrics struct {
	// Placeholder for future metrics from Prometheus
}
