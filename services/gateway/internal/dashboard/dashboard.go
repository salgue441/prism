// Package dashboard provides REST API endpoints for the health dashboard.
package dashboard

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/carlossalguero/prism/services/gateway/internal/circuitbreaker"
	"github.com/carlossalguero/prism/services/gateway/internal/router"
	"github.com/carlossalguero/prism/services/shared/logger"
	"github.com/carlossalguero/prism/services/shared/metrics"
)

// Dashboard provides REST API endpoints for monitoring.
type Dashboard struct {
	router     *router.Router
	metrics    *metrics.Metrics
	cbRegistry *circuitbreaker.Registry
	startTime  time.Time
	version    string
	logger     *logger.Logger
}

// Config holds dashboard configuration.
type Config struct {
	Router            *router.Router
	Metrics           *metrics.Metrics
	CircuitBreaker    *circuitbreaker.Registry
	Version           string
	Logger            *logger.Logger
}

// New creates a new Dashboard instance.
func New(cfg Config) *Dashboard {
	return &Dashboard{
		router:     cfg.Router,
		metrics:    cfg.Metrics,
		cbRegistry: cfg.CircuitBreaker,
		startTime:  time.Now(),
		version:    cfg.Version,
		logger:     cfg.Logger,
	}
}

// RegisterRoutes registers dashboard API routes on the provided mux.
func (d *Dashboard) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/dashboard", d.handleOverview)
	mux.HandleFunc("/api/dashboard/routes", d.handleRoutes)
	mux.HandleFunc("/api/dashboard/upstreams", d.handleUpstreams)
	mux.HandleFunc("/api/dashboard/metrics", d.handleMetrics)
}

// handleOverview returns the overall system status.
func (d *Dashboard) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Calculate circuit breaker states
	cbSummary := d.getCircuitBreakerSummary()

	response := OverviewResponse{
		Status:          d.getSystemStatus(),
		UptimeSeconds:   int64(time.Since(d.startTime).Seconds()),
		Version:         d.version,
		RoutesCount:     d.router.RouteCount(),
		UpstreamsCount:  d.router.UpstreamCount(),
		CircuitBreakers: cbSummary,
	}

	d.writeJSON(w, response)
}

// handleRoutes returns all routes with their configuration.
func (d *Dashboard) handleRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	routes := d.router.ListRoutes()
	routeInfos := make([]RouteInfo, 0, len(routes))

	for _, route := range routes {
		var upstreamID string
		if route.Upstream != nil {
			upstreamID = route.Upstream.ID
		}

		info := RouteInfo{
			ID:             route.ID,
			Name:           route.Name,
			Paths:          route.Paths,
			Hosts:          route.Hosts,
			Methods:        route.Methods,
			UpstreamID:     upstreamID,
			Enabled:        route.Enabled,
			AuthRequired:   route.AuthRequired,
			RequiredRoles:  route.RequiredRoles,
			RequiredScopes: route.RequiredScopes,
			RateLimitKey:   route.RateLimitKey,
			StripPath:      route.StripPath,
			PathRewrite:    route.PathRewrite,
			MirrorEnabled:  route.MirrorEnabled,
			Priority:       route.Priority,
			Headers:        route.Headers,
		}
		routeInfos = append(routeInfos, info)
	}

	response := RoutesResponse{
		Routes: routeInfos,
	}

	d.writeJSON(w, response)
}

// handleUpstreams returns all upstreams with their health status.
func (d *Dashboard) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	upstreams := d.router.ListUpstreams()
	upstreamInfos := make([]UpstreamInfo, 0, len(upstreams))

	for _, upstream := range upstreams {
		targets := make([]TargetInfo, 0, len(upstream.Targets))
		for _, target := range upstream.Targets {
			targets = append(targets, TargetInfo{
				URL:    target.URL.String(),
				Weight: target.Weight,
			})
		}

		// Get circuit breaker state for first target
		var cbState string
		if len(upstream.Targets) > 0 && d.cbRegistry != nil {
			host := upstream.Targets[0].URL.Host
			cb := d.cbRegistry.Get(host)
			cbState = cb.State().String()
		}

		info := UpstreamInfo{
			ID:                  upstream.ID,
			Name:                upstream.Name,
			Targets:             targets,
			CircuitBreakerState: cbState,
		}
		upstreamInfos = append(upstreamInfos, info)
	}

	response := UpstreamsResponse{
		Upstreams: upstreamInfos,
	}

	d.writeJSON(w, response)
}

// handleMetrics returns a summary of key metrics.
func (d *Dashboard) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := MetricsResponse{
		HTTP: HTTPMetrics{
			// These would be populated from actual metric values
			// For now, return placeholder
			RequestsInFlight: 0,
		},
		RateLimiting:    RateLimitingMetrics{},
		CircuitBreakers: CircuitBreakerMetrics{},
		Mirror:          MirrorMetrics{},
	}

	d.writeJSON(w, response)
}

// getSystemStatus returns the overall system health status.
func (d *Dashboard) getSystemStatus() string {
	// Check if any circuit breaker is open
	if d.cbRegistry != nil {
		summary := d.getCircuitBreakerSummary()
		if summary.Open > 0 {
			return "degraded"
		}
	}
	return "healthy"
}

// getCircuitBreakerSummary returns a summary of circuit breaker states.
func (d *Dashboard) getCircuitBreakerSummary() CircuitBreakersSummary {
	summary := CircuitBreakersSummary{}

	if d.cbRegistry == nil {
		return summary
	}

	upstreams := d.router.ListUpstreams()
	for _, upstream := range upstreams {
		for _, target := range upstream.Targets {
			cb := d.cbRegistry.Get(target.URL.Host)
			state := cb.State()
			switch state {
			case circuitbreaker.StateClosed:
				summary.Closed++
			case circuitbreaker.StateOpen:
				summary.Open++
			case circuitbreaker.StateHalfOpen:
				summary.HalfOpen++
			}
		}
	}

	return summary
}

// writeJSON writes a JSON response.
func (d *Dashboard) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if err := json.NewEncoder(w).Encode(data); err != nil {
		d.logger.Error("failed to encode JSON response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
