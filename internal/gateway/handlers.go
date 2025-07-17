package gateway

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"time"
)

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string       `json:"status"`
	Timestamp string       `json:"timestamp"`
	Version   string       `json:"version"`
	Uptime    string       `json:"uptime"`
	System    SystemInfo   `json:"system"`
	Routes    RouteSummary `json:"routes"`
}

// SystemInfo contains basic system information
type SystemInfo struct {
	GoVersion    string `json:"go_version"`
	NumCPU       int    `json:"num_cpu"`
	NumGoroutine int    `json:"num_goroutine"`
}

// RouteSummary contains route statistics
type RouteSummary struct {
	Total    int            `json:"total"`
	ByMethod map[string]int `json:"by_method"`
}

// MetricsResponse represents the metrics endpoint response
type MetricsResponse struct {
	Timestamp string       `json:"timestamp"`
	Uptime    string       `json:"uptime"`
	System    SystemInfo   `json:"system"`
	Routes    RouteSummary `json:"routes"`
	Memory    MemoryStats  `json:"memory"`
}

// MemoryStats contains memory usage information
type MemoryStats struct {
	Alloc      uint64 `json:"alloc_bytes"`
	TotalAlloc uint64 `json:"total_alloc_bytes"`
	Sys        uint64 `json:"sys_bytes"`
	NumGC      uint32 `json:"num_gc"`
}

// HealthHandler handles health check requests
// @Summary Health Check
// @Description Returns the health status of the API gateway
// @Tags monitoring
// @Produce json
// @Success 200 {object} HealthResponse
// @Router /health [get]
func (g *Gateway) HealthHandler(w http.ResponseWriter, r *http.Request) {
	routeStats := g.router.Stats()
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   "1.0.0",
		Uptime:    time.Since(g.startTime).String(),
		System: SystemInfo{
			GoVersion:    runtime.Version(),
			NumCPU:       runtime.NumCPU(),
			NumGoroutine: runtime.NumGoroutine(),
		},
		Routes: RouteSummary{
			Total:    routeStats.TotalRoutes,
			ByMethod: routeStats.RoutesByMethod,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		g.logger.Error("Failed to encode health response",
			slog.String("error", err.Error()))
	}
}

// MetricsHandler handles metrics requests
// @Summary Gateway Metrics
// @Description Returns operational metrics for the API gateway
// @Tags monitoring
// @Produce json
// @Success 200 {object} MetricsResponse
// @Router /metrics [get]
func (g *Gateway) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	routeStats := g.router.Stats()
	response := MetricsResponse{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Uptime:    time.Since(g.startTime).String(),
		System: SystemInfo{
			GoVersion:    runtime.Version(),
			NumCPU:       runtime.NumCPU(),
			NumGoroutine: runtime.NumGoroutine(),
		},
		Routes: RouteSummary{
			Total:    routeStats.TotalRoutes,
			ByMethod: routeStats.RoutesByMethod,
		},
		Memory: MemoryStats{
			Alloc:      memStats.Alloc,
			TotalAlloc: memStats.TotalAlloc,
			Sys:        memStats.Sys,
			NumGC:      memStats.NumGC,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		g.logger.Error("Failed to encode metrics response",
			slog.String("error", err.Error()))
	}
}

// ReadinessHandler handles readiness probe requests
// @Summary Readiness Check
// @Description Returns whether the gateway is ready to serve traffic
// @Tags monitoring
// @Produce json
// @Success 200 {object} map[string]string
// @Success 503 {object} map[string]string
// @Router /ready [get]
func (g *Gateway) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	routes := g.router.GetRoutes()
	if len(routes) == 0 {
		response := map[string]string{
			"status": "not_ready",
			"reason": "no_routes_configured",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := map[string]string{
		"status": "ready",
		"routes": fmt.Sprintf("%d", len(routes)),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
