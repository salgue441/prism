package gateway

import (
	"encoding/json"
	"net/http"
	"time"
)

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version"`
	Uptime    string `json:"uptime"`
}

// MetricsResponse represents the metrics response
type MetricsResponse struct {
	RoutesConfigured int    `json:"routes_configured"`
	Uptime           string `json:"uptime"`
	Timestamp        string `json:"timestamp"`
	// Add more metrics as needed
}

// HealthHandler handles health check requests
// @Summary Health Check
// @Description Check if the API gateway is healthy
// @Tags monitoring
// @Produce json
// @Success 200 {object} HealthResponse
// @Router /health [get]
func (g *Gateway) HealthHandler(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   "1.0.0",
		Uptime:    time.Since(g.startTime).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// MetricsHandler handles metrics requests
// @Summary Basic Metrics
// @Description Get basic gateway metrics
// @Tags monitoring
// @Produce json
// @Success 200 {object} MetricsResponse
// @Router /metrics [get]
func (g *Gateway) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	response := MetricsResponse{
		RoutesConfigured: len(g.router.GetRoutes()),
		Uptime:           time.Since(g.startTime).String(),
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
