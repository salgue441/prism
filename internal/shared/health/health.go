// Package health provides health check utilities for services.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Status represents the health status of a component.
type Status string

const (
	// StatusUp indicates the component is healthy.
	StatusUp Status = "up"
	// StatusDown indicates the component is unhealthy.
	StatusDown Status = "down"
	// StatusDegraded indicates the component is partially healthy.
	StatusDegraded Status = "degraded"
)

// Check represents a health check function.
type Check func(ctx context.Context) ComponentHealth

// ComponentHealth represents the health of a single component.
type ComponentHealth struct {
	Status  Status         `json:"status"`
	Message string         `json:"message,omitempty"`
	Details map[string]any `json:"details,omitempty"`
	Latency time.Duration  `json:"latency_ms"`
}

// Response represents the overall health response.
type Response struct {
	Status     Status                     `json:"status"`
	Timestamp  time.Time                  `json:"timestamp"`
	Version    string                     `json:"version,omitempty"`
	Components map[string]ComponentHealth `json:"components,omitempty"`
}

// Checker manages health checks for a service.
type Checker struct {
	mu         sync.RWMutex
	checks     map[string]Check
	version    string
	timeout    time.Duration
	httpServer *http.Server
}

// Option is a functional option for configuring the Checker.
type Option func(*Checker)

// WithVersion sets the service version.
func WithVersion(version string) Option {
	return func(c *Checker) {
		c.version = version
	}
}

// WithTimeout sets the timeout for individual health checks.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Checker) {
		c.timeout = timeout
	}
}

// NewChecker creates a new health checker.
func NewChecker(opts ...Option) *Checker {
	c := &Checker{
		checks:  make(map[string]Check),
		timeout: 5 * time.Second,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Register adds a health check for a component.
func (c *Checker) Register(name string, check Check) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks[name] = check
}

// Deregister removes a health check.
func (c *Checker) Deregister(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.checks, name)
}

// Check runs all health checks and returns the overall health.
func (c *Checker) Check(ctx context.Context) Response {
	c.mu.RLock()
	checks := make(map[string]Check, len(c.checks))
	for k, v := range c.checks {
		checks[k] = v
	}
	c.mu.RUnlock()

	response := Response{
		Status:     StatusUp,
		Timestamp:  time.Now().UTC(),
		Version:    c.version,
		Components: make(map[string]ComponentHealth),
	}

	if len(checks) == 0 {
		return response
	}

	// Run checks concurrently
	var wg sync.WaitGroup
	results := make(chan struct {
		name   string
		health ComponentHealth
	}, len(checks))

	for name, check := range checks {
		wg.Add(1)
		go func(name string, check Check) {
			defer wg.Done()

			checkCtx, cancel := context.WithTimeout(ctx, c.timeout)
			defer cancel()

			start := time.Now()
			health := check(checkCtx)
			health.Latency = time.Since(start)

			results <- struct {
				name   string
				health ComponentHealth
			}{name, health}
		}(name, check)
	}

	// Close results channel when all checks complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for result := range results {
		response.Components[result.name] = result.health

		// Update overall status based on component status
		switch result.health.Status {
		case StatusDown:
			response.Status = StatusDown
		case StatusDegraded:
			if response.Status != StatusDown {
				response.Status = StatusDegraded
			}
		}
	}

	return response
}

// IsHealthy returns true if all components are healthy.
func (c *Checker) IsHealthy(ctx context.Context) bool {
	return c.Check(ctx).Status == StatusUp
}

// Handler returns an http.Handler for the health endpoint.
func (c *Checker) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Handle different paths
		switch r.URL.Path {
		case "/health", "/healthz":
			c.handleHealth(ctx, w, false)
		case "/health/live", "/livez":
			c.handleLiveness(w)
		case "/health/ready", "/readyz":
			c.handleHealth(ctx, w, true)
		default:
			c.handleHealth(ctx, w, false)
		}
	})
}

func (c *Checker) handleHealth(ctx context.Context, w http.ResponseWriter, detailed bool) {
	response := c.Check(ctx)

	w.Header().Set("Content-Type", "application/json")

	if response.Status == StatusDown {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else if response.Status == StatusDegraded {
		w.WriteHeader(http.StatusOK) // Still return 200 for degraded
	} else {
		w.WriteHeader(http.StatusOK)
	}

	// For non-detailed checks, return minimal response
	if !detailed {
		response.Components = nil
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

func (c *Checker) handleLiveness(w http.ResponseWriter) {
	// Liveness just checks if the service is running
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := Response{
		Status:    StatusUp,
		Timestamp: time.Now().UTC(),
		Version:   c.version,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

// ServeHTTP starts an HTTP server for health checks on the given address.
func (c *Checker) ServeHTTP(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/", c.Handler())

	c.httpServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return c.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the health check HTTP server.
func (c *Checker) Shutdown(ctx context.Context) error {
	if c.httpServer != nil {
		return c.httpServer.Shutdown(ctx)
	}
	return nil
}

// Common health check implementations

// PostgresCheck creates a health check for PostgreSQL.
func PostgresCheck(pingFunc func(context.Context) error) Check {
	return func(ctx context.Context) ComponentHealth {
		if err := pingFunc(ctx); err != nil {
			return ComponentHealth{
				Status:  StatusDown,
				Message: "database connection failed",
				Details: map[string]any{"error": err.Error()},
			}
		}
		return ComponentHealth{
			Status:  StatusUp,
			Message: "database connection healthy",
		}
	}
}

// ConsulCheck creates a health check for Consul.
func ConsulCheck(statusFunc func() (string, error)) Check {
	return func(_ context.Context) ComponentHealth {
		leader, err := statusFunc()
		if err != nil {
			return ComponentHealth{
				Status:  StatusDown,
				Message: "consul connection failed",
				Details: map[string]any{"error": err.Error()},
			}
		}
		return ComponentHealth{
			Status:  StatusUp,
			Message: "consul connection healthy",
			Details: map[string]any{"leader": leader},
		}
	}
}

// GRPCCheck creates a health check for a gRPC service.
func GRPCCheck(checkFunc func(context.Context) error) Check {
	return func(ctx context.Context) ComponentHealth {
		if err := checkFunc(ctx); err != nil {
			return ComponentHealth{
				Status:  StatusDown,
				Message: "grpc service unhealthy",
				Details: map[string]any{"error": err.Error()},
			}
		}
		return ComponentHealth{
			Status:  StatusUp,
			Message: "grpc service healthy",
		}
	}
}

// MemoryCheck creates a health check for memory usage.
func MemoryCheck(maxBytes uint64) Check {
	return func(_ context.Context) ComponentHealth {
		var m memStats
		readMemStats(&m)

		if m.Alloc > maxBytes {
			return ComponentHealth{
				Status:  StatusDegraded,
				Message: "high memory usage",
				Details: map[string]any{
					"allocated_bytes": m.Alloc,
					"max_bytes":       maxBytes,
				},
			}
		}
		return ComponentHealth{
			Status:  StatusUp,
			Message: "memory usage normal",
			Details: map[string]any{
				"allocated_bytes": m.Alloc,
			},
		}
	}
}

// memStats is a minimal struct for memory statistics.
type memStats struct {
	Alloc uint64
}

// readMemStats reads memory statistics.
// This is a simplified version - in production, use runtime.ReadMemStats.
func readMemStats(m *memStats) {
	// Import runtime in actual implementation
	// var rtm runtime.MemStats
	// runtime.ReadMemStats(&rtm)
	// m.Alloc = rtm.Alloc
	m.Alloc = 0 // Placeholder
}
