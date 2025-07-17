package loadbalancer

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// HealthChecker manages health checks for backend servers
type HealthChecker struct {
	pool    *Pool
	logger  *slog.Logger
	client  *http.Client
	stopCh  chan struct{}
	wg      sync.WaitGroup
	running bool
	mu      sync.Mutex
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(pool *Pool, logger *slog.Logger) *HealthChecker {
	return &HealthChecker{
		pool:   pool,
		logger: logger,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     30 * time.Second,
			},
		},
		stopCh: make(chan struct{}),
	}
}

// Start begins health checking for all backends
func (hc *HealthChecker) Start() {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if hc.running {
		return
	}

	hc.running = true
	hc.logger.Info("Starting health checker")
	hc.pool.mu.RLock()

	backends := make([]*Backend, len(hc.pool.Backends))
	copy(backends, hc.pool.Backends)
	hc.pool.mu.RUnlock()

	for _, backend := range backends {
		hc.wg.Add(1)
		go hc.healthCheckLoop(backend)
	}
}

// Stop stops all health checking
func (hc *HealthChecker) Stop() {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if !hc.running {
		return
	}

	hc.logger.Info("Stopping health checker")
	hc.running = false

	close(hc.stopCh)
	hc.wg.Wait()
}

// healthCheckLoop runs health checks for a specific backend
func (hc *HealthChecker) healthCheckLoop(backend *Backend) {
	defer hc.wg.Done()
	ticker := time.NewTicker(backend.HealthInterval)

	defer ticker.Stop()
	hc.checkBackend(backend)

	for {
		select {
		case <-ticker.C:
			hc.checkBackend(backend)

		case <-hc.stopCh:
			return
		}
	}
}

// checkBackend performs a health check on a backend
func (hc *HealthChecker) checkBackend(backend *Backend) {
	ctx, cancel := context.WithTimeout(context.Background(), backend.HealthTimeout)
	defer cancel()

	healthURL := fmt.Sprintf("%s%s", backend.URL.String(), backend.HealthPath)
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		hc.markUnhealthy(backend, fmt.Errorf("failed to create request: %w", err))
		return
	}

	resp, err := hc.client.Do(req)
	if err != nil {
		hc.markUnhealthy(backend, fmt.Errorf("health check failed: %w", err))
		return
	}

	defer resp.Body.Close()

	// Consider 2xx and 3xx as healthy
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		hc.markHealthy(backend)
	} else {
		hc.markUnhealthy(backend, fmt.Errorf("health check returned status %d", resp.StatusCode))
	}
}

// markHealthy marks a backend as healthy
func (hc *HealthChecker) markHealthy(backend *Backend) {
	wasHealthy := backend.IsHealthy()
	backend.SetHealthy(true)

	if !wasHealthy {
		hc.logger.Info("Backend marked as healthy",
			slog.String("backend", backend.URL.String()),
		)
	}
}

// markUnhealthy marks a backend as unhealthy
func (hc *HealthChecker) markUnhealthy(backend *Backend, err error) {
	wasHealthy := backend.IsHealthy()
	backend.SetHealthy(false)
	backend.AddFailure()

	if wasHealthy {
		hc.logger.Warn("Backend marked as unhealthy",
			slog.String("backend", backend.URL.String()),
			slog.String("error", err.Error()),
		)
	}
}

// AddBackend adds a backend to health checking
func (hc *HealthChecker) AddBackend(backend *Backend) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if hc.running {
		hc.wg.Add(1)
		go hc.healthCheckLoop(backend)
	}
}
