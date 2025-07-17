package loadbalancer

import (
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// NewBackend creates a new backend instance
func NewBackend(urlStr string, weight int) (*Backend, error) {
	if urlStr == "" {
		return nil, fmt.Errorf("backend URL cannot be empty")
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid backend URL %s: %w", urlStr, err)
	}

	if u.Scheme == "" {
		return nil, fmt.Errorf("backend URL must have a scheme (http/https): %s",
			urlStr)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("backend URL must use http or https scheme: %s",
			urlStr)
	}

	if u.Host == "" {
		return nil, fmt.Errorf("backend URL must have a host: %s", urlStr)
	}

	if strings.Contains(u.Host, " ") {
		return nil, fmt.Errorf("invalid backend URL format: %s", urlStr)
	}

	return &Backend{
		URL:            u,
		Weight:         weight,
		MaxConns:       100,
		Healthy:        true,
		HealthPath:     "/health",
		HealthInterval: 30 * time.Second,
		HealthTimeout:  5 * time.Second,
		LastCheck:      time.Now(),
	}, nil
}

// IsHealthy returns whether the backend is healthy
func (b *Backend) IsHealthy() bool {
	b.mu.RLock()

	defer b.mu.RUnlock()
	return b.Healthy
}

// SetHealthy sets the backend health status
func (b *Backend) SetHealthy(healthy bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.Healthy = healthy
	b.LastCheck = time.Now()
}

// CanAcceptConnection checks if backend can accept new connections
func (b *Backend) CanAcceptConnection() bool {
	b.mu.RLock()

	defer b.mu.RUnlock()
	return b.Healthy && (b.MaxConns == 0 || b.ActiveConns < b.MaxConns)
}

// AddConnection increments active connection count
func (b *Backend) AddConnection() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.ActiveConns++
	atomic.AddInt64(&b.TotalReqs, 1)
}

// RemoveConnection decrements active connection count
func (b *Backend) RemoveConnection() {
	b.mu.Lock()

	defer b.mu.Unlock()
	if b.ActiveConns > 0 {
		b.ActiveConns--
	}
}

// AddFailure increments failure count
func (b *Backend) AddFailure() {
	b.mu.Lock()

	defer b.mu.Unlock()
	b.Failures++
}

// GetStats returns backend statistics
func (b *Backend) GetStats() BackendStat {
	b.mu.RLock()

	defer b.mu.RUnlock()
	return BackendStat{
		URL:         b.URL.String(),
		Healthy:     b.Healthy,
		Weight:      b.Weight,
		ActiveConns: b.ActiveConns,
		TotalReqs:   b.TotalReqs,
		Failures:    b.Failures,
		LastCheck:   b.LastCheck.Format(time.RFC3339),
	}
}
