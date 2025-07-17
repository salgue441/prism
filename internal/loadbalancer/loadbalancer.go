package loadbalancer

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"prism/pkg/utils"
	"sync"
	"time"
)

// LoadBalancer manages multiple backend pools
type LoadBalancer struct {
	pools         map[string]*Pool
	healthChecker *HealthChecker
	logger        *slog.Logger
	mu            sync.RWMutex
}

// Config represents load balancer configuration
type Config struct {
	Pools map[string]PoolConfig `json:"pools"`
}

// PoolConfig represents a pool configuration
type PoolConfig struct {
	Algorithm          Algorithm       `json:"algorithm"`
	Backends           []BackendConfig `json:"backends"`
	HealthCheckEnabled bool            `json:"health_check_enabled"`
	HealthInterval     time.Duration   `json:"health_interval"`
	HealthTimeout      time.Duration   `json:"health_timeout"`
	HealthPath         string          `json:"health_path"`
}

// BackendConfig represents backend configuration
type BackendConfig struct {
	URL      string `json:"url"`
	Weight   int    `json:"weight"`
	MaxConns int    `json:"max_connections"`
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(logger *slog.Logger) *LoadBalancer {
	return &LoadBalancer{
		pools:  make(map[string]*Pool),
		logger: logger,
	}
}

// LoadConfig loads configuration and creates pools
func (lb *LoadBalancer) LoadConfig(config Config) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for poolName, poolConfig := range config.Pools {
		pool := NewPool(poolConfig.Algorithm)
		pool.HealthCheckEnabled = poolConfig.HealthCheckEnabled

		if poolConfig.HealthInterval > 0 {
			pool.HealthInterval = poolConfig.HealthInterval
		}

		if poolConfig.HealthTimeout > 0 {
			pool.HealthTimeout = poolConfig.HealthTimeout
		}

		if poolConfig.HealthPath != "" {
			pool.HealthPath = poolConfig.HealthPath
		}

		for _, backendConfig := range poolConfig.Backends {
			backend, err := NewBackend(backendConfig.URL, backendConfig.Weight)
			if err != nil {
				return fmt.Errorf("failed to create backend %s: %w",
					backendConfig.URL, err)
			}

			if backendConfig.MaxConns > 0 {
				backend.MaxConns = backendConfig.MaxConns
			}

			pool.AddBackend(backend)
		}

		lb.pools[poolName] = pool
		lb.logger.Info("Pool configured",
			slog.String("pool", poolName),
			slog.String("algorithm", string(poolConfig.Algorithm)),
			slog.Int("backends", len(poolConfig.Backends)),
		)
	}

	return nil
}

// GetPool returns a pool by name
func (lb *LoadBalancer) GetPool(poolName string) (*Pool, bool) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	pool, exists := lb.pools[poolName]
	return pool, exists
}

// CreateHandler creates an HTTP handler for a specific pool
func (lb *LoadBalancer) CreateHandler(poolName string, proxyHandler func(*url.URL, string) http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool, exists := lb.GetPool(poolName)
		if !exists {
			http.Error(w, fmt.Sprintf("Pool not found: %s", poolName),
				http.StatusServiceUnavailable)
			return
		}

		clientIP := utils.GetClientIP(r)
		backend, err := pool.GetNextBackend(clientIP)
		if err != nil {
			lb.logger.Error("Failed to get backend",
				slog.String("pool", poolName),
				slog.String("error", err.Error()),
			)
			http.Error(w, "No healthy backends available", http.StatusServiceUnavailable)
			return
		}

		backend.AddConnection()
		defer backend.RemoveConnection()

		handler := proxyHandler(backend.URL, poolName)
		handler(w, r)
	}
}

// StartHealthChecking starts health checking for all pools
func (lb *LoadBalancer) StartHealthChecking() {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	for poolName, pool := range lb.pools {
		if pool.HealthCheckEnabled {
			hc := NewHealthChecker(pool, lb.logger)
			hc.Start()

			lb.logger.Info("Health checking started",
				slog.String("pool", poolName),
			)
		}
	}
}

// GetStats returns statistics for all pools
func (lb *LoadBalancer) GetStats() map[string]Stats {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	stats := make(map[string]Stats)
	for poolName, pool := range lb.pools {
		stats[poolName] = pool.GetStats()
	}

	return stats
}
