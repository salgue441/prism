package loadbalancer

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"time"
)

// NewPool creates a new backend pool
func NewPool(algorithm Algorithm) *Pool {
	return &Pool{
		Backends:           make([]*Backend, 0),
		Algorithm:          algorithm,
		HealthCheckEnabled: true,
		HealthInterval:     30 * time.Second,
		HealthTimeout:      5 * time.Second,
		HealthPath:         "/health",
	}
}

// AddBackend adds a backend to the pool
func (p *Pool) AddBackend(backend *Backend) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.HealthCheckEnabled {
		backend.HealthPath = p.HealthPath
		backend.HealthInterval = p.HealthInterval
		backend.HealthTimeout = p.HealthTimeout
	}

	p.Backends = append(p.Backends, backend)
}

// RemoveBackend removes a backend from the pool
func (p *Pool) RemoveBackend(urlStr string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, backend := range p.Backends {
		if backend.URL.String() == urlStr {
			p.Backends = append(p.Backends[:i], p.Backends[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("backend not found: %s", urlStr)
}

// GetNextBackend returns the next backend based on the algorithm
func (p *Pool) GetNextBackend(clientIP string) (*Backend, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	healthyBackends := p.getHealthyBackends()
	if len(healthyBackends) == 0 {
		return nil, fmt.Errorf("no healthy backends available")
	}

	switch p.Algorithm {
	case RoundRobin:
		return p.roundRobin(healthyBackends), nil

	case WeightedRound:
		return p.weightedRoundRobin(healthyBackends), nil

	case LeastConn:
		return p.leastConnections(healthyBackends), nil

	case IPHash:
		return p.ipHash(healthyBackends, clientIP), nil

	case Random:
		return p.randomBackend(healthyBackends), nil

	default:
		return p.roundRobin(healthyBackends), nil
	}
}

// getHealthyBackends returns only healthy backends that can accept connections
func (p *Pool) getHealthyBackends() []*Backend {
	var healthy []*Backend
	for _, backend := range p.Backends {
		if backend.CanAcceptConnection() {
			healthy = append(healthy, backend)
		}
	}

	return healthy
}

// roundRobin implements round-robin load balancing
func (p *Pool) roundRobin(backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	backend := backends[p.current%len(backends)]
	p.current++
	return backend
}

// weightedRoundRobin implements weighted round-robin load balancing
func (p *Pool) weightedRoundRobin(backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	totalWeight := 0
	for _, backend := range backends {
		totalWeight += backend.Weight
	}

	if totalWeight == 0 {
		return p.roundRobin(backends)
	}

	target := p.current % totalWeight
	p.current++

	current := 0
	for _, backend := range backends {
		current += backend.Weight
		if target < current {
			return backend
		}
	}

	return backends[0]
}

// leastConnections implements least connections load balancing
func (p *Pool) leastConnections(backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	var chosen *Backend
	minConns := int(^uint(0) >> 1)
	for _, backend := range backends {
		backend.mu.RLock()
		conns := backend.ActiveConns
		backend.mu.RUnlock()

		if conns < minConns {
			minConns = conns
			chosen = backend
		}
	}

	return chosen
}

// ipHash implements IP hash-based load balancing for sticky sessions
func (p *Pool) ipHash(backends []*Backend, clientIP string) *Backend {
	if len(backends) == 0 {
		return nil
	}

	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	hasher := fnv.New32a()
	hasher.Write([]byte(clientIP))
	hash := hasher.Sum32()
	index := int(hash) % len(backends)

	return backends[index]
}

// randomBackend implements random load balancing
func (p *Pool) randomBackend(backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	index := rand.Intn(len(backends))
	return backends[index]
}

// GetStats returns pool statistics
func (p *Pool) GetStats() Stats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := Stats{
		TotalBackends:   len(p.Backends),
		HealthyBackends: 0,
		Algorithm:       p.Algorithm,
		BackendStats:    make(map[string]BackendStat),
	}

	for _, backend := range p.Backends {
		if backend.IsHealthy() {
			stats.HealthyBackends++
		}

		stats.BackendStats[backend.URL.String()] = backend.GetStats()
	}

	return stats
}
