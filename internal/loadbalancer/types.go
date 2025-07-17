package loadbalancer

import (
	"net/url"
	"sync"
	"time"
)

// Algorithm represents the load balancing algorithm
type Algorithm string

const (
	RoundRobin    Algorithm = "round_robin"
	WeightedRound Algorithm = "weighted_round_robin"
	LeastConn     Algorithm = "least_connections"
	IPHash        Algorithm = "ip_hash"
	Random        Algorithm = "random"
)

// Backend represents a backend server
type Backend struct {
	URL       *url.URL  `json:"url"`
	Weight    int       `json:"weight"`
	MaxConns  int       `json:"max_connections"`
	Healthy   bool      `json:"healthy"`
	LastCheck time.Time `json:"last_check"`

	// Runtime stats
	ActiveConns int   `json:"active_connections"`
	TotalReqs   int64 `json:"total_requests"`
	Failures    int   `json:"failures"`

	// Health check settings
	HealthPath     string        `json:"health_path"`
	HealthInterval time.Duration `json:"health_interval"`
	HealthTimeout  time.Duration `json:"health_timeout"`

	mu sync.RWMutex
}

// Pool represents a pool of backend servers
type Pool struct {
	Backends  []*Backend `json:"backends"`
	Algorithm Algorithm  `json:"algorithm"`

	// Round robin state
	current int

	// Health check settings
	HealthCheckEnabled bool          `json:"health_check_enabled"`
	HealthInterval     time.Duration `json:"health_interval"`
	HealthTimeout      time.Duration `json:"health_timeout"`
	HealthPath         string        `json:"health_path"`

	mu sync.RWMutex
}

// Stats contains load balancer statistics
type Stats struct {
	TotalBackends   int                    `json:"total_backends"`
	HealthyBackends int                    `json:"healthy_backends"`
	Algorithm       Algorithm              `json:"algorithm"`
	BackendStats    map[string]BackendStat `json:"backend_stats"`
}

// BackendStat contains individual backend statistics
type BackendStat struct {
	URL         string `json:"url"`
	Healthy     bool   `json:"healthy"`
	Weight      int    `json:"weight"`
	ActiveConns int    `json:"active_connections"`
	TotalReqs   int64  `json:"total_requests"`
	Failures    int    `json:"failures"`
	LastCheck   string `json:"last_check"`
}
