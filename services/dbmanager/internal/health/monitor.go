// Package health provides database health monitoring.
package health

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config holds health monitor configuration.
type Config struct {
	CheckInterval time.Duration
}

// DatabaseHealth contains health information for a database.
type DatabaseHealth struct {
	Database            string
	Healthy             bool
	Status              string
	ActiveConnections   int
	IdleConnections     int
	MaxConnections      int
	CacheHitRatio       float64
	IndexHitRatio       float64
	DatabaseSizeBytes   int64
	Deadlocks           int64
	LongRunningQueries  int
	BloatRatio          float64
	ReplicationLagSecs  float64
	CheckedAt           time.Time
	Issues              []HealthIssue
}

// HealthIssue represents a health issue.
type HealthIssue struct {
	Severity       string // "warning", "critical"
	Message        string
	Recommendation string
}

// ConnectionPoolStats contains connection pool statistics.
type ConnectionPoolStats struct {
	Database           string
	TotalConnections   int
	ActiveConnections  int
	IdleConnections    int
	WaitCount          int
	WaitDuration       time.Duration
	MaxIdleClosed      int
	MaxLifetimeClosed  int
}

// Monitor handles database health monitoring.
type Monitor struct {
	config   Config
	authPool *pgxpool.Pool
	opsPool  *pgxpool.Pool

	mu           sync.RWMutex
	authHealth   *DatabaseHealth
	opsHealth    *DatabaseHealth
	stopChan     chan struct{}
}

// NewMonitor creates a new health monitor.
func NewMonitor(cfg Config, authPool, opsPool *pgxpool.Pool) *Monitor {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 30 * time.Second
	}

	return &Monitor{
		config:   cfg,
		authPool: authPool,
		opsPool:  opsPool,
		stopChan: make(chan struct{}),
	}
}

// Start starts the health monitoring loop.
func (m *Monitor) Start(ctx context.Context) {
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	// Initial check
	m.checkHealth(ctx)

	for {
		select {
		case <-ticker.C:
			m.checkHealth(ctx)
		case <-m.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// Stop stops the health monitoring loop.
func (m *Monitor) Stop() {
	close(m.stopChan)
}

// GetHealth returns health information for a database or all databases.
func (m *Monitor) GetHealth(database string) []DatabaseHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []DatabaseHealth

	if database == "" || database == "auth" {
		if m.authHealth != nil {
			result = append(result, *m.authHealth)
		}
	}

	if database == "" || database == "ops" {
		if m.opsHealth != nil {
			result = append(result, *m.opsHealth)
		}
	}

	return result
}

// GetConnectionPoolStats returns connection pool statistics.
func (m *Monitor) GetConnectionPoolStats(database string) (*ConnectionPoolStats, error) {
	var pool *pgxpool.Pool
	switch database {
	case "auth":
		pool = m.authPool
	case "ops":
		pool = m.opsPool
	default:
		pool = m.authPool
	}

	stats := pool.Stat()

	return &ConnectionPoolStats{
		Database:          database,
		TotalConnections:  int(stats.TotalConns()),
		ActiveConnections: int(stats.AcquiredConns()),
		IdleConnections:   int(stats.IdleConns()),
		WaitCount:         0, // Not directly available in pgxpool
		WaitDuration:      0,
	}, nil
}

func (m *Monitor) checkHealth(ctx context.Context) {
	authHealth := m.checkDatabaseHealth(ctx, "auth", m.authPool)
	opsHealth := m.checkDatabaseHealth(ctx, "ops", m.opsPool)

	m.mu.Lock()
	m.authHealth = authHealth
	m.opsHealth = opsHealth
	m.mu.Unlock()
}

func (m *Monitor) checkDatabaseHealth(ctx context.Context, name string, pool *pgxpool.Pool) *DatabaseHealth {
	health := &DatabaseHealth{
		Database:  name,
		CheckedAt: time.Now(),
		Issues:    []HealthIssue{},
	}

	// Check connection
	if err := pool.Ping(ctx); err != nil {
		health.Healthy = false
		health.Status = "unreachable"
		health.Issues = append(health.Issues, HealthIssue{
			Severity:       "critical",
			Message:        "Database is unreachable",
			Recommendation: "Check database server status and network connectivity",
		})
		return health
	}

	health.Healthy = true
	health.Status = "healthy"

	// Get connection stats from pool
	stats := pool.Stat()
	health.ActiveConnections = int(stats.AcquiredConns())
	health.IdleConnections = int(stats.IdleConns())
	health.MaxConnections = int(stats.MaxConns())

	// Check connection usage
	connUsage := float64(health.ActiveConnections) / float64(health.MaxConnections)
	if connUsage > 0.9 {
		health.Issues = append(health.Issues, HealthIssue{
			Severity:       "critical",
			Message:        "Connection pool usage above 90%",
			Recommendation: "Consider increasing max_connections or optimizing queries",
		})
	} else if connUsage > 0.7 {
		health.Issues = append(health.Issues, HealthIssue{
			Severity:       "warning",
			Message:        "Connection pool usage above 70%",
			Recommendation: "Monitor connection usage and consider scaling",
		})
	}

	// Get database-level metrics
	m.fetchDatabaseMetrics(ctx, pool, health)

	// Update health status based on issues
	for _, issue := range health.Issues {
		if issue.Severity == "critical" {
			health.Healthy = false
			health.Status = "degraded"
			break
		}
	}

	return health
}

func (m *Monitor) fetchDatabaseMetrics(ctx context.Context, pool *pgxpool.Pool, health *DatabaseHealth) {
	// Get database size
	var size int64
	if err := pool.QueryRow(ctx, "SELECT pg_database_size(current_database())").Scan(&size); err == nil {
		health.DatabaseSizeBytes = size
	}

	// Get cache hit ratio
	var cacheHit float64
	query := `
		SELECT
			CASE WHEN sum(blks_hit) + sum(blks_read) = 0 THEN 0
			ELSE sum(blks_hit)::float / (sum(blks_hit) + sum(blks_read))
			END
		FROM pg_stat_database
		WHERE datname = current_database()
	`
	if err := pool.QueryRow(ctx, query).Scan(&cacheHit); err == nil {
		health.CacheHitRatio = cacheHit
		if cacheHit < 0.9 {
			health.Issues = append(health.Issues, HealthIssue{
				Severity:       "warning",
				Message:        "Cache hit ratio below 90%",
				Recommendation: "Consider increasing shared_buffers",
			})
		}
	}

	// Get index hit ratio
	var indexHit float64
	indexQuery := `
		SELECT
			CASE WHEN sum(idx_blks_hit) + sum(idx_blks_read) = 0 THEN 0
			ELSE sum(idx_blks_hit)::float / (sum(idx_blks_hit) + sum(idx_blks_read))
			END
		FROM pg_statio_user_indexes
	`
	if err := pool.QueryRow(ctx, indexQuery).Scan(&indexHit); err == nil {
		health.IndexHitRatio = indexHit
	}

	// Get deadlock count
	var deadlocks int64
	if err := pool.QueryRow(ctx, "SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()").Scan(&deadlocks); err == nil {
		health.Deadlocks = deadlocks
	}

	// Get long-running queries count (> 1 minute)
	var longQueries int
	longQuery := `
		SELECT COUNT(*)
		FROM pg_stat_activity
		WHERE state = 'active'
		AND query NOT LIKE 'COPY%'
		AND NOW() - query_start > interval '1 minute'
		AND datname = current_database()
	`
	if err := pool.QueryRow(ctx, longQuery).Scan(&longQueries); err == nil {
		health.LongRunningQueries = longQueries
		if longQueries > 0 {
			health.Issues = append(health.Issues, HealthIssue{
				Severity:       "warning",
				Message:        "Long-running queries detected",
				Recommendation: "Review and optimize slow queries",
			})
		}
	}
}
