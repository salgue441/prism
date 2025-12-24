// Package migration provides database migration management.
package migration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config holds migration runner configuration.
type Config struct {
	AuthMigrationsPath string
	OpsMigrationsPath  string
}

// Runner handles database migrations.
type Runner struct {
	config   Config
	authPool *pgxpool.Pool
	opsPool  *pgxpool.Pool
}

// MigrationInfo contains information about a migration.
type MigrationInfo struct {
	Version       string
	Name          string
	AppliedAt     time.Time
	Checksum      string
	ExecutionTime time.Duration
	Status        string
}

// Result contains the result of a migration operation.
type Result struct {
	Success bool
	Message string
	Applied []MigrationInfo
	Error   error
}

// NewRunner creates a new migration runner.
func NewRunner(cfg Config, authPool, opsPool *pgxpool.Pool) *Runner {
	return &Runner{
		config:   cfg,
		authPool: authPool,
		opsPool:  opsPool,
	}
}

// RunAll runs all pending migrations for both databases.
func (r *Runner) RunAll(ctx context.Context) error {
	if err := r.Run(ctx, "auth", 0); err != nil {
		return fmt.Errorf("auth migrations failed: %w", err)
	}
	if err := r.Run(ctx, "ops", 0); err != nil {
		return fmt.Errorf("ops migrations failed: %w", err)
	}
	return nil
}

// Run runs migrations for a specific database.
func (r *Runner) Run(ctx context.Context, database string, steps int) error {
	pool, migrationsPath, err := r.getPoolAndPath(database)
	if err != nil {
		return err
	}

	// Ensure migrations table exists
	if err := r.ensureMigrationsTable(ctx, pool); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get pending migrations
	pending, err := r.getPendingMigrations(ctx, pool, migrationsPath)
	if err != nil {
		return fmt.Errorf("failed to get pending migrations: %w", err)
	}

	if len(pending) == 0 {
		return nil // No pending migrations
	}

	// Apply limit if specified
	if steps > 0 && steps < len(pending) {
		pending = pending[:steps]
	}

	// Run each migration
	for _, m := range pending {
		if err := r.applyMigration(ctx, pool, m); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", m.Version, err)
		}
	}

	return nil
}

// Rollback rolls back migrations for a specific database.
func (r *Runner) Rollback(ctx context.Context, database string, steps int) error {
	pool, _, err := r.getPoolAndPath(database)
	if err != nil {
		return err
	}

	// Get applied migrations in reverse order
	applied, err := r.getAppliedMigrations(ctx, pool)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	if len(applied) == 0 {
		return nil // No migrations to rollback
	}

	// Apply limit
	if steps > 0 && steps < len(applied) {
		applied = applied[:steps]
	}

	// Rollback each migration
	for _, m := range applied {
		if err := r.rollbackMigration(ctx, pool, m); err != nil {
			return fmt.Errorf("failed to rollback migration %s: %w", m.Version, err)
		}
	}

	return nil
}

// GetStatus returns the migration status for a database.
func (r *Runner) GetStatus(ctx context.Context, database string) (*Status, error) {
	pool, migrationsPath, err := r.getPoolAndPath(database)
	if err != nil {
		return nil, err
	}

	// Ensure migrations table exists
	if err := r.ensureMigrationsTable(ctx, pool); err != nil {
		return nil, fmt.Errorf("failed to create migrations table: %w", err)
	}

	applied, err := r.getAppliedMigrations(ctx, pool)
	if err != nil {
		return nil, fmt.Errorf("failed to get applied migrations: %w", err)
	}

	pending, err := r.getPendingMigrations(ctx, pool, migrationsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending migrations: %w", err)
	}

	var currentVersion string
	if len(applied) > 0 {
		currentVersion = applied[0].Version
	}

	return &Status{
		Database:       database,
		CurrentVersion: currentVersion,
		Applied:        applied,
		Pending:        pending,
		IsDirty:        false,
	}, nil
}

// Status represents the migration status.
type Status struct {
	Database       string
	CurrentVersion string
	Applied        []MigrationInfo
	Pending        []MigrationInfo
	IsDirty        bool
}

func (r *Runner) getPoolAndPath(database string) (*pgxpool.Pool, string, error) {
	switch database {
	case "auth":
		return r.authPool, r.config.AuthMigrationsPath, nil
	case "ops":
		return r.opsPool, r.config.OpsMigrationsPath, nil
	default:
		return nil, "", fmt.Errorf("unknown database: %s", database)
	}
}

func (r *Runner) ensureMigrationsTable(ctx context.Context, pool *pgxpool.Pool) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(50) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			checksum VARCHAR(64),
			execution_time_ms INT
		)
	`
	_, err := pool.Exec(ctx, query)
	return err
}

func (r *Runner) getAppliedMigrations(ctx context.Context, pool *pgxpool.Pool) ([]MigrationInfo, error) {
	query := `
		SELECT version, name, applied_at, COALESCE(checksum, ''), COALESCE(execution_time_ms, 0)
		FROM schema_migrations
		ORDER BY version DESC
	`

	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var migrations []MigrationInfo
	for rows.Next() {
		var m MigrationInfo
		var execTime int
		if err := rows.Scan(&m.Version, &m.Name, &m.AppliedAt, &m.Checksum, &execTime); err != nil {
			return nil, err
		}
		m.ExecutionTime = time.Duration(execTime) * time.Millisecond
		m.Status = "applied"
		migrations = append(migrations, m)
	}

	return migrations, rows.Err()
}

func (r *Runner) getPendingMigrations(ctx context.Context, pool *pgxpool.Pool, path string) ([]MigrationInfo, error) {
	// Check if path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil // No migrations directory
	}

	// Get applied versions
	appliedVersions := make(map[string]bool)
	applied, err := r.getAppliedMigrations(ctx, pool)
	if err != nil {
		return nil, err
	}
	for _, m := range applied {
		appliedVersions[m.Version] = true
	}

	// Read migration files
	var pending []MigrationInfo
	err = filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".sql") {
			return nil
		}

		// Parse filename (format: 001_name.sql)
		name := d.Name()
		parts := strings.SplitN(strings.TrimSuffix(name, ".sql"), "_", 2)
		if len(parts) != 2 {
			return nil // Skip invalid filenames
		}

		version := parts[0]
		migrationName := parts[1]

		if appliedVersions[version] {
			return nil // Already applied
		}

		// Read file and compute checksum
		content, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		checksum := computeChecksum(content)

		pending = append(pending, MigrationInfo{
			Version:  version,
			Name:     migrationName,
			Checksum: checksum,
			Status:   "pending",
		})

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort by version
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].Version < pending[j].Version
	})

	return pending, nil
}

func (r *Runner) applyMigration(ctx context.Context, pool *pgxpool.Pool, m MigrationInfo) error {
	// Read migration file
	var path string
	if pool == r.authPool {
		path = r.config.AuthMigrationsPath
	} else {
		path = r.config.OpsMigrationsPath
	}

	filePath := filepath.Join(path, fmt.Sprintf("%s_%s.sql", m.Version, m.Name))
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read migration file: %w", err)
	}

	// Start transaction
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Execute migration
	start := time.Now()
	if _, err := tx.Exec(ctx, string(content)); err != nil {
		return fmt.Errorf("failed to execute migration: %w", err)
	}
	duration := time.Since(start)

	// Record migration
	query := `
		INSERT INTO schema_migrations (version, name, checksum, execution_time_ms)
		VALUES ($1, $2, $3, $4)
	`
	if _, err := tx.Exec(ctx, query, m.Version, m.Name, m.Checksum, duration.Milliseconds()); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (r *Runner) rollbackMigration(ctx context.Context, pool *pgxpool.Pool, m MigrationInfo) error {
	// For now, we just remove the migration record
	// In a real implementation, you'd have down migrations
	query := `DELETE FROM schema_migrations WHERE version = $1`
	_, err := pool.Exec(ctx, query, m.Version)
	return err
}

func computeChecksum(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}
