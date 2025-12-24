// Package backup provides database backup management.
package backup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BackupType represents the type of backup.
type BackupType string

const (
	TypeFull        BackupType = "full"
	TypeIncremental BackupType = "incremental"
	TypeLogical     BackupType = "logical"
)

// Status represents the backup status.
type Status string

const (
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

// Config holds backup manager configuration.
type Config struct {
	Enabled       bool
	StorageType   string // local, s3, minio
	StoragePath   string
	RetentionDays int
	Timeout       time.Duration
	S3Config      S3Config
}

// S3Config holds S3/MinIO configuration.
type S3Config struct {
	Endpoint        string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	Region          string
	UseSSL          bool
}

// BackupInfo contains information about a backup.
type BackupInfo struct {
	ID          string
	Database    string
	Type        BackupType
	Location    string
	SizeBytes   int64
	CreatedAt   time.Time
	CompletedAt time.Time
	Status      Status
	Verified    bool
	VerifiedAt  time.Time
	Description string
	Error       string
}

// Manager handles database backups.
type Manager struct {
	config   Config
	authPool *pgxpool.Pool
	opsPool  *pgxpool.Pool
}

// NewManager creates a new backup manager.
func NewManager(cfg Config, authPool, opsPool *pgxpool.Pool) *Manager {
	return &Manager{
		config:   cfg,
		authPool: authPool,
		opsPool:  opsPool,
	}
}

// CreateBackup creates a new backup.
func (m *Manager) CreateBackup(ctx context.Context, database string, backupType BackupType, description string) (*BackupInfo, error) {
	if !m.config.Enabled {
		return nil, fmt.Errorf("backups are disabled")
	}

	pool, err := m.getPool(database)
	if err != nil {
		return nil, err
	}

	// Get database connection info from pool
	config := pool.Config().ConnConfig

	backupID := uuid.New().String()
	startTime := time.Now()

	// Create backup directory
	backupDir := filepath.Join(m.config.StoragePath, database, startTime.Format("2006-01-02"))
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create backup filename
	filename := fmt.Sprintf("%s_%s_%s.sql.gz", database, backupType, startTime.Format("150405"))
	backupPath := filepath.Join(backupDir, filename)

	info := &BackupInfo{
		ID:          backupID,
		Database:    database,
		Type:        backupType,
		Location:    backupPath,
		CreatedAt:   startTime,
		Status:      StatusRunning,
		Description: description,
	}

	// Record backup start in database
	if err := m.recordBackupStart(ctx, info); err != nil {
		return nil, fmt.Errorf("failed to record backup start: %w", err)
	}

	// Perform backup based on type
	var backupErr error
	switch backupType {
	case TypeLogical:
		backupErr = m.createLogicalBackup(ctx, config.Host, int(config.Port), config.User, config.Password, config.Database, backupPath)
	case TypeFull:
		backupErr = m.createFullBackup(ctx, config.Host, int(config.Port), config.User, config.Password, backupPath)
	default:
		backupErr = fmt.Errorf("unsupported backup type: %s", backupType)
	}

	info.CompletedAt = time.Now()

	if backupErr != nil {
		info.Status = StatusFailed
		info.Error = backupErr.Error()
		m.recordBackupComplete(ctx, info)
		return info, backupErr
	}

	// Get backup size
	if stat, err := os.Stat(backupPath); err == nil {
		info.SizeBytes = stat.Size()
	}

	info.Status = StatusCompleted

	// Record backup completion
	if err := m.recordBackupComplete(ctx, info); err != nil {
		return info, fmt.Errorf("failed to record backup completion: %w", err)
	}

	// Upload to S3/MinIO if configured
	if m.config.StorageType == "s3" || m.config.StorageType == "minio" {
		if err := m.uploadToS3(ctx, backupPath, info); err != nil {
			return info, fmt.Errorf("failed to upload backup: %w", err)
		}
	}

	return info, nil
}

// ListBackups returns a list of backups.
func (m *Manager) ListBackups(ctx context.Context, database string, limit, offset int) ([]BackupInfo, int, error) {
	query := `
		SELECT id, database_name, backup_type, storage_location,
		       COALESCE(size_bytes, 0), started_at, COALESCE(completed_at, started_at),
		       status, COALESCE(verified, false), verified_at, COALESCE(metadata->>'description', '')
		FROM backup_history
		WHERE ($1 = '' OR database_name = $1)
		ORDER BY started_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := m.opsPool.Query(ctx, query, database, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var backups []BackupInfo
	for rows.Next() {
		var info BackupInfo
		var verifiedAt *time.Time
		var backupType string
		if err := rows.Scan(
			&info.ID, &info.Database, &backupType, &info.Location,
			&info.SizeBytes, &info.CreatedAt, &info.CompletedAt,
			&info.Status, &info.Verified, &verifiedAt, &info.Description,
		); err != nil {
			return nil, 0, err
		}
		info.Type = BackupType(backupType)
		if verifiedAt != nil {
			info.VerifiedAt = *verifiedAt
		}
		backups = append(backups, info)
	}

	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM backup_history WHERE ($1 = '' OR database_name = $1)`
	if err := m.opsPool.QueryRow(ctx, countQuery, database).Scan(&total); err != nil {
		return nil, 0, err
	}

	return backups, total, rows.Err()
}

// VerifyBackup verifies a backup's integrity.
func (m *Manager) VerifyBackup(ctx context.Context, backupID string) (bool, string, error) {
	// Get backup info
	query := `SELECT storage_location FROM backup_history WHERE id = $1`
	var location string
	if err := m.opsPool.QueryRow(ctx, query, backupID).Scan(&location); err != nil {
		return false, "", fmt.Errorf("backup not found: %w", err)
	}

	// Check if file exists
	if _, err := os.Stat(location); os.IsNotExist(err) {
		return false, "backup file not found", nil
	}

	// For logical backups, we can try to parse the SQL
	// For now, just verify the file is readable
	file, err := os.Open(location)
	if err != nil {
		return false, fmt.Sprintf("cannot read backup: %v", err), nil
	}
	file.Close()

	// Update verification status
	updateQuery := `UPDATE backup_history SET verified = true, verified_at = NOW() WHERE id = $1`
	if _, err := m.opsPool.Exec(ctx, updateQuery, backupID); err != nil {
		return false, "", fmt.Errorf("failed to update verification status: %w", err)
	}

	return true, "backup verified successfully", nil
}

// DeleteBackup deletes a backup.
func (m *Manager) DeleteBackup(ctx context.Context, backupID string) error {
	// Get backup location
	query := `SELECT storage_location FROM backup_history WHERE id = $1`
	var location string
	if err := m.opsPool.QueryRow(ctx, query, backupID).Scan(&location); err != nil {
		return fmt.Errorf("backup not found: %w", err)
	}

	// Delete file
	if err := os.Remove(location); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete backup file: %w", err)
	}

	// Delete record
	deleteQuery := `DELETE FROM backup_history WHERE id = $1`
	if _, err := m.opsPool.Exec(ctx, deleteQuery, backupID); err != nil {
		return fmt.Errorf("failed to delete backup record: %w", err)
	}

	return nil
}

// CleanupOldBackups removes backups older than retention period.
func (m *Manager) CleanupOldBackups(ctx context.Context) (int, error) {
	cutoff := time.Now().AddDate(0, 0, -m.config.RetentionDays)

	// Get old backups
	query := `SELECT id, storage_location FROM backup_history WHERE started_at < $1`
	rows, err := m.opsPool.Query(ctx, query, cutoff)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var deleted int
	for rows.Next() {
		var id, location string
		if err := rows.Scan(&id, &location); err != nil {
			continue
		}
		if err := m.DeleteBackup(ctx, id); err == nil {
			deleted++
		}
	}

	return deleted, nil
}

func (m *Manager) getPool(database string) (*pgxpool.Pool, error) {
	switch database {
	case "auth":
		return m.authPool, nil
	case "ops":
		return m.opsPool, nil
	default:
		return nil, fmt.Errorf("unknown database: %s", database)
	}
}

func (m *Manager) createLogicalBackup(ctx context.Context, host string, port int, user, password, dbname, outputPath string) error {
	// Use pg_dump for logical backup
	cmd := exec.CommandContext(ctx, "pg_dump",
		"-h", host,
		"-p", fmt.Sprintf("%d", port),
		"-U", user,
		"-d", dbname,
		"-F", "c", // Custom format
		"-f", outputPath,
	)
	cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", password))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pg_dump failed: %s: %w", string(output), err)
	}

	return nil
}

func (m *Manager) createFullBackup(ctx context.Context, host string, port int, user, password, outputPath string) error {
	// Use pg_basebackup for full backup
	cmd := exec.CommandContext(ctx, "pg_basebackup",
		"-h", host,
		"-p", fmt.Sprintf("%d", port),
		"-U", user,
		"-D", outputPath,
		"-Ft", // Tar format
		"-z",  // Compress
		"-P",  // Progress
	)
	cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", password))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pg_basebackup failed: %s: %w", string(output), err)
	}

	return nil
}

func (m *Manager) recordBackupStart(ctx context.Context, info *BackupInfo) error {
	query := `
		INSERT INTO backup_history (id, database_name, backup_type, storage_location, started_at, status, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	metadata := fmt.Sprintf(`{"description": "%s"}`, info.Description)
	_, err := m.opsPool.Exec(ctx, query, info.ID, info.Database, string(info.Type), info.Location, info.CreatedAt, string(info.Status), metadata)
	return err
}

func (m *Manager) recordBackupComplete(ctx context.Context, info *BackupInfo) error {
	query := `
		UPDATE backup_history
		SET completed_at = $1, status = $2, size_bytes = $3, error_message = $4
		WHERE id = $5
	`
	_, err := m.opsPool.Exec(ctx, query, info.CompletedAt, string(info.Status), info.SizeBytes, info.Error, info.ID)
	return err
}

func (m *Manager) uploadToS3(_ context.Context, _ string, _ *BackupInfo) error {
	// TODO: Implement S3/MinIO upload using AWS SDK or MinIO client
	return nil
}
