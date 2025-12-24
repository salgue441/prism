// Package server provides the gRPC server implementation for DB Manager.
package server

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/carlossalguero/prism/services/dbmanager/internal/backup"
	"github.com/carlossalguero/prism/services/dbmanager/internal/health"
	"github.com/carlossalguero/prism/services/dbmanager/internal/migration"
	pb "github.com/carlossalguero/prism/services/shared/proto/gen"
)

// DBManagerServer implements the DBManagerService gRPC service.
type DBManagerServer struct {
	pb.UnimplementedDBManagerServiceServer
	migrationRunner *migration.Runner
	backupManager   *backup.Manager
	healthMonitor   *health.Monitor
}

// NewDBManagerServer creates a new DB Manager server.
func NewDBManagerServer(
	migrationRunner *migration.Runner,
	backupManager *backup.Manager,
	healthMonitor *health.Monitor,
) *DBManagerServer {
	return &DBManagerServer{
		migrationRunner: migrationRunner,
		backupManager:   backupManager,
		healthMonitor:   healthMonitor,
	}
}

// RegisterDBManagerServer registers the server with a gRPC server.
func RegisterDBManagerServer(s *grpc.Server, srv *DBManagerServer) {
	pb.RegisterDBManagerServiceServer(s, srv)
}

// =============================================================================
// Migration Operations
// =============================================================================

// GetMigrationStatus returns the migration status for a database.
func (s *DBManagerServer) GetMigrationStatus(ctx context.Context, req *pb.GetMigrationStatusRequest) (*pb.MigrationStatusResponse, error) {
	if req.Database == "" {
		return nil, status.Error(codes.InvalidArgument, "database is required")
	}

	migrationStatus, err := s.migrationRunner.GetStatus(ctx, req.Database)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get migration status: %v", err)
	}

	resp := &pb.MigrationStatusResponse{
		Database:       migrationStatus.Database,
		CurrentVersion: migrationStatus.CurrentVersion,
		IsDirty:        migrationStatus.IsDirty,
	}

	for _, m := range migrationStatus.Applied {
		resp.AppliedMigrations = append(resp.AppliedMigrations, &pb.MigrationInfo{
			Version:         m.Version,
			Name:            m.Name,
			AppliedAt:       timestamppb.New(m.AppliedAt),
			Checksum:        m.Checksum,
			ExecutionTimeMs: m.ExecutionTime.Milliseconds(),
		})
	}

	for _, m := range migrationStatus.Pending {
		resp.PendingMigrations = append(resp.PendingMigrations, &pb.MigrationInfo{
			Version:  m.Version,
			Name:     m.Name,
			Checksum: m.Checksum,
		})
	}

	return resp, nil
}

// RunMigrations runs pending migrations.
func (s *DBManagerServer) RunMigrations(ctx context.Context, req *pb.RunMigrationsRequest) (*pb.MigrationResult, error) {
	if req.Database == "" {
		return nil, status.Error(codes.InvalidArgument, "database is required")
	}

	if req.DryRun {
		// Just get pending migrations
		migrationStatus, err := s.migrationRunner.GetStatus(ctx, req.Database)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to get migration status: %v", err)
		}

		result := &pb.MigrationResult{
			Success: true,
			Message: "Dry run - no changes made",
		}

		for _, m := range migrationStatus.Pending {
			result.Applied = append(result.Applied, &pb.MigrationInfo{
				Version: m.Version,
				Name:    m.Name,
			})
		}

		return result, nil
	}

	if err := s.migrationRunner.Run(ctx, req.Database, int(req.Steps)); err != nil {
		return &pb.MigrationResult{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.MigrationResult{
		Success: true,
		Message: "Migrations applied successfully",
	}, nil
}

// RollbackMigration rolls back migrations.
func (s *DBManagerServer) RollbackMigration(ctx context.Context, req *pb.RollbackMigrationRequest) (*pb.MigrationResult, error) {
	if req.Database == "" {
		return nil, status.Error(codes.InvalidArgument, "database is required")
	}

	if err := s.migrationRunner.Rollback(ctx, req.Database, int(req.Steps)); err != nil {
		return &pb.MigrationResult{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.MigrationResult{
		Success: true,
		Message: "Rollback completed successfully",
	}, nil
}

// =============================================================================
// Backup Operations
// =============================================================================

// CreateBackup creates a new backup.
func (s *DBManagerServer) CreateBackup(ctx context.Context, req *pb.CreateBackupRequest) (*pb.BackupResult, error) {
	if req.Database == "" {
		return nil, status.Error(codes.InvalidArgument, "database is required")
	}

	backupType := backup.TypeLogical
	switch req.Type {
	case pb.BackupType_BACKUP_TYPE_FULL:
		backupType = backup.TypeFull
	case pb.BackupType_BACKUP_TYPE_INCREMENTAL:
		backupType = backup.TypeIncremental
	case pb.BackupType_BACKUP_TYPE_LOGICAL:
		backupType = backup.TypeLogical
	}

	info, err := s.backupManager.CreateBackup(ctx, req.Database, backupType, req.Description)
	if err != nil {
		return &pb.BackupResult{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.BackupResult{
		Success:         true,
		BackupId:        info.ID,
		Location:        info.Location,
		SizeBytes:       info.SizeBytes,
		DurationSeconds: int32(info.CompletedAt.Sub(info.CreatedAt).Seconds()),
		CreatedAt:       timestamppb.New(info.CreatedAt),
	}, nil
}

// ListBackups returns a list of backups.
func (s *DBManagerServer) ListBackups(ctx context.Context, req *pb.ListBackupsRequest) (*pb.BackupListResponse, error) {
	limit := int(req.Limit)
	if limit <= 0 {
		limit = 20
	}

	backups, total, err := s.backupManager.ListBackups(ctx, req.Database, limit, int(req.Offset))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list backups: %v", err)
	}

	resp := &pb.BackupListResponse{
		Total: int32(total),
	}

	for _, b := range backups {
		info := &pb.BackupInfo{
			Id:          b.ID,
			Database:    b.Database,
			Type:        convertBackupType(b.Type),
			Location:    b.Location,
			SizeBytes:   b.SizeBytes,
			CreatedAt:   timestamppb.New(b.CreatedAt),
			CompletedAt: timestamppb.New(b.CompletedAt),
			Status:      convertBackupStatus(b.Status),
			Verified:    b.Verified,
			Description: b.Description,
		}
		if !b.VerifiedAt.IsZero() {
			info.VerifiedAt = timestamppb.New(b.VerifiedAt)
		}
		resp.Backups = append(resp.Backups, info)
	}

	return resp, nil
}

// RestoreBackup restores a backup.
func (s *DBManagerServer) RestoreBackup(_ context.Context, req *pb.RestoreBackupRequest) (*pb.RestoreResult, error) {
	if req.BackupId == "" {
		return nil, status.Error(codes.InvalidArgument, "backup_id is required")
	}

	// TODO: Implement restore functionality
	return &pb.RestoreResult{
		Success: false,
		Error:   "restore not yet implemented",
	}, nil
}

// VerifyBackup verifies a backup's integrity.
func (s *DBManagerServer) VerifyBackup(ctx context.Context, req *pb.VerifyBackupRequest) (*pb.VerifyBackupResult, error) {
	if req.BackupId == "" {
		return nil, status.Error(codes.InvalidArgument, "backup_id is required")
	}

	valid, message, err := s.backupManager.VerifyBackup(ctx, req.BackupId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to verify backup: %v", err)
	}

	return &pb.VerifyBackupResult{
		Valid:   valid,
		Message: message,
	}, nil
}

// DeleteBackup deletes a backup.
func (s *DBManagerServer) DeleteBackup(ctx context.Context, req *pb.DeleteBackupRequest) (*emptypb.Empty, error) {
	if req.BackupId == "" {
		return nil, status.Error(codes.InvalidArgument, "backup_id is required")
	}

	if err := s.backupManager.DeleteBackup(ctx, req.BackupId); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete backup: %v", err)
	}

	return &emptypb.Empty{}, nil
}

// =============================================================================
// Health Monitoring
// =============================================================================

// GetDatabaseHealth returns database health information.
func (s *DBManagerServer) GetDatabaseHealth(_ context.Context, req *pb.GetDatabaseHealthRequest) (*pb.DatabaseHealthResponse, error) {
	healthData := s.healthMonitor.GetHealth(req.Database)

	resp := &pb.DatabaseHealthResponse{}

	for _, h := range healthData {
		dbHealth := &pb.DatabaseHealth{
			Database:              h.Database,
			Healthy:               h.Healthy,
			Status:                h.Status,
			ActiveConnections:     int32(h.ActiveConnections),
			IdleConnections:       int32(h.IdleConnections),
			MaxConnections:        int32(h.MaxConnections),
			CacheHitRatio:         h.CacheHitRatio,
			IndexHitRatio:         h.IndexHitRatio,
			DatabaseSizeBytes:     h.DatabaseSizeBytes,
			Deadlocks:             h.Deadlocks,
			LongRunningQueries:    int32(h.LongRunningQueries),
			BloatRatio:            h.BloatRatio,
			ReplicationLagSeconds: h.ReplicationLagSecs,
			CheckedAt:             timestamppb.New(h.CheckedAt),
		}

		for _, issue := range h.Issues {
			dbHealth.Issues = append(dbHealth.Issues, &pb.HealthIssue{
				Severity:       issue.Severity,
				Message:        issue.Message,
				Recommendation: issue.Recommendation,
			})
		}

		resp.Databases = append(resp.Databases, dbHealth)
	}

	return resp, nil
}

// GetConnectionPoolStats returns connection pool statistics.
func (s *DBManagerServer) GetConnectionPoolStats(_ context.Context, req *pb.GetConnectionPoolStatsRequest) (*pb.ConnectionPoolStatsResponse, error) {
	stats, err := s.healthMonitor.GetConnectionPoolStats(req.Database)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get pool stats: %v", err)
	}

	return &pb.ConnectionPoolStatsResponse{
		Database:          stats.Database,
		TotalConnections:  int32(stats.TotalConnections),
		ActiveConnections: int32(stats.ActiveConnections),
		IdleConnections:   int32(stats.IdleConnections),
		WaitCount:         int32(stats.WaitCount),
		WaitDurationMs:    stats.WaitDuration.Milliseconds(),
		MaxIdleClosed:     int32(stats.MaxIdleClosed),
		MaxLifetimeClosed: int32(stats.MaxLifetimeClosed),
	}, nil
}

// Helper functions

func convertBackupType(t backup.BackupType) pb.BackupType {
	switch t {
	case backup.TypeFull:
		return pb.BackupType_BACKUP_TYPE_FULL
	case backup.TypeIncremental:
		return pb.BackupType_BACKUP_TYPE_INCREMENTAL
	case backup.TypeLogical:
		return pb.BackupType_BACKUP_TYPE_LOGICAL
	default:
		return pb.BackupType_BACKUP_TYPE_UNSPECIFIED
	}
}

func convertBackupStatus(s backup.Status) pb.BackupStatus {
	switch s {
	case backup.StatusRunning:
		return pb.BackupStatus_BACKUP_STATUS_RUNNING
	case backup.StatusCompleted:
		return pb.BackupStatus_BACKUP_STATUS_COMPLETED
	case backup.StatusFailed:
		return pb.BackupStatus_BACKUP_STATUS_FAILED
	default:
		return pb.BackupStatus_BACKUP_STATUS_UNSPECIFIED
	}
}
