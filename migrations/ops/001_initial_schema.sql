-- Prism Operational Database - Initial Schema
-- Migration: 001_initial_schema

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gist";

-- =============================================================================
-- Audit Logs table
-- =============================================================================
-- Stores all significant system events for compliance and debugging
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    service VARCHAR(50) NOT NULL,  -- gateway, auth, config, dbmanager
    action VARCHAR(100) NOT NULL,  -- user.login, token.revoked, config.updated
    actor_id UUID,  -- User ID if applicable
    actor_type VARCHAR(50) NOT NULL DEFAULT 'user',  -- user, system, api_key
    resource_type VARCHAR(100),  -- user, session, api_key, route
    resource_id VARCHAR(255),  -- ID of the affected resource
    ip_address INET,
    user_agent VARCHAR(500),
    request_id UUID,
    trace_id VARCHAR(64),  -- OpenTelemetry trace ID
    details JSONB,  -- Additional event-specific data
    status VARCHAR(20) NOT NULL DEFAULT 'success',  -- success, failure, error
    error_message TEXT
);

-- Partition by month for performance (can be implemented later)
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_service ON audit_logs(service, timestamp DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action, timestamp DESC);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_id, timestamp DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id, timestamp DESC);
CREATE INDEX idx_audit_logs_request_id ON audit_logs(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX idx_audit_logs_trace_id ON audit_logs(trace_id) WHERE trace_id IS NOT NULL;

-- =============================================================================
-- System Events table
-- =============================================================================
-- For async event processing (events published to NATS are also logged here)
CREATE TABLE system_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,  -- user.created, token.revoked, route.updated
    source_service VARCHAR(50) NOT NULL,
    payload JSONB NOT NULL,
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    processed_at TIMESTAMPTZ,
    retry_count INT NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_system_events_type ON system_events(event_type, timestamp DESC);
CREATE INDEX idx_system_events_unprocessed ON system_events(processed, timestamp) WHERE processed = FALSE;
CREATE INDEX idx_system_events_source ON system_events(source_service, timestamp DESC);

-- =============================================================================
-- Metrics Snapshots table
-- =============================================================================
-- Periodic snapshots of key metrics for historical analysis
CREATE TABLE metrics_snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    service VARCHAR(50) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_type VARCHAR(20) NOT NULL,  -- counter, gauge, histogram
    value DOUBLE PRECISION NOT NULL,
    labels JSONB,  -- Additional metric labels

    CONSTRAINT unique_metric_snapshot UNIQUE (timestamp, service, metric_name, labels)
);

CREATE INDEX idx_metrics_snapshots_time ON metrics_snapshots(timestamp DESC);
CREATE INDEX idx_metrics_snapshots_service ON metrics_snapshots(service, metric_name, timestamp DESC);

-- =============================================================================
-- Backup History table
-- =============================================================================
-- Track all backup operations
CREATE TABLE backup_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    database_name VARCHAR(100) NOT NULL,
    backup_type VARCHAR(20) NOT NULL,  -- full, incremental, wal
    storage_location VARCHAR(500) NOT NULL,  -- s3://bucket/path or local path
    size_bytes BIGINT,
    duration_seconds INT,
    status VARCHAR(20) NOT NULL DEFAULT 'running',  -- running, success, failed
    error_message TEXT,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    retention_days INT NOT NULL DEFAULT 30,
    metadata JSONB  -- Additional backup metadata
);

CREATE INDEX idx_backup_history_db ON backup_history(database_name, started_at DESC);
CREATE INDEX idx_backup_history_status ON backup_history(status, started_at DESC);
CREATE INDEX idx_backup_history_type ON backup_history(backup_type, started_at DESC);

-- =============================================================================
-- Database Health Snapshots table
-- =============================================================================
-- Periodic database health checks
CREATE TABLE db_health_snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    database_name VARCHAR(100) NOT NULL,
    connection_count INT NOT NULL,
    active_connections INT NOT NULL,
    idle_connections INT NOT NULL,
    max_connections INT NOT NULL,
    database_size_bytes BIGINT,
    cache_hit_ratio DOUBLE PRECISION,
    index_hit_ratio DOUBLE PRECISION,
    deadlocks BIGINT,
    temp_files_created BIGINT,
    temp_bytes_written BIGINT,
    long_running_queries INT,
    bloat_ratio DOUBLE PRECISION,
    replication_lag_seconds DOUBLE PRECISION,
    details JSONB
);

CREATE INDEX idx_db_health_db ON db_health_snapshots(database_name, timestamp DESC);

-- =============================================================================
-- Migration History table (for DB Manager service)
-- =============================================================================
CREATE TABLE migration_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    database_name VARCHAR(100) NOT NULL,
    version VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    checksum VARCHAR(64),  -- SHA256 of migration file
    execution_time_ms INT,
    status VARCHAR(20) NOT NULL DEFAULT 'applied',  -- applied, rolled_back
    rolled_back_at TIMESTAMPTZ,

    CONSTRAINT unique_migration UNIQUE (database_name, version)
);

CREATE INDEX idx_migration_history_db ON migration_history(database_name, applied_at DESC);

-- =============================================================================
-- Cleanup function for old data
-- =============================================================================
CREATE OR REPLACE FUNCTION cleanup_old_operational_data()
RETURNS void AS $$
BEGIN
    -- Clean up audit logs older than 90 days
    DELETE FROM audit_logs
    WHERE timestamp < NOW() - INTERVAL '90 days';

    -- Clean up processed events older than 7 days
    DELETE FROM system_events
    WHERE processed = TRUE AND timestamp < NOW() - INTERVAL '7 days';

    -- Clean up metrics snapshots older than 30 days
    DELETE FROM metrics_snapshots
    WHERE timestamp < NOW() - INTERVAL '30 days';

    -- Clean up db health snapshots older than 7 days
    DELETE FROM db_health_snapshots
    WHERE timestamp < NOW() - INTERVAL '7 days';
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Down migration
-- =============================================================================
-- To rollback this migration, run:
-- DROP TABLE IF EXISTS migration_history;
-- DROP TABLE IF EXISTS db_health_snapshots;
-- DROP TABLE IF EXISTS backup_history;
-- DROP TABLE IF EXISTS metrics_snapshots;
-- DROP TABLE IF EXISTS system_events;
-- DROP TABLE IF EXISTS audit_logs;
-- DROP FUNCTION IF EXISTS cleanup_old_operational_data();
