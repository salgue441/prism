#!/bin/bash
# =============================================================================
# Prism Database Backup Script
# =============================================================================
# Usage: ./backup.sh [auth|ops|all] [full|delta|wal]
# =============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/prism/backup"
BACKUP_DIR="/var/lib/prism/backups"
DATE=$(date +%Y-%m-%d_%H-%M-%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Create directories
mkdir -p "$LOG_DIR" "$BACKUP_DIR"

# Default values
DATABASE="${1:-all}"
BACKUP_TYPE="${2:-full}"

# Load environment variables
if [ -f "$SCRIPT_DIR/wal-g.env" ]; then
    source "$SCRIPT_DIR/wal-g.env"
fi

# Backup function for a single database
backup_database() {
    local db_name=$1
    local backup_type=$2
    local db_host="${3:-localhost}"
    local db_port="${4:-5432}"
    local db_user="${5:-prism}"

    log_info "Starting $backup_type backup for database: $db_name"

    local backup_file="$BACKUP_DIR/$db_name/${DATE}_${backup_type}.sql.gz"
    mkdir -p "$BACKUP_DIR/$db_name"

    case $backup_type in
        full)
            # Full logical backup using pg_dump
            log_info "Creating full backup with pg_dump..."
            PGPASSWORD="$PGPASSWORD" pg_dump \
                -h "$db_host" \
                -p "$db_port" \
                -U "$db_user" \
                -d "$db_name" \
                -F custom \
                -Z 6 \
                -f "$backup_file" \
                --verbose 2>&1 | tee -a "$LOG_DIR/backup_${db_name}_${DATE}.log"
            ;;

        delta)
            # Delta backup using WAL-G (if available)
            if command -v wal-g &> /dev/null; then
                log_info "Creating delta backup with WAL-G..."
                wal-g backup-push "$PGDATA" --delta-from-name LATEST 2>&1 | \
                    tee -a "$LOG_DIR/backup_${db_name}_${DATE}.log"
            else
                log_warn "WAL-G not found, falling back to full backup"
                backup_database "$db_name" "full" "$db_host" "$db_port" "$db_user"
                return
            fi
            ;;

        wal)
            # WAL archiving
            if command -v wal-g &> /dev/null; then
                log_info "Archiving WAL files..."
                wal-g wal-push "$1" 2>&1 | \
                    tee -a "$LOG_DIR/wal_${db_name}_${DATE}.log"
            else
                log_error "WAL-G not found, cannot archive WAL"
                exit 1
            fi
            ;;

        *)
            log_error "Unknown backup type: $backup_type"
            exit 1
            ;;
    esac

    if [ -f "$backup_file" ]; then
        local size=$(du -h "$backup_file" | cut -f1)
        log_info "Backup completed: $backup_file ($size)"
    fi
}

# Verify backup function
verify_backup() {
    local backup_file=$1

    log_info "Verifying backup: $backup_file"

    if [ ! -f "$backup_file" ]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi

    # Test pg_dump file integrity
    if pg_restore --list "$backup_file" > /dev/null 2>&1; then
        log_info "Backup verification passed"
        return 0
    else
        log_error "Backup verification failed"
        return 1
    fi
}

# Cleanup old backups
cleanup_old_backups() {
    local db_name=$1
    local retention_days=${2:-30}

    log_info "Cleaning up backups older than $retention_days days for $db_name"

    find "$BACKUP_DIR/$db_name" -type f -name "*.sql.gz" -mtime +$retention_days -delete

    # Also cleanup WAL-G if available
    if command -v wal-g &> /dev/null; then
        log_info "Cleaning up WAL-G backups..."
        wal-g delete retain FULL "$WALG_RETENTION_FULL_BACKUP_COUNT" --confirm 2>&1 | \
            tee -a "$LOG_DIR/cleanup_${DATE}.log"
    fi
}

# Upload to S3/MinIO
upload_to_s3() {
    local backup_file=$1
    local s3_path=$2

    if command -v aws &> /dev/null; then
        log_info "Uploading to S3: $s3_path"
        aws s3 cp "$backup_file" "$s3_path" \
            --endpoint-url "${AWS_ENDPOINT:-}" \
            2>&1 | tee -a "$LOG_DIR/upload_${DATE}.log"
    elif command -v mc &> /dev/null; then
        log_info "Uploading to MinIO: $s3_path"
        mc cp "$backup_file" "$s3_path" 2>&1 | tee -a "$LOG_DIR/upload_${DATE}.log"
    else
        log_warn "No S3 client found, skipping upload"
    fi
}

# Main execution
main() {
    log_info "=== Prism Backup Script Started ==="
    log_info "Database: $DATABASE, Type: $BACKUP_TYPE"

    case $DATABASE in
        auth)
            backup_database "prism_auth" "$BACKUP_TYPE" "${PGHOST:-localhost}" "${PGPORT:-5432}" "${PGUSER:-prism}"
            ;;
        ops)
            backup_database "prism_ops" "$BACKUP_TYPE" "${PGHOST:-localhost}" "${PGPORT_OPS:-5433}" "${PGUSER:-prism}"
            ;;
        all)
            backup_database "prism_auth" "$BACKUP_TYPE" "${PGHOST:-localhost}" "${PGPORT:-5432}" "${PGUSER:-prism}"
            backup_database "prism_ops" "$BACKUP_TYPE" "${PGHOST:-localhost}" "${PGPORT_OPS:-5433}" "${PGUSER:-prism}"
            ;;
        *)
            log_error "Unknown database: $DATABASE"
            echo "Usage: $0 [auth|ops|all] [full|delta|wal]"
            exit 1
            ;;
    esac

    log_info "=== Backup Script Completed ==="
}

# Run main
main "$@"
