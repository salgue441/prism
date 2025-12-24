#!/bin/bash
# =============================================================================
# Prism Database Restore Script
# =============================================================================
# Usage: ./restore.sh <backup_file> <target_database> [--dry-run]
# =============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/prism/backup"
DATE=$(date +%Y-%m-%d_%H-%M-%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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

# Parse arguments
BACKUP_FILE="${1:-}"
TARGET_DB="${2:-}"
DRY_RUN=false

for arg in "$@"; do
    case $arg in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
    esac
done

# Validate arguments
if [ -z "$BACKUP_FILE" ] || [ -z "$TARGET_DB" ]; then
    echo "Usage: $0 <backup_file> <target_database> [--dry-run]"
    echo ""
    echo "Arguments:"
    echo "  backup_file     Path to the backup file (.sql.gz or .dump)"
    echo "  target_database Name of the target database"
    echo "  --dry-run       Show what would be done without executing"
    exit 1
fi

# Load environment variables
if [ -f "$SCRIPT_DIR/wal-g.env" ]; then
    source "$SCRIPT_DIR/wal-g.env"
fi

# Verify backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    log_error "Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Create log directory
mkdir -p "$LOG_DIR"

# Restore function
restore_database() {
    local backup_file=$1
    local target_db=$2
    local db_host="${PGHOST:-localhost}"
    local db_port="${PGPORT:-5432}"
    local db_user="${PGUSER:-prism}"

    log_info "=== Starting Database Restore ==="
    log_info "Backup file: $backup_file"
    log_info "Target database: $target_db"
    log_info "Host: $db_host:$db_port"

    if [ "$DRY_RUN" = true ]; then
        log_warn "DRY RUN MODE - No changes will be made"

        # Show backup contents
        log_info "Backup contents:"
        pg_restore --list "$backup_file" | head -50

        log_info "Would execute:"
        echo "  1. Drop existing connections to $target_db"
        echo "  2. Drop and recreate database $target_db"
        echo "  3. Restore from $backup_file"
        echo "  4. Verify restoration"

        return 0
    fi

    # Confirm before proceeding
    echo ""
    log_warn "WARNING: This will DROP and recreate the database '$target_db'"
    read -p "Are you sure you want to continue? (yes/no): " confirm

    if [ "$confirm" != "yes" ]; then
        log_info "Restore cancelled by user"
        exit 0
    fi

    # Terminate existing connections
    log_info "Terminating existing connections..."
    PGPASSWORD="$PGPASSWORD" psql -h "$db_host" -p "$db_port" -U "$db_user" -d postgres <<EOF
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = '$target_db' AND pid <> pg_backend_pid();
EOF

    # Drop and recreate database
    log_info "Dropping and recreating database..."
    PGPASSWORD="$PGPASSWORD" psql -h "$db_host" -p "$db_port" -U "$db_user" -d postgres <<EOF
DROP DATABASE IF EXISTS $target_db;
CREATE DATABASE $target_db OWNER $db_user;
EOF

    # Restore from backup
    log_info "Restoring from backup..."
    PGPASSWORD="$PGPASSWORD" pg_restore \
        -h "$db_host" \
        -p "$db_port" \
        -U "$db_user" \
        -d "$target_db" \
        --verbose \
        --no-owner \
        --no-privileges \
        "$backup_file" 2>&1 | tee "$LOG_DIR/restore_${target_db}_${DATE}.log"

    # Verify restoration
    log_info "Verifying restoration..."
    local table_count=$(PGPASSWORD="$PGPASSWORD" psql -h "$db_host" -p "$db_port" -U "$db_user" -d "$target_db" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';")

    log_info "Restore completed. Tables found: $table_count"

    # Run ANALYZE to update statistics
    log_info "Running ANALYZE..."
    PGPASSWORD="$PGPASSWORD" psql -h "$db_host" -p "$db_port" -U "$db_user" -d "$target_db" -c "ANALYZE;"

    log_info "=== Restore Completed Successfully ==="
}

# WAL-G restore (for point-in-time recovery)
restore_with_walg() {
    local target_time=$1
    local target_db=$2

    if ! command -v wal-g &> /dev/null; then
        log_error "WAL-G not found"
        exit 1
    fi

    log_info "Starting WAL-G point-in-time recovery..."
    log_info "Target time: $target_time"

    if [ "$DRY_RUN" = true ]; then
        log_warn "DRY RUN - Would restore to: $target_time"
        wal-g backup-list
        return 0
    fi

    # Stop PostgreSQL
    log_info "Stopping PostgreSQL..."
    pg_ctl stop -D "$PGDATA" -m fast

    # Clear data directory
    log_info "Clearing data directory..."
    rm -rf "$PGDATA"/*

    # Restore base backup
    log_info "Restoring base backup..."
    wal-g backup-fetch "$PGDATA" LATEST

    # Configure recovery
    log_info "Configuring recovery..."
    cat > "$PGDATA/recovery.signal" <<EOF
# Point-in-time recovery
EOF

    cat >> "$PGDATA/postgresql.auto.conf" <<EOF
restore_command = 'wal-g wal-fetch %f %p'
recovery_target_time = '$target_time'
recovery_target_action = 'promote'
EOF

    # Start PostgreSQL
    log_info "Starting PostgreSQL..."
    pg_ctl start -D "$PGDATA"

    log_info "Recovery initiated. Check PostgreSQL logs for progress."
}

# Main execution
main() {
    restore_database "$BACKUP_FILE" "$TARGET_DB"
}

main "$@"
