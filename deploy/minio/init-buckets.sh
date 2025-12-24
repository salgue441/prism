#!/bin/bash
# =============================================================================
# MinIO Bucket Initialization Script
# =============================================================================
# This script creates the required buckets and applies policies
# Run this after MinIO is started
# =============================================================================

set -e

# Configuration
MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://localhost:9000}"
MINIO_ACCESS_KEY="${MINIO_ROOT_USER:-minioadmin}"
MINIO_SECRET_KEY="${MINIO_ROOT_PASSWORD:-minioadmin}"
MINIO_ALIAS="prism"

# Wait for MinIO to be ready
echo "Waiting for MinIO to be ready..."
until mc alias set "$MINIO_ALIAS" "$MINIO_ENDPOINT" "$MINIO_ACCESS_KEY" "$MINIO_SECRET_KEY" 2>/dev/null; do
    echo "MinIO not ready, retrying in 5 seconds..."
    sleep 5
done

echo "MinIO is ready!"

# Create buckets
echo "Creating buckets..."

# Backups bucket
if ! mc ls "$MINIO_ALIAS/prism-backups" &>/dev/null; then
    mc mb "$MINIO_ALIAS/prism-backups"
    echo "Created bucket: prism-backups"
else
    echo "Bucket already exists: prism-backups"
fi

# WAL archive bucket
if ! mc ls "$MINIO_ALIAS/prism-wal" &>/dev/null; then
    mc mb "$MINIO_ALIAS/prism-wal"
    echo "Created bucket: prism-wal"
else
    echo "Bucket already exists: prism-wal"
fi

# Set bucket policies
echo "Setting bucket policies..."

# Allow versioning for backups (for recovery)
mc version enable "$MINIO_ALIAS/prism-backups"
echo "Enabled versioning on prism-backups"

# Set lifecycle policy to expire old backups after 30 days
mc ilm rule add --expire-days 30 "$MINIO_ALIAS/prism-backups"
echo "Set 30-day expiry lifecycle rule on prism-backups"

# Set lifecycle for WAL files (7 days)
mc ilm rule add --expire-days 7 "$MINIO_ALIAS/prism-wal"
echo "Set 7-day expiry lifecycle rule on prism-wal"

# Create service account for backup operations (optional)
# mc admin user add "$MINIO_ALIAS" backup-service "$BACKUP_SERVICE_PASSWORD"
# mc admin policy attach "$MINIO_ALIAS" readwrite --user backup-service

echo "MinIO initialization complete!"
echo ""
echo "Buckets created:"
mc ls "$MINIO_ALIAS"
