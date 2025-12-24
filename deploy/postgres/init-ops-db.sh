#!/bin/bash
# =============================================================================
# Prism Operational Database Initialization Script
# =============================================================================
# This script runs on first container startup to initialize the ops database.
# It creates necessary extensions and sets up the schema for operational data.
# =============================================================================

set -e

echo "Initializing Prism Operational Database..."

# Create extensions
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- UUID generation
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

    -- Cryptographic functions
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";

    -- Time-series data optimization
    CREATE EXTENSION IF NOT EXISTS "btree_gist";

    -- JSON operations
    CREATE EXTENSION IF NOT EXISTS "pg_trgm";

    -- Performance statistics
    CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

    -- Grant permissions
    GRANT ALL PRIVILEGES ON DATABASE "$POSTGRES_DB" TO "$POSTGRES_USER";
EOSQL

# Run migrations if they exist
if [ -d "/migrations" ]; then
    echo "Running migrations from /migrations..."
    for f in /migrations/*.sql; do
        if [ -f "$f" ]; then
            echo "Applying migration: $f"
            psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f "$f"
        fi
    done
    echo "Migrations complete."
else
    echo "No migrations directory found, skipping migrations."
fi

echo "Operational database initialization complete."
