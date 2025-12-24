#!/bin/bash
# =============================================================================
# Prism Development Environment Setup Script
# =============================================================================
# This script sets up the complete development environment
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}==>${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."

    local missing=()

    command -v docker &> /dev/null || missing+=("docker")
    command -v docker compose &> /dev/null || command -v docker-compose &> /dev/null || missing+=("docker-compose")
    command -v go &> /dev/null || missing+=("go")

    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi

    log_info "All prerequisites satisfied"
}

# Setup environment file
setup_env() {
    log_step "Setting up environment..."

    local env_file="$PROJECT_ROOT/deploy/docker-compose/.env"
    local example_file="$PROJECT_ROOT/deploy/docker-compose/.env.example"

    if [ ! -f "$env_file" ]; then
        if [ -f "$example_file" ]; then
            cp "$example_file" "$env_file"
            log_info "Created .env from .env.example"

            # Generate random passwords for development
            sed -i "s/CHANGE_ME_auth_password_here/$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9')/" "$env_file"
            sed -i "s/CHANGE_ME_ops_password_here/$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9')/" "$env_file"
            sed -i "s/CHANGE_ME_redis_password_here/$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9')/" "$env_file"
            sed -i "s/CHANGE_ME_minio_password_here/$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9')/" "$env_file"
            sed -i "s/CHANGE_ME_grafana_password_here/admin123/" "$env_file"

            log_warn "Generated random passwords - check $env_file"
        else
            log_error "No .env.example found"
            exit 1
        fi
    else
        log_info ".env already exists"
    fi
}

# Generate JWT keys
setup_keys() {
    log_step "Setting up JWT keys..."

    local keys_dir="$PROJECT_ROOT/keys"
    mkdir -p "$keys_dir"

    if [ ! -f "$keys_dir/private.pem" ]; then
        log_info "Generating RSA key pair..."
        openssl genrsa -out "$keys_dir/private.pem" 4096
        openssl rsa -in "$keys_dir/private.pem" -pubout -out "$keys_dir/public.pem"
        chmod 600 "$keys_dir/private.pem"
        log_info "JWT keys generated in $keys_dir"
    else
        log_info "JWT keys already exist"
    fi
}

# Start infrastructure
start_infrastructure() {
    log_step "Starting infrastructure services..."

    cd "$PROJECT_ROOT/deploy/docker-compose"

    docker compose -f docker-compose.infra.yml up -d

    log_info "Waiting for services to be healthy..."
    sleep 10

    # Check health
    docker compose -f docker-compose.infra.yml ps
}

# Run migrations
run_migrations() {
    log_step "Running database migrations..."

    # Wait for PostgreSQL
    log_info "Waiting for PostgreSQL..."
    for i in {1..30}; do
        if docker compose -f docker-compose.infra.yml exec -T postgres-auth pg_isready -U prism &> /dev/null; then
            break
        fi
        sleep 1
    done

    # Run migrations using psql
    log_info "Applying auth migrations..."
    docker compose -f docker-compose.infra.yml exec -T postgres-auth psql -U prism -d prism_auth -f /migrations/001_initial_schema.sql || true

    log_info "Applying ops migrations..."
    docker compose -f docker-compose.infra.yml exec -T postgres-ops psql -U prism -d prism_ops -f /migrations/001_initial_schema.sql || true

    log_info "Migrations complete"
}

# Build services
build_services() {
    log_step "Building services..."

    cd "$PROJECT_ROOT"

    make build

    log_info "Services built successfully"
}

# Print summary
print_summary() {
    echo ""
    echo -e "${GREEN}=== Development Environment Ready ===${NC}"
    echo ""
    echo "Services:"
    echo "  - PostgreSQL (Auth): localhost:5432"
    echo "  - PostgreSQL (Ops):  localhost:5433"
    echo "  - Redis:             localhost:6379"
    echo "  - NATS:              localhost:4222"
    echo "  - Consul:            localhost:8500"
    echo "  - MinIO:             localhost:9000 (console: 9001)"
    echo ""
    echo "To start core services:"
    echo "  cd deploy/docker-compose && docker compose up -d"
    echo ""
    echo "To start observability stack:"
    echo "  cd deploy/docker-compose && docker compose -f docker-compose.observability.yml up -d"
    echo ""
    echo "Dashboards:"
    echo "  - Consul:     http://localhost:8500"
    echo "  - MinIO:      http://localhost:9001"
    echo "  - Grafana:    http://localhost:3000 (admin/admin123)"
    echo "  - Prometheus: http://localhost:9090"
    echo "  - Jaeger:     http://localhost:16686"
    echo ""
}

# Main
main() {
    echo -e "${BLUE}=== Prism Development Setup ===${NC}"
    echo ""

    check_prerequisites
    setup_env
    setup_keys
    start_infrastructure
    run_migrations
    build_services
    print_summary
}

main "$@"
