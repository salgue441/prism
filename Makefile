.PHONY: all build test clean proto lint fmt run-gateway run-auth run-config docker-build docker-up docker-down generate-keys migrate help

# Variables
BINARY_DIR := bin
PROTO_DIR := services/shared/proto
PROTO_OUT := services/shared/proto/gen
GO := go
GOFLAGS := -v
COMPOSE_DIR := deploy/docker-compose
DOCKER_COMPOSE := docker compose -f $(COMPOSE_DIR)/docker-compose.yml
DOCKER_COMPOSE_INFRA := docker compose -f $(COMPOSE_DIR)/docker-compose.infra.yml
DOCKER_COMPOSE_OBS := docker compose -f $(COMPOSE_DIR)/docker-compose.observability.yml
DOCKER_COMPOSE_ALL := $(DOCKER_COMPOSE) -f $(COMPOSE_DIR)/docker-compose.infra.yml -f $(COMPOSE_DIR)/docker-compose.observability.yml

# Build flags for production
LDFLAGS := -ldflags="-s -w"

# Colors for terminal output
GREEN := \033[0;32m
NC := \033[0m

all: proto build ## Build everything

help: ## Display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

# =============================================================================
# Build targets
# =============================================================================

build: build-gateway build-auth build-config build-dbmanager ## Build all services

build-gateway: ## Build gateway service
	@echo "Building gateway..."
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_DIR)/gateway ./services/gateway/cmd

build-auth: ## Build auth service
	@echo "Building auth service..."
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_DIR)/auth ./services/auth/cmd

build-config: ## Build config service
	@echo "Building config service..."
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_DIR)/config ./services/config/cmd

build-dbmanager: ## Build dbmanager service
	@echo "Building dbmanager service..."
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_DIR)/dbmanager ./services/dbmanager/cmd

# =============================================================================
# Development targets
# =============================================================================

run-gateway: ## Run gateway service locally
	$(GO) run ./services/gateway/cmd

run-auth: ## Run auth service locally
	$(GO) run ./services/auth/cmd

run-config: ## Run config service locally
	$(GO) run ./services/config/cmd

# =============================================================================
# Protocol Buffers
# =============================================================================

proto: ## Generate protobuf code
	@echo "Generating protobuf code..."
	@mkdir -p $(PROTO_OUT)
	protoc --go_out=$(PROTO_OUT) --go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_OUT) --go-grpc_opt=paths=source_relative \
		-I $(PROTO_DIR) \
		-I $(HOME)/.local/include \
		$(PROTO_DIR)/*.proto

proto-clean: ## Clean generated protobuf files
	rm -rf $(PROTO_OUT)

# =============================================================================
# Testing
# =============================================================================

test: ## Run all tests
	$(GO) test -v -race -cover ./...

test-unit: ## Run unit tests only
	$(GO) test -v -race -cover -short ./...

test-integration: ## Run integration tests
	$(GO) test -v -race -cover -run Integration ./...

test-coverage: ## Generate test coverage report
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

bench: ## Run benchmarks
	$(GO) test -bench=. -benchmem ./...

# =============================================================================
# Code quality
# =============================================================================

lint: ## Run linter
	golangci-lint run ./...

fmt: ## Format code
	$(GO) fmt ./...
	gofumpt -l -w .

vet: ## Run go vet
	$(GO) vet ./...

tidy: ## Tidy and verify go modules
	$(GO) mod tidy
	$(GO) mod verify

# =============================================================================
# Docker
# =============================================================================

docker-build: ## Build all Docker images
	$(DOCKER_COMPOSE_ALL) build

docker-up: ## Start core services
	$(DOCKER_COMPOSE) up -d

docker-down: ## Stop all Docker Compose services
	$(DOCKER_COMPOSE_ALL) down

docker-logs: ## View Docker Compose logs (usage: make docker-logs service=gateway)
	$(DOCKER_COMPOSE_ALL) logs -f $(service)

docker-ps: ## List running containers
	$(DOCKER_COMPOSE_ALL) ps

docker-infra-up: ## Start infrastructure services only
	$(DOCKER_COMPOSE_INFRA) up -d

docker-infra-down: ## Stop infrastructure services
	$(DOCKER_COMPOSE_INFRA) down

docker-obs-up: ## Start observability stack
	$(DOCKER_COMPOSE_OBS) up -d

docker-obs-down: ## Stop observability stack
	$(DOCKER_COMPOSE_OBS) down

docker-full-up: ## Start all services (infra + core + observability)
	$(DOCKER_COMPOSE_ALL) up -d

docker-full-down: ## Stop all services
	$(DOCKER_COMPOSE_ALL) down

docker-restart: ## Restart all services
	$(DOCKER_COMPOSE_ALL) restart

docker-clean: ## Remove all containers, networks, and volumes
	$(DOCKER_COMPOSE_ALL) down -v --remove-orphans

# =============================================================================
# Database
# =============================================================================

migrate-up: ## Run database migrations
	@echo "Running migrations..."
	$(GO) run ./cmd/migrate up

migrate-down: ## Rollback database migrations
	@echo "Rolling back migrations..."
	$(GO) run ./cmd/migrate down

migrate-create: ## Create a new migration (usage: make migrate-create name=migration_name)
	@echo "Creating migration: $(name)"
	migrate create -ext sql -dir migrations -seq $(name)

# =============================================================================
# Security
# =============================================================================

generate-keys: ## Generate RSA key pair for JWT signing
	@echo "Generating RSA key pair..."
	@mkdir -p keys
	openssl genrsa -out keys/private.pem 4096
	openssl rsa -in keys/private.pem -pubout -out keys/public.pem
	@chmod 600 keys/private.pem
	@echo "Keys generated in ./keys directory"

security-scan: ## Run security scanner
	gosec ./...

# =============================================================================
# Cleanup
# =============================================================================

clean: ## Clean build artifacts
	rm -rf $(BINARY_DIR)
	rm -f coverage.out coverage.html
	$(GO) clean -cache

clean-all: clean proto-clean ## Clean everything including generated files
	rm -rf vendor

# =============================================================================
# Installation
# =============================================================================

install-tools: ## Install development tools
	@echo "Installing development tools..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install mvdan.cc/gofumpt@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

deps: ## Download dependencies
	$(GO) mod download

vendor: ## Vendor dependencies
	$(GO) mod vendor

# =============================================================================
# Development Setup
# =============================================================================

dev-setup: ## Setup complete development environment
	@./scripts/dev-setup.sh

dev: docker-infra-up ## Start development mode (infra + local services)
	@echo "Infrastructure started. Run services locally with 'make run-*'"

# =============================================================================
# Backup Operations
# =============================================================================

backup-auth: ## Create backup of auth database
	@./deploy/backup/backup.sh auth full

backup-ops: ## Create backup of ops database
	@./deploy/backup/backup.sh ops full

backup-all: ## Create backup of all databases
	@./deploy/backup/backup.sh all full

backup-list: ## List available backups
	@ls -la /var/lib/prism/backups/*/
