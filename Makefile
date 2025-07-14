.PHONY: build run test clean fmt lint help

# Variables
BINARY_NAME=gateway
GO_VERSION=1.21

# Colors for output
GREEN=\033[0;32m
YELLOW=\033[0;33m
NC=\033[0m # No Color

## Help
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## Development
build: ## Build the binary
	@echo "$(GREEN)Building binary...$(NC)"
	go build -o bin/$(BINARY_NAME) cmd/gateway/main.go

run: build ## Build and run the application
	@echo "$(GREEN)Starting application...$(NC)"
	./bin/$(BINARY_NAME)

## Testing
test: ## Run tests
	@echo "$(GREEN)Running tests...$(NC)"
	go test -v -race ./...

test-coverage: ## Run tests with coverage
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## Code Quality
fmt: ## Format code
	@echo "$(GREEN)Formatting code...$(NC)"
	go fmt ./...

lint: ## Run linter
	@echo "$(GREEN)Running linter...$(NC)"
	golangci-lint run

vet: ## Run go vet
	@echo "$(GREEN)Running go vet...$(NC)"
	go vet ./...

## Setup
setup: ## Setup development environment
	@echo "$(GREEN)Setting up development environment...$(NC)"
	go mod download
	go mod tidy

## Cleanup
clean: ## Clean build artifacts
	@echo "$(YELLOW)Cleaning up...$(NC)"
	rm -rf bin/
	rm -f coverage.out coverage.html

## Docker (Future)
docker-build: ## Build Docker image (placeholder)
	@echo "$(YELLOW)Docker build coming in next iteration...$(NC)"

docker-run: ## Run Docker container (placeholder)
	@echo "$(YELLOW)Docker run coming in next iteration...$(NC)"

## Docs 
docs: 
	@echo "Generating OpenAPI docs"
	@swag init -g cmd/prism/main.go -o ./docs/openapi
	@mkdir -p ./docs/swagger
	@cp ./docs/openapi/swagger.json ./docs/swagger/openapi.yaml
	@echo "Docs generated at ./docs/"