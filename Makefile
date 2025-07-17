.PHONY: build run test clean deps fmt lint

# Build the application
build:
	go build -o bin/prism ./cmd/prism

# Run the application
run:
	go run ./cmd/prism

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -rf bin/

# Download dependencies
deps:
	go mod download
	go mod tidy

# Format code
fmt:
	go fmt ./...

# Lint code
lint:
	golangci-lint run

# Run with race detection
run-race:
	go run -race ./cmd/prism

# Generate mocks
generate:
	go generate ./...

# Build for production
build-prod:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/prism ./cmd/prism