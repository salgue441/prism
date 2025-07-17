// Package main provides the entry point for the API Gateway application.
//
// The gateway command starts a reverse proxy API gateway server that routes
// HTTP requests to backend services based on configurable rules.
//
// Usage:
//
//	go run ./cmd/prism
//
// Environment Variables:
//
//   - CONFIG_FILE: Path to configuration file (default: configs/config.yml)
//   - GATEWAY_SERVER_PORT: Server port (default: 8080)
//   - GATEWAY_SERVER_HOST: Server host (default: 0.0.0.0)
//
// # The application supports graceful shutdown on SIGINT and SIGTERM
//
// Example:
//
//	# Start with default configuration
//	go run ./cmd/prism
//
//	# Start with custom config file
//	CONFIG_FILE=custom-config.yaml go run ./cmd/prism
//
//	# Override port via environment
//	GATEWAY_SERVER_PORT=9090 go run ./cmd/prism
package main
