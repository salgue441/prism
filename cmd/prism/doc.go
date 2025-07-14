// Package main provides the entry point and command-line interface for the
// Prism reverse API gateway.
//
// # Overview
//
// The cmd/prism package contains the main application logic for starting and
// managing the Prism gateway service. It handles command-line arguments,
// configuration loading, service initialization, and graceful shutdown.
//
// # Key Features
//
//   - Command-line interface with support for multiple commands
//   - Configuration loading and validation
//   - Service lifecycle management
//   - Graceful shutdown handling
//   - Signal handling for production deployments
//   - Version and build information display
//
// # Commands
//
// The application supports the following commands:
//
//   - start: Start the gateway service (default command)
//   - version: Display version and build information
//   - config: Validate and display configuration
//
// # Basic Usage
//
// Start the service with default configuration:
//
//	./prism
//
// Start with custom configuration file:
//
//	./prism --config /path/to/config.yaml
//
// Display version information:
//
//	./prism version
//
// # Command-line Flags
//
// The following flags are available for the start command:
//
//	--config string      Path to configuration file (default "configs/Prism.yaml")
//	--env string         Environment name (development, staging, production)
//	--log-level string   Log level (debug, info, warn, error)
//	--pprof              Enable pprof profiling server
//	--pprof-port int     pprof server port (default 6060)
//
// # Environment Variables
//
// All configuration options from the config package can be overridden using
// environment variables with the PRISM_ prefix. See the config package
// documentation for details.
//
// # Signal Handling
//
// The application handles the following signals for graceful shutdown:
//
//   - SIGINT (Ctrl+C)
//   - SIGTERM
//
// When received, the server will:
//
//  1. Stop accepting new connections
//  2. Wait for existing connections to complete
//  3. Close all resources
//  4. Exit
//
// The shutdown timeout can be configured via server.graceful_timeout in the
// configuration.
//
// # Production Usage
//
// For production deployments:
//
//   - Use environment variables for sensitive configuration
//   - Set appropriate resource limits
//   - Monitor the service health endpoints
//   - Configure proper logging and log rotation
//   - Use process supervision (systemd, Kubernetes, etc.)
//
// # Build Information
//
// Version information is embedded during build using ldflags. Typical build
// command:
//
//	go build -ldflags "-X main.version=1.0.0 -X main.commit=$(git rev-parse HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
//
// # Error Handling
//
// The main package provides consistent error handling and exit codes:
//
//   - 0: Success
//   - 1: General error
//   - 2: Configuration error
//   - 3: Runtime error
//   - 4: Signal interrupt
package main
