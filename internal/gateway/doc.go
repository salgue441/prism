// Package gateway provides the core API gateway orchestration and HTTP server \
// management.
//
// This package acts as the main coordinator that brings together routing, 
// proxying, middleware, and server lifecycle management. It implements the 
// primary Gateway type that serves as the entry point for the entire 
// application.
//
// Key Components:
//
//	Gateway    - Main orchestrator that manages server lifecycle
//	Middleware - HTTP middleware functions for cross-cutting concerns
//	Handlers   - HTTP handlers for system endpoints (health, metrics)
//
// The Gateway type is responsible for:
//
//	- Initializing and configuring the HTTP server
//	- Setting up the middleware chain
//	- Registering routes and handlers
//	- Managing graceful startup and shutdown
//	- Coordinating between router, proxy, and configuration components
//
// Middleware Chain:
//
// The gateway applies middleware in a specific order to ensure proper
// request processing:
//
//	1. Recovery middleware (panic recovery)
//	2. Logging middleware (request/response logging)
//	3. CORS middleware (cross-origin support)
//	4. Route handlers (business logic)
//
// System Endpoints:
//
// The gateway provides built-in system endpoints for monitoring and health 
// checks:
//
//	/health  - Health check endpoint returning gateway status
//	/metrics - Basic metrics endpoint with operational data
//
// Lifecycle Management:
//
// The gateway supports graceful startup and shutdown with proper resource
// cleanup and connection draining to ensure zero-downtime deployments.
//
// Example usage:
//
//	cfg := &config.Config{...}
//	logger := slog.Default()
//	
//	gw, err := gateway.New(cfg, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	
//	// Start server (blocking)
//	if err := gw.Start(); err != nil {
//	    log.Fatal(err)
//	}
//	
//	// Graceful shutdown
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	gw.Stop(ctx)
package gateway