// Package server provides high-performance HTTP server implementation
// for the Prism API Gateway with comprehensive security, observability,
// and performance optimization features.
//
// This package implements an enterprise-grade HTTP server optimized for
// high-throughput, low-latency operations with built-in security controls,
// comprehensive monitoring, and graceful lifecycle management.
//
// # Design Principles
//
//   - High-performance concurrent request handling with optimized connection management
//   - Security-first approach with built-in protection against common attacks
//   - Comprehensive observability with metrics, tracing, and structured logging
//   - Graceful lifecycle management with proper resource cleanup
//   - Memory-efficient operations with connection pooling and buffer reuse
//   - Thread-safe operations optimized for concurrent access patterns
//
// # Security Features
//
//   - Request size and timeout limits to prevent resource exhaustion
//   - Built-in protection against slowloris and similar attacks
//   - Secure headers and CORS configuration
//   - Rate limiting and IP-based access controls
//   - Input validation and sanitization
//   - TLS/SSL support with modern cipher suites
//   - Security event logging and monitoring
//
// # Performance Optimizations
//
//   - HTTP/2 support with optimized connection management
//   - Connection pooling and keep-alive optimization
//   - Request/response buffering with configurable limits
//   - Zero-allocation paths for hot code paths
//   - Efficient middleware chain execution
//   - Memory pool usage for frequent allocations
//   - Optimized JSON serialization and compression
//
// # Observability
//
//   - Comprehensive metrics collection (Prometheus compatible)
//   - Distributed tracing support (OpenTelemetry/Jaeger)
//   - Structured request/response logging
//   - Health checks with detailed service status
//   - Performance monitoring and alerting
//   - Real-time connection and resource monitoring
//
// # Usage Examples
//
// Basic server setup:
//
//	cfg := &config.Config{
//		Server: config.ServerConfig{
//			Host: "0.0.0.0",
//			Port: 8080,
//			ReadTimeout:  30 * time.Second,
//			WriteTimeout: 30 * time.Second,
//		},
//	}
//
//	logger, _ := logger.New(&logger.Config{
//		Level:  "info",
//		Format: "json",
//		Output: "stdout",
//	})
//
//	srv := server.New(cfg, logger)
//
//	// Start server
//	if err := srv.Start(); err != nil {
//		log.Fatal("Failed to start server:", err)
//	}
//
// Advanced configuration with middleware:
//
//	srv := server.New(cfg, logger)
//
//	// Add custom middleware
//	srv.Use(middleware.RequestID())
//	srv.Use(middleware.CORS(cfg.CORS))
//	srv.Use(middleware.RateLimit(cfg.Security.RateLimiting))
//	srv.Use(middleware.Security(cfg.Security))
//
//	// Register routes
//	srv.GET("/health", handlers.Health)
//	srv.GET("/metrics", handlers.Metrics)
//	srv.Any("/proxy/*path", handlers.Proxy)
//
//	// Start with graceful shutdown
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	go func() {
//		if err := srv.Start(); err != nil {
//			log.Error("Server error:", err)
//		}
//	}()
//
//	// Wait for shutdown signal
//	<-ctx.Done()
//	srv.Shutdown(ctx)
//
// # Middleware Chain
//
// The server supports a flexible middleware chain for request processing:
//
//  1. Recovery middleware (panic recovery)
//  2. Request ID generation
//  3. Logging middleware
//  4. Security headers
//  5. CORS handling
//  6. Rate limiting
//  7. Authentication/authorization
//  8. Request validation
//  9. Compression
//  10. Application handlers
//
// # Health Checks
//
// The server provides comprehensive health checking capabilities:
//
//   - Liveness probes for basic server status
//   - Readiness probes for service dependencies
//   - Detailed health reports with component status
//   - Configurable health check intervals and timeouts
//   - Dependency health monitoring
//
// # Metrics and Monitoring
//
// Built-in metrics collection includes:
//
//   - Request count and rate
//   - Response time percentiles (P50, P95, P99)
//   - Error rates by status code
//   - Active connection count
//   - Memory and CPU usage
//   - Custom business metrics
//
// # TLS/SSL Configuration
//
// Secure transport configuration:
//
//	cfg.Server.TLS = config.TLSConfig{
//		Enabled:   true,
//		CertFile:  "/path/to/cert.pem",
//		KeyFile:   "/path/to/key.pem",
//		MinVersion: "1.2",
//		CipherSuites: []string{
//			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
//			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
//		},
//	}
//
// # Graceful Shutdown
//
// The server supports graceful shutdown with:
//
//   - Configurable shutdown timeout
//   - Proper connection draining
//   - Resource cleanup
//   - Final log flushing
//   - Metrics finalization
//
// # Performance Tuning
//
// Key performance configurations:
//
//   - Connection limits and timeouts
//   - Buffer sizes and pooling
//   - Compression settings
//   - Keep-alive configuration
//   - HTTP/2 stream limits
//   - Memory allocation optimization
//
// # Security Considerations
//
// The server implements security best practices:
//
//   - Default deny for CORS origins
//   - Secure headers by default
//   - Request size limits
//   - Timeout protection
//   - Input validation
//   - Security event logging
//   - Rate limiting by IP
//
// # Production Deployment
//
// Recommended production settings:
//
//   - Enable TLS with strong cipher suites
//   - Configure appropriate timeouts and limits
//   - Enable comprehensive logging and monitoring
//   - Set up health checks for load balancers
//   - Configure rate limiting and security headers
//   - Use connection pooling and keep-alives
//   - Enable graceful shutdown handling
package server
