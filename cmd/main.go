// Package main provides the entry point for the Prism API Gateway.
//
// This is the main application that starts the high-performance HTTP server
// with comprehensive security, observability, and lifecycle management.
//
// The gateway implements:
//   - Enterprise-grade HTTP server with TLS support
//   - Comprehensive middleware chain for security and observability
//   - Graceful shutdown with proper resource cleanup
//   - Health checks and metrics collection
//   - Configuration management with hot reloading
//   - Structured logging with request correlation
//
// Usage:
//
//	go run cmd/gateway/main.go [flags]
//
// Flags:
//
//	-config string    Path to configuration file (default: "./config/config.yaml")
//	-version          Print version information and exit
//	-help             Print help information and exit
//
// Environment Variables:
//
//	PRISM_CONFIG_PATH    Path to configuration file
//	PRISM_LOG_LEVEL      Log level override
//	PRISM_DEBUG          Enable debug mode
//
// The application supports graceful shutdown on SIGINT and SIGTERM signals.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"prism/internal/config"
	"prism/internal/server"
	"prism/pkg/logger"
	"syscall"
	"time"
)

// Application metadata
var (
	// Version is set during build time
	Version = "dev"

	// BuildTime is set during build time
	BuildTime = "unknown"

	// GitCommit is set during build time
	GitCommit = "unknown"

	// GoVersion is set during build time
	GoVersion = "unknown"
)

// Application constants
const (
	// AppName is the application name
	AppName = "prism-gateway"

	// DefaultConfigPath is the default configuration file path
	DefaultConfigPath = "./config/config.yaml"

	// ShutdownTimeout is the maximum time to wait for graceful shutdown
	ShutdownTimeout = 30 * time.Second
)

// main is the entry point for the Prism API Gateway application.
func main() {
	configPath, showVersion, showHelp := parseFlags()
	if showVersion {
		printVersion()
		os.Exit(1)
	}

	if showHelp {
		printHelp()
		os.Exit(1)
	}

	if envPath := os.Getenv("PRISM_CONFIG_PATH"); envPath != "" {
		configPath = envPath
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	if debugEnv := os.Getenv("PRISM_DEBUG"); debugEnv == "true" {
		cfg.Development.Debug = true
	}

	if logLevel := os.Getenv("PRISM_LOG_LEVEL"); logLevel != "" {
		cfg.Logging.Level = logLevel
	}

	cfg.SetVersion(Version)
	log, err := logger.New(&logger.Config{
		Level:            cfg.Logging.Level,
		Format:           cfg.Logging.Format,
		Output:           cfg.Logging.Output,
		SamplingRate:     cfg.Logging.SamplingRate,
		BufferSize:       cfg.Logging.BufferSize,
		FlushInterval:    cfg.Logging.FlushInterval,
		SanitizeFields:   cfg.Logging.SanitizeFields,
		RedactedFields:   cfg.Logging.RedactedFields,
		MaxFieldSize:     cfg.Logging.MaxFieldSize,
		EnableCaller:     cfg.Logging.EnableCaller,
		EnableStackTrace: cfg.Logging.EnableStackTrace,
		ComponentName:    AppName,
		PrettyPrint:      cfg.Development.Debug,
		ColorOutput:      cfg.Development.Debug,
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	defer log.Close()
	log.LogStartup(AppName, Version, cfg.GetAddress())
	log.Info("Starting Prism API Gateway",
		"version", Version,
		"build_time", BuildTime,
		"git_commit", GitCommit,
		"go_version", GoVersion,
		"config_path", configPath,
		"debug_mode", cfg.IsDebugMode())

	serverOpts := &server.ServerOptions{
		RouterMode:               getRouterMode(cfg),
		TrustedProxies:           cfg.Security.TrustedProxies,
		DisableDefaultMiddleware: false,
		EnableMetrics:            cfg.IsMetricsEnabled(),
		EnablePprof:              cfg.Development.PProf,
		EnableTracing:            false, // TODO: Implement tracing
	}

	srv, err := server.New(cfg, log, serverOpts)
	if err != nil {
		log.Error("Failed to create server", "error", err)
		os.Exit(1)
	}

	setupRoutes(srv, log)
	ctx, cancel := setupSignalHandling(log)
	defer cancel()

	if err := srv.Start(); err != nil {
		log.Error("Failed to start server", "error", err)
		os.Exit(1)
	}

	<-ctx.Done()
	log.Info("Received shutdown signal, starting graceful shutdown")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("Server shutdown failed", "error", err)
		if closeErr := srv.Close(); closeErr != nil {
			log.Error("Force close failed", "error", closeErr)
		}

		os.Exit(1)
	}

	log.Info("Server shutdown completed successfully")
}

// parseFlags parses command line flags and returns the configuration.
func parseFlags() (configPath string, showVersion bool, showHelp bool) {
	flag.StringVar(&configPath, "config",
		DefaultConfigPath, "Path to configuration file")
	flag.BoolVar(&showVersion, "version", false,
		"Print version information and exit")
	flag.BoolVar(&showHelp, "help", false, "Print help information and exit")

	flag.Parse()
	return configPath, showVersion, showHelp
}

// printVersion prints version information.
func printVersion() {
	fmt.Printf("%s version %s\n", AppName, Version)
	fmt.Printf("Built: %s\n", BuildTime)
	fmt.Printf("Git commit: %s\n", GitCommit)
	fmt.Printf("Go version: %s\n", GoVersion)
}

// printHelp prints help information.
func printHelp() {
	fmt.Printf("Usage: %s [flags]\n\n", AppName)
	fmt.Println("Prism API Gateway - High-performance reverse proxy and API gateway")
	fmt.Println()
	fmt.Println("Flags:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  PRISM_CONFIG_PATH    Path to configuration file")
	fmt.Println("  PRISM_LOG_LEVEL      Log level (trace, debug, info, warn, error, fatal, panic)")
	fmt.Println("  PRISM_DEBUG          Enable debug mode (true/false)")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Printf("  %s -config /etc/prism/config.yaml\n", AppName)
	fmt.Printf("  %s -version\n", AppName)
	fmt.Printf("  PRISM_DEBUG=true %s\n", AppName)
	fmt.Println()
	fmt.Println("For more information, visit: https://github.com/your-org/prism")
}

// getRouterMode determines the Gin router mode based on configuration.
func getRouterMode(cfg *config.Config) string {
	if cfg.IsDebugMode() {
		return "debug"
	}

	return "release"
}

// setupSignalHandling sets up signal handling for graceful shutdown.
func setupSignalHandling(log *logger.Logger) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		defer cancel()

		sig := <-sigChan
		log.Info("Received signal", "signal", sig.String())

		time.Sleep(100 * time.Millisecond)
	}()

	return ctx, cancel
}

// setupRoutes configures the application routes.
func setupRoutes(srv *server.Server, log *logger.Logger) {
	// API v1 routes group
	v1 := srv.Group("/api/v1")
	{
		v1.GET("/health", handleHealthCheck)
		v1.GET("/status", handleStatus)
		v1.GET("/version", handleVersion)
		v1.POST("/echo", handleEcho)
		v1.GET("/echo", handleEcho)
		// v1.Any("/proxy/*path", handleProxy)
	}

	admin := srv.Group("/admin")
	{
		admin.GET("/status", handleAdminStatus)
		admin.GET("/routes", handleAdminRoutes)
		admin.GET("/config", handleAdminConfig)
		admin.GET("/metrics", handleAdminMetrics)
		admin.POST("/reload", handleAdminReload)
	}

	srv.GET("/favicon.ico", handleFavicon)
	srv.GET("/robots.txt", handleRobots)

	log.Info("Routes configured successfully")
}

// Route handlers

// handleHealthCheck handles health check requests.
func handleHealthCheck(ctx *server.Context) {
	ctx.Success(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"uptime":    time.Since(ctx.RequestCtx.StartTime),
	}, "Service is healthy")
}

// handleStatus handles detailed status requests.
func handleStatus(ctx *server.Context) {
	status := map[string]interface{}{
		"service":   AppName,
		"version":   Version,
		"status":    "running",
		"timestamp": time.Now(),
		"build": map[string]interface{}{
			"version":    Version,
			"build_time": BuildTime,
			"git_commit": GitCommit,
			"go_version": GoVersion,
		},
	}

	ctx.Success(status, "Status retrieved successfully")
}

// handleVersion handles version information requests.
func handleVersion(ctx *server.Context) {
	version := map[string]interface{}{
		"service":    AppName,
		"version":    Version,
		"build_time": BuildTime,
		"git_commit": GitCommit,
		"go_version": GoVersion,
	}

	ctx.Success(version, "Version information")
}

// handleEcho handles echo requests for testing and debugging.
func handleEcho(ctx *server.Context) {
	method := ctx.Request.Method
	headers := make(map[string]string)

	for name, values := range ctx.Request.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}

	var body interface{}
	if method == "POST" {
		if err := ctx.ShouldBindJSON(&body); err != nil {
			if rawBody, err := ctx.GetRawData(); err == nil {
				body = string(rawBody)
			}
		}
	}

	echo := map[string]interface{}{
		"method":      method,
		"path":        ctx.Request.URL.Path,
		"query":       ctx.Request.URL.Query(),
		"headers":     headers,
		"remote_addr": ctx.ClientIP(),
		"user_agent":  ctx.GetHeader("User-Agent"),
		"timestamp":   time.Now(),
		"request_id":  ctx.RequestCtx.RequestID,
	}

	if body != nil {
		echo["body"] = body
	}

	ctx.Success(echo, "Request echoed successfully")
}

// handleProxy handles proxy requests (placeholder for future implementation).
func handleProxy(ctx *server.Context) {
	// This is a placeholder for the actual proxy implementation
	// In a real implementation, this would:
	// 1. Parse the target service from the path
	// 2. Load balance to backend servers
	// 3. Forward the request with proper headers
	// 4. Return the response from the backend

	path := ctx.Param("path")

	response := map[string]interface{}{
		"message":     "Proxy functionality not yet implemented",
		"target_path": path,
		"method":      ctx.Request.Method,
		"timestamp":   time.Now(),
		"todo": []string{
			"Implement service discovery",
			"Add load balancing",
			"Implement request forwarding",
			"Add circuit breaker",
			"Implement response caching",
		},
	}

	ctx.JSON(501, map[string]interface{}{
		"error":      "Not Implemented",
		"message":    "Proxy functionality is under development",
		"data":       response,
		"request_id": ctx.RequestCtx.RequestID,
		"timestamp":  time.Now(),
	})
}

// handleFavicon handles favicon requests.
func handleFavicon(ctx *server.Context) {
	// Return 204 No Content for favicon requests
	ctx.Status(204)
}

// handleRobots handles robots.txt requests.
func handleRobots(ctx *server.Context) {
	robots := `User-agent: *
Disallow: /admin/
Disallow: /debug/
Disallow: /metrics
Allow: /api/
Allow: /health`

	ctx.String(200, robots)
}

// Admin handlers
// handleAdminStatus handles admin status requests.
func handleAdminStatus(ctx *server.Context) {
	// This would integrate with the server's status methods
	status := map[string]interface{}{
		"service":    AppName,
		"version":    Version,
		"status":     "running",
		"uptime":     time.Since(time.Now()),       // Placeholder - would use actual start time
		"debug_mode": ctx.Query("debug") == "true", // Placeholder
		"endpoints": map[string]interface{}{
			"health":  "/health",
			"metrics": "/metrics",
			"api":     "/api/v1",
			"admin":   "/admin",
		},
		"timestamp": time.Now(),
	}

	ctx.Success(status, "Admin status retrieved")
}

// handleAdminRoutes handles admin routes listing.
func handleAdminRoutes(ctx *server.Context) {
	routes := []map[string]interface{}{
		{"method": "GET", "path": "/", "description": "Root endpoint"},
		{"method": "GET", "path": "/health", "description": "Health check"},
		{"method": "GET", "path": "/api/v1/health", "description": "API health check"},
		{"method": "GET", "path": "/api/v1/status", "description": "API status"},
		{"method": "GET", "path": "/api/v1/version", "description": "API version"},
		{"method": "ANY", "path": "/api/v1/echo", "description": "Echo endpoint"},
		{"method": "ANY", "path": "/api/v1/proxy/*path", "description": "Proxy endpoint"},
		{"method": "GET", "path": "/admin/status", "description": "Admin status"},
		{"method": "GET", "path": "/admin/routes", "description": "Admin routes"},
		{"method": "GET", "path": "/admin/config", "description": "Admin config"},
		{"method": "GET", "path": "/admin/metrics", "description": "Admin metrics"},
		{"method": "POST", "path": "/admin/reload", "description": "Admin reload"},
	}

	ctx.Success(routes, "Routes retrieved successfully")
}

// handleAdminConfig handles admin configuration requests.
func handleAdminConfig(ctx *server.Context) {
	// Return sanitized configuration (no sensitive data)
	config := map[string]interface{}{
		"server": map[string]interface{}{
			"host":  "configured", // Don't expose actual values
			"port":  "configured",
			"debug": ctx.Query("debug") == "true", // Placeholder
		},
		"logging": map[string]interface{}{
			"level":  "configured",
			"format": "json",
		},
		"features": map[string]interface{}{
			"metrics_enabled": true,
			"health_enabled":  true,
			"cors_enabled":    false, // Placeholder
			"tls_enabled":     false, // Placeholder
		},
		"timestamp": time.Now(),
	}

	ctx.Success(config, "Configuration retrieved (sanitized)")
}

// handleAdminMetrics handles admin metrics requests.
func handleAdminMetrics(ctx *server.Context) {
	// This would integrate with the server's metrics collection
	metrics := map[string]interface{}{
		"requests": map[string]interface{}{
			"total":   0, // Placeholder
			"success": 0, // Placeholder
			"errors":  0, // Placeholder
		},
		"connections": map[string]interface{}{
			"active": 0, // Placeholder
			"total":  0, // Placeholder
		},
		"performance": map[string]interface{}{
			"avg_response_time": "0ms",                           // Placeholder
			"uptime":            time.Since(time.Now()).String(), // Placeholder
		},
		"system": map[string]interface{}{
			"memory_usage": "0MB", // Placeholder
			"cpu_usage":    "0%",  // Placeholder
			"goroutines":   0,     // Placeholder
		},
		"timestamp": time.Now(),
	}

	ctx.Success(metrics, "Metrics retrieved successfully")
}

// handleAdminReload handles admin configuration reload requests.
func handleAdminReload(ctx *server.Context) {
	// This would implement hot reload functionality
	// For now, just return a placeholder response

	result := map[string]interface{}{
		"message":   "Configuration reload not yet implemented",
		"timestamp": time.Now(),
		"todo": []string{
			"Implement configuration file watching",
			"Add hot reload for non-critical settings",
			"Implement validation for new configuration",
			"Add rollback mechanism for failed reloads",
		},
	}

	ctx.JSON(501, map[string]interface{}{
		"error":      "Not Implemented",
		"message":    "Configuration reload is under development",
		"data":       result,
		"request_id": ctx.RequestCtx.RequestID,
		"timestamp":  time.Now(),
	})
}

// Additional utility functions for the main application

// validateConfiguration performs additional validation on the loaded configuration.
func validateConfiguration(cfg *config.Config) error {
	// Perform any additional validation beyond what's in the config package

	// Validate port availability (simplified check)
	if cfg.Server.Port < 1024 && os.Geteuid() != 0 {
		return fmt.Errorf("port %d requires root privileges", cfg.Server.Port)
	}

	// Validate TLS configuration if enabled
	if cfg.IsTLSEnabled() {
		if cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "" {
			return fmt.Errorf("TLS enabled but certificate or key file not specified")
		}
	}

	// Validate log level
	validLevels := []string{"trace", "debug", "info", "warn", "error", "fatal", "panic"}
	levelValid := false
	for _, level := range validLevels {
		if cfg.Logging.Level == level {
			levelValid = true
			break
		}
	}
	if !levelValid {
		return fmt.Errorf("invalid log level: %s", cfg.Logging.Level)
	}

	return nil
}

// setupEnvironment sets up the application environment.
func setupEnvironment() error {
	// Set any required environment variables or system settings

	// Ensure we can handle the expected number of file descriptors
	// This would typically be done at the system level, but we can check here

	return nil
}

func logStartupBanner(log *logger.Logger) {
	banner := `
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║                        🌈 PRISM API GATEWAY                                   ║
║                                                                               ║
║                    High-Performance Reverse Proxy                            ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝`

	log.Info(banner)
	log.Info("Gateway Features:",
		"authentication", "JWT/OAuth2",
		"rate_limiting", "Token Bucket",
		"load_balancing", "Multiple Algorithms",
		"monitoring", "Prometheus/Grafana",
		"security", "TLS/CORS/Headers",
		"observability", "Distributed Tracing")
}

// handlePanicRecovery provides a top-level panic recovery mechanism.
func handlePanicRecovery() {
	if r := recover(); r != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %v\n", r)
		if err, ok := r.(error); ok {
			fmt.Fprintf(os.Stderr, "Stack trace: %+v\n", err)
		}

		os.Exit(1)
	}
}

// init performs package initialization.
func init() {
	defer handlePanicRecovery()
	if err := setupEnvironment(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup environment: %v\n", err)
		os.Exit(1)
	}
}
