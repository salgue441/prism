package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"prism/internal/config"
	"prism/pkg/logger"
	"prism/pkg/redis"
	"syscall"
	"time"
)

// Application holds the main applicatino dependencies and configuration
type Application struct {
	config      *config.Config
	logger      logger.Logger
	redisClient redis.Client
	server      *http.Server
}

// main is the entry point of the gateway application.
// It loads configuration, initializes dependencies, starts the HTTP server,
// and handles graceful shutdown.
func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger with loaded configuration
	log, err := logger.New(logger.Config{
		Level:     cfg.Logging.Level,
		Format:    cfg.Logging.Format,
		Output:    cfg.Logging.Output,
		AddSource: cfg.Logging.AddSource,
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	// Create app instance
	app := &Application{
		config: cfg,
		logger: log.With("component", "main"),
	}

	if err := app.Run(); err != nil {
		app.logger.Error("Application failed to start", "error", err)
		os.Exit(1)
	}
}

// Run initializes all application dependencies and starts the HTTP server.
// It blocks until the application receives a shutdown signal.
func (a *Application) Run() error {
	a.logger.Info("Starting prisma",
		"version", getVersion(),
		"config", a.config,
	)

	// Initialize redis client
	if err := a.initRedis(); err != nil {
		return fmt.Errorf("failed to initialize Redis: %w", err)
	}

	defer a.closeRedis()

	// Initialize HTTP server
	if err := a.initServer(); err != nil {
		return fmt.Errorf("failed to initialize HTTP server: %w", err)
	}

	// Start server in a goroutine
	serverErrChan := make(chan error, 1)
	go func() {
		a.logger.Info("Starting HTTP server", "address", a.server.Addr)

		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrChan <- fmt.Errorf("HTTP server failed: %w", err)
		}
	}()

	// Wait for interrupt signal or server error
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrChan:
		return err

	case sig := <-sigChan:
		a.logger.Info("Received shutdown signal", "signal", sig.String())
		return a.shutdown()
	}
}

// initRedis initializes the Redis client with the configured settings.
func (a *Application) initRedis() error {
	redisConfig := redis.Config{
		Host:            a.config.Redis.Host,
		Port:            a.config.Redis.Port,
		Password:        a.config.Redis.Password,
		DB:              a.config.Redis.DB,
		PoolSize:        a.config.Redis.PoolSize,
		MinIdleConns:    a.config.Redis.MinIdleConns,
		ConnectTimeout:  a.config.Redis.ConnectTimeout,
		ReadTimeout:     a.config.Redis.ReadTimeout,
		WriteTimeout:    a.config.Redis.WriteTimeout,
		MaxRetries:      3,
		MinRetryBackoff: 8 * time.Millisecond,
		MaxRetryBackoff: 512 * time.Millisecond,
	}

	client, err := redis.NewClient(redisConfig, a.logger)
	if err != nil {
		return err
	}

	a.redisClient = client
	a.logger.Info("Redis client initialized successfully")
	return nil
}

// closeRedis gracefully closes the Redis client connection.
func (a *Application) closeRedis() {
	if a.redisClient != nil {
		if err := a.redisClient.Close(); err != nil {
			a.logger.Error("Failed to close Redis client", "error", err)
		}
	}
}

// initServer initializes the HTTP server with routes and middleware.
func (a *Application) initServer() error {
	router := a.setupRoutes()
	a.server = &http.Server{
		Addr:         a.config.Server.ServerAddr(),
		Handler:      router,
		ReadTimeout:  a.config.Server.ReadTimeout,
		WriteTimeout: a.config.Server.WriteTimeout,
		IdleTimeout:  a.config.Server.IdleTimeout,
	}

	return nil
}

// setupRoutes configures the HTTP routes and middleware chain.
func (a *Application) setupRoutes() http.Handler {
	mux := http.NewServeMux()
	if a.config.Monitoring.HealthCheckPath != "" {
		mux.HandleFunc(a.config.Monitoring.HealthCheckPath, a.handleHealthCheck)
	}

	if a.config.Monitoring.MetricsEnabled &&
		a.config.Monitoring.MetricsPath != "" {
		mux.HandleFunc(a.config.Monitoring.MetricsPath, a.handleMetrics)
	}

	// Routes (placeholders)
	mux.HandleFunc("/api/", a.handleAPI)
	mux.HandleFunc("/", a.handleRoot)

	return a.applyMiddleware(mux)
}

// applyMiddleware applies the middleware chain to the handler.
// Apply middleware in reverse order (last middleware wraps first)
func (a *Application) applyMiddleware(handler http.Handler) http.Handler {
	handler = a.recoveryMiddleware(handler)
	handler = a.loggingMiddleware(handler)
	handler = a.corsMiddleware(handler)

	return handler
}

// handleHealthCheck provides a health check endpoint.
func (a *Application) handleHealthCheck(w http.ResponseWriter,
	r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var redisHealthy bool
	if a.redisClient != nil {
		if err := a.redisClient.Ping(ctx); err != nil {
			a.logger.Warn("Redis health check failed", "error", err)
		} else {
			redisHealthy = true
		}
	}

	status := "Healthy"
	statusCode := http.StatusOK

	if !redisHealthy {
		status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	response := map[string]any{
		"status":    status,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"service":   "prisma",
		"version":   getVersion(),
		"checks": map[string]any{
			"redis": map[string]any{
				"status": func() string {
					if redisHealthy {
						return "healthy"
					}

					return "unhealthy"
				}(),
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	fmt.Fprintf(w, `{
		"status": "%s",
		"timestamp": "%s",
		"service": "prisma",
		"version": "%s",
		"checks": {
			"redis": {
				"status: "%s"
			}
		}
	`,
		response["status"],
		response["timestamp"],
		response["version"],
		response["checks"].(map[string]any)["redis"].(map[string]any)["status"])
}

// handleMetrics provides metrics endpoint (placeholder implementation).
// TODO: Implement proper metrics collection
func (a *Application) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	stats := a.redisClient.PoolStats()
	fmt.Fprintf(w, "# HELP redis_pool_total_conns Total Redis connections\n")
	fmt.Fprintf(w, "# TYPE redis_pool_total_conns gauge\n")
	fmt.Fprintf(w, "redis_pool_total_conns %d\n", stats.TotalConns)

	fmt.Fprintf(w, "# HELP redis_pool_idle_conns Idle Redis connections\n")
	fmt.Fprintf(w, "# TYPE redis_pool_idle_conns gauge\n")
	fmt.Fprintf(w, "redis_pool_idle_conns %d\n", stats.IdleConns)

	fmt.Fprintf(w, "# HELP redis_pool_stale_conns Stale Redis connections\n")
	fmt.Fprintf(w, "# TYPE redis_pool_stale_conns gauge\n")
	fmt.Fprintf(w, "redis_pool_stale_conns %d\n", stats.StaleConns)
}

// handleAPI handles API requests (placeholder implementation).
// TODO: Implement API routing logic
func (a *Application) handleAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w,
		`{"message": "API Gateway is running", "path": "%s", "method": "%s"}`,
		r.URL.Path, r.Method)
}

// handleRoot handles requests to the root path.
func (a *Application) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{
		"service": "reverse-api-gateway",
		"version": "%s",
		"status": "running",
		"endpoints": {
			"health": "%s",
			"metrics": "%s",
			"api": "/api/"
		}
	}`,
		getVersion(),
		a.config.Monitoring.HealthCheckPath,
		a.config.Monitoring.MetricsPath,
	)
}

// Middleware implementations

// recoveryMiddleware recovers from panics and returns a 500 error.
func (a *Application) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				a.logger.Error("Panic recovered",
					"error", err,
					"path", r.URL.Path,
					"method", r.Method,
				)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `{"error": "Internal server error"}`)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs HTTP requests and responses.
func (a *Application) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)
		duration := time.Since(start)

		a.logger.InfoContext(r.Context(), "HTTP request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.statusCode,
			"duration", duration.String(),
			"user_agent", r.UserAgent(),
			"remote_addr", r.RemoteAddr,
		)
	})
}

// corsMiddleware adds CORS headers to responses.
func (a *Application) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods",
			"GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers",
			"Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code and calls the underlying WriteHeader.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// shutdown gracefully shuts down the HTTP server.
func (a *Application) shutdown() error {
	a.logger.Info("Shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(),
		a.config.Server.GracefulTimeout)
	defer cancel()

	if err := a.server.Shutdown(ctx); err != nil {
		a.logger.Error("Failed to shutdown HTTP server gracefully", "error", err)
		return err
	}

	a.logger.Info("Gateway shutdown completed successfully")
	return nil
}

// getVersion returns the application version.
// In production, this would typically be set at build time using ldflags.
// go build -ldflags "-X main.version=1.0.0"
func getVersion() string {
	// TODO: Set version at build time
	return "dev"
}
