package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"prism/internal/config"
	"prism/internal/router"
	"time"

	"github.com/gorilla/mux"
)

// Gateway represents the main gateway instance
type Gateway struct {
	config    *config.Config
	router    *router.Router
	server    *http.Server
	logger    *slog.Logger
	startTime time.Time
}

// New creates a new gateway instance
func New(cfg *config.Config, logger *slog.Logger) (*Gateway, error) {
	r := router.New(logger)
	gateway := &Gateway{
		config:    cfg,
		router:    r,
		logger:    logger,
		startTime: time.Now(),
	}

	if err := gateway.setupRoutes(); err != nil {
		return nil, fmt.Errorf("failed to setup routes: %w", err)
	}

	gateway.setupServer()
	return gateway, nil
}

// Start starts the gateway server
func (g *Gateway) Start() error {
	g.logger.Info("Starting API Gateway",
		slog.String("address", g.server.Addr),
		slog.Int("configured_routes", len(g.config.Routes)),
		slog.String("version", "1.0.0"),
	)

	if err := g.server.ListenAndServe(); err != nil &&
		err != http.ErrServerClosed {
		return fmt.Errorf("HTTP server failed to start: %w", err)
	}

	return nil
}

// Stop gracefully stops the gateway
func (g *Gateway) Stop(ctx context.Context) error {
	g.logger.Info("Shutting down API Gateway...")
	if err := g.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown HTTP server: %w", err)
	}

	g.logger.Info("API Gateway stopped successfully",
		slog.Duration("uptime", time.Since(g.startTime)),
	)

	return nil
}

// GetRouter returns the router instance (for testing)
func (g *Gateway) GetRouter() *router.Router {
	return g.router
}

// GetConfig returns the configuration (for testing)
func (g *Gateway) GetConfig() *config.Config {
	return g.config
}

// Helper methods

// setupServer configures the HTTP server with middleware chain
func (g *Gateway) setupServer() {
	handler := g.router.Handler()
	middlewares := []Middleware{
		SecurityMiddleware(),
		CORSMiddleware(),
		RequestIDMiddleware(),
		LoggingMiddleware(g.logger),
		RecoveryMiddleware(g.logger),
	}

	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}

	addr := fmt.Sprintf("%s:%d", g.config.Server.Host, g.config.Server.Port)
	g.server = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  g.config.Server.ReadTimeout,
		WriteTimeout: g.config.Server.WriteTimeout,
		IdleTimeout:  g.config.Server.IdleTimeout,
		ErrorLog:     nil,
	}

	g.logger.Debug("HTTP server configured",
		slog.String("address", addr),
		slog.Duration("read_timeout", g.config.Server.ReadTimeout),
		slog.Duration("write_timeout", g.config.Server.WriteTimeout),
		slog.Duration("idle_timeout", g.config.Server.IdleTimeout),
	)
}

// setupRoutes configures the HTTP server with middleware
func (g *Gateway) setupRoutes() error {
	for i, route := range g.config.Routes {
		if err := g.router.AddRoute(route); err != nil {
			return fmt.Errorf("failed to add route %d (%s): %w", i, route.ID, err)
		}
	}

	g.addSystemRoutes()
	g.logger.Info("Routes configured successfully",
		slog.Int("total_routes", len(g.config.Routes)),
		slog.Int("system_routes", 3),
	)

	return nil
}

// addSystemRoutes adds built-in system endpoints
func (g *Gateway) addSystemRoutes() {
	mux := g.router.Handler().(*mux.Router)

	mux.HandleFunc("/health", g.HealthHandler).Methods("GET")
	mux.HandleFunc("/metrics", g.MetricsHandler).Methods("GET")
	mux.HandleFunc("/ready", g.ReadinessHandler).Methods("GET")

	g.logger.Debug("System routes registered",
		slog.String("health", "/health"),
		slog.String("metrics", "/metrics"),
		slog.String("readiness", "/ready"),
	)
}
