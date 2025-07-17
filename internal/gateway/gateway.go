package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"prism/internal/config"
	"prism/internal/router"
	"time"
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

// setupRoutes configures all routes
func (g *Gateway) setupRoutes() error {
	for _, route := range g.config.Routes {
		if err := g.router.AddRoute(route); err != nil {
			return fmt.Errorf("failed to add route %s: %w", route.ID, err)
		}
	}

	g.router.Handler().(*http.ServeMux).HandleFunc("/health", g.HealthHandler)
	g.router.Handler().(*http.ServeMux).HandleFunc("/metrics", g.MetricsHandler)

	return nil
}

// setupServer configures the HTTP server with middleware
func (g *Gateway) setupServer() {
	handler := g.router.Handler()
	handler = CORSMiddleware(g.logger)(handler)
	handler = LoggingMiddleware(g.logger)(handler)
	handler = RecoveryMiddleware(g.logger)(handler)

	g.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", g.config.Server.Host, g.config.Server.Port),
		Handler:      handler,
		ReadTimeout:  g.config.Server.ReadTimeout,
		WriteTimeout: g.config.Server.WriteTimeout,
		IdleTimeout:  g.config.Server.IdleTimeout,
	}
}

// Start starts the gateway server
func (g *Gateway) Start() error {
	g.logger.Info("Starting API Gateway",
		slog.String("address", g.server.Addr),
		slog.Int("routes", len(g.router.GetRoutes())),
	)

	if err := g.server.ListenAndServe(); err != nil &&
		err != http.ErrServerClosed {
		return fmt.Errorf("server failed to start: %w", err)
	}

	return nil
}

// Stop gracefully stops the gateway
func (g *Gateway) Stop(ctx context.Context) error {
	g.logger.Info("Stopping API Gateway")
	return g.server.Shutdown(ctx)
}
