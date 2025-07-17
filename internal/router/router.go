package router

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"prism/internal/config"
	"prism/internal/proxy"

	"github.com/gorilla/mux"
)

// Router handles HTTP routing
type Router struct {
	mux    *mux.Router
	routes map[string]*Route
	logger *slog.Logger
	proxy  *proxy.ReverseProxy
}

// New creates a new router instance
func New(logger *slog.Logger) *Router {
	return &Router{
		mux:    mux.NewRouter(),
		routes: make(map[string]*Route),
		logger: logger,
		proxy:  proxy.New(logger),
	}
}

// AddRoute adds a new route to the router
func (r *Router) AddRoute(routeConfig config.Route) error {
	targetURL, err := url.Parse(routeConfig.Target)
	if err != nil {
		return fmt.Errorf("invalid target URL %s: %w", routeConfig.Target, err)
	}

	route := &Route{
		ID:        routeConfig.ID,
		Path:      routeConfig.Path,
		Method:    routeConfig.Method,
		Target:    targetURL,
		StripPath: routeConfig.StripPath,
		Handler:   r.proxy.CreateHandler(targetURL, routeConfig.StripPath, routeConfig.Path),
	}

	if route.Method != "" {
		r.mux.HandleFunc(route.Path, route.Handler).Methods(route.Method)
	} else {
		r.mux.HandleFunc(route.Path, route.Handler)
	}

	r.routes[route.ID] = route
	r.logger.Info("Route registered",
		slog.String("id", route.ID),
		slog.String("path", route.Path),
		slog.String("method", route.Method),
		slog.String("target", route.Target.String()),
	)

	return nil
}

// Handler returns the HTTP handler
func (r *Router) Handler() http.Handler {
	return r.mux
}

// GetRoutes returns all registered routes
func (r *Router) GetRoutes() map[string]*Route {
	return r.routes
}
