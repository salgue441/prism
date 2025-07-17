package router

import (
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"prism/internal/config"
	"prism/internal/loadbalancer"
	"prism/internal/proxy"
	"sync"

	"github.com/gorilla/mux"
)

// Router handles HTTP routing
type Router struct {
	mux          *mux.Router
	routes       map[string]*Route
	proxy        *proxy.ReverseProxy
	loadBalancer *loadbalancer.LoadBalancer
	logger       *slog.Logger
	mu           sync.RWMutex
}

// New creates a new router instance
func New(logger *slog.Logger) *Router {
	return &Router{
		mux:          mux.NewRouter(),
		routes:       make(map[string]*Route),
		proxy:        proxy.New(logger),
		loadBalancer: loadbalancer.NewLoadBalancer(logger),
		logger:       logger,
	}
}

// NewWithProxyConfig creates a new router with custom proxy configuration
func NewWithProxyConfig(logger *slog.Logger, proxyConfig *proxy.Config) *Router {
	return &Router{
		mux:    mux.NewRouter(),
		routes: make(map[string]*Route),
		proxy:  proxy.NewWithConfig(logger, proxyConfig),
		logger: logger,
	}
}

// AddRoute adds a new route to the router
func (r *Router) AddRoute(routeConfig config.Route) error {
	routeID := routeConfig.ID
	if routeID == "" {
		routeID = fmt.Sprintf("%s-%s", routeConfig.Method, routeConfig.Path)
	}

	var handler http.HandlerFunc
	if routeConfig.Pool != "" {
		handler = r.loadBalancer.CreateHandler(routeConfig.Pool,
			func(target *url.URL, poolName string) http.HandlerFunc {
				return r.proxy.CreateHandler(target, routeConfig.StripPath,
					routeConfig.Path)
			})
	} else if routeConfig.Target != "" {
		targetURL, err := url.Parse(routeConfig.Target)
		if err != nil {
			return fmt.Errorf("invalid target URL %s: %w", routeConfig.Target, err)
		}

		handler = r.proxy.CreateHandler(targetURL, routeConfig.StripPath,
			routeConfig.Path)
	} else {
		return fmt.Errorf("route must specify either 'target' or 'pool'")
	}

	route := &Route{
		ID:        routeID,
		Path:      routeConfig.Path,
		Method:    routeConfig.Method,
		StripPath: routeConfig.StripPath,
		Handler:   handler,
	}

	if route.Method != "" {
		r.mux.HandleFunc(route.Path, route.Handler).Methods(route.Method)
	} else {
		r.mux.HandleFunc(route.Path, route.Handler)
	}

	r.mu.Lock()
	r.routes[route.ID] = route
	r.mu.Unlock()

	target := routeConfig.Target
	if routeConfig.Pool != "" {
		target = fmt.Sprintf("pool:%s", routeConfig.Pool)
	}

	r.logger.Info("Route registered with load balancing",
		slog.String("id", route.ID),
		slog.String("path", route.Path),
		slog.String("method", route.Method),
		slog.String("target", target),
		slog.Bool("strip_path", route.StripPath),
	)

	return nil
}

// RemoveRoute removes a route by ID
func (r *Router) RemoveRoute(routeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[routeID]
	if !exists {
		return fmt.Errorf("route not found: %s", routeID)
	}

	delete(r.routes, routeID)
	r.logger.Info("Route removed",
		slog.String("id", route.ID),
		slog.String("path", route.Path),
	)

	return nil
}

// GetRoute retrieves a route by ID
func (r *Router) GetRoute(routeID string) (*Route, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	route, exists := r.routes[routeID]
	return route, exists
}

// GetRoutes returns all registered routes (thread-safe copy)
func (r *Router) GetRoutes() map[string]*Route {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routesCopy := make(map[string]*Route, len(r.routes))
	maps.Copy(routesCopy, r.routes)

	return routesCopy
}

// Handler returns the HTTP handler
func (r *Router) Handler() http.Handler {
	return r.mux
}

// Close gracefully closes the router and its proxy
func (r *Router) Close() error {
	return r.proxy.Close()
}

// Add method to configure load balancer:
func (r *Router) ConfigureLoadBalancer(config loadbalancer.Config) error {
	err := r.loadBalancer.LoadConfig(config)
	if err != nil {
		return fmt.Errorf("failed to configure load balancer: %w", err)
	}

	r.loadBalancer.StartHealthChecking()
	return nil
}

// Stats

// Stats returns routing statistics
func (r *Router) Stats() RouterStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := RouterStats{
		TotalRoutes:    len(r.routes),
		RoutesByMethod: make(map[string]int),
		ProxyStats:     r.proxy.GetStats(),
	}

	for _, route := range r.routes {
		method := route.Method
		if method == "" {
			method = "ALL"
		}

		stats.RoutesByMethod[method]++
	}

	return stats
}

// RouterStats contains routing statistics
type RouterStats struct {
	TotalRoutes    int              `json:"total_routes"`
	RoutesByMethod map[string]int   `json:"routes_by_method"`
	ProxyStats     proxy.ProxyStats `json:"proxy_stats"`
}
