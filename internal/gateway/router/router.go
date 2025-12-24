// Package router provides request routing for the gateway.
package router

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/carlossalguero/prism/internal/gateway/proxy"
	"github.com/carlossalguero/prism/internal/shared/errors"
)

// Route represents a routing rule.
type Route struct {
	ID       string
	Name     string
	Priority int

	// Matching criteria
	Hosts    []string          // Host headers to match
	Paths    []string          // Path prefixes to match
	Methods  []string          // HTTP methods to match
	Headers  map[string]string // Headers to match

	// Target configuration
	Upstream   *Upstream
	StripPath  bool   // Strip matched path prefix
	PathRewrite string // Path rewrite pattern

	// Middleware configuration
	AuthRequired   bool
	RequiredRoles  []string
	RequiredScopes []string
	RateLimitKey   string

	Enabled bool
}

// Upstream represents a backend service.
type Upstream struct {
	ID      string
	Name    string
	Targets []*Target
	lb      *proxy.LoadBalancer
}

// Target represents a single backend server.
type Target struct {
	URL    *url.URL
	Weight int
}

// Router handles request routing.
type Router struct {
	mu        sync.RWMutex
	routes    []*Route
	upstreams map[string]*Upstream
}

// New creates a new router.
func New() *Router {
	return &Router{
		upstreams: make(map[string]*Upstream),
	}
}

// AddRoute adds a route to the router.
func (r *Router) AddRoute(route *Route) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove existing route with same ID
	for i, existing := range r.routes {
		if existing.ID == route.ID {
			r.routes = append(r.routes[:i], r.routes[i+1:]...)
			break
		}
	}

	r.routes = append(r.routes, route)

	// Sort by priority (higher priority first)
	sort.Slice(r.routes, func(i, j int) bool {
		return r.routes[i].Priority > r.routes[j].Priority
	})
}

// RemoveRoute removes a route from the router.
func (r *Router) RemoveRoute(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, route := range r.routes {
		if route.ID == id {
			r.routes = append(r.routes[:i], r.routes[i+1:]...)
			return
		}
	}
}

// GetRoute returns a route by ID.
func (r *Router) GetRoute(id string) *Route {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, route := range r.routes {
		if route.ID == id {
			return route
		}
	}
	return nil
}

// ListRoutes returns all routes.
func (r *Router) ListRoutes() []*Route {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*Route, len(r.routes))
	copy(result, r.routes)
	return result
}

// AddUpstream adds an upstream to the router.
func (r *Router) AddUpstream(upstream *Upstream) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create load balancer for upstream
	targets := make([]*proxy.Target, len(upstream.Targets))
	for i, t := range upstream.Targets {
		targets[i] = &proxy.Target{
			URL:    t.URL,
			Weight: t.Weight,
		}
	}
	upstream.lb = proxy.NewLoadBalancer(targets, proxy.RoundRobin)

	r.upstreams[upstream.ID] = upstream
}

// RemoveUpstream removes an upstream from the router.
func (r *Router) RemoveUpstream(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.upstreams, id)
}

// GetUpstream returns an upstream by ID.
func (r *Router) GetUpstream(id string) *Upstream {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.upstreams[id]
}

// Match finds the best matching route for a request.
func (r *Router) Match(req *http.Request) (*Route, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, route := range r.routes {
		if !route.Enabled {
			continue
		}

		if r.matchRoute(route, req) {
			return route, nil
		}
	}

	return nil, errors.RouteNotFound("no matching route found")
}

func (r *Router) matchRoute(route *Route, req *http.Request) bool {
	// Match hosts
	if len(route.Hosts) > 0 {
		host := req.Host
		if colonIdx := strings.Index(host, ":"); colonIdx != -1 {
			host = host[:colonIdx]
		}

		matched := false
		for _, h := range route.Hosts {
			if matchHost(host, h) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match paths
	if len(route.Paths) > 0 {
		matched := false
		for _, p := range route.Paths {
			if matchPath(req.URL.Path, p) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match methods
	if len(route.Methods) > 0 {
		matched := false
		for _, m := range route.Methods {
			if strings.EqualFold(req.Method, m) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match headers
	for key, value := range route.Headers {
		if req.Header.Get(key) != value {
			return false
		}
	}

	return true
}

// matchHost checks if a host matches a pattern (supports wildcard prefix).
func matchHost(host, pattern string) bool {
	if pattern == "*" {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		// Wildcard subdomain match
		suffix := pattern[1:] // Remove *
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}

	return strings.EqualFold(host, pattern)
}

// matchPath checks if a path matches a pattern (prefix match).
func matchPath(path, pattern string) bool {
	// Exact match
	if path == pattern {
		return true
	}

	// Prefix match
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(path, pattern)
	}

	// Pattern without trailing slash matches path with or without it
	return strings.HasPrefix(path, pattern+"/") || path == pattern
}

// Handler returns an HTTP handler that routes requests.
func (r *Router) Handler(proxyHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		route, err := r.Match(req)
		if err != nil {
			writeRouterError(w, err)
			return
		}

		// Get target URL from upstream
		var targetURL *url.URL
		if route.Upstream != nil && route.Upstream.lb != nil {
			target := route.Upstream.lb.Next()
			if target != nil {
				targetURL = target.URL
			}
		}

		if targetURL == nil {
			writeRouterError(w, errors.NoHealthyTargets("no available upstream targets"))
			return
		}

		// Apply path transformations
		originalPath := req.URL.Path
		if route.StripPath && len(route.Paths) > 0 {
			for _, p := range route.Paths {
				if strings.HasPrefix(originalPath, p) {
					req.URL.Path = strings.TrimPrefix(originalPath, strings.TrimSuffix(p, "/"))
					if req.URL.Path == "" {
						req.URL.Path = "/"
					}
					break
				}
			}
		}

		if route.PathRewrite != "" {
			req.URL.Path = route.PathRewrite
		}

		// Store route info in context for middleware
		ctx := context.WithValue(req.Context(), routeContextKey{}, route)
		ctx = context.WithValue(ctx, proxy.TargetKey, targetURL)

		proxyHandler.ServeHTTP(w, req.WithContext(ctx))
	})
}

// routeContextKey is the context key for route info.
type routeContextKey struct{}

// GetRouteFromContext retrieves the matched route from context.
func GetRouteFromContext(ctx context.Context) *Route {
	if route, ok := ctx.Value(routeContextKey{}).(*Route); ok {
		return route
	}
	return nil
}

func writeRouterError(w http.ResponseWriter, err error) {
	var appErr *errors.Error
	if e, ok := err.(*errors.Error); ok {
		appErr = e
	} else {
		appErr = errors.Internal(err.Error())
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(appErr.HTTPStatusCode())

	response := `{"error":"` + appErr.Message + `","code":"` + string(appErr.Code) + `"}`
	w.Write([]byte(response))
}

// ConfigureFromRoutes configures the router from a list of route configurations.
func (r *Router) ConfigureFromRoutes(routes []RouteConfig) error {
	for _, rc := range routes {
		// Parse upstream targets
		var upstream *Upstream
		if rc.Upstream != "" {
			upstream = r.GetUpstream(rc.Upstream)
			if upstream == nil {
				return errors.InvalidInput("upstream not found: " + rc.Upstream)
			}
		} else if len(rc.Targets) > 0 {
			targets := make([]*Target, 0, len(rc.Targets))
			for _, t := range rc.Targets {
				u, err := url.Parse(t)
				if err != nil {
					return errors.InvalidInput("invalid target URL: " + t)
				}
				targets = append(targets, &Target{URL: u, Weight: 1})
			}
			upstream = &Upstream{
				ID:      rc.ID + "-upstream",
				Name:    rc.Name + " Upstream",
				Targets: targets,
			}
			r.AddUpstream(upstream)
		}

		route := &Route{
			ID:             rc.ID,
			Name:           rc.Name,
			Priority:       rc.Priority,
			Hosts:          rc.Hosts,
			Paths:          rc.Paths,
			Methods:        rc.Methods,
			Headers:        rc.Headers,
			Upstream:       upstream,
			StripPath:      rc.StripPath,
			PathRewrite:    rc.PathRewrite,
			AuthRequired:   rc.AuthRequired,
			RequiredRoles:  rc.RequiredRoles,
			RequiredScopes: rc.RequiredScopes,
			RateLimitKey:   rc.RateLimitKey,
			Enabled:        rc.Enabled,
		}

		r.AddRoute(route)
	}

	return nil
}

// RouteConfig is a configuration-based route definition.
type RouteConfig struct {
	ID             string
	Name           string
	Priority       int
	Hosts          []string
	Paths          []string
	Methods        []string
	Headers        map[string]string
	Upstream       string   // Upstream ID
	Targets        []string // Direct target URLs (alternative to Upstream)
	StripPath      bool
	PathRewrite    string
	AuthRequired   bool
	RequiredRoles  []string
	RequiredScopes []string
	RateLimitKey   string
	Enabled        bool
}
