// Package router provides HTTP request routing and route management for the
// API gateway.
//
// This package implements the routing layer that determines how incoming HTTP
// requests are matched against configured routes and forwarded to appropriate
// backend services. It uses the Gorilla Mux router for flexible and efficient
// URL pattern matching.
//
// Core Components:
//
//	Router - Main routing coordinator that manages route registration and matching
//	Route  - Individual route configuration with matching rules and handlers
//
// Route Matching:
//
// Routes are matched based on several criteria:
//
//   - URL path patterns (exact or prefix matching)
//   - HTTP methods (GET, POST, PUT, DELETE, etc.)
//   - Custom headers (future enhancement)
//
// The router supports both exact path matching and prefix-based routing for
// RESTful API patterns.
//
// Route Configuration:
//
// Each route consists of:
//
//   - Unique identifier for management and debugging
//   - Path pattern to match incoming requests
//   - HTTP method filter (optional, matches all if empty)
//   - Target backend service URL
//   - Path manipulation options (strip prefix, rewrite, etc.)
//
// Dynamic Routing:
//
// The router supports dynamic route registration and removal, enabling
// runtime configuration changes without server restart. Routes can be
// added, modified, or removed through the management API.
//
// Performance Considerations:
//
// The router is optimized for high-throughput scenarios:
//
//   - Efficient pattern matching using Gorilla Mux
//   - Minimal memory allocations during request processing
//   - Connection pooling and reuse for backend connections
//   - Lazy initialization of proxy handlers
//
// Example route configuration:
//
//	route := config.Route{
//	    ID:        "users-api",
//	    Path:      "/api/users",
//	    Method:    "GET",
//	    Target:    "http://users-service:8080",
//	    StripPath: false,
//	}
//
//	router := router.New(logger)
//	err := router.AddRoute(route)
//
// Path Manipulation:
//
// The router supports various path manipulation strategies:
//
//   - Pass-through: Forward the original path unchanged
//   - Strip prefix: Remove the matched portion from the forwarded path
//   - Rewrite: Transform the path using configurable rules
package router
