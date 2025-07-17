// Package proxy provides reverse proxy functionality for forwarding requests
// to backend services.
//
// This package implements the reverse proxy layer that handles the actual
// forwarding of HTTP requests to backend services. It wraps Go's standard
// library httputil.ReverseProxy with additional features for header
// manipulation, error handling, and request transformation.
//
// Key Features:
//
//   - HTTP/HTTPS request forwarding
//   - Automatic header management (X-Forwarded-*, X-Real-IP)
//   - Path manipulation and rewriting
//   - Connection pooling and keep-alive
//   - Error handling and fallback responses
//   - Request/response transformation hooks
//
// Header Management:
//
// The proxy automatically manages forwarding headers to provide backend
// services with client information:
//
//	X-Forwarded-Host  - Original host header from client
//	X-Forwarded-Proto - Original protocol (http/https)
//	X-Forwarded-For   - Client IP and proxy chain
//	X-Real-IP         - Direct client IP address
//
// Path Transformation:
//
// The proxy supports several path transformation modes:
//
//  1. Pass-through: Forward the complete original path
//  2. Strip prefix: Remove the routing prefix from the forwarded path
//  3. Rewrite: Apply custom transformation rules to the path
//
// Connection Management:
//
// The proxy leverages Go's built-in HTTP client for efficient connection
// management:
//
//   - Connection pooling and reuse
//   - Keep-alive connections
//   - Configurable timeouts
//   - Automatic retry logic (future enhancement)
//
// Error Handling:
//
// The proxy provides comprehensive error handling for common failure scenarios:
//
//   - Backend service unavailable (503 Service Unavailable)
//   - Connection timeouts (504 Gateway Timeout)
//   - Invalid responses (502 Bad Gateway)
//   - Circuit breaker activation (future enhancement)
//
// Performance Optimizations:
//
//   - Zero-copy request/response streaming
//   - Minimal memory allocations
//   - Efficient header manipulation
//   - Connection reuse across requests
//
// Example usage:
//
//	proxy := proxy.New(logger)
//	targetURL, _ := url.Parse("http://backend-service:8080")
//
//	handler := proxy.CreateHandler(targetURL, false, "/api")
//	http.HandleFunc("/api/", handler)
//
// Security Considerations:
//
// The proxy includes security features to protect against common attacks:
//
//   - Header sanitization to prevent injection
//   - Request size limiting
//   - Timeout enforcement to prevent resource exhaustion
//   - Host header validation
package proxy
