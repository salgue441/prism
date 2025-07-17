// Package utils provides common HTTP utilities and helper functions for web
// applications.
//
// This package contains utility functions that are commonly needed when
// building HTTP services, particularly for handling client information,
// request parsing, and response formatting. These utilities are designed
// to be reusable across different projects and components.
//
// HTTP Client Utilities:
//
// Functions for extracting and processing client information from HTTP
// requests:
//
//   - Client IP address extraction with proxy support
//   - Request scheme detection (HTTP/HTTPS)
//   - User agent parsing and normalization
//   - Geolocation from IP addresses (future enhancement)
//
// Request Processing:
//
// Utilities for common request processing tasks:
//
//   - Header parsing and validation
//   - Query parameter extraction and conversion
//   - Request body size limiting and validation
//   - Content type detection and negotiation
//
// Response Helpers:
//
// Functions to simplify HTTP response handling:
//
//   - JSON response encoding with proper headers
//   - Error response formatting with consistent structure
//   - Status code determination based on error types
//   - Response compression and caching headers
//
// Security Utilities:
//
// Helper functions for common security operations:
//
//   - Input sanitization and validation
//   - Header injection prevention
//   - Request rate limiting helpers
//   - CSRF token generation and validation
//
// Client IP Detection:
//
// The GetClientIP function implements a robust algorithm for detecting
// the real client IP address, accounting for various proxy configurations:
//
//  1. X-Forwarded-For header (load balancers, CDNs)
//  2. X-Real-IP header (reverse proxies)
//  3. RemoteAddr field (direct connections)
//
// Example usage:
//
//	// Extract client IP
//	clientIP := utils.GetClientIP(request)
//
//	// Determine request scheme
//	scheme := utils.GetScheme(request)
//
//	// Format JSON response
//	utils.WriteJSONResponse(writer, http.StatusOK, data)
//
//	// Handle errors consistently
//	utils.WriteErrorResponse(writer, err)
//
// Proxy Compatibility:
//
// All utilities are designed to work correctly behind common proxy
// configurations including:
//
//   - Load balancers (HAProxy, nginx, AWS ALB)
//   - CDNs (CloudFlare, CloudFront, Fastly)
//   - Reverse proxies (nginx, Apache, Traefik)
//   - API gateways (Kong, Ambassador, Istio)
//
// Performance:
//
// Utility functions are optimized for performance in high-traffic scenarios:
//
//   - Minimal string allocations and copying
//   - Efficient header parsing algorithms
//   - Cached regex compilation for validation
//   - Reusable buffer pools for response formatting
//
// Thread Safety:
//
// All utility functions are thread-safe and can be called concurrently
// from multiple goroutines without additional synchronization.
package utils
