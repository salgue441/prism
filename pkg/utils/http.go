package utils

import (
	"net"
	"net/http"
	"strings"
)

// GetClientIP extracts the real client IP address from the request
func GetClientIP(r *http.Request) string {
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff != "" {
		ips := strings.Split(xff, ",")
		clientIP := strings.TrimSpace(ips[0])

		if isValidIP(clientIP) {
			return clientIP
		}
	}

	xri := strings.TrimSpace(r.Header.Get("X-Real-IP"))
	if xri != "" && isValidIP(xri) {
		return xri
	}

	cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))
	if cfIP != "" && isValidIP(cfIP) {
		return cfIP
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

// GetScheme determines the request scheme (http or https)
func GetScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}

	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return strings.ToLower(strings.TrimSpace(proto))
	}

	if ssl := r.Header.Get("X-Forwarded-SSL"); ssl == "on" {
		return "https"
	}

	if scheme := r.Header.Get("X-Url-Scheme"); scheme != "" {
		return strings.ToLower(strings.TrimSpace(scheme))
	}

	return "http"
}

// isValidIP checks if the string is a valid IP address
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// GetUserAgent extracts and normalizes the User-Agent header
func GetUserAgent(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("User-Agent"))
}

// GetReferer extracts the Referer header
func GetReferer(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("Referer"))
}

// IsWebSocketRequest checks if the request is a WebSocket upgrade request
func IsWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade" &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}
