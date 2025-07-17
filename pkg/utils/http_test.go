package utils

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name: "X-Forwarded-For header",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.1, 10.0.0.1",
			},
			remoteAddr: "127.0.0.1:8080",
			expected:   "192.168.1.1",
		},
		{
			name: "X-Real-IP header",
			headers: map[string]string{
				"X-Real-IP": "192.168.1.2",
			},
			remoteAddr: "127.0.0.1:8080",
			expected:   "192.168.1.2",
		},
		{
			name: "CF-Connecting-IP header",
			headers: map[string]string{
				"CF-Connecting-IP": "192.168.1.3",
			},
			remoteAddr: "127.0.0.1:8080",
			expected:   "192.168.1.3",
		},
		{
			name:       "RemoteAddr fallback",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.4:8080",
			expected:   "192.168.1.4",
		},
		{
			name: "X-Forwarded-For priority",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.1",
				"X-Real-IP":       "192.168.1.2",
			},
			remoteAddr: "127.0.0.1:8080",
			expected:   "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			result := GetClientIP(req)
			if result != tt.expected {
				t.Errorf("GetClientIP() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestGetScheme(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		hasTLS   bool
		expected string
	}{
		{
			name:     "HTTPS with TLS",
			headers:  map[string]string{},
			hasTLS:   true,
			expected: "https",
		},
		{
			name: "X-Forwarded-Proto",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
			},
			hasTLS:   false,
			expected: "https",
		},
		{
			name: "X-Forwarded-SSL",
			headers: map[string]string{
				"X-Forwarded-SSL": "on",
			},
			hasTLS:   false,
			expected: "https",
		},
		{
			name: "X-Url-Scheme",
			headers: map[string]string{
				"X-Url-Scheme": "https",
			},
			hasTLS:   false,
			expected: "https",
		},
		{
			name:     "HTTP fallback",
			headers:  map[string]string{},
			hasTLS:   false,
			expected: "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)

			if tt.hasTLS {
				req.TLS = &tls.ConnectionState{}
			}

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			result := GetScheme(req)
			if result != tt.expected {
				t.Errorf("GetScheme() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsValidIP(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"192.168.1.1", true},
		{"::1", true},
		{"127.0.0.1", true},
		{"2001:db8::1", true},
		{"invalid", false},
		{"", false},
		{"300.300.300.300", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isValidIP(tt.input)
			if result != tt.expected {
				t.Errorf("isValidIP(%s) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsWebSocketRequest(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name: "WebSocket request",
			headers: map[string]string{
				"Connection": "upgrade",
				"Upgrade":    "websocket",
			},
			expected: true,
		},
		{
			name: "Not WebSocket",
			headers: map[string]string{
				"Connection": "keep-alive",
			},
			expected: false,
		},
		{
			name:     "No headers",
			headers:  map[string]string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			result := IsWebSocketRequest(req)
			if result != tt.expected {
				t.Errorf("IsWebSocketRequest() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
