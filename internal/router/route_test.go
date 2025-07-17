package router

import (
	"net/http"
	"net/url"
	"testing"
)

func TestRoute_Match(t *testing.T) {
	targetURL, _ := url.Parse("http://localhost:3000")

	tests := []struct {
		name     string
		route    Route
		method   string
		path     string
		expected bool
	}{
		{
			name: "exact path match",
			route: Route{
				Path:   "/api/users",
				Method: "GET",
				Target: targetURL,
			},
			method:   "GET",
			path:     "/api/users",
			expected: true,
		},
		{
			name: "method mismatch",
			route: Route{
				Path:   "/api/users",
				Method: "GET",
				Target: targetURL,
			},
			method:   "POST",
			path:     "/api/users",
			expected: false,
		},
		{
			name: "path mismatch",
			route: Route{
				Path:   "/api/users",
				Method: "GET",
				Target: targetURL,
			},
			method:   "GET",
			path:     "/api/orders",
			expected: false,
		},
		{
			name: "prefix match",
			route: Route{
				Path:   "/api/users",
				Method: "",
				Target: targetURL,
			},
			method:   "GET",
			path:     "/api/users/123",
			expected: true,
		},
		{
			name: "any method match",
			route: Route{
				Path:   "/api/users",
				Method: "",
				Target: targetURL,
			},
			method:   "POST",
			path:     "/api/users",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, tt.path, nil)
			result := tt.route.Match(req)
			if result != tt.expected {
				t.Errorf("Route.Match() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestRoute_String(t *testing.T) {
	targetURL, _ := url.Parse("http://localhost:3000")

	tests := []struct {
		name     string
		route    Route
		expected string
	}{
		{
			name: "with method",
			route: Route{
				Path:   "/api/users",
				Method: "GET",
				Target: targetURL,
			},
			expected: "GET /api/users -> http://localhost:3000",
		},
		{
			name: "without method",
			route: Route{
				Path:   "/api/users",
				Method: "",
				Target: targetURL,
			},
			expected: "* /api/users -> http://localhost:3000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.route.String()
			if result != tt.expected {
				t.Errorf("Route.String() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
