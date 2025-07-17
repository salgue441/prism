package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestReverseProxy_FullIntegration(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := map[string]string{
			"method":          r.Method,
			"path":            r.URL.Path,
			"x_forwarded_for": r.Header.Get("X-Forwarded-For"),
			"x_real_ip":       r.Header.Get("X-Real-IP"),
			"x_forwarded_by":  r.Header.Get("X-Forwarded-By"),
		}

		json.NewEncoder(w).Encode(response)
	}))
	defer backend.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	proxy := New(logger)

	targetURL, _ := url.Parse(backend.URL)
	handler := proxy.CreateHandler(targetURL, false, "/api")

	req := httptest.NewRequest("POST", "/api/users",
		strings.NewReader(`{"name":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-client/1.0")
	req.RemoteAddr = "192.168.1.100:12345"

	recorder := httptest.NewRecorder()
	handler(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "POST") {
		t.Errorf("Expected method POST in response, got: %s", body)
	}

	if !strings.Contains(body, "api-gateway") {
		t.Errorf("Expected X-Forwarded-By header in response, got: %s", body)
	}
}

func TestReverseProxy_PathStripping(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(r.URL.Path))
	}))
	defer backend.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	proxy := New(logger)

	targetURL, _ := url.Parse(backend.URL)
	tests := []struct {
		name       string
		stripPath  bool
		routePath  string
		reqPath    string
		expectPath string
	}{
		{
			name:       "strip path enabled",
			stripPath:  true,
			routePath:  "/api",
			reqPath:    "/api/users/123",
			expectPath: "/users/123",
		},
		{
			name:       "strip path disabled",
			stripPath:  false,
			routePath:  "/api",
			reqPath:    "/api/users/123",
			expectPath: "/api/users/123",
		},
		{
			name:       "exact path match with strip",
			stripPath:  true,
			routePath:  "/api/users",
			reqPath:    "/api/users",
			expectPath: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := proxy.CreateHandler(targetURL, tt.stripPath, tt.routePath)

			req := httptest.NewRequest("GET", tt.reqPath, nil)
			recorder := httptest.NewRecorder()
			handler(recorder, req)

			if recorder.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", recorder.Code)
			}

			actualPath := recorder.Body.String()
			if actualPath != tt.expectPath {
				t.Errorf("Expected path %s, got %s", tt.expectPath, actualPath)
			}
		})
	}
}

func TestReverseProxy_ErrorHandling(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	proxy := New(logger)

	targetURL, _ := url.Parse("http://non-existent-host:99999")
	handler := proxy.CreateHandler(targetURL, false, "/api")

	req := httptest.NewRequest("GET", "/api/test", nil)
	recorder := httptest.NewRecorder()
	handler(recorder, req)

	if recorder.Code < 500 {
		t.Errorf("Expected 5xx status for unreachable host, got %d", recorder.Code)
	}

	contentType := recorder.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected JSON content type, got %s", contentType)
	}
}

func TestReverseProxy_Timeout(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	config := DefaultConfig()

	config.RequestTimeout = 500 * time.Millisecond
	proxy := NewWithConfig(logger, config)
	targetURL, _ := url.Parse(backend.URL)
	handler := proxy.CreateHandler(targetURL, false, "/api")
	req := httptest.NewRequest("GET", "/api/test", nil)

	ctx, cancel := context.WithTimeout(req.Context(), 1*time.Second)
	defer cancel()

	req = req.WithContext(ctx)
	recorder := httptest.NewRecorder()
	handler(recorder, req)

	if recorder.Code != http.StatusGatewayTimeout {
		t.Errorf("Expected status 504 Gateway Timeout, got %d", recorder.Code)
	}
}
