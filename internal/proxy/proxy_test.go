package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestReverseProxy_New(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	proxy := New(logger)

	if proxy == nil {
		t.Error("New() returned nil proxy")
	}

	if proxy.logger == nil {
		t.Error("Proxy logger is nil")
	}

	if proxy.client == nil {
		t.Error("Proxy client is nil")
	}
}

func TestReverseProxy_CreateHandler(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "success", "path": "` + r.URL.Path + `"}`))
	}))
	defer backend.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	proxy := New(logger)

	targetURL, _ := url.Parse(backend.URL)
	handler := proxy.CreateHandler(targetURL, false, "/api")
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("X-Test-Header", "test-value")
	
	recorder := httptest.NewRecorder()
	handler(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "success") {
		t.Errorf("Expected response to contain 'success', got: %s", body)
	}
}