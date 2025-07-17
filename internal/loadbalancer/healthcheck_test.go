package loadbalancer

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestHealthChecker_CheckHealthyBackend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	backend, err := NewBackend(server.URL, 1)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	backend.HealthTimeout = 1 * time.Second
	pool := NewPool(RoundRobin)
	pool.AddBackend(backend)

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	hc := NewHealthChecker(pool, logger)
	hc.checkBackend(backend)

	if !backend.IsHealthy() {
		t.Error("Backend should be healthy after successful health check")
	}
}

func TestHealthChecker_CheckUnhealthyBackend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	backend, err := NewBackend(server.URL, 1)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	backend.HealthTimeout = 1 * time.Second
	pool := NewPool(RoundRobin)
	pool.AddBackend(backend)

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	hc := NewHealthChecker(pool, logger)

	hc.checkBackend(backend)
	if backend.IsHealthy() {
		t.Error("Backend should be unhealthy after failed health check")
	}

	if backend.Failures == 0 {
		t.Error("Backend failure count should be incremented")
	}
}

func TestHealthChecker_CheckUnreachableBackend(t *testing.T) {
	backend, err := NewBackend("http://unreachable-host:99999", 1)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	backend.HealthTimeout = 1 * time.Second
	pool := NewPool(RoundRobin)
	pool.AddBackend(backend)

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	hc := NewHealthChecker(pool, logger)

	hc.checkBackend(backend)
	if backend.IsHealthy() {
		t.Error("Unreachable backend should be marked unhealthy")
	}
}

func TestHealthChecker_StartStop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	backend, err := NewBackend(server.URL, 1)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	backend.HealthInterval = 100 * time.Millisecond
	backend.HealthTimeout = 1 * time.Second
	pool := NewPool(RoundRobin)
	pool.AddBackend(backend)
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	hc := NewHealthChecker(pool, logger)

	hc.Start()
	time.Sleep(300 * time.Millisecond)
	hc.Stop()

	if !backend.IsHealthy() {
		t.Error("Backend should be healthy after health checks")
	}
}
