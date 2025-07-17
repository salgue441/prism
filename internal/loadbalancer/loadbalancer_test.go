package loadbalancer

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestLoadBalancer_LoadConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	lb := NewLoadBalancer(logger)

	config := Config{
		Pools: map[string]PoolConfig{
			"test-pool": {
				Algorithm: RoundRobin,
				Backends: []BackendConfig{
					{URL: "http://localhost:8001", Weight: 1},
					{URL: "http://localhost:8002", Weight: 2},
				},
				HealthCheckEnabled: true,
				HealthInterval:     30 * time.Second,
				HealthPath:         "/health",
			},
		},
	}

	err := lb.LoadConfig(config)
	if err != nil {
		t.Errorf("LoadConfig() error = %v", err)
	}

	pool, exists := lb.GetPool("test-pool")
	if !exists {
		t.Error("Pool 'test-pool' was not created")
	}

	if pool.Algorithm != RoundRobin {
		t.Errorf("Expected algorithm %s, got %s", RoundRobin, pool.Algorithm)
	}

	if len(pool.Backends) != 2 {
		t.Errorf("Expected 2 backends, got %d", len(pool.Backends))
	}
}

func TestLoadBalancer_CreateHandler(t *testing.T) {
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		w.Write([]byte("server1"))
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		w.Write([]byte("server2"))
	}))
	defer server2.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	lb := NewLoadBalancer(logger)

	config := Config{
		Pools: map[string]PoolConfig{
			"test-pool": {
				Algorithm: RoundRobin,
				Backends: []BackendConfig{
					{URL: server1.URL, Weight: 1},
					{URL: server2.URL, Weight: 1},
				},
				HealthCheckEnabled: false,
			},
		},
	}

	err := lb.LoadConfig(config)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	handler := lb.CreateHandler("test-pool", func(target *url.URL,
		poolName string) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp, err := http.Get(target.String())
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}

			defer resp.Body.Close()
			w.WriteHeader(resp.StatusCode)

			body, _ := io.ReadAll(resp.Body)
			w.Write(body)
		})
	})

	responses := make(map[string]int)
	for range 4 {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "127.0.0.1:12345"

		recorder := httptest.NewRecorder()
		handler(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", recorder.Code)
			continue
		}

		body := recorder.Body.String()
		responses[body]++
	}

	if len(responses) != 2 {
		t.Errorf("Expected responses from 2 servers, got %d: %v", len(responses), responses)
	}
}

func TestLoadBalancer_NonExistentPool(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	lb := NewLoadBalancer(logger)

	handler := lb.CreateHandler("non-existent", func(target *url.URL,
		poolName string) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	recorder := httptest.NewRecorder()

	handler(recorder, req)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503 for non-existent pool, got %d", recorder.Code)
	}
}

func TestLoadBalancer_GetStats(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	lb := NewLoadBalancer(logger)

	config := Config{
		Pools: map[string]PoolConfig{
			"pool1": {
				Algorithm: RoundRobin,
				Backends: []BackendConfig{
					{URL: "http://localhost:8001", Weight: 1},
				},
			},
			"pool2": {
				Algorithm: LeastConn,
				Backends: []BackendConfig{
					{URL: "http://localhost:8002", Weight: 1},
					{URL: "http://localhost:8003", Weight: 1},
				},
			},
		},
	}

	err := lb.LoadConfig(config)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	stats := lb.GetStats()

	if len(stats) != 2 {
		t.Errorf("Expected stats for 2 pools, got %d", len(stats))
	}

	pool1Stats, exists := stats["pool1"]
	if !exists {
		t.Error("Stats for pool1 not found")
	} else {
		if pool1Stats.TotalBackends != 1 {
			t.Errorf("Expected 1 backend in pool1, got %d", pool1Stats.TotalBackends)
		}

		if pool1Stats.Algorithm != RoundRobin {
			t.Errorf("Expected algorithm %s for pool1, got %s", RoundRobin, pool1Stats.Algorithm)
		}
	}

	pool2Stats, exists := stats["pool2"]
	if !exists {
		t.Error("Stats for pool2 not found")
	} else {
		if pool2Stats.TotalBackends != 2 {
			t.Errorf("Expected 2 backends in pool2, got %d", pool2Stats.TotalBackends)
		}

		if pool2Stats.Algorithm != LeastConn {
			t.Errorf("Expected algorithm %s for pool2, got %s", LeastConn, pool2Stats.Algorithm)
		}
	}
}

func TestLoadBalancer_Integration(t *testing.T) {
	servers := make([]*httptest.Server, 3)
	for i := range servers {
		serverID := i + 1
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"server_id": %d, "path": "%s"}`, serverID, r.URL.Path)
		}))
	}

	defer func() {
		for _, server := range servers {
			server.Close()
		}
	}()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	lb := NewLoadBalancer(logger)
	config := Config{
		Pools: map[string]PoolConfig{
			"api-pool": {
				Algorithm: RoundRobin,
				Backends: []BackendConfig{
					{URL: servers[0].URL, Weight: 1},
					{URL: servers[1].URL, Weight: 1},
					{URL: servers[2].URL, Weight: 1},
				},
				HealthCheckEnabled: false,
			},
		},
	}

	err := lb.LoadConfig(config)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	handler := lb.CreateHandler("api-pool", func(target *url.URL,
		poolName string) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendURL := fmt.Sprintf("%s%s", target.String(), r.URL.Path)
			resp, err := http.Get(backendURL)
			if err != nil {
				http.Error(w, fmt.Sprintf("Backend error: %v", err), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			w.WriteHeader(resp.StatusCode)

			body, _ := io.ReadAll(resp.Body)
			w.Write(body)
		})
	})

	serverCounts := make(map[string]int)
	numRequests := 9

	for i := range numRequests {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = fmt.Sprintf("192.168.1.%d:12345", 100+i)

		recorder := httptest.NewRecorder()
		handler(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("Request %d: expected status 200, got %d", i, recorder.Code)
			continue
		}

		body := recorder.Body.String()
		serverCounts[body]++
	}

	expectedPerServer := numRequests / len(servers)
	for serverResponse, count := range serverCounts {
		if count != expectedPerServer {
			t.Errorf("Server response %s: expected %d requests, got %d", serverResponse, expectedPerServer, count)
		}
	}

	if len(serverCounts) != len(servers) {
		t.Errorf("Expected responses from %d servers, got %d", len(servers),
			len(serverCounts))
	}
}
