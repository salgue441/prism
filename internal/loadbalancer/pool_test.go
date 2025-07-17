package loadbalancer

import (
	"testing"
)

func TestNewPool(t *testing.T) {
	pool := NewPool(RoundRobin)

	if pool == nil {
		t.Error("NewPool() returned nil")
	}

	if pool.Algorithm != RoundRobin {
		t.Errorf("Expected algorithm %s, got %s", RoundRobin, pool.Algorithm)
	}

	if len(pool.Backends) != 0 {
		t.Errorf("Expected 0 backends initially, got %d", len(pool.Backends))
	}
}

func TestPool_AddRemoveBackend(t *testing.T) {
	pool := NewPool(RoundRobin)

	backend1, _ := NewBackend("http://localhost:8001", 1)
	backend2, _ := NewBackend("http://localhost:8002", 1)
	pool.AddBackend(backend1)
	pool.AddBackend(backend2)

	if len(pool.Backends) != 2 {
		t.Errorf("Expected 2 backends, got %d", len(pool.Backends))
	}

	err := pool.RemoveBackend("http://localhost:8001")
	if err != nil {
		t.Errorf("Failed to remove backend: %v", err)
	}

	if len(pool.Backends) != 1 {
		t.Errorf("Expected 1 backend after removal, got %d", len(pool.Backends))
	}

	err = pool.RemoveBackend("http://localhost:9999")
	if err == nil {
		t.Error("Expected error when removing non-existent backend")
	}
}

func TestPool_RoundRobin(t *testing.T) {
	pool := NewPool(RoundRobin)
	backend1, _ := NewBackend("http://localhost:8001", 1)
	backend2, _ := NewBackend("http://localhost:8002", 1)
	backend3, _ := NewBackend("http://localhost:8003", 1)

	pool.AddBackend(backend1)
	pool.AddBackend(backend2)
	pool.AddBackend(backend3)

	expectedOrder := []string{
		"http://localhost:8001",
		"http://localhost:8002",
		"http://localhost:8003",
		"http://localhost:8001", 
	}

	for i, expected := range expectedOrder {
		backend, err := pool.GetNextBackend("127.0.0.1")
		if err != nil {
			t.Errorf("GetNextBackend() error = %v", err)
			continue
		}

		if backend.URL.String() != expected {
			t.Errorf("Round %d: expected %s, got %s", i, expected, 
			backend.URL.String())
		}
	}
}

func TestPool_WeightedRoundRobin(t *testing.T) {
	pool := NewPool(WeightedRound)
	backend1, _ := NewBackend("http://localhost:8001", 1) 
	backend2, _ := NewBackend("http://localhost:8002", 3) 

	pool.AddBackend(backend1)
	pool.AddBackend(backend2)
	selections := make(map[string]int)
	rounds := 40

	for i := 0; i < rounds; i++ {
		backend, err := pool.GetNextBackend("127.0.0.1")
		if err != nil {
			t.Errorf("GetNextBackend() error = %v", err)
			continue
		}

		selections[backend.URL.String()]++
	}

	expected1 := rounds / 4       
	expected2 := (rounds * 3) / 4 

	if selections["http://localhost:8001"] != expected1 {
		t.Errorf("Expected backend1 selected %d times, got %d", expected1, selections["http://localhost:8001"])
	}

	if selections["http://localhost:8002"] != expected2 {
		t.Errorf("Expected backend2 selected %d times, got %d", expected2, selections["http://localhost:8002"])
	}
}

func TestPool_LeastConnections(t *testing.T) {
	pool := NewPool(LeastConn)

	backend1, _ := NewBackend("http://localhost:8001", 1)
	backend2, _ := NewBackend("http://localhost:8002", 1)
	pool.AddBackend(backend1)
	pool.AddBackend(backend2)

	chosen, err := pool.GetNextBackend("127.0.0.1")
	if err != nil {
		t.Fatalf("GetNextBackend() error = %v", err)
	}

	chosen.AddConnection()
	chosen.AddConnection()

	next, err := pool.GetNextBackend("127.0.0.1")
	if err != nil {
		t.Fatalf("GetNextBackend() error = %v", err)
	}

	if next == chosen {
		t.Error("Least connections should choose backend with fewer connections")
	}
}

func TestPool_IPHash(t *testing.T) {
	pool := NewPool(IPHash)

	backend1, _ := NewBackend("http://localhost:8001", 1)
	backend2, _ := NewBackend("http://localhost:8002", 1)

	pool.AddBackend(backend1)
	pool.AddBackend(backend2)
	clientIP := "192.168.1.100"

	first, err := pool.GetNextBackend(clientIP)
	if err != nil {
		t.Fatalf("GetNextBackend() error = %v", err)
	}

	for range 5 {
		backend, err := pool.GetNextBackend(clientIP)
		if err != nil {
			t.Errorf("GetNextBackend() error = %v", err)
			continue
		}

		if backend != first {
			t.Error("IP hash should consistently return same backend for same IP")
		}
	}

	different, err := pool.GetNextBackend("192.168.1.200")
	if err != nil {
		t.Fatalf("GetNextBackend() error = %v", err)
	}

	// Note: We can't guarantee it's different due to hash collisions,
	// but the algorithm should be consistent for each IP
	_ = different
}

func TestPool_NoHealthyBackends(t *testing.T) {
	pool := NewPool(RoundRobin)

	backend1, _ := NewBackend("http://localhost:8001", 1)
	backend2, _ := NewBackend("http://localhost:8002", 1)
	backend1.SetHealthy(false)
	backend2.SetHealthy(false)

	pool.AddBackend(backend1)
	pool.AddBackend(backend2)

	_, err := pool.GetNextBackend("127.0.0.1")
	if err == nil {
		t.Error("Expected error when no healthy backends available")
	}
}

func TestPool_Stats(t *testing.T) {
	pool := NewPool(RoundRobin)

	backend1, _ := NewBackend("http://localhost:8001", 1)
	backend2, _ := NewBackend("http://localhost:8002", 1)
	backend2.SetHealthy(false) 

	pool.AddBackend(backend1)
	pool.AddBackend(backend2)
	stats := pool.GetStats()

	if stats.TotalBackends != 2 {
		t.Errorf("Expected 2 total backends, got %d", stats.TotalBackends)
	}

	if stats.HealthyBackends != 1 {
		t.Errorf("Expected 1 healthy backend, got %d", stats.HealthyBackends)
	}

	if stats.Algorithm != RoundRobin {
		t.Errorf("Expected algorithm %s, got %s", RoundRobin, stats.Algorithm)
	}

	if len(stats.BackendStats) != 2 {
		t.Errorf("Expected 2 backend stats, got %d", len(stats.BackendStats))
	}
}
