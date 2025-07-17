package loadbalancer

import (
	"testing"
)

func TestNewBackend(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		weight  int
		wantErr bool
	}{
		{
			name:    "valid HTTP URL",
			url:     "http://localhost:8080",
			weight:  1,
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL",
			url:     "https://api.example.com",
			weight:  2,
			wantErr: false,
		},
		{
			name:    "invalid URL",
			url:     "not-a-url",
			weight:  1,
			wantErr: true,
		},
		{
			name:    "empty URL",
			url:     "",
			weight:  1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := NewBackend(tt.url, tt.weight)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewBackend() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if backend == nil {
					t.Error("NewBackend() returned nil backend")
				}

				if backend.Weight != tt.weight {
					t.Errorf("Expected weight %d, got %d", tt.weight, backend.Weight)
				}

				if !backend.IsHealthy() {
					t.Error("New backend should be healthy by default")
				}

				if backend.URL.String() != tt.url {
					t.Errorf("Expected URL %s, got %s", tt.url, backend.URL.String())
				}
			}
		})
	}
}

func TestBackend_HealthStatus(t *testing.T) {
	backend, err := NewBackend("http://localhost:8080", 1)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	if !backend.IsHealthy() {
		t.Error("New backend should be healthy")
	}

	backend.SetHealthy(false)
	if backend.IsHealthy() {
		t.Error("Backend should be unhealthy after SetHealthy(false)")
	}

	backend.SetHealthy(true)
	if !backend.IsHealthy() {
		t.Error("Backend should be healthy after SetHealthy(true)")
	}
}

func TestBackend_ConnectionManagement(t *testing.T) {
	backend, err := NewBackend("http://localhost:8080", 1)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	if !backend.CanAcceptConnection() {
		t.Error("Healthy backend should accept connections")
	}

	backend.AddConnection()
	backend.AddConnection()

	if backend.ActiveConns != 2 {
		t.Errorf("Expected 2 active connections, got %d", backend.ActiveConns)
	}

	if backend.TotalReqs != 2 {
		t.Errorf("Expected 2 total requests, got %d", backend.TotalReqs)
	}

	backend.RemoveConnection()
	if backend.ActiveConns != 1 {
		t.Errorf("Expected 1 active connection after removal, got %d", backend.ActiveConns)
	}

	backend.MaxConns = 1
	if backend.CanAcceptConnection() {
		t.Error("Backend at max capacity should not accept new connections")
	}

	backend.RemoveConnection()
	if !backend.CanAcceptConnection() {
		t.Error("Backend below max capacity should accept connections")
	}
}

func TestBackend_FailureTracking(t *testing.T) {
	backend, err := NewBackend("http://localhost:8080", 1)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	if backend.Failures != 0 {
		t.Errorf("Expected 0 failures initially, got %d", backend.Failures)
	}

	backend.AddFailure()
	backend.AddFailure()

	if backend.Failures != 2 {
		t.Errorf("Expected 2 failures, got %d", backend.Failures)
	}
}

func TestBackend_Stats(t *testing.T) {
	backend, err := NewBackend("http://localhost:8080", 2)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	backend.AddConnection()
	backend.AddFailure()
	backend.SetHealthy(false)
	stats := backend.GetStats()

	if stats.URL != "http://localhost:8080" {
		t.Errorf("Expected URL in stats, got %s", stats.URL)
	}

	if stats.Weight != 2 {
		t.Errorf("Expected weight 2 in stats, got %d", stats.Weight)
	}

	if stats.Healthy {
		t.Error("Expected unhealthy status in stats")
	}

	if stats.ActiveConns != 1 {
		t.Errorf("Expected 1 active connection in stats, got %d", stats.ActiveConns)
	}

	if stats.Failures != 1 {
		t.Errorf("Expected 1 failure in stats, got %d", stats.Failures)
	}
}
