package gateway

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"prism/internal/config"
)

func TestGateway_New(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:         8080,
			Host:         "localhost",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		Routes: []config.Route{},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	gateway, err := New(cfg, logger)
	if err != nil {
		t.Errorf("New() error = %v", err)
	}

	if gateway == nil {
		t.Error("New() returned nil gateway")
	}
}

func TestGateway_StartStop(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:         0,
			Host:         "localhost",
			ReadTimeout:  1 * time.Second,
			WriteTimeout: 1 * time.Second,
			IdleTimeout:  1 * time.Second,
		},
		Routes: []config.Route{},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	gateway, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = gateway.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}
