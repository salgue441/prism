package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"prism/internal/config"
	"prism/internal/gateway"
	"prism/pkg/logger"
	"syscall"
	"time"
)

func main() {
	log := logger.New()
	cfg, err := config.Load()

	if err != nil {
		log.Error("Failed to load configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}

	gw, err := gateway.New(cfg, log)
	if err != nil {
		log.Error("Failed to create gateway", slog.String("error", err.Error()))
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := gw.Start(); err != nil {
			log.Error("Gateway failed to start", slog.String("error", err.Error()))
			cancel()
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigChan:
		log.Info("Received shutdown signal")

	case <-ctx.Done():
		log.Info("Context cancelled")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(),
		30*time.Second)
	defer shutdownCancel()

	if err := gw.Stop(shutdownCtx); err != nil {
		log.Error("Failed to stop gateway gracefully",
			slog.String("error", err.Error()))
	}

	log.Info("Gateway stopped successfully")
}
