package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"prism/internal/config"
	"prism/internal/gateway"
	"prism/pkg/logger"
	"syscall"
	"time"
)

var (
	configFile = flag.String("config", "", "Path to configuration file")
	logLevel   = flag.String("log-level", "info",
		"Log level (debug, info, warn, error)")
	version = flag.Bool("version", false, "Show version information")
)

const (
	appName    = "api-gateway"
	appVersion = "1.0.0"
)

func main() {
	flag.Parse()
	if *version {
		println(fmt.Sprintf("%s version %s", appName, appVersion))
		os.Exit(0)
	}

	if *configFile != "" {
		os.Setenv("CONFIG_FILE", *configFile)
	}

	log := logger.NewWithConfig(logger.Config{
		Level:  *logLevel,
		Format: "json",
		Source: *logLevel == "debug",
	})

	cfg, err := config.Load()
	if err != nil {
		log.Error("Failed to load configuration",
			slog.String("error", err.Error()))
		os.Exit(1)
	}

	log.Info("Configuration loaded successfully",
		slog.String("config_source", getConfigSource()),
		slog.Int("routes_count", len(cfg.Routes)),
		slog.Int("server_port", cfg.Server.Port),
	)

	gw, err := gateway.New(cfg, log)
	if err != nil {
		log.Error("Failed to create gateway instance",
			slog.String("error", err.Error()))
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErrors := make(chan error, 1)
	go func() {
		if err := gw.Start(); err != nil {
			serverErrors <- err
		}
	}()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		log.Error("Server error", slog.String("error", err.Error()))
		cancel()

	case sig := <-signalChan:
		log.Info("Received shutdown signal", slog.String("signal", sig.String()))
		cancel()

	case <-ctx.Done():
		log.Info("Shutdown initiated")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(),
		30*time.Second)
	defer shutdownCancel()

	if err := gw.Stop(shutdownCtx); err != nil {
		log.Error("Failed to shutdown gracefully",
			slog.String("error", err.Error()))
		os.Exit(1)
	}

	log.Info("Gateway shutdown completed successfully")
}

// getConfigSource returns the configuration source for logging
func getConfigSource() string {
	if configFile := os.Getenv("CONFIG_FILE"); configFile != "" {
		return configFile
	}
	if _, err := os.Stat("configs/config.json"); err == nil {
		return "configs/config.json"
	}

	return "environment_variables"
}
