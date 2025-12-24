// Package main is the entry point for the Prism Gateway service.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/viper"

	"github.com/carlossalguero/prism/internal/gateway/middleware"
	"github.com/carlossalguero/prism/internal/gateway/proxy"
	"github.com/carlossalguero/prism/internal/gateway/router"
	"github.com/carlossalguero/prism/internal/shared/health"
	"github.com/carlossalguero/prism/internal/shared/logger"
)

// Config holds the gateway configuration.
type Config struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`

	Auth struct {
		GRPCAddress string `mapstructure:"grpc_address"`
	} `mapstructure:"auth"`

	RateLimit struct {
		RequestsPerSecond float64 `mapstructure:"requests_per_second"`
		BurstSize         int     `mapstructure:"burst_size"`
	} `mapstructure:"rate_limit"`

	Log struct {
		Level  string `mapstructure:"level"`
		Format string `mapstructure:"format"`
	} `mapstructure:"log"`
}

func main() {
	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger.Init(logger.Config{
		Level:       cfg.Log.Level,
		Format:      cfg.Log.Format,
		ServiceName: "prism-gateway",
		Environment: os.Getenv("ENVIRONMENT"),
	})

	log := logger.Default()
	log.Info("starting prism gateway",
		"host", cfg.Host,
		"port", cfg.Port,
	)

	// Initialize health checker
	healthChecker := health.NewChecker(
		health.WithVersion(version()),
		health.WithTimeout(5*time.Second),
	)

	// Initialize router
	rtr := router.New()

	// Initialize proxy
	prx := proxy.New(proxy.Config{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	})

	// Build middleware chain
	var handler http.Handler = prx

	// Add rate limiting middleware
	rateLimiter := middleware.NewRateLimiter(
		cfg.RateLimit.RequestsPerSecond,
		cfg.RateLimit.BurstSize,
	)
	handler = rateLimiter.Middleware(handler)

	// Add logging middleware
	handler = middleware.Logging(log)(handler)

	// Add recovery middleware
	handler = middleware.Recovery(log)(handler)

	// Add request ID middleware
	handler = middleware.RequestID()(handler)

	// Wrap with router
	handler = rtr.Handler(handler)

	// Create main HTTP server
	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:           handler,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start health check server in background
	go func() {
		healthAddr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port+1000)
		log.Info("starting health check server", "address", healthAddr)
		if err := healthChecker.ServeHTTP(healthAddr); err != nil && err != http.ErrServerClosed {
			log.Error("health check server error", "error", err)
		}
	}()

	// Start main server in background
	go func() {
		log.Info("starting HTTP server", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown servers gracefully
	if err := server.Shutdown(ctx); err != nil {
		log.Error("server shutdown error", "error", err)
	}

	if err := healthChecker.Shutdown(ctx); err != nil {
		log.Error("health checker shutdown error", "error", err)
	}

	log.Info("server stopped")
}

func loadConfig() (*Config, error) {
	viper.SetConfigName("gateway")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath("/etc/prism")

	// Set defaults
	viper.SetDefault("host", "0.0.0.0")
	viper.SetDefault("port", 8080)
	viper.SetDefault("read_timeout", "30s")
	viper.SetDefault("write_timeout", "30s")
	viper.SetDefault("idle_timeout", "120s")
	viper.SetDefault("auth.grpc_address", "localhost:50051")
	viper.SetDefault("rate_limit.requests_per_second", 100)
	viper.SetDefault("rate_limit.burst_size", 200)
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", "json")

	// Bind environment variables
	viper.SetEnvPrefix("GATEWAY")
	viper.AutomaticEnv()

	// Try to read config file (not required)
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	return &cfg, nil
}

func version() string {
	if v := os.Getenv("VERSION"); v != "" {
		return v
	}
	return "dev"
}
