// Package main is the entry point for the Prism Config service.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/carlossalguero/prism/internal/shared/health"
	"github.com/carlossalguero/prism/internal/shared/logger"
)

// Config holds the config service configuration.
type Config struct {
	GRPC struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"grpc"`

	Consul struct {
		Address    string `mapstructure:"address"`
		Token      string `mapstructure:"token"`
		Datacenter string `mapstructure:"datacenter"`
	} `mapstructure:"consul"`

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
		ServiceName: "prism-config",
		Environment: os.Getenv("ENVIRONMENT"),
	})

	log := logger.Default()
	log.Info("starting prism config service")

	// Initialize Consul client
	consulConfig := api.DefaultConfig()
	consulConfig.Address = cfg.Consul.Address
	if cfg.Consul.Token != "" {
		consulConfig.Token = cfg.Consul.Token
	}
	if cfg.Consul.Datacenter != "" {
		consulConfig.Datacenter = cfg.Consul.Datacenter
	}

	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		log.Error("failed to create Consul client", "error", err)
		os.Exit(1)
	}

	// Verify Consul connection
	_, err = consulClient.Status().Leader()
	if err != nil {
		log.Error("failed to connect to Consul", "error", err)
		os.Exit(1)
	}

	log.Info("connected to Consul", "address", cfg.Consul.Address)

	// Initialize health checker
	healthChecker := health.NewChecker(
		health.WithVersion(version()),
		health.WithTimeout(5*time.Second),
	)
	healthChecker.Register("consul", health.ConsulCheck(consulClient.Status().Leader))

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// TODO: Register config service when implemented
	// configService := configsvc.New(consulClient)
	// configpb.RegisterConfigServiceServer(grpcServer, configService)

	// Enable reflection for development
	if os.Getenv("ENVIRONMENT") != "production" {
		reflection.Register(grpcServer)
	}

	// Start gRPC server
	grpcAddr := fmt.Sprintf("%s:%d", cfg.GRPC.Host, cfg.GRPC.Port)
	grpcListener, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Error("failed to listen for gRPC", "error", err)
		os.Exit(1)
	}

	go func() {
		log.Info("starting gRPC server", "address", grpcAddr)
		if err := grpcServer.Serve(grpcListener); err != nil {
			log.Error("gRPC server error", "error", err)
		}
	}()

	// Start health check server
	go func() {
		healthAddr := fmt.Sprintf("%s:%d", cfg.GRPC.Host, cfg.GRPC.Port+1000)
		log.Info("starting health check server", "address", healthAddr)
		if err := healthChecker.ServeHTTP(healthAddr); err != nil && err != http.ErrServerClosed {
			log.Error("health check server error", "error", err)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down servers...")

	// Create shutdown context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Graceful shutdown
	grpcServer.GracefulStop()

	if err := healthChecker.Shutdown(ctx); err != nil {
		log.Error("health checker shutdown error", "error", err)
	}

	log.Info("servers stopped")
}

func loadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath("/etc/prism")

	// Set defaults
	viper.SetDefault("grpc.host", "0.0.0.0")
	viper.SetDefault("grpc.port", 50052)
	viper.SetDefault("consul.address", "localhost:8500")
	viper.SetDefault("consul.datacenter", "dc1")
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", "json")

	// Bind environment variables
	viper.SetEnvPrefix("CONFIG")
	viper.AutomaticEnv()

	// Try to read config file
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
