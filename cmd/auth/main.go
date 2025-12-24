// Package main is the entry point for the Prism Auth service.
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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/carlossalguero/prism/internal/auth/jwt"
	"github.com/carlossalguero/prism/internal/auth/oauth"
	"github.com/carlossalguero/prism/internal/auth/repository"
	"github.com/carlossalguero/prism/internal/auth/server"
	"github.com/carlossalguero/prism/internal/auth/service"
	"github.com/carlossalguero/prism/internal/shared/health"
	"github.com/carlossalguero/prism/internal/shared/logger"
)

// Config holds the auth service configuration.
type Config struct {
	GRPC struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"grpc"`

	HTTP struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"http"`

	Database struct {
		Host            string        `mapstructure:"host"`
		Port            int           `mapstructure:"port"`
		User            string        `mapstructure:"user"`
		Password        string        `mapstructure:"password"`
		Name            string        `mapstructure:"name"`
		SSLMode         string        `mapstructure:"ssl_mode"`
		MaxOpenConns    int           `mapstructure:"max_open_conns"`
		MaxIdleConns    int           `mapstructure:"max_idle_conns"`
		ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	} `mapstructure:"database"`

	JWT struct {
		PrivateKeyPath  string        `mapstructure:"private_key_path"`
		PublicKeyPath   string        `mapstructure:"public_key_path"`
		AccessTokenTTL  time.Duration `mapstructure:"access_token_ttl"`
		RefreshTokenTTL time.Duration `mapstructure:"refresh_token_ttl"`
		Issuer          string        `mapstructure:"issuer"`
	} `mapstructure:"jwt"`

	OAuth struct {
		Google struct {
			ClientID     string `mapstructure:"client_id"`
			ClientSecret string `mapstructure:"client_secret"`
			RedirectURL  string `mapstructure:"redirect_url"`
		} `mapstructure:"google"`
		GitHub struct {
			ClientID     string `mapstructure:"client_id"`
			ClientSecret string `mapstructure:"client_secret"`
			RedirectURL  string `mapstructure:"redirect_url"`
		} `mapstructure:"github"`
	} `mapstructure:"oauth"`

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
		ServiceName: "prism-auth",
		Environment: os.Getenv("ENVIRONMENT"),
	})

	log := logger.Default()
	log.Info("starting prism auth service")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize database connection
	dbPool, err := initDatabase(ctx, cfg)
	if err != nil {
		log.Error("failed to initialize database", "error", err)
		os.Exit(1)
	}
	defer dbPool.Close()

	// Initialize JWT manager
	jwtManager, err := jwt.NewManager(jwt.Config{
		PrivateKeyPath:  cfg.JWT.PrivateKeyPath,
		PublicKeyPath:   cfg.JWT.PublicKeyPath,
		AccessTokenTTL:  cfg.JWT.AccessTokenTTL,
		RefreshTokenTTL: cfg.JWT.RefreshTokenTTL,
		Issuer:          cfg.JWT.Issuer,
	})
	if err != nil {
		log.Error("failed to initialize JWT manager", "error", err)
		os.Exit(1)
	}

	// Initialize OAuth providers
	oauthProviders := make(map[string]oauth.Provider)

	if cfg.OAuth.Google.ClientID != "" {
		oauthProviders["google"] = oauth.NewGoogleProvider(oauth.GoogleConfig{
			ClientID:     cfg.OAuth.Google.ClientID,
			ClientSecret: cfg.OAuth.Google.ClientSecret,
			RedirectURL:  cfg.OAuth.Google.RedirectURL,
		})
	}

	if cfg.OAuth.GitHub.ClientID != "" {
		oauthProviders["github"] = oauth.NewGitHubProvider(oauth.GitHubConfig{
			ClientID:     cfg.OAuth.GitHub.ClientID,
			ClientSecret: cfg.OAuth.GitHub.ClientSecret,
			RedirectURL:  cfg.OAuth.GitHub.RedirectURL,
		})
	}

	// Initialize repository
	repo := repository.NewPostgres(dbPool)

	// Initialize auth service
	authService := service.New(service.Config{
		Repository:     repo,
		JWTManager:     jwtManager,
		OAuthProviders: oauthProviders,
	})

	// Initialize health checker
	healthChecker := health.NewChecker(
		health.WithVersion(version()),
		health.WithTimeout(5*time.Second),
	)
	healthChecker.Register("database", health.PostgresCheck(dbPool.Ping))

	// Create gRPC server
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			server.LoggingInterceptor(log),
			server.RecoveryInterceptor(log),
		),
	)

	// Register auth service
	authGRPCServer := server.NewAuthServer(authService)
	server.RegisterAuthServer(grpcServer, authGRPCServer)

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

	// Start HTTP server for OAuth callbacks
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/auth/google/callback", authGRPCServer.HandleGoogleCallback)
	httpMux.HandleFunc("/auth/github/callback", authGRPCServer.HandleGitHubCallback)

	httpAddr := fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port)
	httpServer := &http.Server{
		Addr:              httpAddr,
		Handler:           httpMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("starting HTTP server", "address", httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("HTTP server error", "error", err)
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
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Graceful shutdown
	grpcServer.GracefulStop()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error("HTTP server shutdown error", "error", err)
	}

	if err := healthChecker.Shutdown(shutdownCtx); err != nil {
		log.Error("health checker shutdown error", "error", err)
	}

	log.Info("servers stopped")
}

func initDatabase(ctx context.Context, cfg *Config) (*pgxpool.Pool, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.SSLMode,
	)

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing database config: %w", err)
	}

	poolConfig.MaxConns = int32(cfg.Database.MaxOpenConns)
	poolConfig.MinConns = int32(cfg.Database.MaxIdleConns)
	poolConfig.MaxConnLifetime = cfg.Database.ConnMaxLifetime

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return pool, nil
}

func loadConfig() (*Config, error) {
	viper.SetConfigName("auth")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath("/etc/prism")

	// Set defaults
	viper.SetDefault("grpc.host", "0.0.0.0")
	viper.SetDefault("grpc.port", 50051)
	viper.SetDefault("http.host", "0.0.0.0")
	viper.SetDefault("http.port", 8081)
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "prism")
	viper.SetDefault("database.password", "prism_secret")
	viper.SetDefault("database.name", "prism")
	viper.SetDefault("database.ssl_mode", "disable")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", "5m")
	viper.SetDefault("jwt.private_key_path", "./keys/private.pem")
	viper.SetDefault("jwt.public_key_path", "./keys/public.pem")
	viper.SetDefault("jwt.access_token_ttl", "15m")
	viper.SetDefault("jwt.refresh_token_ttl", "168h") // 7 days
	viper.SetDefault("jwt.issuer", "prism")
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", "json")

	// Bind environment variables
	viper.SetEnvPrefix("AUTH")
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
