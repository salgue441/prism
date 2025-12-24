// Package main is the entry point for the Prism Auth service.
package main

import (
	"context"
	"crypto/tls"
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
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/carlossalguero/prism/services/auth/internal/jwt"
	"github.com/carlossalguero/prism/services/auth/internal/oauth"
	"github.com/carlossalguero/prism/services/auth/internal/repository"
	"github.com/carlossalguero/prism/services/auth/internal/server"
	"github.com/carlossalguero/prism/services/auth/internal/service"
	"github.com/carlossalguero/prism/services/shared/cache"
	"github.com/carlossalguero/prism/services/shared/events"
	"github.com/carlossalguero/prism/services/shared/health"
	"github.com/carlossalguero/prism/services/shared/logger"
	"github.com/carlossalguero/prism/services/shared/metrics"
	prismtls "github.com/carlossalguero/prism/services/shared/tls"
	"github.com/carlossalguero/prism/services/shared/tracing"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
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

	TLS struct {
		Enabled  bool   `mapstructure:"enabled"`
		CertFile string `mapstructure:"cert_file"`
		KeyFile  string `mapstructure:"key_file"`
		CAFile   string `mapstructure:"ca_file"`
	} `mapstructure:"tls"`

	Redis struct {
		Address      string        `mapstructure:"address"`
		Password     string        `mapstructure:"password"`
		DB           int           `mapstructure:"db"`
		PoolSize     int           `mapstructure:"pool_size"`
		DialTimeout  time.Duration `mapstructure:"dial_timeout"`
		ReadTimeout  time.Duration `mapstructure:"read_timeout"`
		WriteTimeout time.Duration `mapstructure:"write_timeout"`
	} `mapstructure:"redis"`

	NATS struct {
		URL             string        `mapstructure:"url"`
		Name            string        `mapstructure:"name"`
		MaxReconnects   int           `mapstructure:"max_reconnects"`
		ReconnectWait   time.Duration `mapstructure:"reconnect_wait"`
		EnableJetStream bool          `mapstructure:"enable_jetstream"`
	} `mapstructure:"nats"`

	Log struct {
		Level  string `mapstructure:"level"`
		Format string `mapstructure:"format"`
	} `mapstructure:"log"`

	Tracing struct {
		Enabled    bool    `mapstructure:"enabled"`
		Endpoint   string  `mapstructure:"endpoint"`
		SampleRate float64 `mapstructure:"sample_rate"`
		Insecure   bool    `mapstructure:"insecure"`
	} `mapstructure:"tracing"`
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
	log.Info("starting prism auth service",
		"tls_enabled", cfg.TLS.Enabled,
	)

	// Initialize tracing
	var tracingCleanup func(context.Context) error
	if cfg.Tracing.Enabled {
		var err error
		tracingCleanup, err = tracing.InitGlobal(tracing.Config{
			ServiceName:    "prism-auth",
			ServiceVersion: version(),
			Environment:    os.Getenv("ENVIRONMENT"),
			Endpoint:       cfg.Tracing.Endpoint,
			SampleRate:     cfg.Tracing.SampleRate,
			Insecure:       cfg.Tracing.Insecure,
			Enabled:        true,
		})
		if err != nil {
			log.Error("failed to initialize tracing", "error", err)
		} else {
			log.Info("tracing initialized", "endpoint", cfg.Tracing.Endpoint)
		}
	}

	// Initialize metrics
	metricsInstance := metrics.Init(metrics.Config{
		ServiceName: "auth",
		Namespace:   "prism",
		Subsystem:   "auth",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize database connection
	dbPool, err := initDatabase(ctx, cfg)
	if err != nil {
		log.Error("failed to initialize database", "error", err)
		os.Exit(1)
	}
	defer dbPool.Close()

	// Start background goroutine to update DB connection metrics
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				stats := dbPool.Stat()
				metricsInstance.SetDBConnections("postgres",
					int(stats.AcquiredConns()),
					int(stats.IdleConns()),
				)
			case <-ctx.Done():
				return
			}
		}
	}()

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

	// Initialize Redis client (optional - service works without it)
	var cacheClient *cache.Client
	if cfg.Redis.Address != "" {
		var err error
		cacheClient, err = cache.New(cache.Config{
			Address:      cfg.Redis.Address,
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.DB,
			PoolSize:     cfg.Redis.PoolSize,
			DialTimeout:  cfg.Redis.DialTimeout,
			ReadTimeout:  cfg.Redis.ReadTimeout,
			WriteTimeout: cfg.Redis.WriteTimeout,
			KeyPrefix:    "prism:auth:",
		})
		if err != nil {
			log.Warn("failed to connect to Redis, continuing without cache", "error", err)
		} else {
			log.Info("connected to Redis", "address", cfg.Redis.Address)
		}
	}

	// Initialize NATS client (optional - service works without it)
	var eventsClient *events.Client
	if cfg.NATS.URL != "" {
		var err error
		eventsClient, err = events.New(events.Config{
			URL:             cfg.NATS.URL,
			Name:            cfg.NATS.Name,
			MaxReconnects:   cfg.NATS.MaxReconnects,
			ReconnectWait:   cfg.NATS.ReconnectWait,
			EnableJetStream: cfg.NATS.EnableJetStream,
		})
		if err != nil {
			log.Warn("failed to connect to NATS, continuing without events", "error", err)
		} else {
			log.Info("connected to NATS", "url", cfg.NATS.URL)
		}
	}

	// Initialize auth service
	authService := service.New(service.Config{
		Repository:     repo,
		JWTManager:     jwtManager,
		OAuthProviders: oauthProviders,
		Cache:          cacheClient,
		Events:         eventsClient,
	})

	// Initialize health checker
	healthChecker := health.NewChecker(
		health.WithVersion(version()),
		health.WithTimeout(5*time.Second),
	)
	healthChecker.Register("database", health.PostgresCheck(dbPool.Ping))
	if cacheClient != nil {
		healthChecker.Register("redis", health.GRPCCheck(cacheClient.Ping))
	}
	if eventsClient != nil {
		healthChecker.Register("nats", health.GRPCCheck(func(ctx context.Context) error {
			if !eventsClient.IsConnected() {
				return fmt.Errorf("not connected to NATS")
			}
			return nil
		}))
	}

	// Create gRPC server options
	grpcOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			server.LoggingInterceptor(log),
			server.RecoveryInterceptor(log),
			server.MetricsInterceptor(metricsInstance),
		),
	}

	// Add tracing interceptors if enabled
	if cfg.Tracing.Enabled {
		grpcOpts = append(grpcOpts,
			grpc.StatsHandler(otelgrpc.NewServerHandler()),
		)
	}

	// Add TLS if enabled
	var grpcTLSConfig *tls.Config
	if cfg.TLS.Enabled {
		var err error
		grpcTLSConfig, err = prismtls.GRPCServerTLSConfig(&prismtls.Config{
			CertFile: cfg.TLS.CertFile,
			KeyFile:  cfg.TLS.KeyFile,
			CAFile:   cfg.TLS.CAFile,
		})
		if err != nil {
			log.Error("failed to configure gRPC TLS", "error", err)
			os.Exit(1)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(grpcTLSConfig)))
	}

	// Create gRPC server
	grpcServer := grpc.NewServer(grpcOpts...)

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

	// Start health check server with metrics endpoint
	go func() {
		healthAddr := fmt.Sprintf("%s:%d", cfg.GRPC.Host, cfg.GRPC.Port+1000)
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", healthChecker.HealthHandler)
		healthMux.HandleFunc("/health/live", healthChecker.LiveHandler)
		healthMux.HandleFunc("/health/ready", healthChecker.ReadyHandler)
		healthMux.Handle("/metrics", metricsInstance.Handler())

		healthServer := &http.Server{
			Addr:    healthAddr,
			Handler: healthMux,
		}

		log.Info("starting health/metrics server", "address", healthAddr)
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("health server error", "error", err)
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

	// Close Redis connection
	if cacheClient != nil {
		if err := cacheClient.Close(); err != nil {
			log.Error("Redis client close error", "error", err)
		}
	}

	// Close NATS connection
	if eventsClient != nil {
		if err := eventsClient.Close(); err != nil {
			log.Error("NATS client close error", "error", err)
		}
	}

	// Shutdown tracing
	if tracingCleanup != nil {
		if err := tracingCleanup(shutdownCtx); err != nil {
			log.Error("tracing shutdown error", "error", err)
		}
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
	viper.SetDefault("tls.enabled", false)
	viper.SetDefault("redis.address", "")
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.pool_size", 10)
	viper.SetDefault("redis.dial_timeout", "5s")
	viper.SetDefault("redis.read_timeout", "3s")
	viper.SetDefault("redis.write_timeout", "3s")
	viper.SetDefault("nats.url", "")
	viper.SetDefault("nats.name", "prism-auth")
	viper.SetDefault("nats.max_reconnects", 10)
	viper.SetDefault("nats.reconnect_wait", "2s")
	viper.SetDefault("nats.enable_jetstream", true)
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", "json")

	// Tracing defaults
	viper.SetDefault("tracing.enabled", false)
	viper.SetDefault("tracing.endpoint", "localhost:4317")
	viper.SetDefault("tracing.sample_rate", 1.0)
	viper.SetDefault("tracing.insecure", true)

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
