// Package main is the entry point for the Prism Gateway service.
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/viper"

	"github.com/carlossalguero/prism/services/gateway/internal/auth"
	"github.com/carlossalguero/prism/services/gateway/internal/circuitbreaker"
	"github.com/carlossalguero/prism/services/gateway/internal/config"
	"github.com/carlossalguero/prism/services/gateway/internal/dashboard"
	"github.com/carlossalguero/prism/services/gateway/internal/middleware"
	"github.com/carlossalguero/prism/services/gateway/internal/mirror"
	"github.com/carlossalguero/prism/services/gateway/internal/proxy"
	"github.com/carlossalguero/prism/services/gateway/internal/router"
	"github.com/carlossalguero/prism/services/shared/cache"
	"github.com/carlossalguero/prism/services/shared/events"
	"github.com/carlossalguero/prism/services/shared/health"
	"github.com/carlossalguero/prism/services/shared/logger"
	"github.com/carlossalguero/prism/services/shared/metrics"
	"github.com/carlossalguero/prism/services/shared/tls"
	"github.com/carlossalguero/prism/services/shared/tracing"
)

// Config holds the gateway configuration.
type Config struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`

	TLS struct {
		Enabled  bool   `mapstructure:"enabled"`
		CertFile string `mapstructure:"cert_file"`
		KeyFile  string `mapstructure:"key_file"`
		CAFile   string `mapstructure:"ca_file"`
	} `mapstructure:"tls"`

	Auth struct {
		GRPCAddress string `mapstructure:"grpc_address"`
	} `mapstructure:"auth"`

	RateLimit struct {
		RequestsPerSecond float64 `mapstructure:"requests_per_second"`
		BurstSize         int     `mapstructure:"burst_size"`
	} `mapstructure:"rate_limit"`

	CircuitBreaker struct {
		FailureThreshold    int           `mapstructure:"failure_threshold"`
		SuccessThreshold    int           `mapstructure:"success_threshold"`
		Timeout             time.Duration `mapstructure:"timeout"`
		MaxHalfOpenRequests int           `mapstructure:"max_half_open_requests"`
	} `mapstructure:"circuit_breaker"`

	Log struct {
		Level  string `mapstructure:"level"`
		Format string `mapstructure:"format"`
	} `mapstructure:"log"`

	Redis struct {
		Address      string        `mapstructure:"address"`
		Password     string        `mapstructure:"password"`
		DB           int           `mapstructure:"db"`
		PoolSize     int           `mapstructure:"pool_size"`
		MinIdleConns int           `mapstructure:"min_idle_conns"`
		DialTimeout  time.Duration `mapstructure:"dial_timeout"`
		ReadTimeout  time.Duration `mapstructure:"read_timeout"`
		WriteTimeout time.Duration `mapstructure:"write_timeout"`
	} `mapstructure:"redis"`

	NATS struct {
		URL           string        `mapstructure:"url"`
		Name          string        `mapstructure:"name"`
		ReconnectWait time.Duration `mapstructure:"reconnect_wait"`
		MaxReconnects int           `mapstructure:"max_reconnects"`
	} `mapstructure:"nats"`

	Tracing struct {
		Enabled    bool    `mapstructure:"enabled"`
		Endpoint   string  `mapstructure:"endpoint"`
		SampleRate float64 `mapstructure:"sample_rate"`
		Insecure   bool    `mapstructure:"insecure"`
	} `mapstructure:"tracing"`

	ConfigService struct {
		GRPCAddress   string        `mapstructure:"grpc_address"`
		Timeout       time.Duration `mapstructure:"timeout"`
		RetryInterval time.Duration `mapstructure:"retry_interval"`
		MaxRetries    int           `mapstructure:"max_retries"`
	} `mapstructure:"config_service"`
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
		"tls_enabled", cfg.TLS.Enabled,
	)

	// Initialize tracing
	var tracingCleanup func(context.Context) error
	if cfg.Tracing.Enabled {
		var err error
		tracingCleanup, err = tracing.InitGlobal(tracing.Config{
			ServiceName:    "prism-gateway",
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
		ServiceName: "gateway",
		Namespace:   "prism",
		Subsystem:   "gateway",
	})

	// Initialize Redis cache client (optional)
	var cacheClient *cache.Client
	if cfg.Redis.Address != "" {
		var err error
		cacheClient, err = cache.New(cache.Config{
			Address:      cfg.Redis.Address,
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.DB,
			PoolSize:     cfg.Redis.PoolSize,
			MinIdleConns: cfg.Redis.MinIdleConns,
			DialTimeout:  cfg.Redis.DialTimeout,
			ReadTimeout:  cfg.Redis.ReadTimeout,
			WriteTimeout: cfg.Redis.WriteTimeout,
		})
		if err != nil {
			log.Warn("failed to connect to Redis, cache disabled", "error", err)
		} else {
			log.Info("connected to Redis", "address", cfg.Redis.Address)
		}
	}

	// Initialize NATS events client (optional)
	var eventsClient *events.Client
	if cfg.NATS.URL != "" {
		var err error
		eventsClient, err = events.New(events.Config{
			URL:           cfg.NATS.URL,
			Name:          cfg.NATS.Name,
			ReconnectWait: cfg.NATS.ReconnectWait,
			MaxReconnects: cfg.NATS.MaxReconnects,
		})
		if err != nil {
			log.Warn("failed to connect to NATS, events disabled", "error", err)
		} else {
			log.Info("connected to NATS", "url", cfg.NATS.URL)
		}
	}

	// Initialize circuit breaker registry
	cbConfig := circuitbreaker.Config{
		FailureThreshold:    cfg.CircuitBreaker.FailureThreshold,
		SuccessThreshold:    cfg.CircuitBreaker.SuccessThreshold,
		Timeout:             cfg.CircuitBreaker.Timeout,
		MaxHalfOpenRequests: cfg.CircuitBreaker.MaxHalfOpenRequests,
		OnStateChange: func(name string, from, to circuitbreaker.State) {
			log.Info("circuit breaker state changed",
				"name", name,
				"from", from.String(),
				"to", to.String(),
			)
			metricsInstance.SetCircuitBreakerState(name, int(to))
			if to == circuitbreaker.StateOpen {
				metricsInstance.RecordCircuitBreakerTrip(name)
			}
		},
	}
	cbRegistry := circuitbreaker.NewRegistry(cbConfig)

	// Initialize health checker
	healthChecker := health.NewChecker(
		health.WithVersion(version()),
		health.WithTimeout(5*time.Second),
	)

	// Register infrastructure health checks
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

	// Initialize auth validator
	var authValidator *auth.Validator
	if cfg.Auth.GRPCAddress != "" {
		validatorCfg := auth.Config{
			AuthServiceAddress: cfg.Auth.GRPCAddress,
		}
		if cacheClient != nil {
			validatorCfg.Cache = cacheClient
		}
		var err error
		authValidator, err = auth.NewValidator(validatorCfg)
		if err != nil {
			log.Error("failed to create auth validator", "error", err)
			os.Exit(1)
		}
		log.Info("auth validator initialized", "auth_service", cfg.Auth.GRPCAddress)
	}

	// Initialize router
	rtr := router.New()

	// Initialize dynamic rate limit manager
	rateLimitMgr := config.NewRateLimitManager(log)
	rateLimitMgr.SetMetrics(metricsInstance)

	// Initialize config manager (if Config Service is configured)
	var configMgr *config.Manager
	if cfg.ConfigService.GRPCAddress != "" {
		configMgr = config.NewManager(config.ManagerConfig{
			Client: config.ClientConfig{
				Address:       cfg.ConfigService.GRPCAddress,
				Timeout:       cfg.ConfigService.Timeout,
				RetryInterval: cfg.ConfigService.RetryInterval,
				MaxRetries:    cfg.ConfigService.MaxRetries,
			},
			Router:      rtr,
			RateLimiter: rateLimitMgr,
			Events:      eventsClient,
			Logger:      log,
		})

		// Start config manager (connects and loads initial config)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := configMgr.Start(ctx); err != nil {
			log.Warn("failed to start config manager, continuing without dynamic config", "error", err)
			configMgr = nil
		} else {
			log.Info("config manager started",
				"routes", rtr.RouteCount(),
				"upstreams", rtr.UpstreamCount(),
				"rate_limit_rules", rateLimitMgr.RuleCount(),
			)

			// Start watching for config updates
			configMgr.StartWatching(context.Background())
		}
		cancel()
	}

	// Initialize mirror handler for traffic mirroring
	mirrorHandler := mirror.NewHandler(mirror.HandlerConfig{
		Transport: &http.Transport{
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     30 * time.Second,
		},
		Logger:  log,
		Metrics: metricsInstance,
		Events:  eventsClient,
		UpstreamResolver: func(upstreamID string) *url.URL {
			if u := rtr.GetUpstream(upstreamID); u != nil && len(u.Targets) > 0 {
				// Use first target for simplicity (could use load balancer)
				return u.Targets[0].URL
			}
			return nil
		},
		MaxBodySize: 10 * 1024 * 1024, // 10MB
	})
	log.Info("mirror handler initialized")

	// Initialize proxy with circuit breaker and mirror handler
	prx := proxy.New(proxy.Config{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
		CircuitBreakerRegistry: cbRegistry,
		MirrorHandler:          mirrorHandler,
	})

	// Build middleware chain
	var handler http.Handler = prx

	// Add request events middleware (if NATS is available)
	if eventsClient != nil {
		handler = middleware.Events(middleware.EventsConfig{
			Publisher: eventsClient,
			Subject:   "prism.gateway.request.logged",
		})(handler)
	}

	// Add auth middleware (if validator is available)
	if authValidator != nil {
		handler = middleware.Auth(middleware.AuthConfig{
			Validator: authValidator,
			Logger:    log,
			SkipPaths: []string{"/health", "/health/live", "/health/ready", "/metrics"},
		})(handler)
	}

	// Add rate limiting middleware
	// Use dynamic rate limiter if config manager is available, otherwise fall back to static
	if configMgr != nil {
		// Dynamic rate limiting based on route configuration
		getRuleID := func(r *http.Request) string {
			if route := router.GetRouteFromContext(r.Context()); route != nil {
				return route.RateLimitKey
			}
			return ""
		}
		getUserID := func(r *http.Request) string {
			if userInfo := middleware.GetUserInfo(r.Context()); userInfo != nil {
				return userInfo.ID
			}
			return ""
		}
		handler = rateLimitMgr.Middleware(getRuleID, getUserID)(handler)
	} else {
		// Fallback to static rate limiter
		rateLimiter := middleware.NewRateLimiter(
			cfg.RateLimit.RequestsPerSecond,
			cfg.RateLimit.BurstSize,
		)
		rateLimiter.SetMetrics(metricsInstance)
		handler = rateLimiter.Middleware(handler)
	}

	// Add metrics middleware
	handler = metricsInstance.HTTPMiddleware(handler)

	// Add logging middleware
	handler = middleware.Logging(log)(handler)

	// Add recovery middleware
	handler = middleware.Recovery(log)(handler)

	// Add request ID middleware
	handler = middleware.RequestID()(handler)

	// Add tracing middleware (outermost to capture full request lifecycle)
	if cfg.Tracing.Enabled {
		handler = middleware.Tracing(middleware.TracingConfig{
			ServiceName: "prism-gateway",
			SkipPaths:   []string{"/health", "/health/live", "/health/ready", "/metrics"},
		})(handler)
	}

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

	// Configure TLS if enabled
	if cfg.TLS.Enabled {
		tlsConfig, err := tls.ServerTLSConfig(&tls.Config{
			CertFile: cfg.TLS.CertFile,
			KeyFile:  cfg.TLS.KeyFile,
			CAFile:   cfg.TLS.CAFile,
		})
		if err != nil {
			log.Error("failed to configure TLS", "error", err)
			os.Exit(1)
		}
		server.TLSConfig = tlsConfig
	}

	// Initialize dashboard API
	dashboardAPI := dashboard.New(dashboard.Config{
		Router:         rtr,
		Metrics:        metricsInstance,
		CircuitBreaker: cbRegistry,
		Version:        version(),
		Logger:         log,
	})

	// Start health check server with metrics and dashboard endpoints in background
	go func() {
		healthAddr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port+1000)
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", healthChecker.HealthHandler)
		healthMux.HandleFunc("/health/live", healthChecker.LiveHandler)
		healthMux.HandleFunc("/health/ready", healthChecker.ReadyHandler)
		healthMux.Handle("/metrics", metricsInstance.Handler())

		// Register dashboard API routes
		dashboardAPI.RegisterRoutes(healthMux)

		healthServer := &http.Server{
			Addr:    healthAddr,
			Handler: healthMux,
		}

		log.Info("starting health/metrics/dashboard server", "address", healthAddr)
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("health server error", "error", err)
		}
	}()

	// Start main server in background
	go func() {
		log.Info("starting HTTP server", "address", server.Addr, "tls", cfg.TLS.Enabled)
		var err error
		if cfg.TLS.Enabled {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal or SIGHUP for reload
	quit := make(chan os.Signal, 1)
	reload := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(reload, syscall.SIGHUP)

	// Handle signals
	for {
		select {
		case <-reload:
			if configMgr != nil {
				log.Info("received SIGHUP, triggering config reload")
				if err := configMgr.TriggerReload(context.Background()); err != nil {
					log.Error("config reload failed", "error", err)
				} else {
					log.Info("config reload completed",
						"routes", rtr.RouteCount(),
						"upstreams", rtr.UpstreamCount(),
					)
				}
			} else {
				log.Warn("received SIGHUP but config manager is not running")
			}
		case <-quit:
			goto shutdown
		}
	}

shutdown:
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

	// Close auth validator connection
	if authValidator != nil {
		if err := authValidator.Close(); err != nil {
			log.Error("auth validator close error", "error", err)
		}
	}

	// Close Redis connection
	if cacheClient != nil {
		if err := cacheClient.Close(); err != nil {
			log.Error("redis close error", "error", err)
		}
	}

	// Close NATS connection
	if eventsClient != nil {
		eventsClient.Close()
	}

	// Stop config manager
	if configMgr != nil {
		if err := configMgr.Stop(); err != nil {
			log.Error("config manager stop error", "error", err)
		}
	}

	// Shutdown tracing
	if tracingCleanup != nil {
		if err := tracingCleanup(ctx); err != nil {
			log.Error("tracing shutdown error", "error", err)
		}
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
	viper.SetDefault("tls.enabled", false)
	viper.SetDefault("auth.grpc_address", "localhost:50051")
	viper.SetDefault("rate_limit.requests_per_second", 100)
	viper.SetDefault("rate_limit.burst_size", 200)
	viper.SetDefault("circuit_breaker.failure_threshold", 5)
	viper.SetDefault("circuit_breaker.success_threshold", 2)
	viper.SetDefault("circuit_breaker.timeout", "30s")
	viper.SetDefault("circuit_breaker.max_half_open_requests", 1)
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", "json")

	// Redis defaults
	viper.SetDefault("redis.address", "")
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.pool_size", 10)
	viper.SetDefault("redis.min_idle_conns", 5)
	viper.SetDefault("redis.dial_timeout", "5s")
	viper.SetDefault("redis.read_timeout", "3s")
	viper.SetDefault("redis.write_timeout", "3s")

	// NATS defaults
	viper.SetDefault("nats.url", "")
	viper.SetDefault("nats.name", "prism-gateway")
	viper.SetDefault("nats.reconnect_wait", "2s")
	viper.SetDefault("nats.max_reconnects", 60)

	// Tracing defaults
	viper.SetDefault("tracing.enabled", false)
	viper.SetDefault("tracing.endpoint", "localhost:4317")
	viper.SetDefault("tracing.sample_rate", 1.0)
	viper.SetDefault("tracing.insecure", true)

	// Config service defaults
	viper.SetDefault("config_service.grpc_address", "")
	viper.SetDefault("config_service.timeout", "5s")
	viper.SetDefault("config_service.retry_interval", "2s")
	viper.SetDefault("config_service.max_retries", 10)

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
