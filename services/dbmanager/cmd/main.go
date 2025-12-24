// Package main is the entry point for the Prism DB Manager service.
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

	"github.com/carlossalguero/prism/services/dbmanager/internal/backup"
	"github.com/carlossalguero/prism/services/dbmanager/internal/health"
	"github.com/carlossalguero/prism/services/dbmanager/internal/migration"
	"github.com/carlossalguero/prism/services/dbmanager/internal/scheduler"
	"github.com/carlossalguero/prism/services/dbmanager/internal/server"
	sharedhealth "github.com/carlossalguero/prism/services/shared/health"
	"github.com/carlossalguero/prism/services/shared/logger"
	"github.com/carlossalguero/prism/services/shared/metrics"
)

// Config holds the DB Manager service configuration.
type Config struct {
	GRPC struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"grpc"`

	Databases struct {
		Auth DatabaseConfig `mapstructure:"auth"`
		Ops  DatabaseConfig `mapstructure:"ops"`
	} `mapstructure:"databases"`

	Migrations struct {
		AuthPath string `mapstructure:"auth_path"`
		OpsPath  string `mapstructure:"ops_path"`
		AutoRun  bool   `mapstructure:"auto_run"`
	} `mapstructure:"migrations"`

	Backup struct {
		Enabled       bool          `mapstructure:"enabled"`
		Schedule      string        `mapstructure:"schedule"` // Cron expression
		RetentionDays int           `mapstructure:"retention_days"`
		StorageType   string        `mapstructure:"storage_type"` // local, s3, minio
		StoragePath   string        `mapstructure:"storage_path"`
		S3            S3Config      `mapstructure:"s3"`
		Timeout       time.Duration `mapstructure:"timeout"`
	} `mapstructure:"backup"`

	Health struct {
		CheckInterval time.Duration `mapstructure:"check_interval"`
	} `mapstructure:"health"`

	Log struct {
		Level  string `mapstructure:"level"`
		Format string `mapstructure:"format"`
	} `mapstructure:"log"`
}

// DatabaseConfig holds database connection configuration.
type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	Name            string        `mapstructure:"name"`
	SSLMode         string        `mapstructure:"ssl_mode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// S3Config holds S3/MinIO configuration for backups.
type S3Config struct {
	Endpoint        string `mapstructure:"endpoint"`
	Bucket          string `mapstructure:"bucket"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	SecretAccessKey string `mapstructure:"secret_access_key"`
	Region          string `mapstructure:"region"`
	UseSSL          bool   `mapstructure:"use_ssl"`
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
		ServiceName: "prism-dbmanager",
		Environment: os.Getenv("ENVIRONMENT"),
	})

	log := logger.Default()
	log.Info("starting prism db manager service")

	// Initialize metrics
	metricsInstance := metrics.Init(metrics.Config{
		ServiceName: "dbmanager",
		Namespace:   "prism",
		Subsystem:   "dbmanager",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize database connections
	authPool, err := initDatabase(ctx, cfg.Databases.Auth)
	if err != nil {
		log.Error("failed to connect to auth database", "error", err)
		os.Exit(1)
	}
	defer authPool.Close()

	opsPool, err := initDatabase(ctx, cfg.Databases.Ops)
	if err != nil {
		log.Error("failed to connect to ops database", "error", err)
		os.Exit(1)
	}
	defer opsPool.Close()

	// Initialize migration runner
	migrationRunner := migration.NewRunner(migration.Config{
		AuthMigrationsPath: cfg.Migrations.AuthPath,
		OpsMigrationsPath:  cfg.Migrations.OpsPath,
	}, authPool, opsPool)

	// Run migrations on startup if enabled
	if cfg.Migrations.AutoRun {
		log.Info("running auto-migrations")
		if err := migrationRunner.RunAll(ctx); err != nil {
			log.Error("failed to run auto-migrations", "error", err)
			// Don't exit - continue running the service
		}
	}

	// Initialize backup manager
	backupManager := backup.NewManager(backup.Config{
		Enabled:       cfg.Backup.Enabled,
		StorageType:   cfg.Backup.StorageType,
		StoragePath:   cfg.Backup.StoragePath,
		RetentionDays: cfg.Backup.RetentionDays,
		Timeout:       cfg.Backup.Timeout,
		S3Config: backup.S3Config{
			Endpoint:        cfg.Backup.S3.Endpoint,
			Bucket:          cfg.Backup.S3.Bucket,
			AccessKeyID:     cfg.Backup.S3.AccessKeyID,
			SecretAccessKey: cfg.Backup.S3.SecretAccessKey,
			Region:          cfg.Backup.S3.Region,
			UseSSL:          cfg.Backup.S3.UseSSL,
		},
	}, authPool, opsPool)

	// Initialize health monitor
	healthMonitor := health.NewMonitor(health.Config{
		CheckInterval: cfg.Health.CheckInterval,
	}, authPool, opsPool)

	// Start health monitoring
	go healthMonitor.Start(ctx)

	// Initialize scheduler for automated backups
	sched := scheduler.New()
	if cfg.Backup.Enabled && cfg.Backup.Schedule != "" {
		if err := sched.AddJob("backup-auth", cfg.Backup.Schedule, func() {
			log.Info("running scheduled backup for auth database")
			if _, err := backupManager.CreateBackup(context.Background(), "auth", backup.TypeFull, "scheduled"); err != nil {
				log.Error("scheduled backup failed", "database", "auth", "error", err)
			}
		}); err != nil {
			log.Error("failed to schedule backup job", "error", err)
		}

		if err := sched.AddJob("backup-ops", cfg.Backup.Schedule, func() {
			log.Info("running scheduled backup for ops database")
			if _, err := backupManager.CreateBackup(context.Background(), "ops", backup.TypeFull, "scheduled"); err != nil {
				log.Error("scheduled backup failed", "database", "ops", "error", err)
			}
		}); err != nil {
			log.Error("failed to schedule backup job", "error", err)
		}

		sched.Start()
		defer sched.Stop()
	}

	// Initialize health checker
	healthChecker := sharedhealth.NewChecker(
		sharedhealth.WithVersion(version()),
		sharedhealth.WithTimeout(5*time.Second),
	)
	healthChecker.Register("auth_database", sharedhealth.PostgresCheck(authPool.Ping))
	healthChecker.Register("ops_database", sharedhealth.PostgresCheck(opsPool.Ping))

	// Create gRPC server
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			server.LoggingInterceptor(log),
			server.RecoveryInterceptor(log),
			server.MetricsInterceptor(metricsInstance),
		),
	)

	// Register DB Manager service
	dbManagerServer := server.NewDBManagerServer(migrationRunner, backupManager, healthMonitor)
	server.RegisterDBManagerServer(grpcServer, dbManagerServer)

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

	// Start health check server with metrics endpoint
	go func() {
		healthAddr := fmt.Sprintf("%s:%d", cfg.GRPC.Host, cfg.GRPC.Port+1000)
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", healthChecker.HealthHandler)
		healthMux.HandleFunc("/health/live", healthChecker.LiveHandler)
		healthMux.HandleFunc("/health/ready", healthChecker.ReadyHandler)
		healthMux.Handle("/metrics", metricsInstance.Handler())

		healthServer := &http.Server{
			Addr:              healthAddr,
			Handler:           healthMux,
			ReadHeaderTimeout: 10 * time.Second,
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

	// Graceful shutdown
	grpcServer.GracefulStop()

	log.Info("servers stopped")
}

func initDatabase(ctx context.Context, cfg DatabaseConfig) (*pgxpool.Pool, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host,
		cfg.Port,
		cfg.User,
		cfg.Password,
		cfg.Name,
		cfg.SSLMode,
	)

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing database config: %w", err)
	}

	if cfg.MaxOpenConns > 0 {
		poolConfig.MaxConns = int32(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		poolConfig.MinConns = int32(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime > 0 {
		poolConfig.MaxConnLifetime = cfg.ConnMaxLifetime
	}

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
	viper.SetConfigName("dbmanager")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath("/etc/prism")

	// Set defaults
	viper.SetDefault("grpc.host", "0.0.0.0")
	viper.SetDefault("grpc.port", 50053)

	viper.SetDefault("databases.auth.host", "localhost")
	viper.SetDefault("databases.auth.port", 5432)
	viper.SetDefault("databases.auth.user", "prism")
	viper.SetDefault("databases.auth.name", "prism_auth")
	viper.SetDefault("databases.auth.ssl_mode", "disable")
	viper.SetDefault("databases.auth.max_open_conns", 10)
	viper.SetDefault("databases.auth.max_idle_conns", 2)
	viper.SetDefault("databases.auth.conn_max_lifetime", "5m")

	viper.SetDefault("databases.ops.host", "localhost")
	viper.SetDefault("databases.ops.port", 5433)
	viper.SetDefault("databases.ops.user", "prism")
	viper.SetDefault("databases.ops.name", "prism_ops")
	viper.SetDefault("databases.ops.ssl_mode", "disable")
	viper.SetDefault("databases.ops.max_open_conns", 10)
	viper.SetDefault("databases.ops.max_idle_conns", 2)
	viper.SetDefault("databases.ops.conn_max_lifetime", "5m")

	viper.SetDefault("migrations.auth_path", "./migrations/auth")
	viper.SetDefault("migrations.ops_path", "./migrations/ops")
	viper.SetDefault("migrations.auto_run", false)

	viper.SetDefault("backup.enabled", true)
	viper.SetDefault("backup.schedule", "0 2 * * *") // 2 AM daily
	viper.SetDefault("backup.retention_days", 30)
	viper.SetDefault("backup.storage_type", "local")
	viper.SetDefault("backup.storage_path", "/var/lib/prism/backups")
	viper.SetDefault("backup.timeout", "30m")

	viper.SetDefault("health.check_interval", "30s")

	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", "json")

	// Bind environment variables
	viper.SetEnvPrefix("DBMANAGER")
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
