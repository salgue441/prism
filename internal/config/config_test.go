package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	cfg, err := Load()
	require.NoError(t, err)
	assert.NotNil(t, cfg)

	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, "localhost", cfg.Redis.Host)
	assert.Equal(t, 6379, cfg.Redis.Port)
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)
	assert.True(t, cfg.Monitoring.MetricsEnabled)
}

func TestLoadWithEnvironmentVariables(t *testing.T) {
	envVars := map[string]string{
		"GATEWAY_SERVER_PORT":                "9090",
		"GATEWAY_SERVER_HOST":                "127.0.0.1",
		"GATEWAY_REDIS_HOST":                 "redis.example.com",
		"GATEWAY_REDIS_PORT":                 "6380",
		"GATEWAY_LOGGING_LEVEL":              "debug",
		"GATEWAY_MONITORING_METRICS_ENABLED": "false",
	}

	for key, value := range envVars {
		t.Setenv(key, value)
	}

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1", cfg.Server.Host)
	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "redis.example.com", cfg.Redis.Host)
	assert.Equal(t, 6380, cfg.Redis.Port)
	assert.Equal(t, "debug", cfg.Logging.Level)
	assert.False(t, cfg.Monitoring.MetricsEnabled)
}

func TestServerConfigValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  ServerConfig
		wantErr bool
		errType string
	}{
		{
			name: "valid config",
			config: ServerConfig{
				Host:            "0.0.0.0",
				Port:            8080,
				ReadTimeout:     30 * time.Second,
				WriteTimeout:    30 * time.Second,
				IdleTimeout:     60 * time.Second,
				GracefulTimeout: 10 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "invalid port - too low",
			config: ServerConfig{
				Port:            0,
				ReadTimeout:     30 * time.Second,
				WriteTimeout:    30 * time.Second,
				IdleTimeout:     60 * time.Second,
				GracefulTimeout: 10 * time.Second,
			},
			wantErr: true,
			errType: "port",
		},
		{
			name: "invalid port - too high",
			config: ServerConfig{
				Port:            65536,
				ReadTimeout:     30 * time.Second,
				WriteTimeout:    30 * time.Second,
				IdleTimeout:     60 * time.Second,
				GracefulTimeout: 10 * time.Second,
			},
			wantErr: true,
			errType: "port",
		},
		{
			name: "invalid read timeout",
			config: ServerConfig{
				Port:            8080,
				ReadTimeout:     0,
				WriteTimeout:    30 * time.Second,
				IdleTimeout:     60 * time.Second,
				GracefulTimeout: 10 * time.Second,
			},
			wantErr: true,
			errType: "read_timeout",
		},
		{
			name: "invalid write timeout",
			config: ServerConfig{
				Port:            8080,
				ReadTimeout:     30 * time.Second,
				WriteTimeout:    0,
				IdleTimeout:     60 * time.Second,
				GracefulTimeout: 10 * time.Second,
			},
			wantErr: true,
			errType: "write_timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != "" {
					var validationErr *ValidationError
					require.ErrorAs(t, err, &validationErr)
					assert.Equal(t, tt.errType, validationErr.Field)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRedisConfigValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  RedisConfig
		wantErr bool
		errType string
	}{
		{
			name: "valid config",
			config: RedisConfig{
				Host:           "localhost",
				Port:           6379,
				DB:             0,
				PoolSize:       10,
				MinIdleConns:   5,
				ConnectTimeout: 5 * time.Second,
				ReadTimeout:    3 * time.Second,
				WriteTimeout:   3 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "empty host",
			config: RedisConfig{
				Host:           "",
				Port:           6379,
				DB:             0,
				PoolSize:       10,
				MinIdleConns:   5,
				ConnectTimeout: 5 * time.Second,
				ReadTimeout:    3 * time.Second,
				WriteTimeout:   3 * time.Second,
			},
			wantErr: true,
			errType: "host",
		},
		{
			name: "invalid database number",
			config: RedisConfig{
				Host:           "localhost",
				Port:           6379,
				DB:             16,
				PoolSize:       10,
				MinIdleConns:   5,
				ConnectTimeout: 5 * time.Second,
				ReadTimeout:    3 * time.Second,
				WriteTimeout:   3 * time.Second,
			},
			wantErr: true,
			errType: "db",
		},
		{
			name: "min idle conns greater than pool size",
			config: RedisConfig{
				Host:           "localhost",
				Port:           6379,
				DB:             0,
				PoolSize:       5,
				MinIdleConns:   10,
				ConnectTimeout: 5 * time.Second,
				ReadTimeout:    3 * time.Second,
				WriteTimeout:   3 * time.Second,
			},
			wantErr: true,
			errType: "min_idle_conns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != "" {
					var validationErr *ValidationError
					require.ErrorAs(t, err, &validationErr)
					assert.Equal(t, tt.errType, validationErr.Field)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLoggingConfigValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  LoggingConfig
		wantErr bool
		errType string
	}{
		{
			name: "valid config",
			config: LoggingConfig{
				Level:  "info",
				Format: "json",
				Output: "stdout",
			},
			wantErr: false,
		},
		{
			name: "invalid level",
			config: LoggingConfig{
				Level:  "invalid",
				Format: "json",
				Output: "stdout",
			},
			wantErr: true,
			errType: "level",
		},
		{
			name: "invalid format",
			config: LoggingConfig{
				Level:  "info",
				Format: "invalid",
				Output: "stdout",
			},
			wantErr: true,
			errType: "format",
		},
		{
			name: "empty output",
			config: LoggingConfig{
				Level:  "info",
				Format: "json",
				Output: "",
			},
			wantErr: true,
			errType: "output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != "" {
					var validationErr *ValidationError
					require.ErrorAs(t, err, &validationErr)
					assert.Equal(t, tt.errType, validationErr.Field)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMonitoringConfigValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  MonitoringConfig
		wantErr bool
		errType string
	}{
		{
			name: "valid config",
			config: MonitoringConfig{
				MetricsEnabled:  true,
				MetricsPath:     "/metrics",
				HealthCheckPath: "/health",
			},
			wantErr: false,
		},
		{
			name: "empty metrics path",
			config: MonitoringConfig{
				MetricsEnabled:  true,
				MetricsPath:     "",
				HealthCheckPath: "/health",
			},
			wantErr: true,
			errType: "metrics_path",
		},
		{
			name: "same paths",
			config: MonitoringConfig{
				MetricsEnabled:  true,
				MetricsPath:     "/metrics",
				HealthCheckPath: "/metrics",
			},
			wantErr: true,
			errType: "metrics_path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != "" {
					var validationErr *ValidationError
					require.ErrorAs(t, err, &validationErr)
					assert.Equal(t, tt.errType, validationErr.Field)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: Config{
				Server: ServerConfig{
					Host:            "0.0.0.0",
					Port:            8080,
					ReadTimeout:     30 * time.Second,
					WriteTimeout:    30 * time.Second,
					IdleTimeout:     60 * time.Second,
					GracefulTimeout: 10 * time.Second,
				},
				Redis: RedisConfig{
					Host:           "localhost",
					Port:           6379,
					DB:             0,
					PoolSize:       10,
					MinIdleConns:   5,
					ConnectTimeout: 5 * time.Second,
					ReadTimeout:    3 * time.Second,
					WriteTimeout:   3 * time.Second,
				},
				Logging: LoggingConfig{
					Level:  "info",
					Format: "json",
					Output: "stdout",
				},
				Monitoring: MonitoringConfig{
					MetricsEnabled:  true,
					MetricsPath:     "/metrics",
					HealthCheckPath: "/health",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid server config",
			config: Config{
				Server: ServerConfig{
					Port: 0, // Invalid port
				},
				Redis: RedisConfig{
					Host:           "localhost",
					Port:           6379,
					DB:             0,
					PoolSize:       10,
					MinIdleConns:   5,
					ConnectTimeout: 5 * time.Second,
					ReadTimeout:    3 * time.Second,
					WriteTimeout:   3 * time.Second,
				},
				Logging: LoggingConfig{
					Level:  "info",
					Format: "json",
					Output: "stdout",
				},
				Monitoring: MonitoringConfig{
					MetricsEnabled:  true,
					MetricsPath:     "/metrics",
					HealthCheckPath: "/health",
				},
			},
			wantErr: true,
			errMsg:  "server config",
		},
		{
			name: "invalid redis config",
			config: Config{
				Server: ServerConfig{
					Host:            "0.0.0.0",
					Port:            8080,
					ReadTimeout:     30 * time.Second,
					WriteTimeout:    30 * time.Second,
					IdleTimeout:     60 * time.Second,
					GracefulTimeout: 10 * time.Second,
				},
				Redis: RedisConfig{
					Host: "", // Invalid empty host
				},
				Logging: LoggingConfig{
					Level:  "info",
					Format: "json",
					Output: "stdout",
				},
				Monitoring: MonitoringConfig{
					MetricsEnabled:  true,
					MetricsPath:     "/metrics",
					HealthCheckPath: "/health",
				},
			},
			wantErr: true,
			errMsg:  "redis config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRedisAddr(t *testing.T) {
	t.Parallel()

	config := RedisConfig{
		Host: "redis.example.com",
		Port: 6380,
	}

	assert.Equal(t, "redis.example.com:6380", config.RedisAddr())
}

func TestServerAddr(t *testing.T) {
	t.Parallel()

	config := ServerConfig{
		Host: "0.0.0.0",
		Port: 8080,
	}

	assert.Equal(t, "0.0.0.0:8080", config.ServerAddr())
}

func TestValidationError(t *testing.T) {
	t.Parallel()

	err := &ValidationError{
		Field:   "port",
		Value:   "0",
		Message: "must be between 1 and 65535",
	}

	expected := "invalid port '0': must be between 1 and 65535"
	assert.Equal(t, expected, err.Error())
}

func TestConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Load()
	require.NoError(t, err)

	// Test server defaults
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, 30*time.Second, cfg.Server.ReadTimeout)
	assert.Equal(t, 30*time.Second, cfg.Server.WriteTimeout)
	assert.Equal(t, 60*time.Second, cfg.Server.IdleTimeout)
	assert.Equal(t, 10*time.Second, cfg.Server.GracefulTimeout)

	// Test Redis defaults
	assert.Equal(t, "localhost", cfg.Redis.Host)
	assert.Equal(t, 6379, cfg.Redis.Port)
	assert.Equal(t, "", cfg.Redis.Password)
	assert.Equal(t, 0, cfg.Redis.DB)
	assert.Equal(t, 10, cfg.Redis.PoolSize)
	assert.Equal(t, 5, cfg.Redis.MinIdleConns)
	assert.Equal(t, 5*time.Second, cfg.Redis.ConnectTimeout)
	assert.Equal(t, 3*time.Second, cfg.Redis.ReadTimeout)
	assert.Equal(t, 3*time.Second, cfg.Redis.WriteTimeout)

	// Test logging defaults
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)
	assert.Equal(t, "stdout", cfg.Logging.Output)
	assert.False(t, cfg.Logging.AddSource)

	// Test monitoring defaults
	assert.True(t, cfg.Monitoring.MetricsEnabled)
	assert.Equal(t, "/metrics", cfg.Monitoring.MetricsPath)
	assert.Equal(t, "/health", cfg.Monitoring.HealthCheckPath)
}

func TestTimeoutValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		timeout time.Duration
		field   string
		wantErr bool
	}{
		{
			name:    "positive duration",
			timeout: 30 * time.Second,
			field:   "read_timeout",
			wantErr: false,
		},
		{
			name:    "zero duration",
			timeout: 0,
			field:   "read_timeout",
			wantErr: true,
		},
		{
			name:    "negative duration",
			timeout: -5 * time.Second,
			field:   "read_timeout",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := ServerConfig{
				Port:            8080,
				ReadTimeout:     tt.timeout,
				WriteTimeout:    30 * time.Second,
				IdleTimeout:     60 * time.Second,
				GracefulTimeout: 10 * time.Second,
			}

			err := config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.field)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRedisConnectionPoolValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		poolSize     int
		minIdleConns int
		wantErr      bool
		errField     string
	}{
		{
			name:         "valid pool configuration",
			poolSize:     10,
			minIdleConns: 5,
			wantErr:      false,
		},
		{
			name:         "min idle equals pool size",
			poolSize:     10,
			minIdleConns: 10,
			wantErr:      false,
		},
		{
			name:         "zero pool size",
			poolSize:     0,
			minIdleConns: 0,
			wantErr:      true,
			errField:     "pool_size",
		},
		{
			name:         "negative min idle conns",
			poolSize:     10,
			minIdleConns: -1,
			wantErr:      true,
			errField:     "min_idle_conns",
		},
		{
			name:         "min idle greater than pool size",
			poolSize:     5,
			minIdleConns: 10,
			wantErr:      true,
			errField:     "min_idle_conns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := RedisConfig{
				Host:           "localhost",
				Port:           6379,
				DB:             0,
				PoolSize:       tt.poolSize,
				MinIdleConns:   tt.minIdleConns,
				ConnectTimeout: 5 * time.Second,
				ReadTimeout:    3 * time.Second,
				WriteTimeout:   3 * time.Second,
			}

			err := config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errField != "" {
					var validationErr *ValidationError
					require.ErrorAs(t, err, &validationErr)
					assert.Equal(t, tt.errField, validationErr.Field)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLoggingLevelCaseInsensitive(t *testing.T) {
	t.Parallel()

	levels := []string{"DEBUG", "Info", "WARN", "error", "Debug", "INFO", "warn", "ERROR"}

	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			t.Parallel()

			config := LoggingConfig{
				Level:  level,
				Format: "json",
				Output: "stdout",
			}

			err := config.Validate()
			require.NoError(t, err)
		})
	}
}

func TestMonitoringPathValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		metricsPath     string
		healthCheckPath string
		wantErr         bool
		errField        string
	}{
		{
			name:            "different valid paths",
			metricsPath:     "/metrics",
			healthCheckPath: "/health",
			wantErr:         false,
		},
		{
			name:            "same paths",
			metricsPath:     "/status",
			healthCheckPath: "/status",
			wantErr:         true,
			errField:        "metrics_path",
		},
		{
			name:            "empty metrics path",
			metricsPath:     "",
			healthCheckPath: "/health",
			wantErr:         true,
			errField:        "metrics_path",
		},
		{
			name:            "empty health check path",
			metricsPath:     "/metrics",
			healthCheckPath: "",
			wantErr:         true,
			errField:        "health_check_path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := MonitoringConfig{
				MetricsEnabled:  true,
				MetricsPath:     tt.metricsPath,
				HealthCheckPath: tt.healthCheckPath,
			}

			err := config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errField != "" {
					var validationErr *ValidationError
					require.ErrorAs(t, err, &validationErr)
					assert.Equal(t, tt.errField, validationErr.Field)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// BenchmarkLoad tests the performance of configuration loading
func BenchmarkLoad(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cfg, err := Load()
		if err != nil {
			b.Fatal(err)
		}
		_ = cfg
	}
}

// BenchmarkValidate tests the performance of configuration validation
func BenchmarkValidate(b *testing.B) {
	cfg, err := Load()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := cfg.Validate()
		if err != nil {
			b.Fatal(err)
		}
	}
}
