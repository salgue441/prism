package config

import (
	"os"
	"testing"
	"time"
)

func TestConfig_Load(t *testing.T) {
	tests := []struct {
		name         string
		envVars      map[string]string
		configFile   string
		wantErr      bool
		expectedPort int
	}{
		{
			name: "default config",
			envVars: map[string]string{
				"CONFIG_FILE": "",
			},
			wantErr:      false,
			expectedPort: 8080,
		},
		{
			name: "environment override",
			envVars: map[string]string{
				"GATEWAY_SERVER_PORT": "9090",
				"CONFIG_FILE":         "",
			},
			wantErr:      false,
			expectedPort: 9090,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range tt.envVars {
				os.Setenv(key, value)
				defer os.Unsetenv(key)
			}

			cfg, err := Load()
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && cfg.Server.Port != tt.expectedPort {
				t.Errorf("Expected port %d, got %d", tt.expectedPort, cfg.Server.Port)
			}
		})
	}
}

func TestServerConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  ServerConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: ServerConfig{
				Port:         8080,
				Host:         "localhost",
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  60 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "invalid port - too low",
			config: ServerConfig{
				Port:         0,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  60 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "invalid port - too high",
			config: ServerConfig{
				Port:         70000,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  60 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "invalid timeout",
			config: ServerConfig{
				Port:         8080,
				ReadTimeout:  -1 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  60 * time.Second,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ServerConfig.Validate() error = %v, wantErr %v",
					err, tt.wantErr)
			}
		})
	}
}

func TestRoute_Validate(t *testing.T) {
	tests := []struct {
		name    string
		route   Route
		wantErr bool
	}{
		{
			name: "valid route",
			route: Route{
				ID:     "test",
				Path:   "/api/test",
				Target: "http://localhost:3000",
			},
			wantErr: false,
		},
		{
			name: "missing path",
			route: Route{
				ID:     "test",
				Target: "http://localhost:3000",
			},
			wantErr: true,
		},
		{
			name: "missing target",
			route: Route{
				ID:   "test",
				Path: "/api/test",
			},
			wantErr: true,
		},
		{
			name: "invalid target URL",
			route: Route{
				ID:     "test",
				Path:   "/api/test",
				Target: "invalid-url",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.route.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Route.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
