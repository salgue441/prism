package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Server ServerConfig `json:"server" yaml:"server" envconfig:"SERVER"`
	Routes []Route      `json:"routes" yaml:"routes"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Port         int           `json:"port" yaml:"port" envconfig:"PORT" default:"8080"`
	Host         string        `json:"host" yaml:"host" envconfig:"HOST" default:"0.0.0.0"`
	ReadTimeout  time.Duration `json:"read_timeout" yaml:"read_timeout" envconfig:"READ_TIMEOUT" default:"30s"`
	WriteTimeout time.Duration `json:"write_timeout" yaml:"write_timeout" envconfig:"WRITE_TIMEOUT" default:"30s"`
	IdleTimeout  time.Duration `json:"idle_timeout" yaml:"idle_timeout" envconfig:"IDLE_TIMEOUT" default:"60s"`
}

// Route represents a routing rule
type Route struct {
	ID        string `json:"id" yaml:"id"`
	Path      string `json:"path" yaml:"path"`
	Method    string `json:"method" yaml:"method"`
	Target    string `json:"target" yaml:"target"`
	StripPath bool   `json:"strip_path" yaml:"strip_path"`
}

// Load loads configuration from multiple sources
func Load() (*Config, error) {
	cfg := &Config{}
	cfg.Server = ServerConfig{
		Port:         8080,
		Host:         "0.0.0.0",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := envconfig.Process("GATEWAY", cfg); err != nil {
		return nil, fmt.Errorf("failed to load env config: %w", err)
	}

	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = "configs/config.json"
	}

	if _, err := os.Stat(configFile); err == nil {
		if err := loadFromFile(configFile, cfg); err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if err := c.Server.Validate(); err != nil {
		return fmt.Errorf("server config invalid: %w", err)
	}

	routeIDs := make(map[string]bool)
	for i, route := range c.Routes {
		if err := route.Validate(); err != nil {
			return fmt.Errorf("route %d invalid: %w", i, err)
		}

		if route.ID != "" {
			if routeIDs[route.ID] {
				return fmt.Errorf("duplicate route ID: %s", route.ID)
			}

			routeIDs[route.ID] = true
		}
	}

	return nil
}

// Validate validates server configuration
func (sc *ServerConfig) Validate() error {
	if sc.Port <= 0 || sc.Port > 65535 {
		return fmt.Errorf("invalid port: %d (must be 1-65535)", sc.Port)
	}

	if sc.ReadTimeout <= 0 {
		return fmt.Errorf("read_timeout must be positive")
	}

	if sc.WriteTimeout <= 0 {
		return fmt.Errorf("write_timeout must be positive")
	}

	if sc.IdleTimeout <= 0 {
		return fmt.Errorf("idle_timeout must be positive")
	}

	return nil
}

// Validate validates route configuration
func (r *Route) Validate() error {
	if r.Path == "" {
		return fmt.Errorf("path is required")
	}

	if r.Target == "" {
		return fmt.Errorf("target is required")
	}

	if len(r.Target) < 7 ||
		(r.Target[:7] != "http://" && r.Target[:8] != "https://") {
		return fmt.Errorf("target must be a valid HTTP/HTTPS URL")
	}

	return nil
}

// Private methods

// loadFromFile loads configuration from a JSON or a YAML file.
func loadFromFile(filename string, cfg *Config) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	if isYAMLFile(filename) {
		return yaml.Unmarshal(data, cfg)
	}

	return json.Unmarshal(data, cfg)
}

// isYAMLFile checks if the file is a YAML file based on extension
func isYAMLFile(filename string) bool {
	return len(filename) > 5 && filename[len(filename)-5:] == ".yaml" ||
		len(filename) > 4 && filename[len(filename)-4:] == ".yml"
}
