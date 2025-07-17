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

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// loadFromFile loads configuration from a JSON or a YAML file.
func loadFromFile(filename string, cfg *Config) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	switch {
	case len(filename) > 5 &&
		filename[len(filename)-5:] == ".yaml":
		fallthrough

	case len(filename) > 4 &&
		filename[len(filename)-4:] == ".yml":
		return yaml.Unmarshal(data, cfg)

	default:
		return json.Unmarshal(data, cfg)
	}
}

// validate ensures the configuration is valid
func (c *Config) validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Server.Port)
	}

	for i, route := range c.Routes {
		if route.Path == "" {
			return fmt.Errorf("route %d: path is required", i)
		}

		if route.Target == "" {
			return fmt.Errorf("route %d: target is required", i)
		}
	}

	return nil
}
