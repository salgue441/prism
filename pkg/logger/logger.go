package logger

import (
	"log/slog"
	"os"
	"strings"
)

// Config holds logger configuration
type Config struct {
	Level  string `envconfig:"LOG_LEVEL" default:"info"`
	Format string `envconfig:"LOG_FORMAT" default:"json"`
	Source bool   `envconfig:"LOG_SOURCE" default:"false"`
}

// New creates a new structured logger with default settings
func New() *slog.Logger {
	return NewWithConfig(Config{})
}

// NewWithLevel creates a logger with the specified level
func NewWithLevel(level slog.Level) *slog.Logger {
	config := Config{
		Level:  level.String(),
		Format: "json",
		Source: level == slog.LevelDebug,
	}
	
	return NewWithConfig(config)
}

// NewWithConfig creates a logger with the specified configuration
func NewWithConfig(config Config) *slog.Logger {
	level := parseLogLevel(config.Level)
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: config.Source,
	}

	var handler slog.Handler
	switch strings.ToLower(config.Format) {
	case "text", "console":
		handler = slog.NewTextHandler(os.Stdout, opts)

	default:
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

// parseLogLevel converts string to slog.Level
func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
		
	case "info":
		return slog.LevelInfo

	case "warn", "warning":
		return slog.LevelWarn

	case "error":
		return slog.LevelError

	default:
		return slog.LevelInfo
	}
}
