package logger

import (
	"log/slog"
	"testing"
)

func TestNew(t *testing.T) {
	logger := New()
	if logger == nil {
		t.Error("New() returned nil logger")
	}
}

func TestNewWithLevel(t *testing.T) {
	logger := NewWithLevel(slog.LevelDebug)
	if logger == nil {
		t.Error("NewWithLevel() returned nil logger")
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"unknown", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseLogLevel(tt.input)
			if result != tt.expected {
				t.Errorf("parseLogLevel(%s) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}
