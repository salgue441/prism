package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errType string
	}{
		{
			name:    "default config",
			config:  Config{},
			wantErr: false,
		},
		{
			name: "valid json config",
			config: Config{
				Level:  "debug",
				Format: "json",
				Output: "stdout",
			},
			wantErr: false,
		},
		{
			name: "valid text config",
			config: Config{
				Level:  "info",
				Format: "text",
				Output: "stderr",
			},
			wantErr: false,
		},
		{
			name: "invalid level",
			config: Config{
				Level: "invalid",
			},
			wantErr: true,
			errType: "level",
		},
		{
			name: "invalid format",
			config: Config{
				Format: "invalid",
			},
			wantErr: true,
			errType: "format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, err := New(tt.config)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, logger)

				if tt.errType != "" {
					var configErr *ConfigError

					require.ErrorAs(t, err, &configErr)
					assert.Equal(t, tt.errType, configErr.Field)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, logger)
			}
		})
	}
}

func TestLogger_JSONOutput(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	tmpFile, err := os.CreateTemp("", "test-log-*.json")
	require.NoError(t, err)

	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger, err := New(Config{
		Level:  "debug",
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	logger.Info("test message", "key1", "value1", "key2", 42)
	w.Close()
	os.Stdout = oldStdout

	_, err = buf.ReadFrom(r)
	require.NoError(t, err)

	var logEntry map[string]any
	err = json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err)

	assert.Equal(t, "INFO", logEntry["level"])
	assert.Equal(t, "test message", logEntry["msg"])
	assert.Equal(t, "value1", logEntry["key1"])
	assert.Equal(t, float64(42), logEntry["key2"])
	assert.Contains(t, logEntry, "time")
}

func TestLogger_WithFields(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger, err := New(Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	loggerWithFields := logger.With("service", "gateway", "version", "1.0.0")
	loggerWithFields.Info("operation completed", "duration", "5ms")

	w.Close()
	os.Stdout = oldStdout

	_, err = buf.ReadFrom(r)
	require.NoError(t, err)

	var logEntry map[string]any
	err = json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err)

	assert.Equal(t, "gateway", logEntry["service"])
	assert.Equal(t, "1.0.0", logEntry["version"])
	assert.Equal(t, "5ms", logEntry["duration"])
	assert.Equal(t, "operation completed", logEntry["msg"])
}

func TestLogger_WithGroup(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger, err := New(Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	groupedLogger := logger.WithGroup("http")
	groupedLogger.Info("request received", "method", "GET", "path",
		"/api/v1/users")

	w.Close()
	os.Stdout = oldStdout

	_, err = buf.ReadFrom(r)
	require.NoError(t, err)

	var logEntry map[string]any
	err = json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err)

	assert.Equal(t, "request received", logEntry["msg"])

	httpGroup, ok := logEntry["http"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "GET", httpGroup["method"])
	assert.Equal(t, "/api/v1/users", httpGroup["path"])
}

func TestLogger_Context(t *testing.T) {
	t.Parallel()

	logger, err := New(Config{
		Level:  "debug",
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)
	ctx := context.Background()

	logger.DebugContext(ctx, "debug with context")
	logger.InfoContext(ctx, "info with context")
	logger.WarnContext(ctx, "warn with context")
	logger.ErrorContext(ctx, "error with context")
}

func TestLogger_Levels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		logLevel  string
		shouldLog map[string]bool
	}{
		{
			name:     "debug level",
			logLevel: "debug",
			shouldLog: map[string]bool{
				"debug": true,
				"info":  true,
				"warn":  true,
				"error": true,
			},
		},
		{
			name:     "info level",
			logLevel: "info",
			shouldLog: map[string]bool{
				"debug": false,
				"info":  true,
				"warn":  true,
				"error": true,
			},
		},
		{
			name:     "warn level",
			logLevel: "warn",
			shouldLog: map[string]bool{
				"debug": false,
				"info":  false,
				"warn":  true,
				"error": true,
			},
		},
		{
			name:     "error level",
			logLevel: "error",
			shouldLog: map[string]bool{
				"debug": false,
				"info":  false,
				"warn":  false,
				"error": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			logger, err := New(Config{
				Level:  tt.logLevel,
				Format: "json",
				Output: "stdout",
			})
			require.NoError(t, err)

			logger.Debug("debug message")
			logger.Info("info message")
			logger.Warn("warn message")
			logger.Error("error message")

			w.Close()
			os.Stdout = oldStdout

			_, err = buf.ReadFrom(r)
			require.NoError(t, err)

			output := buf.String()
			lines := strings.Split(strings.TrimSpace(output), "\n")

			var nonEmptyLines []string
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					nonEmptyLines = append(nonEmptyLines, line)
				}
			}

			expectedLogs := 0
			for _, shouldLog := range tt.shouldLog {
				if shouldLog {
					expectedLogs++
				}
			}

			assert.Equal(t, expectedLogs, len(nonEmptyLines),
				"Expected %d log entries, got %d for level %s. Output: %s",
				expectedLogs, len(nonEmptyLines), tt.logLevel, output)
		})
	}
}

func TestConfigError(t *testing.T) {
	t.Parallel()

	err := &ConfigError{
		Field:       "level",
		Value:       "invalid",
		ValidValues: []string{"debug", "info", "warn", "error"},
	}

	expected := "invalid level 'invalid', valid values: debug, info, warn, error"
	assert.Equal(t, expected, err.Error())
}

// BenchmarkLogger tests the performance of logging operations
func BenchmarkLogger(b *testing.B) {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(b, err)
	defer devNull.Close()

	logger, err := New(Config{
		Level:  "info",
		Format: "json",
		Output: devNull.Name(),
	})
	require.NoError(b, err)

	b.Run("simple message", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			logger.Info("benchmark message")
		}
	})

	b.Run("with fields", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			logger.Info("benchmark message", "count", i, "timestamp", time.Now())
		}
	})

	b.Run("with context", func(b *testing.B) {
		ctx := context.Background()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			logger.InfoContext(ctx, "benchmark message", "count", i)
		}
	})

	b.Run("with persistent fields", func(b *testing.B) {
		loggerWithFields := logger.With("service", "gateway", "version", "1.0.0")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			loggerWithFields.Info("benchmark message", "count", i)
		}
	})
}
