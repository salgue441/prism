package redis

import (
	"context"
	"fmt"
	"math/rand"
	"prism/pkg/logger"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestClient creates a Redis client for testing.
// Note: This requires a Redis server running on localhost:6379
func setupTestClient(t *testing.T) Client {
	t.Helper()

	log, err := logger.New(logger.Config{
		Level:  "debug",
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	cfg := Config{
		Host:     "localhost",
		Port:     6379,
		DB:       1,
		Password: "",
	}

	redisClient, err := NewClient(cfg, log)
	require.NoError(t, err)

	ctx := context.Background()
	err = redisClient.(*client).rdb.FlushDB(ctx).Err()
	require.NoError(t, err, "Failed to flush test database")

	return redisClient
}

// generateTestKey creates a unique test key to avoid conflicts
func generateTestKey(prefix string) string {
	return fmt.Sprintf("test:%s:%d:%d", prefix,
		time.Now().UnixNano(), rand.Intn(10000))
}

func TestNewClient(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Host: "localhost",
				Port: 6379,
				DB:   0,
			},
			wantErr: false,
		},
		{
			name: "invalid host - whitespace",
			config: Config{
				Host: "   ",
				Port: 6379,
			},
			wantErr: true,
		},
		{
			name: "invalid port - negative",
			config: Config{
				Host: "localhost",
				Port: -1,
			},
			wantErr: true,
		},
		{
			name: "invalid port - too high",
			config: Config{
				Host: "localhost",
				Port: 70000,
			},
			wantErr: true,
		},
		{
			name: "invalid database",
			config: Config{
				Host: "localhost",
				Port: 6379,
				DB:   16,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config, log)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				if err != nil {
					t.Skip("Redis server not available for testing")
				}
				assert.NoError(t, err)
				assert.NotNil(t, client)
				if client != nil {
					client.Close()
				}
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := Config{}
	setConfigDefaults(&cfg)

	assert.Equal(t, "localhost", cfg.Host)
	assert.Equal(t, 6379, cfg.Port)
	assert.Equal(t, 10, cfg.PoolSize)
	assert.Equal(t, 5, cfg.MinIdleConns)
	assert.Equal(t, 5*time.Second, cfg.ConnectTimeout)
	assert.Equal(t, 3*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 3*time.Second, cfg.WriteTimeout)
	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 8*time.Millisecond, cfg.MinRetryBackoff)
	assert.Equal(t, 512*time.Millisecond, cfg.MaxRetryBackoff)
}

func TestValidateConfig(t *testing.T) {
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
			config: Config{
				Host: "",
				Port: 6379,
			},
			wantErr: true,
			errMsg:  "host cannot be empty",
		},
		{
			name: "invalid port - too low",
			config: Config{
				Host: "localhost",
				Port: 0,
			},
			wantErr: true,
			errMsg:  "port must be between 1 and 65535",
		},
		{
			name: "invalid port - too high",
			config: Config{
				Host: "localhost",
				Port: 65536,
			},
			wantErr: true,
			errMsg:  "port must be between 1 and 65535",
		},
		{
			name: "invalid database",
			config: Config{
				Host: "localhost",
				Port: 6379,
				DB:   16,
			},
			wantErr: true,
			errMsg:  "db must be between 0 and 15",
		},
		{
			name: "invalid pool size",
			config: Config{
				Host:     "localhost",
				Port:     6379,
				PoolSize: 0,
			},
			wantErr: true,
			errMsg:  "pool_size must be at least 1",
		},
		{
			name: "min idle conns greater than pool size",
			config: Config{
				Host:         "localhost",
				Port:         6379,
				PoolSize:     5,
				MinIdleConns: 10,
			},
			wantErr: true,
			errMsg:  "min_idle_conns (10) cannot be greater than pool_size (5)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateConfig(tt.config)

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

func TestBasicOperations(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	t.Run("Set and Get", func(t *testing.T) {
		key := "test:basic:set_get"
		value := "test_value"

		// Test Set
		err := client.Set(ctx, key, value, time.Hour)
		require.NoError(t, err)

		// Test Get
		result, err := client.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, result)

		// Test Get non-existent key
		_, err = client.Get(ctx, "test:nonexistent")
		assert.Equal(t, redis.Nil, err)
	})

	t.Run("Del and Exists", func(t *testing.T) {
		key := "test:basic:del_exists"
		value := "test_value"

		// Set a key
		err := client.Set(ctx, key, value, time.Hour)
		require.NoError(t, err)

		// Test Exists
		count, err := client.Exists(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, int64(1), count)

		// Test Del
		deleted, err := client.Del(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, int64(1), deleted)

		// Verify key is deleted
		count, err = client.Exists(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})
}

func TestHashOperations(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	key := "test:hash"

	t.Run("HSet and HGet", func(t *testing.T) {
		field := "field1"
		value := "value1"

		err := client.HSet(ctx, key, field, value)
		require.NoError(t, err)

		result, err := client.HGet(ctx, key, field)
		require.NoError(t, err)
		assert.Equal(t, value, result)

		_, err = client.HGet(ctx, key, "nonexistent")
		assert.Equal(t, redis.Nil, err)
	})

	t.Run("HGetAll", func(t *testing.T) {
		err := client.HSet(ctx, key, "field2", "value2", "field3", "value3")
		require.NoError(t, err)

		result, err := client.HGetAll(ctx, key)
		require.NoError(t, err)
		assert.Contains(t, result, "field2")
		assert.Contains(t, result, "field3")
		assert.Equal(t, "value2", result["field2"])
		assert.Equal(t, "value3", result["field3"])
	})

	t.Run("HDel", func(t *testing.T) {
		deleted, err := client.HDel(ctx, key, "field2")
		require.NoError(t, err)
		assert.Equal(t, int64(1), deleted)

		_, err = client.HGet(ctx, key, "field2")
		assert.Equal(t, redis.Nil, err)
	})
}

func TestListOperations(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	key := generateTestKey("list")

	t.Run("Push and Pop operations", func(t *testing.T) {
		client.Del(ctx, key)

		// Test LPush
		length, err := client.LPush(ctx, key, "value1", "value2")
		require.NoError(t, err)
		assert.Equal(t, int64(2), length)

		// Test RPush
		length, err = client.RPush(ctx, key, "value3")
		require.NoError(t, err)
		assert.Equal(t, int64(3), length)

		// Test LLen
		length, err = client.LLen(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, int64(3), length)

		// Test LPop
		value, err := client.LPop(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, "value2", value)

		// Test RPop
		value, err = client.RPop(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, "value3", value)

		// Verify length
		length, err = client.LLen(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, int64(1), length)
	})

	t.Run("Pop from empty list", func(t *testing.T) {
		emptyKey := "test:empty_list"

		_, err := client.LPop(ctx, emptyKey)
		assert.Equal(t, redis.Nil, err)

		_, err = client.RPop(ctx, emptyKey)
		assert.Equal(t, redis.Nil, err)
	})
}

func TestSetOperations(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	key := generateTestKey("set")

	t.Run("Set operations", func(t *testing.T) {
		client.Del(ctx, key)

		// Test SAdd
		added, err := client.SAdd(ctx, key, "member1", "member2", "member3")
		require.NoError(t, err)
		assert.Equal(t, int64(3), added)

		// Test SIsMember
		isMember, err := client.SIsMember(ctx, key, "member1")
		require.NoError(t, err)
		assert.True(t, isMember)

		isMember, err = client.SIsMember(ctx, key, "nonexistent")
		require.NoError(t, err)
		assert.False(t, isMember)

		// Test SMembers
		members, err := client.SMembers(ctx, key)
		require.NoError(t, err)
		assert.Len(t, members, 3)
		assert.Contains(t, members, "member1")
		assert.Contains(t, members, "member2")
		assert.Contains(t, members, "member3")

		// Test SRem
		removed, err := client.SRem(ctx, key, "member2")
		require.NoError(t, err)
		assert.Equal(t, int64(1), removed)

		// Verify member is removed
		isMember, err = client.SIsMember(ctx, key, "member2")
		require.NoError(t, err)
		assert.False(t, isMember)
	})
}

func TestExpirationOperations(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	key := "test:expiration"

	t.Run("Expire and TTL", func(t *testing.T) {
		err := client.Set(ctx, key, "value", 0)
		require.NoError(t, err)

		result, err := client.Expire(ctx, key, 10*time.Second)
		require.NoError(t, err)
		assert.True(t, result)

		ttl, err := client.TTL(ctx, key)
		require.NoError(t, err)
		assert.True(t, ttl > 0 && ttl <= 10*time.Second)
	})

	t.Run("Set with expiration", func(t *testing.T) {
		expKey := "test:expiration:set"
		err := client.Set(ctx, expKey, "value", 5*time.Second)
		require.NoError(t, err)

		ttl, err := client.TTL(ctx, expKey)
		require.NoError(t, err)
		assert.True(t, ttl > 0 && ttl <= 5*time.Second)
	})
}

func TestAdvancedOperations(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	t.Run("Increment operations", func(t *testing.T) {
		key := generateTestKey("counter")

		// Test Incr
		value, err := client.Incr(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, int64(1), value)

		// Test IncrBy
		value, err = client.IncrBy(ctx, key, 5)
		require.NoError(t, err)
		assert.Equal(t, int64(6), value)

		// Test Decr
		value, err = client.Decr(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, int64(5), value)

		// Test DecrBy
		value, err = client.DecrBy(ctx, key, 3)
		require.NoError(t, err)
		assert.Equal(t, int64(2), value)
	})
}

func TestPipelineOperations(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	t.Run("Pipeline", func(t *testing.T) {
		key1 := generateTestKey("pipe_key1")
		counterKey := generateTestKey("pipe_counter")

		client.Del(ctx, key1, counterKey)
		pipe := client.Pipeline()

		// Queue multiple commands
		setCmd := pipe.Set(ctx, key1, "value1", 0)
		incrCmd := pipe.Incr(ctx, counterKey)
		getCmd := pipe.Get(ctx, key1)

		// Execute pipeline
		_, err := pipe.Exec(ctx)
		require.NoError(t, err)

		// Check results
		assert.NoError(t, setCmd.Err())
		assert.NoError(t, incrCmd.Err())
		assert.NoError(t, getCmd.Err())

		assert.Equal(t, int64(1), incrCmd.Val())
		assert.Equal(t, "value1", getCmd.Val())
	})

	t.Run("TxPipeline", func(t *testing.T) {
		key1 := generateTestKey("tx_key1")
		counterKey := generateTestKey("tx_counter")

		client.Del(ctx, key1, counterKey)
		txPipe := client.TxPipeline()

		// Queue multiple commands in transaction
		setCmd := txPipe.Set(ctx, key1, "value1", 0)
		incrCmd := txPipe.Incr(ctx, counterKey)

		// Execute transaction
		_, err := txPipe.Exec(ctx)
		require.NoError(t, err)

		// Check results
		assert.NoError(t, setCmd.Err())
		assert.NoError(t, incrCmd.Err())
	})
}

func TestHealthAndMonitoring(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	t.Run("Ping", func(t *testing.T) {
		err := client.Ping(ctx)
		require.NoError(t, err)
	})

	t.Run("Info", func(t *testing.T) {
		info, err := client.Info(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, info)

		// Test specific section
		serverInfo, err := client.Info(ctx, "server")
		require.NoError(t, err)
		assert.NotEmpty(t, serverInfo)
		assert.Contains(t, serverInfo, "redis_version")
	})

	t.Run("PoolStats", func(t *testing.T) {
		stats := client.PoolStats()
		assert.NotNil(t, stats)
		assert.GreaterOrEqual(t, stats.TotalConns, uint32(0))
	})
}

func TestContextTimeout(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	t.Run("Operation with timeout", func(t *testing.T) {
		// Create context with very short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		// This should timeout
		err := client.Set(ctx, "test:timeout", "value", 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context deadline exceeded")
	})
}

func TestConcurrentOperations(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	const goroutines = 10
	const operations = 100

	t.Run("Concurrent increments", func(t *testing.T) {
		key := generateTestKey("concurrent_counter")
		client.Del(ctx, key)

		// Initialize counter
		err := client.Set(ctx, key, "0", 0)
		require.NoError(t, err)

		// Channel to collect errors
		errChan := make(chan error, goroutines*operations)

		// Start concurrent goroutines
		for range goroutines {
			go func() {
				for range operations {
					_, err := client.Incr(ctx, key)
					errChan <- err
				}
			}()
		}

		// Collect all errors
		for range goroutines * operations {
			err := <-errChan
			assert.NoError(t, err)
		}

		// Verify final value
		finalValue, err := client.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, "1000", finalValue) // 10 goroutines * 100 operations
	})
}

// BenchmarkBasicOperations benchmarks basic Redis operations
func BenchmarkBasicOperations(b *testing.B) {
	log, err := logger.New(logger.Config{
		Level:  "error", // Reduce log noise during benchmarks
		Format: "json",
		Output: "stdout",
	})
	require.NoError(b, err)

	cfg := Config{
		Host: "localhost",
		Port: 6379,
		DB:   1,
	}

	client, err := NewClient(cfg, log)
	if err != nil {
		b.Skip("Redis server not available for benchmarking")
	}
	defer client.Close()

	ctx := context.Background()

	b.Run("Set", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := client.Set(ctx, "bench:set", "value", 0)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Get", func(b *testing.B) {
		// Setup
		client.Set(ctx, "bench:get", "value", 0)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := client.Get(ctx, "bench:get")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Incr", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := client.Incr(ctx, "bench:incr")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Pipeline", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			pipe := client.Pipeline()
			pipe.Set(ctx, "bench:pipe1", "value1", 0)
			pipe.Set(ctx, "bench:pipe2", "value2", 0)
			pipe.Get(ctx, "bench:pipe1")
			_, err := pipe.Exec(ctx)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
