// Package cache provides a Redis client wrapper for caching and session management.
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Common errors.
var (
	ErrKeyNotFound = errors.New("key not found")
	ErrNilValue    = errors.New("nil value")
)

// Config holds Redis client configuration.
type Config struct {
	Address      string        `mapstructure:"address"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	MaxRetries   int           `mapstructure:"max_retries"`
	KeyPrefix    string        `mapstructure:"key_prefix"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Address:      "localhost:6379",
		Password:     "",
		DB:           0,
		PoolSize:     10,
		MinIdleConns: 2,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		MaxRetries:   3,
		KeyPrefix:    "prism:",
	}
}

// Client wraps the Redis client with additional functionality.
type Client struct {
	client    *redis.Client
	keyPrefix string
}

// New creates a new Redis client.
func New(cfg Config) (*Client, error) {
	if cfg.PoolSize == 0 {
		cfg.PoolSize = 10
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 3 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 3 * time.Second
	}

	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Address,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		MaxRetries:   cfg.MaxRetries,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &Client{
		client:    client,
		keyPrefix: cfg.KeyPrefix,
	}, nil
}

// Close closes the Redis connection.
func (c *Client) Close() error {
	return c.client.Close()
}

// Ping checks the Redis connection.
func (c *Client) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Client returns the underlying Redis client.
func (c *Client) Client() *redis.Client {
	return c.client
}

// prefixKey adds the configured prefix to a key.
func (c *Client) prefixKey(key string) string {
	return c.keyPrefix + key
}

// --- String Operations ---

// Get retrieves a string value by key.
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	val, err := c.client.Get(ctx, c.prefixKey(key)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrKeyNotFound
	}
	return val, err
}

// Set stores a string value with optional expiration.
func (c *Client) Set(ctx context.Context, key, value string, expiration time.Duration) error {
	return c.client.Set(ctx, c.prefixKey(key), value, expiration).Err()
}

// SetNX sets a value only if the key doesn't exist (for distributed locks).
func (c *Client) SetNX(ctx context.Context, key, value string, expiration time.Duration) (bool, error) {
	return c.client.SetNX(ctx, c.prefixKey(key), value, expiration).Result()
}

// Delete removes a key.
func (c *Client) Delete(ctx context.Context, keys ...string) error {
	prefixedKeys := make([]string, len(keys))
	for i, key := range keys {
		prefixedKeys[i] = c.prefixKey(key)
	}
	return c.client.Del(ctx, prefixedKeys...).Err()
}

// Exists checks if a key exists.
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	n, err := c.client.Exists(ctx, c.prefixKey(key)).Result()
	return n > 0, err
}

// Expire sets a timeout on a key.
func (c *Client) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return c.client.Expire(ctx, c.prefixKey(key), expiration).Err()
}

// TTL returns the remaining time to live of a key.
func (c *Client) TTL(ctx context.Context, key string) (time.Duration, error) {
	return c.client.TTL(ctx, c.prefixKey(key)).Result()
}

// --- JSON Operations ---

// GetJSON retrieves and unmarshals a JSON value.
func (c *Client) GetJSON(ctx context.Context, key string, dest any) error {
	val, err := c.Get(ctx, key)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(val), dest)
}

// SetJSON marshals and stores a value as JSON.
func (c *Client) SetJSON(ctx context.Context, key string, value any, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}
	return c.Set(ctx, key, string(data), expiration)
}

// --- Counter Operations ---

// Incr increments a counter.
func (c *Client) Incr(ctx context.Context, key string) (int64, error) {
	return c.client.Incr(ctx, c.prefixKey(key)).Result()
}

// IncrBy increments a counter by a specific amount.
func (c *Client) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	return c.client.IncrBy(ctx, c.prefixKey(key), value).Result()
}

// Decr decrements a counter.
func (c *Client) Decr(ctx context.Context, key string) (int64, error) {
	return c.client.Decr(ctx, c.prefixKey(key)).Result()
}

// --- Hash Operations ---

// HGet retrieves a hash field.
func (c *Client) HGet(ctx context.Context, key, field string) (string, error) {
	val, err := c.client.HGet(ctx, c.prefixKey(key), field).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrKeyNotFound
	}
	return val, err
}

// HSet sets hash fields.
func (c *Client) HSet(ctx context.Context, key string, values ...any) error {
	return c.client.HSet(ctx, c.prefixKey(key), values...).Err()
}

// HGetAll retrieves all hash fields.
func (c *Client) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	return c.client.HGetAll(ctx, c.prefixKey(key)).Result()
}

// HDel deletes hash fields.
func (c *Client) HDel(ctx context.Context, key string, fields ...string) error {
	return c.client.HDel(ctx, c.prefixKey(key), fields...).Err()
}

// --- Set Operations ---

// SAdd adds members to a set.
func (c *Client) SAdd(ctx context.Context, key string, members ...any) error {
	return c.client.SAdd(ctx, c.prefixKey(key), members...).Err()
}

// SMembers returns all members of a set.
func (c *Client) SMembers(ctx context.Context, key string) ([]string, error) {
	return c.client.SMembers(ctx, c.prefixKey(key)).Result()
}

// SIsMember checks if a value is a member of a set.
func (c *Client) SIsMember(ctx context.Context, key string, member any) (bool, error) {
	return c.client.SIsMember(ctx, c.prefixKey(key), member).Result()
}

// SRem removes members from a set.
func (c *Client) SRem(ctx context.Context, key string, members ...any) error {
	return c.client.SRem(ctx, c.prefixKey(key), members...).Err()
}

// --- Rate Limiting ---

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	Key      string
	Limit    int64
	Window   time.Duration
	BurstMax int64
}

// CheckRateLimit checks if a request is within rate limits using sliding window.
func (c *Client) CheckRateLimit(ctx context.Context, cfg RateLimitConfig) (allowed bool, remaining int64, resetAt time.Time, err error) {
	now := time.Now()
	windowStart := now.Add(-cfg.Window)
	key := c.prefixKey("ratelimit:" + cfg.Key)

	// Use a pipeline for atomic operations
	pipe := c.client.Pipeline()

	// Remove old entries outside the window
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart.UnixNano()))

	// Count current entries
	countCmd := pipe.ZCard(ctx, key)

	// Execute pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		return false, 0, time.Time{}, err
	}

	count := countCmd.Val()
	limit := cfg.Limit
	if cfg.BurstMax > 0 && cfg.BurstMax > limit {
		limit = cfg.BurstMax
	}

	remaining = limit - count
	if remaining < 0 {
		remaining = 0
	}

	// Calculate reset time
	resetAt = now.Add(cfg.Window)

	if count >= limit {
		return false, remaining, resetAt, nil
	}

	// Add current request
	err = c.client.ZAdd(ctx, key, redis.Z{
		Score:  float64(now.UnixNano()),
		Member: fmt.Sprintf("%d", now.UnixNano()),
	}).Err()
	if err != nil {
		return false, remaining, resetAt, err
	}

	// Set expiration on the key
	c.client.Expire(ctx, key, cfg.Window+time.Minute)

	return true, remaining - 1, resetAt, nil
}

// --- Distributed Lock ---

// Lock represents a distributed lock.
type Lock struct {
	client *Client
	key    string
	value  string
	ttl    time.Duration
}

// AcquireLock attempts to acquire a distributed lock.
func (c *Client) AcquireLock(ctx context.Context, key string, ttl time.Duration) (*Lock, error) {
	lockKey := "lock:" + key
	lockValue := fmt.Sprintf("%d", time.Now().UnixNano())

	acquired, err := c.SetNX(ctx, lockKey, lockValue, ttl)
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, errors.New("lock already held")
	}

	return &Lock{
		client: c,
		key:    lockKey,
		value:  lockValue,
		ttl:    ttl,
	}, nil
}

// Release releases the distributed lock.
func (l *Lock) Release(ctx context.Context) error {
	// Use a Lua script for atomic check-and-delete
	script := redis.NewScript(`
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
	`)
	return script.Run(ctx, l.client.client, []string{l.client.prefixKey(l.key)}, l.value).Err()
}

// Extend extends the lock TTL.
func (l *Lock) Extend(ctx context.Context, ttl time.Duration) error {
	script := redis.NewScript(`
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("pexpire", KEYS[1], ARGV[2])
		else
			return 0
		end
	`)
	result, err := script.Run(ctx, l.client.client, []string{l.client.prefixKey(l.key)}, l.value, ttl.Milliseconds()).Int64()
	if err != nil {
		return err
	}
	if result == 0 {
		return errors.New("lock not held or expired")
	}
	l.ttl = ttl
	return nil
}

// --- Pool Stats ---

// PoolStats returns connection pool statistics.
func (c *Client) PoolStats() *redis.PoolStats {
	return c.client.PoolStats()
}

// Global client instance.
var globalClient *Client

// Init initializes the global Redis client.
func Init(cfg Config) (*Client, error) {
	client, err := New(cfg)
	if err != nil {
		return nil, err
	}
	globalClient = client
	return client, nil
}

// Default returns the global Redis client.
func Default() *Client {
	return globalClient
}
