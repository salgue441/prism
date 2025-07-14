// Package redis provides a high-performance Redis client with connection
// pooling, health monitoring, and comprehensive error handling for the reverse
// API gateway.
//
// This package offers a production-ready Redis client that abstracts away the
// complexity of connection management while providing excellent performance
// and reliability characteristics.
//
// Basic usage:
//
//	client, err := redis.NewClient(redis.Config{
//		Host:     "localhost",
//		Port:     6379,
//		Password: "",
//		DB:       0,
//	}, logger)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Set a key with expiration
//	err = client.Set(ctx, "user:123", "data", time.Hour)
//	if err != nil {
//		log.Error("Failed to set key", "error", err)
//	}
//
//	// Get a key
//	value, err := client.Get(ctx, "user:123")
//	if err != nil {
//		log.Error("Failed to get key", "error", err)
//	}

package redis

import (
	"context"
	"fmt"
	"prism/pkg/logger"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

// Client defines the Redis client interface used throughout the application.
// It provides high-level operations with context support and error handling.
type Client interface {
	// Basic key-value operations
	Set(ctx context.Context, key string, value any, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Del(ctx context.Context, keys ...string) (int64, error)
	Exists(ctx context.Context, keys ...string) (int64, error)

	// Hash operations
	HSet(ctx context.Context, key string, values ...any) error
	HGet(ctx context.Context, key, field string) (string, error)
	HGetAll(ctx context.Context, key string) (map[string]string, error)
	HDel(ctx context.Context, key string, fields ...string) (int64, error)

	// List operations
	LPush(ctx context.Context, key string, values ...any) (int64, error)
	RPush(ctx context.Context, key string, values ...any) (int64, error)
	LPop(ctx context.Context, key string) (string, error)
	RPop(ctx context.Context, key string) (string, error)
	LLen(ctx context.Context, key string) (int64, error)

	// Set operations
	SAdd(ctx context.Context, key string, members ...any) (int64, error)
	SRem(ctx context.Context, key string, members ...any) (int64, error)
	SMembers(ctx context.Context, key string) ([]string, error)
	SIsMember(ctx context.Context, key string, member any) (bool, error)

	// Expiration operations
	Expire(ctx context.Context, key string, expiration time.Duration) (bool, error)
	TTL(ctx context.Context, key string) (time.Duration, error)

	// Advanced operations
	Incr(ctx context.Context, key string) (int64, error)
	IncrBy(ctx context.Context, key string, value int64) (int64, error)
	Decr(ctx context.Context, key string) (int64, error)
	DecrBy(ctx context.Context, key string, value int64) (int64, error)

	// Transaction support
	TxPipeline() redis.Pipeliner
	Pipeline() redis.Pipeliner

	// Health and monitoring
	Ping(ctx context.Context) error
	Info(ctx context.Context, section ...string) (string, error)
	PoolStats() *redis.PoolStats

	// Connection management
	Close() error
}

// Config holds the Redis client configuration.
type Config struct {
	// Host is the Redis server hostname or IP address.
	Host string `json:"host" yaml:"host"`

	// Port is the Redis server port number.
	Port int `json:"port" yaml:"port"`

	// Password for Redis authentication. Leave empty if no auth required.
	Password string `json:"password,omitempty" yaml:"password,omitempty"`

	// DB is the Redis database number to select.
	DB int `json:"db" yaml:"db"`

	// PoolSize is the maximum number of socket connections.
	PoolSize int `json:"pool_size" yaml:"pool_size"`

	// MinIdleConns is the minimum number of idle connections.
	MinIdleConns int `json:"min_idle_conns" yaml:"min_idle_conns"`

	// ConnectTimeout is the timeout for connecting to Redis.
	ConnectTimeout time.Duration `json:"connect_timeout" yaml:"connect_timeout"`

	// ReadTimeout is the timeout for reading from Redis.
	ReadTimeout time.Duration `json:"read_timeout" yaml:"read_timeout"`

	// WriteTimeout is the timeout for writing to Redis.
	WriteTimeout time.Duration `json:"write_timeout" yaml:"write_timeout"`

	// MaxRetries is the maximum number of retries before giving up.
	MaxRetries int `json:"max_retries" yaml:"max_retries"`

	// MinRetryBackoff is the minimum backoff between each retry.
	MinRetryBackoff time.Duration `json:"min_retry_backoff" yaml:"min_retry_backoff"`

	// MaxRetryBackoff is the maximum backoff between each retry.
	MaxRetryBackoff time.Duration `json:"max_retry_backoff" yaml:"max_retry_backoff"`
}

// client implements the Client interface using go-redis.
type client struct {
	rdb    *redis.Client
	logger logger.Logger
	config Config
}

// NewClient creates a new Redis client with the given configuration.
// It establishes a connection pool and verifies connectivity.
//
// The client uses connection pooling for optimal performance and includes
// automatic retry logic with exponential backoff for transient failures.
func NewClient(cfg Config, log logger.Logger) (Client, error) {
	if err := validateCriticalConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid redis config: %w", err)
	}

	setConfigDefaults(&cfg)
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid redis config: %w", err)
	}

	opts := &redis.Options{
		Addr:            fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:        cfg.Password,
		DB:              cfg.DB,
		PoolSize:        cfg.PoolSize,
		MinIdleConns:    cfg.MinIdleConns,
		DialTimeout:     cfg.ConnectTimeout,
		ReadTimeout:     cfg.ReadTimeout,
		WriteTimeout:    cfg.WriteTimeout,
		MaxRetries:      cfg.MaxRetries,
		MinRetryBackoff: cfg.MinRetryBackoff,
		MaxRetryBackoff: cfg.MaxRetryBackoff,
	}

	rdb := redis.NewClient(opts)
	c := &client{
		rdb:    rdb,
		logger: log.With("component", "redis"),
		config: cfg,
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
	defer cancel()

	if err := c.Ping(ctx); err != nil {
		rdb.Close()
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	c.logger.Info("Redis client connected successfully",
		"host", cfg.Host,
		"port", cfg.Port,
		"db", cfg.DB,
		"pool_size", cfg.PoolSize,
	)

	return c, nil
}

// validateCriticalConfig validates critical configuration fields that
// shouldn't have defaults applied
// This catches invalid explicit values before defaults are set
func validateCriticalConfig(cfg Config) error {
	if cfg.Host != "" && len(strings.TrimSpace(cfg.Host)) == 0 {
		return fmt.Errorf("host cannot be whitespace only")
	}

	if cfg.Port != 0 && (cfg.Port < 1 || cfg.Port > 65535) {
		return fmt.Errorf("port must be between 1 and 65535, got %d", cfg.Port)
	}

	if cfg.DB < 0 || cfg.DB > 15 {
		return fmt.Errorf("db must be between 0 and 15, got %d", cfg.DB)
	}

	if cfg.PoolSize < 0 {
		return fmt.Errorf("pool_size cannot be negative, got %d", cfg.PoolSize)
	}

	if cfg.MinIdleConns < 0 {
		return fmt.Errorf("min_idle_conns cannot be negative, got %d",
			cfg.MinIdleConns)
	}

	// Check timeout values if they're explicitly set (non-zero)
	if cfg.ConnectTimeout < 0 {
		return fmt.Errorf("connect_timeout cannot be negative, got %v",
			cfg.ConnectTimeout)
	}

	if cfg.ReadTimeout < 0 {
		return fmt.Errorf("read_timeout cannot be negative, got %v",
			cfg.ReadTimeout)
	}

	if cfg.WriteTimeout < 0 {
		return fmt.Errorf("write_timeout cannot be negative, got %v",
			cfg.WriteTimeout)
	}

	return nil
}

// setConfigDefaults sets default values for missing configuration options.
func setConfigDefaults(cfg *Config) {
	if cfg.Host == "" {
		cfg.Host = "localhost"
	}

	if cfg.Port == 0 {
		cfg.Port = 6379
	}

	if cfg.PoolSize == 0 {
		cfg.PoolSize = 10
	}

	if cfg.MinIdleConns == 0 {
		cfg.MinIdleConns = 5
	}

	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 5 * time.Second
	}

	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 3 * time.Second
	}

	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 3 * time.Second
	}

	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}

	if cfg.MinRetryBackoff == 0 {
		cfg.MinRetryBackoff = 8 * time.Millisecond
	}

	if cfg.MaxRetryBackoff == 0 {
		cfg.MaxRetryBackoff = 512 * time.Millisecond
	}
}

// validateConfig validates the Redis configuration.
func validateConfig(cfg Config) error {
	if cfg.Host == "" {
		return fmt.Errorf("host cannot be empty")
	}

	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", cfg.Port)
	}

	if cfg.DB < 0 || cfg.DB > 15 {
		return fmt.Errorf("db must be between 0 and 15, got %d", cfg.DB)
	}

	if cfg.PoolSize < 1 {
		return fmt.Errorf("pool_size must be at least 1, got %d", cfg.PoolSize)
	}

	if cfg.MinIdleConns < 0 {
		return fmt.Errorf("min_idle_conns cannot be negative, got %d", cfg.MinIdleConns)
	}

	if cfg.MinIdleConns > cfg.PoolSize {
		return fmt.Errorf("min_idle_conns (%d) cannot be greater than pool_size (%d)", cfg.MinIdleConns, cfg.PoolSize)
	}

	if cfg.ConnectTimeout <= 0 {
		return fmt.Errorf("connect_timeout must be positive, got %v", cfg.ConnectTimeout)
	}

	if cfg.ReadTimeout <= 0 {
		return fmt.Errorf("read_timeout must be positive, got %v", cfg.ReadTimeout)
	}

	if cfg.WriteTimeout <= 0 {
		return fmt.Errorf("write_timeout must be positive, got %v", cfg.WriteTimeout)
	}

	return nil
}

// Basic key-value operations

// Set sets the key to hold the string value with optional expiration.
// If expiration is 0, the key will persist until manually deleted.
func (c *client) Set(ctx context.Context, key string, value any,
	expiration time.Duration) error {
	cmd := c.rdb.Set(ctx, key, value, expiration)
	if err := cmd.Err(); err != nil {
		c.logger.ErrorContext(ctx, "Failed to set key",
			"key", key,
			"expiration", expiration,
			"error", err,
		)

		return err
	}

	c.logger.DebugContext(ctx, "Key set successfully",
		"key", key,
		"expiration", expiration,
	)

	return nil
}

// Get returns the value of key. If the key does not exist, redis.Nil is
// returned.
func (c *client) Get(ctx context.Context, key string) (string, error) {
	cmd := c.rdb.Get(ctx, key)
	value, err := cmd.Result()

	if err != nil {
		if err == redis.Nil {
			c.logger.DebugContext(ctx, "Key not found", "key", key)
		} else {
			c.logger.ErrorContext(ctx, "Failed to get key",
				"key", key,
				"error", err,
			)
		}

		return "", err
	}

	c.logger.DebugContext(ctx, "Key retrieved successfully",
		"key", key,
		"value_length", len(value),
	)

	return value, nil
}

// Del removes the specified keys. Returns the number of keys that were removed.
func (c *client) Del(ctx context.Context, keys ...string) (int64, error) {
	cmd := c.rdb.Del(ctx, keys...)
	deleted, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to delete keys",
			"keys", keys,
			"error", err,
		)

		return 0, err
	}

	c.logger.DebugContext(ctx, "Keys deleted successfully",
		"keys", keys,
		"deleted_count", deleted,
	)

	return deleted, nil
}

// Exists returns the number of keys that exist from those specified.
func (c *client) Exists(ctx context.Context, keys ...string) (int64, error) {
	cmd := c.rdb.Exists(ctx, keys...)
	count, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to check key existence",
			"keys", keys,
			"error", err,
		)

		return 0, err
	}

	c.logger.DebugContext(ctx, "Key existence checked",
		"keys", keys,
		"existing_count", count,
	)

	return count, nil
}

// Hash operations

// HSet sets field in the hash stored at key to value.
func (c *client) HSet(ctx context.Context, key string, values ...any) error {
	cmd := c.rdb.HSet(ctx, key, values...)
	if err := cmd.Err(); err != nil {
		c.logger.ErrorContext(ctx, "Failed to set hash fields",
			"key", key,
			"field_count", len(values)/2,
			"error", err,
		)

		return err
	}

	c.logger.DebugContext(ctx, "Hash fields set successfully",
		"key", key,
		"field_count", len(values)/2,
	)

	return nil
}

// HGet returns the value associated with field in the hash stored at key.
func (c *client) HGet(ctx context.Context, key, field string) (string, error) {
	cmd := c.rdb.HGet(ctx, key, field)
	value, err := cmd.Result()

	if err != nil {
		if err == redis.Nil {
			c.logger.DebugContext(ctx, "Hash field not found",
				"key", key,
				"field", field,
				"value", value,
			)
		} else {
			c.logger.ErrorContext(ctx, "Failed to get hash field",
				"key", key,
				"field", field,
				"error", err,
			)
		}
		return "", err
	}

	c.logger.DebugContext(ctx, "Hash field retrieved successfully",
		"key", key,
		"field", field,
		"value_length", len(value),
	)

	return value, nil
}

// HGetAll returns all fields and values of the hash stored at key.
func (c *client) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	cmd := c.rdb.HGetAll(ctx, key)
	result, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to get all hash fields",
			"key", key,
			"error", err,
		)

		return nil, err
	}

	c.logger.DebugContext(ctx, "All hash fields retrieved successfully",
		"key", key,
		"field_count", len(result),
	)

	return result, nil
}

// HDel removes the specified fields from the hash stored at key.
func (c *client) HDel(ctx context.Context, key string,
	fields ...string) (int64, error) {
	cmd := c.rdb.HDel(ctx, key, fields...)
	deleted, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to delete hash fields",
			"key", key,
			"fields", fields,
			"error", err,
		)

		return 0, err
	}

	c.logger.DebugContext(ctx, "Hash fields deleted successfully",
		"key", key,
		"fields", fields,
		"deleted_count", deleted,
	)

	return deleted, nil
}

// List operations

// LPush inserts all the specified values at the head of the list stored at key.
func (c *client) LPush(ctx context.Context, key string, values ...any) (int64, error) {
	cmd := c.rdb.LPush(ctx, key, values...)
	length, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to push to list head",
			"key", key,
			"value_count", len(values),
			"error", err,
		)

		return 0, err
	}

	c.logger.DebugContext(ctx, "Values pushed to list head successfully",
		"key", key,
		"value_count", len(values),
		"new_length", length,
	)

	return length, nil
}

// RPush inserts all the specified values at the tail of the list stored at key.
func (c *client) RPush(ctx context.Context, key string, values ...any) (int64, error) {
	cmd := c.rdb.RPush(ctx, key, values...)
	length, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to push to list tail",
			"key", key,
			"value_count", len(values),
			"error", err,
		)

		return 0, err
	}

	c.logger.DebugContext(ctx, "Values pushed to list tail successfully",
		"key", key,
		"value_count", len(values),
		"new_length", length,
	)

	return length, nil
}

// LPop removes and returns the first element of the list stored at key.
func (c *client) LPop(ctx context.Context, key string) (string, error) {
	cmd := c.rdb.LPop(ctx, key)
	value, err := cmd.Result()

	if err != nil {
		if err == redis.Nil {
			c.logger.DebugContext(ctx, "List is empty", "key", key)
		} else {
			c.logger.ErrorContext(ctx, "Failed to pop from list head",
				"key", key,
				"error", err,
			)
		}

		return "", err
	}

	c.logger.DebugContext(ctx, "Value popped from list head successfully",
		"key", key,
		"value_length", len(value),
	)

	return value, nil
}

// RPop removes and returns the last element of the list stored at key.
func (c *client) RPop(ctx context.Context, key string) (string, error) {
	cmd := c.rdb.RPop(ctx, key)
	value, err := cmd.Result()

	if err != nil {
		if err == redis.Nil {
			c.logger.DebugContext(ctx, "List is empty", "key", key)
		} else {
			c.logger.ErrorContext(ctx, "Failed to pop from list tail",
				"key", key,
				"error", err,
			)
		}

		return "", err
	}

	c.logger.DebugContext(ctx, "Value popped from list tail successfully",
		"key", key,
		"value_length", len(value),
	)

	return value, nil
}

// LLen returns the length of the list stored at key.
func (c *client) LLen(ctx context.Context, key string) (int64, error) {
	cmd := c.rdb.LLen(ctx, key)
	length, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to get list length",
			"key", key,
			"error", err,
		)

		return 0, err
	}

	c.logger.DebugContext(ctx, "List length retrieved successfully",
		"key", key,
		"length", length,
	)

	return length, nil
}

// Set operations

// SAdd adds the specified members to the set stored at key.
func (c *client) SAdd(ctx context.Context, key string, members ...any) (int64, error) {
	cmd := c.rdb.SAdd(ctx, key, members...)
	added, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to add members to set",
			"key", key,
			"member_count", len(members),
			"error", err,
		)

		return 0, err
	}

	c.logger.DebugContext(ctx, "Members added to set successfully",
		"key", key,
		"member_count", len(members),
		"added_count", added,
	)

	return added, nil
}

// SRem removes the specified members from the set stored at key.
func (c *client) SRem(ctx context.Context, key string, members ...any) (int64, error) {
	cmd := c.rdb.SRem(ctx, key, members...)
	removed, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to remove members from set",
			"key", key,
			"member_count", len(members),
			"error", err,
		)

		return 0, err
	}

	c.logger.DebugContext(ctx, "Members removed from set successfully",
		"key", key,
		"member_count", len(members),
		"removed_count", removed,
	)

	return removed, nil
}

// SMembers returns all the members of the set stored at key.
func (c *client) SMembers(ctx context.Context, key string) ([]string, error) {
	cmd := c.rdb.SMembers(ctx, key)
	members, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to get set members",
			"key", key,
			"error", err,
		)

		return nil, err
	}

	c.logger.DebugContext(ctx, "Set members retrieved successfully",
		"key", key,
		"member_count", len(members),
	)

	return members, nil
}

// SIsMember returns if member is a member of the set stored at key.
func (c *client) SIsMember(ctx context.Context, key string, member any) (bool, error) {
	cmd := c.rdb.SIsMember(ctx, key, member)
	isMember, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to check set membership",
			"key", key,
			"member", member,
			"error", err,
		)

		return false, err
	}

	c.logger.DebugContext(ctx, "Set membership checked successfully",
		"key", key,
		"member", member,
		"is_member", isMember,
	)

	return isMember, nil
}

// Expiration operations

// Expire sets a timeout on key.
func (c *client) Expire(ctx context.Context, key string,
	expiration time.Duration) (bool, error) {
	cmd := c.rdb.Expire(ctx, key, expiration)
	result, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to set key expiration",
			"key", key,
			"expiration", expiration,
			"error", err,
		)

		return false, err
	}

	c.logger.DebugContext(ctx, "Key expiration set successfully",
		"key", key,
		"expiration", expiration,
		"result", result,
	)

	return result, nil
}

// TTL returns the remaining time to live of a key that has a timeout.
func (c *client) TTL(ctx context.Context, key string) (time.Duration, error) {
	cmd := c.rdb.TTL(ctx, key)
	ttl, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to get key TTL",
			"key", key,
			"error", err,
		)

		return 0, err
	}

	c.logger.DebugContext(ctx, "Key TTL retrieved successfully",
		"key", key,
		"ttl", ttl,
	)

	return ttl, nil
}

// Advanced operations

// Incr increments the number stored at key by one.
func (c *client) Incr(ctx context.Context, key string) (int64, error) {
	cmd := c.rdb.Incr(ctx, key)
	value, err := cmd.Result()
	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to increment key",
			"key", key,
			"error", err,
		)

		return 0, err
	}

	c.logger.DebugContext(ctx, "Key incremented successfully",
		"key", key,
		"new_value", value,
	)

	return value, nil
}

// IncrBy increments the number stored at key by increment.
func (c *client) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	cmd := c.rdb.IncrBy(ctx, key, value)
	newValue, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to increment key by value",
			"key", key,
			"increment", value,
			"error", err,
		)

		return 0, err
	}

	c.logger.DebugContext(ctx, "Key incremented by value successfully",
		"key", key,
		"increment", value,
		"new_value", newValue,
	)

	return newValue, nil
}

// Decr decrements the number stored at key by one.
func (c *client) Decr(ctx context.Context, key string) (int64, error) {
	cmd := c.rdb.Decr(ctx, key)
	value, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to decrement key",
			"key", key,
			"error", err,
		)

		return 0, err
	}

	c.logger.DebugContext(ctx, "Key decremented successfully",
		"key", key,
		"new_value", value,
	)

	return value, nil
}

// DecrBy decrements the number stored at key by decrement.
func (c *client) DecrBy(ctx context.Context, key string, value int64) (int64, error) {
	cmd := c.rdb.DecrBy(ctx, key, value)
	newValue, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to decrement key by value",
			"key", key,
			"decrement", value,
			"error", err,
		)

		return 0, err
	}

	c.logger.DebugContext(ctx, "Key decremented by value successfully",
		"key", key,
		"decrement", value,
		"new_value", newValue,
	)

	return newValue, nil
}

// Transaction support

// TxPipeline returns a new transaction pipeline.
func (c *client) TxPipeline() redis.Pipeliner {
	return c.rdb.TxPipeline()
}

// Pipeline returns a new pipeline.
func (c *client) Pipeline() redis.Pipeliner {
	return c.rdb.Pipeline()
}

// Health and monitoring

// Ping checks the connection to Redis server.
func (c *client) Ping(ctx context.Context) error {
	cmd := c.rdb.Ping(ctx)
	if err := cmd.Err(); err != nil {
		c.logger.ErrorContext(ctx, "Redis ping failed", "error", err)
		return err
	}

	c.logger.DebugContext(ctx, "Redis ping successful")
	return nil
}

// Info returns information and statistics about the Redis server.
func (c *client) Info(ctx context.Context, section ...string) (string, error) {
	cmd := c.rdb.Info(ctx, section...)
	info, err := cmd.Result()

	if err != nil {
		c.logger.ErrorContext(ctx, "Failed to get Redis info",
			"sections", section,
			"error", err,
		)

		return "", err
	}

	c.logger.DebugContext(ctx, "Redis info retrieved successfully",
		"sections", section,
		"info_length", len(info),
	)

	return info, nil
}

// PoolStats returns connection pool statistics.
func (c *client) PoolStats() *redis.PoolStats {
	return c.rdb.PoolStats()
}

// Connection management

// Close closes the Redis client and releases all open connections.
func (c *client) Close() error {
	c.logger.Info("Closing Redis client")

	if err := c.rdb.Close(); err != nil {
		c.logger.Error("Failed to close Redis client", "error", err)
		return err
	}

	c.logger.Info("Redis client closed successfully")
	return nil
}
