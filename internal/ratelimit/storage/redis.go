package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"prism/internal/ratelimit"
	"prism/pkg/logger"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStorage implements Redis-based storage for distributed rate limiting.
// This storage backend provides high performance with persistence and
// is suitable for multi-instance deployments requiring shared rate limits.
type RedisStorage struct {
	config *ratelimit.Config
	logger *logger.Logger
	client redis.Cmdable

	// Connection management
	pool    *redis.Client
	cluster *redis.ClusterClient
	ring    *redis.Ring

	// Circuit breaker state
	mu           sync.RWMutex
	circuitOpen  bool
	lastFailure  time.Time
	failureCount int64

	// Metrics
	metrics *redisMetrics

	// Lua scripts for atomic operations
	scripts *redisScripts
}

// redisMetrics tracks Redis operation metrics.
type redisMetrics struct {
	mu             sync.RWMutex
	gets           int64
	sets           int64
	deletes        int64
	increments     int64
	batchOps       int64
	hits           int64
	misses         int64
	errors         int64
	timeouts       int64
	circuitBreaks  int64
	reconnections  int64
	totalLatency   time.Duration
	operationCount int64
	avgLatency     time.Duration
	lastError      string
	lastErrorTime  time.Time
	connPoolStats  *redis.PoolStats
}

// redisScripts contains precompiled Lua scripts for atomic operations.
type redisScripts struct {
	increment *redis.Script
	batchGet  *redis.Script
	batchSet  *redis.Script
	cleanup   *redis.Script
	rateLimit *redis.Script
}

// Redis Lua scripts for atomic operations
const (
	// Atomic increment with TTL
	incrementScript = `
		local key = KEYS[1]
		local delta = tonumber(ARGV[1])
		local ttl = tonumber(ARGV[2])
		
		local current = redis.call('GET', key)
		if current == false then
			current = 0
		else
			current = tonumber(current)
		end
		
		local new_value = current + delta
		redis.call('SET', key, new_value, 'EX', ttl)
		return new_value
	`

	// Batch get with JSON decoding
	batchGetScript = `
		local keys = KEYS
		local result = {}
		
		for i = 1, #keys do
			local value = redis.call('GET', keys[i])
			if value ~= false then
				result[keys[i]] = value
			end
		end
		
		return result
	`

	// Rate limiting check with token bucket logic
	rateLimitScript = `
		local key = KEYS[1]
		local capacity = tonumber(ARGV[1])
		local refill_rate = tonumber(ARGV[2])
		local requested = tonumber(ARGV[3])
		local ttl = tonumber(ARGV[4])
		local now = tonumber(ARGV[5])
		
		local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
		local tokens = tonumber(bucket[1]) or capacity
		local last_refill = tonumber(bucket[2]) or now
		
		-- Calculate tokens to add
		local elapsed = (now - last_refill) / 1000.0
		local tokens_to_add = elapsed * refill_rate
		tokens = math.min(tokens + tokens_to_add, capacity)
		
		-- Check if request can be satisfied
		local allowed = tokens >= requested
		if allowed then
			tokens = tokens - requested
		end
		
		-- Update bucket state
		redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
		redis.call('EXPIRE', key, ttl)
		
		return {allowed and 1 or 0, math.floor(tokens)}
	`
)

// NewRedisStorage creates a new Redis-based storage backend.
func NewRedisStorage(config *ratelimit.Config, log *logger.Logger) (*RedisStorage, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if log == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	if config.RedisURL == "" {
		return nil, fmt.Errorf("redis_url is required for Redis storage")
	}

	rs := &RedisStorage{
		config:  config,
		logger:  log,
		metrics: &redisMetrics{},
	}

	rs.scripts = &redisScripts{
		increment: redis.NewScript(incrementScript),
		batchGet:  redis.NewScript(batchGetScript),
		rateLimit: redis.NewScript(rateLimitScript),
	}

	if err := rs.initRedisClient(); err != nil {
		return nil, fmt.Errorf("failed to initialize Redis client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rs.client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	log.Info("Redis storage initialized",
		"url", rs.sanitizeURL(config.RedisURL),
		"pool_size", config.RedisPool)

	return rs, nil
}

// Get retrieves a value from Redis storage.
func (rs *RedisStorage) Get(ctx context.Context, key string) (*ratelimit.StorageValue, error) {
	start := time.Now()
	rs.recordLatency(time.Since(start))

	if rs.isCircuitOpen() {
		rs.metrics.mu.Lock()
		rs.metrics.circuitBreaks++
		rs.metrics.mu.Unlock()
		return nil, ratelimit.ErrStorageUnavailable
	}

	rs.metrics.mu.Lock()
	rs.metrics.gets++
	rs.metrics.mu.Unlock()

	result, err := rs.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			rs.metrics.mu.Lock()
			rs.metrics.misses++
			rs.metrics.mu.Unlock()

			return nil, nil
		}

		rs.handleError(err)
		return nil, err
	}

	value, err := rs.deserializeValue(result)
	if err != nil {
		rs.handleError(err)
		return nil, fmt.Errorf("failed to deserialize value: %w", err)
	}

	rs.metrics.mu.Lock()
	rs.metrics.hits++
	rs.metrics.mu.Unlock()

	return value, nil
}

// Set stores a value in Redis storage with TTL.
func (rs *RedisStorage) Set(ctx context.Context, key string, value *ratelimit.StorageValue, ttl time.Duration) error {
	start := time.Now()
	rs.recordLatency(time.Since(start))

	if rs.isCircuitOpen() {
		rs.metrics.mu.Lock()
		rs.metrics.circuitBreaks++
		rs.metrics.mu.Unlock()
		return ratelimit.ErrStorageUnavailable
	}

	if value == nil {
		return fmt.Errorf("value cannot be nil")
	}

	data, err := rs.serializeValue(value)
	if err != nil {
		return fmt.Errorf("failed to serialize value: %w", err)
	}

	rs.metrics.mu.Lock()
	rs.metrics.sets++
	rs.metrics.mu.Unlock()

	err = rs.client.Set(ctx, key, data, ttl).Err()
	if err != nil {
		rs.handleError(err)
		return err
	}

	return nil
}

// Increment atomically increments a counter with TTL using Lua script.
func (rs *RedisStorage) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	start := time.Now()
	rs.recordLatency(time.Since(start))

	if rs.isCircuitOpen() {
		rs.metrics.mu.Lock()
		rs.metrics.circuitBreaks++
		rs.metrics.mu.Unlock()
		return 0, ratelimit.ErrStorageUnavailable
	}

	rs.metrics.mu.Lock()
	rs.metrics.increments++
	rs.metrics.mu.Unlock()

	result, err := rs.scripts.increment.Run(ctx, rs.client,
		[]string{key},
		delta,
		int64(ttl.Seconds())).Result()

	if err != nil {
		rs.handleError(err)
		return 0, err
	}

	newValue, ok := result.(int64)
	if !ok {
		return 0, fmt.Errorf("unexpected result type from increment script")
	}

	return newValue, nil
}

// Delete removes a key from Redis storage.
func (rs *RedisStorage) Delete(ctx context.Context, key string) error {
	start := time.Now()
	rs.recordLatency(time.Since(start))

	if rs.isCircuitOpen() {
		rs.metrics.mu.Lock()
		rs.metrics.circuitBreaks++
		rs.metrics.mu.Unlock()
		return ratelimit.ErrStorageUnavailable
	}

	rs.metrics.mu.Lock()
	rs.metrics.deletes++
	rs.metrics.mu.Unlock()

	err := rs.client.Del(ctx, key).Err()
	if err != nil {
		rs.handleError(err)
		return err
	}

	return nil
}

// Exists checks if a key exists in Redis storage.
func (rs *RedisStorage) Exists(ctx context.Context, key string) (bool, error) {
	start := time.Now()
	rs.recordLatency(time.Since(start))

	if rs.isCircuitOpen() {
		rs.metrics.mu.Lock()
		rs.metrics.circuitBreaks++
		rs.metrics.mu.Unlock()
		return false, ratelimit.ErrStorageUnavailable
	}

	result, err := rs.client.Exists(ctx, key).Result()
	if err != nil {
		rs.handleError(err)
		return false, err
	}

	return result > 0, nil
}

// BatchGet retrieves multiple values efficiently using pipeline.
func (rs *RedisStorage) BatchGet(ctx context.Context, keys []string) (map[string]*ratelimit.StorageValue, error) {
	start := time.Now()
	rs.recordLatency(time.Since(start))

	if rs.isCircuitOpen() {
		rs.metrics.mu.Lock()
		rs.metrics.circuitBreaks++
		rs.metrics.mu.Unlock()
		return nil, ratelimit.ErrStorageUnavailable
	}

	if len(keys) == 0 {
		return make(map[string]*ratelimit.StorageValue), nil
	}

	rs.metrics.mu.Lock()
	rs.metrics.batchOps++
	rs.metrics.gets += int64(len(keys))
	rs.metrics.mu.Unlock()

	results, err := rs.client.MGet(ctx, keys...).Result()
	if err != nil {
		rs.handleError(err)
		return nil, err
	}

	response := make(map[string]*ratelimit.StorageValue)
	hits := int64(0)

	for i, result := range results {
		if result != nil {
			if str, ok := result.(string); ok {
				value, err := rs.deserializeValue(str)
				if err != nil {
					rs.logger.Error("Failed to deserialize batch value",
						"key", keys[i],
						"error", err)
					continue
				}

				response[keys[i]] = value
				hits++
			}
		}
	}

	rs.metrics.mu.Lock()
	rs.metrics.hits += hits
	rs.metrics.misses += int64(len(keys)) - hits
	rs.metrics.mu.Unlock()

	return response, nil
}

// BatchSet stores multiple values efficiently using pipeline.
func (rs *RedisStorage) BatchSet(ctx context.Context, values map[string]*ratelimit.StorageValue, ttl time.Duration) error {
	start := time.Now()
	rs.recordLatency(time.Since(start))

	if rs.isCircuitOpen() {
		rs.metrics.mu.Lock()
		rs.metrics.circuitBreaks++
		rs.metrics.mu.Unlock()
		return ratelimit.ErrStorageUnavailable
	}

	if len(values) == 0 {
		return nil
	}

	rs.metrics.mu.Lock()
	rs.metrics.batchOps++
	rs.metrics.sets += int64(len(values))
	rs.metrics.mu.Unlock()

	pipe := rs.client.Pipeline()
	for key, value := range values {
		if value == nil {
			continue
		}

		data, err := rs.serializeValue(value)
		if err != nil {
			return fmt.Errorf("failed to serialize value for key %s: %w", key, err)
		}

		pipe.Set(ctx, key, data, ttl)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		rs.handleError(err)
		return err
	}

	return nil
}

// Close closes the Redis connection.
func (rs *RedisStorage) Close() error {
	rs.logger.Info("Closing Redis storage")

	if rs.pool != nil {
		return rs.pool.Close()
	}

	if rs.cluster != nil {
		return rs.cluster.Close()
	}

	if rs.ring != nil {
		return rs.ring.Close()
	}

	return nil
}

// Ping checks if Redis is available.
func (rs *RedisStorage) Ping(ctx context.Context) error {
	if rs.isCircuitOpen() {
		return ratelimit.ErrStorageUnavailable
	}

	err := rs.client.Ping(ctx).Err()
	if err != nil {
		rs.handleError(err)
		return err
	}

	rs.mu.Lock()
	rs.circuitOpen = false
	rs.failureCount = 0
	rs.mu.Unlock()

	return nil
}

// Private methods

// initRedisClient initializes the appropriate Redis client based on configuration.
func (rs *RedisStorage) initRedisClient() error {
	if strings.Contains(rs.config.RedisURL, "redis-cluster://") {
		return rs.initClusterClient()
	} else if strings.Contains(rs.config.RedisURL, "redis-ring://") {
		return rs.initRingClient()
	} else {
		return rs.initStandardClient()
	}
}

// initStandardClient initializes a standard Redis client.
func (rs *RedisStorage) initStandardClient() error {
	opt, err := redis.ParseURL(rs.config.RedisURL)
	if err != nil {
		return fmt.Errorf("invalid Redis URL: %w", err)
	}

	if rs.config.RedisPool > 0 {
		opt.PoolSize = rs.config.RedisPool
	}

	opt.MaxRetries = 3
	opt.MinRetryBackoff = 100 * time.Millisecond
	opt.MaxRetryBackoff = 1 * time.Second
	opt.DialTimeout = 5 * time.Second
	opt.ReadTimeout = 3 * time.Second
	opt.WriteTimeout = 3 * time.Second
	opt.PoolTimeout = 4 * time.Second

	rs.pool = redis.NewClient(opt)
	rs.client = rs.pool

	return nil
}

// initClusterClient initializes a Redis cluster client.
func (rs *RedisStorage) initClusterClient() error {
	urls := []string{strings.Replace(rs.config.RedisURL,
		"redis-cluster://", "redis://", 1)}

	opt := &redis.ClusterOptions{
		Addrs:           urls,
		MaxRetries:      3,
		MinRetryBackoff: 100 * time.Millisecond,
		MaxRetryBackoff: 1 * time.Second,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		PoolTimeout:     4 * time.Second,
	}

	if rs.config.RedisPool > 0 {
		opt.PoolSize = rs.config.RedisPool
	}

	rs.cluster = redis.NewClusterClient(opt)
	rs.client = rs.cluster

	return nil
}

// initRingClient initializes a Redis ring client for sharding.
func (rs *RedisStorage) initRingClient() error {
	addrs := map[string]string{
		"server1": strings.Replace(rs.config.RedisURL,
			"redis-ring://", "redis://", 1),
	}

	opt := &redis.RingOptions{
		Addrs:           addrs,
		MaxRetries:      3,
		MinRetryBackoff: 100 * time.Millisecond,
		MaxRetryBackoff: 1 * time.Second,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		PoolTimeout:     4 * time.Second,
	}

	if rs.config.RedisPool > 0 {
		opt.PoolSize = rs.config.RedisPool
	}

	rs.ring = redis.NewRing(opt)
	rs.client = rs.ring

	return nil
}

// serializeValue converts a StorageValue to JSON for Redis storage.
func (rs *RedisStorage) serializeValue(value *ratelimit.StorageValue) (string, error) {
	if value == nil {
		return "", fmt.Errorf("cannot serialize nil value")
	}

	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("JSON marshal failed: %w", err)
	}

	return string(data), nil
}

// deserializeValue converts JSON data back to a StorageValue.
func (rs *RedisStorage) deserializeValue(data string) (*ratelimit.StorageValue, error) {
	if data == "" {
		return nil, fmt.Errorf("cannot deserialize empty data")
	}

	var value ratelimit.StorageValue
	err := json.Unmarshal([]byte(data), &value)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	return &value, nil
}

// handleError handles Redis operation errors and manages circuit breaker.
func (rs *RedisStorage) handleError(err error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.failureCount++
	rs.lastFailure = time.Now()

	rs.metrics.mu.Lock()
	rs.metrics.errors++
	rs.metrics.lastError = err.Error()
	rs.metrics.lastErrorTime = time.Now()
	rs.metrics.mu.Unlock()

	if rs.failureCount >= 5 {
		rs.circuitOpen = true
		rs.logger.Error("Redis circuit breaker opened",
			"failure_count", rs.failureCount,
			"last_error", err.Error())
	}

	if err == context.DeadlineExceeded {
		rs.metrics.mu.Lock()
		rs.metrics.timeouts++
		rs.metrics.mu.Unlock()
	}
}

// isCircuitOpen checks if the circuit breaker is open.
func (rs *RedisStorage) isCircuitOpen() bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if !rs.circuitOpen {
		return false
	}

	if time.Since(rs.lastFailure) > 30*time.Second {
		rs.circuitOpen = false
		rs.failureCount = 0
		rs.logger.Info("Redis circuit breaker reset")
		return false
	}

	return true
}

// recordLatency records operation latency for metrics.
func (rs *RedisStorage) recordLatency(duration time.Duration) {
	rs.metrics.mu.Lock()
	defer rs.metrics.mu.Unlock()

	rs.metrics.totalLatency += duration
	rs.metrics.operationCount++

	if rs.metrics.operationCount > 0 {
		rs.metrics.avgLatency = rs.metrics.totalLatency / time.Duration(rs.metrics.operationCount)
	}
}

// sanitizeURL removes sensitive information from Redis URL for logging.
func (rs *RedisStorage) sanitizeURL(url string) string {
	if idx := strings.Index(url, "@"); idx != -1 {
		if colonIdx := strings.LastIndex(url[:idx], ":"); colonIdx != -1 {
			return url[:colonIdx] + ":***" + url[idx:]
		}
	}

	return url
}

// Advanced Redis operations

// RateLimitCheck performs atomic rate limit check using Lua script.
func (rs *RedisStorage) RateLimitCheck(
	ctx context.Context,
	key string,
	capacity, refillRate, requested int64,
	ttl time.Duration,
) (bool, int64, error) {
	start := time.Now()
	rs.recordLatency(time.Since(start))

	if rs.isCircuitOpen() {
		rs.metrics.mu.Lock()
		rs.metrics.circuitBreaks++
		rs.metrics.mu.Unlock()
		return false, 0, ratelimit.ErrStorageUnavailable
	}

	now := time.Now().UnixMilli()
	result, err := rs.scripts.rateLimit.Run(ctx, rs.client,
		[]string{key},
		capacity,
		refillRate,
		requested,
		int64(ttl.Seconds()),
		now).Result()

	if err != nil {
		rs.handleError(err)
		return false, 0, err
	}

	results, ok := result.([]interface{})
	if !ok || len(results) != 2 {
		return false, 0, fmt.Errorf("unexpected result from rate limit script")
	}

	allowed := results[0].(int64) == 1
	remaining := results[1].(int64)

	return allowed, remaining, nil
}

// SetTTL updates the TTL for an existing key.
func (rs *RedisStorage) SetTTL(ctx context.Context, key string, ttl time.Duration) error {
	start := time.Now()
	rs.recordLatency(time.Since(start))

	if rs.isCircuitOpen() {
		return ratelimit.ErrStorageUnavailable
	}

	err := rs.client.Expire(ctx, key, ttl).Err()
	if err != nil {
		rs.handleError(err)
		return err
	}

	return nil
}

// GetTTL returns the remaining TTL for a key.
func (rs *RedisStorage) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	start := time.Now()
	rs.recordLatency(time.Since(start))

	if rs.isCircuitOpen() {
		return 0, ratelimit.ErrStorageUnavailable
	}

	ttl, err := rs.client.TTL(ctx, key).Result()
	if err != nil {
		rs.handleError(err)
		return 0, err
	}

	return ttl, nil
}

// GetSize returns the memory usage of a key (Redis MEMORY USAGE command).
func (rs *RedisStorage) GetSize(ctx context.Context, key string) (int64, error) {
	start := time.Now()
	rs.recordLatency(time.Since(start))

	if rs.isCircuitOpen() {
		return 0, ratelimit.ErrStorageUnavailable
	}

	size, err := rs.client.MemoryUsage(ctx, key).Result()
	if err != nil {
		val, getErr := rs.client.Get(ctx, key).Result()
		if getErr != nil {
			rs.handleError(getErr)
			return 0, getErr
		}

		return int64(len(val)), nil
	}

	return size, nil
}

// Scan returns keys matching a pattern.
func (rs *RedisStorage) Scan(ctx context.Context, pattern string, count int64) ([]string, error) {
	start := time.Now()
	rs.recordLatency(time.Since(start))

	if rs.isCircuitOpen() {
		return nil, ratelimit.ErrStorageUnavailable
	}

	var keys []string
	iter := rs.client.Scan(ctx, 0, pattern, count).Iterator()

	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}

	if err := iter.Err(); err != nil {
		rs.handleError(err)
		return nil, err
	}

	return keys, nil
}

// FlushPattern deletes all keys matching a pattern.
func (rs *RedisStorage) FlushPattern(ctx context.Context, pattern string) (int64, error) {
	start := time.Now()
	rs.recordLatency(time.Since(start))

	if rs.isCircuitOpen() {
		return 0, ratelimit.ErrStorageUnavailable
	}

	keys, err := rs.Scan(ctx, pattern, 1000)
	if err != nil {
		return 0, err
	}

	if len(keys) == 0 {
		return 0, nil
	}

	deleted := int64(0)
	batchSize := 1000

	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}

		batch := keys[i:end]
		result, err := rs.client.Del(ctx, batch...).Result()
		if err != nil {
			rs.handleError(err)
			return deleted, err
		}

		deleted += result
	}

	return deleted, nil
}

// Metrics and monitoring

// GetMetrics returns current Redis storage metrics.
type RedisStorageMetrics struct {
	Gets          int64            `json:"gets"`
	Sets          int64            `json:"sets"`
	Deletes       int64            `json:"deletes"`
	Increments    int64            `json:"increments"`
	BatchOps      int64            `json:"batch_ops"`
	Hits          int64            `json:"hits"`
	Misses        int64            `json:"misses"`
	HitRatio      float64          `json:"hit_ratio"`
	Errors        int64            `json:"errors"`
	Timeouts      int64            `json:"timeouts"`
	CircuitBreaks int64            `json:"circuit_breaks"`
	Reconnections int64            `json:"reconnections"`
	AvgLatency    time.Duration    `json:"avg_latency"`
	LastError     string           `json:"last_error,omitempty"`
	LastErrorTime time.Time        `json:"last_error_time,omitempty"`
	CircuitOpen   bool             `json:"circuit_open"`
	FailureCount  int64            `json:"failure_count"`
	ConnPoolStats *redis.PoolStats `json:"connection_pool_stats,omitempty"`
}

func (rs *RedisStorage) GetMetrics() *RedisStorageMetrics {
	rs.metrics.mu.RLock()
	defer rs.metrics.mu.RUnlock()

	var hitRatio float64
	totalRequests := rs.metrics.hits + rs.metrics.misses
	if totalRequests > 0 {
		hitRatio = float64(rs.metrics.hits) / float64(totalRequests)
	}

	rs.mu.RLock()
	circuitOpen := rs.circuitOpen
	failureCount := rs.failureCount
	rs.mu.RUnlock()

	var poolStats *redis.PoolStats
	if rs.pool != nil {
		poolStats = rs.pool.PoolStats()
	}

	return &RedisStorageMetrics{
		Gets:          rs.metrics.gets,
		Sets:          rs.metrics.sets,
		Deletes:       rs.metrics.deletes,
		Increments:    rs.metrics.increments,
		BatchOps:      rs.metrics.batchOps,
		Hits:          rs.metrics.hits,
		Misses:        rs.metrics.misses,
		HitRatio:      hitRatio,
		Errors:        rs.metrics.errors,
		Timeouts:      rs.metrics.timeouts,
		CircuitBreaks: rs.metrics.circuitBreaks,
		Reconnections: rs.metrics.reconnections,
		AvgLatency:    rs.metrics.avgLatency,
		LastError:     rs.metrics.lastError,
		LastErrorTime: rs.metrics.lastErrorTime,
		CircuitOpen:   circuitOpen,
		FailureCount:  failureCount,
		ConnPoolStats: poolStats,
	}
}

// HealthCheck performs a comprehensive health check on Redis.
func (rs *RedisStorage) HealthCheck() error {
	if rs.isCircuitOpen() {
		return fmt.Errorf("redis circuit breaker is open")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rs.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}

	testKey := rs.config.KeyPrefix + "__health_check__"
	testValue := &ratelimit.StorageValue{Count: 1}

	if err := rs.Set(ctx, testKey, testValue, time.Second*10); err != nil {
		return fmt.Errorf("redis health check set failed: %w", err)
	}

	if _, err := rs.Get(ctx, testKey); err != nil {
		return fmt.Errorf("redis health check get failed: %w", err)
	}

	if err := rs.Delete(ctx, testKey); err != nil {
		return fmt.Errorf("redis health check delete failed: %w", err)
	}

	rs.mu.Lock()
	rs.circuitOpen = false
	rs.failureCount = 0
	rs.mu.Unlock()

	return nil
}

// Info returns Redis server information.
func (rs *RedisStorage) Info(ctx context.Context) (map[string]string, error) {
	if rs.isCircuitOpen() {
		return nil, ratelimit.ErrStorageUnavailable
	}

	result, err := rs.client.Info(ctx).Result()
	if err != nil {
		rs.handleError(err)
		return nil, err
	}

	info := make(map[string]string)
	lines := strings.Split(result, "\r\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			info[parts[0]] = parts[1]
		}
	}

	return info, nil
}

// String returns a string representation of the Redis storage state.
func (rs *RedisStorage) String() string {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	status := "connected"
	if rs.circuitOpen {
		status = "circuit_open"
	}

	return fmt.Sprintf("RedisStorage{url: %s, status: %s, failures: %d}",
		rs.sanitizeURL(rs.config.RedisURL), status, rs.failureCount)
}

// Cleanup and maintenance

// Cleanup removes expired keys using Redis SCAN.
func (rs *RedisStorage) Cleanup(ctx context.Context, pattern string) (int64, error) {
	if rs.isCircuitOpen() {
		return 0, ratelimit.ErrStorageUnavailable
	}

	// This is a simplified cleanup - in production you might want
	// to use Redis keyspace notifications or TTL-based expiration
	return rs.FlushPattern(ctx, pattern)
}

// Configuration update

// UpdateConfig updates the Redis storage configuration.
func (rs *RedisStorage) UpdateConfig(newConfig *ratelimit.Config) error {
	if newConfig == nil {
		return fmt.Errorf("config cannot be nil")
	}

	if newConfig.RedisURL != rs.config.RedisURL ||
		newConfig.RedisPool != rs.config.RedisPool {
		rs.logger.Info("Redis configuration changed, reconnection required")
	}

	rs.config = newConfig
	return nil
}

// Factory function

// NewRedisStorageFromURL creates Redis storage from a URL string.
func NewRedisStorageFromURL(url string, logger *logger.Logger) (*RedisStorage, error) {
	config := &ratelimit.Config{
		RedisURL:  url,
		RedisPool: DefaultRedisPool,
		KeyPrefix: DefaultKeyPrefix,
		TTL:       DefaultTTL,
	}

	return NewRedisStorage(config, logger)
}

// Constants for default values
const (
	DefaultRedisPool = 10
	DefaultKeyPrefix = "prism:ratelimit:"
	DefaultTTL       = time.Hour
)
