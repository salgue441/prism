// Package redis provides a high-performance Redis client with comprehensive
// features for the reverse API gateway application.
//
// # Overview
//
// This package offers a production-ready Redis client that abstracts away the
// complexity of connection management while providing excellent performance,
// reliability, and observability characteristics. It's designed specifically
// for high-throughput gateway applications that require distributed caching,
// session storage, and rate limiting capabilities.
//
// # Key Features
//
//   - High-performance connection pooling with configurable pool sizes
//   - Comprehensive Redis operations (strings, hashes, lists, sets)
//   - Context-aware operations with timeout support
//   - Structured logging integration with operation tracing
//   - Transaction and pipeline support for batch operations
//   - Health monitoring and connection statistics
//   - Automatic retry logic with exponential backoff
//   - Thread-safe operations for concurrent use
//
// # Basic Usage
//
//	// Create a new Redis client
//	client, err := redis.NewClient(redis.Config{
//		Host:     "localhost",
//		Port:     6379,
//		Password: "",
//		DB:       0,
//		PoolSize: 10,
//	}, logger)
//	if err != nil {
//		log.Fatal("Failed to create Redis client:", err)
//	}
//	defer client.Close()
//
//	// Basic key-value operations
//	ctx := context.Background()
//	err = client.Set(ctx, "user:123", "john_doe", time.Hour)
//	if err != nil {
//		log.Error("Failed to set key:", err)
//	}
//
//	value, err := client.Get(ctx, "user:123")
//	if err != nil {
//		if err == redis.Nil {
//			log.Info("Key not found")
//		} else {
//			log.Error("Failed to get key:", err)
//		}
//	}
//
// # Advanced Usage
//
//	// Hash operations for user sessions
//	sessionKey := "session:abc123"
//	err = client.HSet(ctx, sessionKey,
//		"user_id", "123",
//		"email", "user@example.com",
//		"role", "admin",
//		"created_at", time.Now().Unix())
//
//	// Get specific session field
//	userID, err := client.HGet(ctx, sessionKey, "user_id")
//
//	// Get entire session
//	session, err := client.HGetAll(ctx, sessionKey)
//
//	// Rate limiting with sorted sets
//	rateLimitKey := "rate_limit:user:123"
//	now := time.Now().Unix()
//	pipe := client.Pipeline()
//
//	// Add current request
//	pipe.ZAdd(ctx, rateLimitKey, &redis.Z{Score: float64(now), Member: now})
//	// Remove old entries (older than 1 minute)
//	pipe.ZRemRangeByScore(ctx, rateLimitKey, "-inf", fmt.Sprintf("%d", now-60))
//	// Count current requests
//	pipe.ZCard(ctx, rateLimitKey)
//	// Set expiration
//	pipe.Expire(ctx, rateLimitKey, time.Minute)
//
//	results, err := pipe.Exec(ctx)
//
// # Configuration
//
// The client supports comprehensive configuration options:
//
//	config := redis.Config{
//		Host:     "redis.example.com",  // Redis server host
//		Port:     6379,                 // Redis server port
//		Password: "secret",             // Authentication password
//		DB:       0,                    // Database number (0-15)
//
//		// Connection pooling
//		PoolSize:     20,               // Maximum connections
//		MinIdleConns: 5,                // Minimum idle connections
//
//		// Timeouts
//		ConnectTimeout: 5 * time.Second,  // Connection timeout
//		ReadTimeout:    3 * time.Second,  // Read operation timeout
//		WriteTimeout:   3 * time.Second,  // Write operation timeout
//
//		// Retry configuration
//		MaxRetries:      3,                      // Maximum retry attempts
//		MinRetryBackoff: 8 * time.Millisecond,  // Minimum backoff
//		MaxRetryBackoff: 512 * time.Millisecond, // Maximum backoff
//	}
//
// # Error Handling
//
// The client provides clear error handling patterns:
//
//	value, err := client.Get(ctx, "some_key")
//	if err != nil {
//		if err == redis.Nil {
//			// Key doesn't exist - this is normal
//			log.Debug("Key not found")
//		} else {
//			// Actual error occurred
//			log.Error("Redis operation failed:", err)
//		}
//	}
//
// # Performance Optimizations
//
// For high-performance applications:
//
//	// Use pipelines for batch operations
//	pipe := client.Pipeline()
//	pipe.Set(ctx, "key1", "value1", 0)
//	pipe.Set(ctx, "key2", "value2", 0)
//	pipe.Set(ctx, "key3", "value3", 0)
//	results, err := pipe.Exec(ctx)
//
//	// Use transactions for atomic operations
//	txPipe := client.TxPipeline()
//	txPipe.Incr(ctx, "counter")
//	txPipe.Set(ctx, "last_update", time.Now().Unix(), 0)
//	_, err = txPipe.Exec(ctx)
//
// # Health Monitoring
//
// The client provides comprehensive health monitoring:
//
//	// Check Redis connectivity
//	err := client.Ping(ctx)
//	if err != nil {
//		log.Error("Redis health check failed:", err)
//	}
//
//	// Get connection pool statistics
//	stats := client.PoolStats()
//	log.Info("Redis pool stats",
//		"total_conns", stats.TotalConns,
//		"idle_conns", stats.IdleConns,
//		"stale_conns", stats.StaleConns)
//
//	// Get Redis server information
//	info, err := client.Info(ctx, "memory", "stats")
//	if err == nil {
//		log.Debug("Redis server info", "info", info)
//	}
//
// # Common Use Cases
//
// ## Session Storage
//
//	// Store user session data
//	sessionID := "sess_" + generateUUID()
//	err = client.HSet(ctx, sessionID,
//		"user_id", userID,
//		"expires_at", time.Now().Add(24*time.Hour).Unix(),
//		"permissions", strings.Join(permissions, ","))
//	client.Expire(ctx, sessionID, 24*time.Hour)
//
// ## Distributed Rate Limiting
//
//	// Sliding window rate limiting
//	func checkRateLimit(userID string, limit int, window time.Duration) (bool, error) {
//		key := fmt.Sprintf("rate_limit:%s", userID)
//		now := time.Now()
//		windowStart := now.Add(-window).Unix()
//
//		pipe := client.Pipeline()
//		pipe.ZRemRangeByScore(ctx, key, "-inf", fmt.Sprintf("%d", windowStart))
//		pipe.ZCard(ctx, key)
//		pipe.ZAdd(ctx, key, &redis.Z{Score: float64(now.Unix()), Member: now.UnixNano()})
//		pipe.Expire(ctx, key, window)
//
//		results, err := pipe.Exec(ctx)
//		if err != nil {
//			return false, err
//		}
//
//		currentCount := results[1].(*redis.IntCmd).Val()
//		return currentCount < int64(limit), nil
//	}
//
// ## Response Caching
//
//	// Cache API responses
//	func cacheResponse(endpoint string, response []byte, ttl time.Duration) error {
//		key := fmt.Sprintf("cache:response:%s", endpoint)
//		return client.Set(ctx, key, response, ttl)
//	}
//
//	func getCachedResponse(endpoint string) ([]byte, error) {
//		key := fmt.Sprintf("cache:response:%s", endpoint)
//		result, err := client.Get(ctx, key)
//		if err != nil {
//			return nil, err
//		}
//		return []byte(result), nil
//	}
//
// # Thread Safety
//
// All client operations are thread-safe and can be used concurrently from
// multiple goroutines without additional synchronization. The underlying
// connection pool manages concurrent access efficiently.
//
// # Performance Considerations
//
//   - Use connection pooling with appropriate pool sizes for your workload
//   - Utilize pipelines for batch operations to reduce network round trips
//   - Set appropriate timeouts to prevent hanging operations
//   - Monitor connection pool statistics to optimize pool configuration
//   - Use transactions for atomic multi-key operations
//   - Consider using compression for large values
//
// # Production Deployment
//
// For production deployments:
//
//   - Enable Redis persistence (RDB/AOF) for data durability
//   - Configure Redis memory policies for your use case
//   - Set up Redis monitoring and alerting
//   - Use Redis Sentinel or Cluster for high availability
//   - Implement proper backup and recovery procedures
//   - Configure appropriate connection pool sizes
//   - Set reasonable timeout values based on your SLA requirements
//
// # Extending the Client
//
// To add custom operations, extend the Client interface:
//
//	type ExtendedClient interface {
//		redis.Client
//		CustomOperation(ctx context.Context, args ...interface{}) error
//	}# pkg/redis/client.go
//
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
