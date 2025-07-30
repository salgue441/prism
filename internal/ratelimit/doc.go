// Package ratelimit provides high-performance, thread-safe rate limiting
// for the Prism API Gateway with support for multiple algorithms, distributed
// storage backends, and comprehensive security features.
//
// This package implements enterprise-grade rate limiting capabilities optimized
// for high-throughput, low-latency operations with built-in security controls,
// flexible key generation, and comprehensive monitoring.
//
// # Design Principles
//
//   - High-performance concurrent rate limiting with minimal lock contention
//   - Multiple algorithms optimized for different use cases and traffic patterns
//   - Distributed rate limiting across multiple gateway instances
//   - Security-first approach with DDoS protection and abuse prevention
//   - Memory-efficient operations with configurable cleanup and TTL
//   - Thread-safe operations optimized for concurrent access patterns
//
// # Supported Algorithms
//
//   - Token Bucket: Allows bursts while maintaining average rate
//   - Sliding Window: Smooth rate limiting with precise time-based control
//   - Fixed Window: Simple, efficient rate limiting with reset intervals
//   - Leaky Bucket: Smooth output rate with queue-based buffering
//
// # Storage Backends
//
//   - In-Memory: High-performance local storage with automatic cleanup
//   - Redis: Distributed storage for multi-instance deployments
//   - Hybrid: Local cache with Redis fallback for optimal performance
//
// # Key Generation Strategies
//
//   - IP-based: Rate limit by client IP address
//   - User-based: Rate limit by authenticated user ID
//   - API Key: Rate limit by API key or application ID
//   - Custom: Flexible key generation with custom logic
//   - Composite: Multiple key strategies combined
//
// # Security Features
//
//   - DDoS protection with automatic IP blocking
//   - Graduated penalties for repeat offenders
//   - Whitelist/blacklist support for IPs and users
//   - Suspicious pattern detection and alerting
//   - Rate limit bypass for trusted sources
//
// # Performance Optimizations
//
//   - Lock-free algorithms for hot paths
//   - Connection pooling for Redis operations
//   - Batch operations for improved throughput
//   - Memory pooling for reduced garbage collection
//   - Configurable cleanup intervals and TTL
//
// # Usage Examples
//
// Basic rate limiting with token bucket:
//
//	config := &ratelimit.Config{
//		Algorithm:         "token_bucket",
//		RequestsPerSecond: 100,
//		BurstSize:         200,
//		Storage:           "memory",
//		KeyGenerator:      "ip",
//	}
//
//	limiter, err := ratelimit.New(config, logger)
//	if err != nil {
//		panic(err)
//	}
//
//	// Check if request is allowed
//	key := "192.168.1.100"
//	allowed, remaining, resetTime, err := limiter.Allow(key)
//	if err != nil {
//		log.Error("Rate limit check failed:", err)
//	}
//
//	if !allowed {
//		// Request should be rejected
//		log.Warn("Rate limit exceeded", "key", key, "remaining", remaining)
//	}
//
// Distributed rate limiting with Redis:
//
//	config := &ratelimit.Config{
//		Algorithm:         "sliding_window",
//		RequestsPerSecond: 1000,
//		WindowSize:        time.Minute,
//		Storage:           "redis",
//		RedisURL:          "redis://localhost:6379",
//		KeyPrefix:         "prism:ratelimit:",
//	}
//
//	limiter, err := ratelimit.New(config, logger)
//	if err != nil {
//		panic(err)
//	}
//
// Custom key generation:
//
//	config := &ratelimit.Config{
//		Algorithm:         "token_bucket",
//		RequestsPerSecond: 50,
//		BurstSize:         100,
//		KeyGenerator:      "custom",
//		CustomKeyFunc: func(req *http.Request) string {
//			userID := req.Header.Get("X-User-ID")
//			if userID != "" {
//				return "user:" + userID
//			}
//			return "ip:" + req.RemoteAddr
//		},
//	}
//
// Multiple rate limits with different algorithms:
//
//	// Per-IP rate limiting (aggressive)
//	ipLimiter, _ := ratelimit.New(&ratelimit.Config{
//		Algorithm:         "token_bucket",
//		RequestsPerSecond: 10,
//		BurstSize:         20,
//		KeyGenerator:      "ip",
//	}, logger)
//
//	// Per-user rate limiting (generous)
//	userLimiter, _ := ratelimit.New(&ratelimit.Config{
//		Algorithm:         "sliding_window",
//		RequestsPerSecond: 1000,
//		WindowSize:        time.Minute,
//		KeyGenerator:      "user",
//	}, logger)
//
// # Middleware Integration
//
// The package provides ready-to-use middleware for popular frameworks:
//
//	// Gin middleware
//	router.Use(ratelimit.GinMiddleware(limiter))
//
//	// Custom middleware with multiple limiters
//	router.Use(ratelimit.CustomMiddleware([]ratelimit.Limiter{
//		ipLimiter,
//		userLimiter,
//	}))
//
// # Configuration Options
//
// Comprehensive configuration for different deployment scenarios:
//
//	config := &ratelimit.Config{
//		// Algorithm configuration
//		Algorithm:           "token_bucket",
//		RequestsPerSecond:   100,
//		BurstSize:          200,
//		WindowSize:         time.Minute,
//
//		// Storage configuration
//		Storage:      "redis",
//		RedisURL:     "redis://localhost:6379",
//		RedisPool:    10,
//		KeyPrefix:    "prism:rl:",
//		TTL:          time.Hour,
//
//		// Key generation
//		KeyGenerator:  "composite",
//		KeyGenerators: []string{"ip", "user"},
//		CustomKeyFunc: customKeyFunction,
//
//		// Security settings
//		EnableBlacklist:     true,
//		BlacklistThreshold:  1000,
//		BlacklistDuration:   time.Hour,
//		TrustedIPs:         []string{"10.0.0.0/8"},
//
//		// Performance tuning
//		CleanupInterval:    time.Minute * 5,
//		MaxKeys:           10000,
//		BatchSize:         100,
//
//		// Response configuration
//		Headers: map[string]string{
//			"X-RateLimit-Limit":     "100",
//			"X-RateLimit-Remaining": "{remaining}",
//			"X-RateLimit-Reset":     "{reset}",
//		},
//		RetryAfterHeader: true,
//		CustomMessage:    "Rate limit exceeded. Please try again later.",
//	}
//
// # Monitoring and Metrics
//
// Built-in metrics collection for monitoring and alerting:
//
//	metrics := limiter.GetMetrics()
//	log.Info("Rate limiter stats",
//		"total_requests", metrics.TotalRequests,
//		"blocked_requests", metrics.BlockedRequests,
//		"hit_rate", metrics.HitRate,
//		"avg_response_time", metrics.AvgResponseTime)
//
// # Error Handling
//
// Comprehensive error handling with graceful degradation:
//
//	allowed, remaining, resetTime, err := limiter.Allow(key)
//	switch {
//	case err == ratelimit.ErrStorageUnavailable:
//		// Storage backend is down, allow request with logging
//		log.Warn("Rate limiter storage unavailable, allowing request")
//		allowed = true
//	case err == ratelimit.ErrInvalidKey:
//		// Invalid key format, block request
//		log.Error("Invalid rate limit key", "key", key)
//		allowed = false
//	case err != nil:
//		// Other errors, fail secure
//		log.Error("Rate limiter error", "error", err)
//		allowed = false
//	}
//
// # Performance Considerations
//
// The rate limiter is optimized for high-throughput scenarios:
//
//   - Lock-free atomic operations for counters
//   - Memory pooling for reduced garbage collection
//   - Connection pooling for Redis operations
//   - Batch processing for improved throughput
//   - Configurable cleanup to prevent memory leaks
//
// # Security Best Practices
//
// When using the rate limiter in production:
//
//   - Use IP-based limiting as the first line of defense
//   - Implement graduated penalties for repeat offenders
//   - Configure proper whitelists for trusted sources
//   - Monitor for suspicious patterns and automated attacks
//   - Use distributed storage for multi-instance deployments
//   - Implement circuit breakers for storage backend failures
//
// # Production Deployment
//
// Recommended production settings:
//
//   - Use Redis for distributed deployments
//   - Configure appropriate TTL values
//   - Set up monitoring and alerting
//   - Implement proper key cleanup
//   - Use composite key strategies
//   - Configure storage backend redundancy
//   - Enable comprehensive logging and metrics
package ratelimit
