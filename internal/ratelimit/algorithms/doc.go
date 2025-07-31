// Package algorithms implements various rate limiting algorithms for
// controlling the flow of requests in distributed systems. It provides
// thread-safe implementations of common rate limiting patterns with
// comprehensive metrics and monitoring capabilities.
//
// The package includes four main rate limiting algorithms:
//
// 1. Fixed Window: Simple and efficient, but allows bursts at window boundaries
// 2. Sliding Window: More precise than fixed window, but uses more memory
// 3. Token Bucket: Allows bursts up to capacity while maintaining average rate
// 4. Leaky Bucket: Provides smooth output rate with queueing capability
//
// Each implementation provides:
// - Thread-safe operations
// - Comprehensive metrics collection
// - Configuration management
// - State persistence capabilities
// - Testing utilities
//
// The algorithms are designed for high performance in concurrent scenarios
// and include optimizations for different usage patterns.
//
// Example usage:
//
//	// Create a fixed window rate limiter: 100 requests per minute
//	limiter := algorithms.NewFixedWindow(100, time.Minute)
//	if limiter.Allow() {
//	    // Request allowed
//	} else {
//	    // Request rate limited
//	}
//
//	// Get metrics
//	metrics := limiter.GetMetrics()
//	fmt.Printf("Utilization: %.2f%%\n", metrics.Utilization*100)
package algorithms
