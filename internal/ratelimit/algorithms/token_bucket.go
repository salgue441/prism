package algorithms

import (
	"fmt"
	"sync"
	"time"
)

// TokenBucket implements the token bucket rate limiting algorithm.
// This algorithm allows for burst of requests up to the bucket capacity
// while maintaining an average rate over time.
//
// The token bucket algorithm works by:
// 1. Maintaining a bucket with a maximum capacity of tokens
// 2. Adding tokens to the bucket at a fixed rate
// 3. Consuming tokens for each request
// 4. Allowing requests only if sufficient tokens are available
//
// This provides smooth rate limiting with burst capability.
type TokenBucket struct {
	// Configuration
	capacity     int64         // Maximum number of tokens in the bucket
	refillRate   int64         // Tokens added per second
	refillPeriod time.Duration // How often to add tokens

	// State (protected by mutex)
	mu         sync.RWMutex
	tokens     float64   // Current number of tokens
	lastRefill time.Time // Last time tokens were added

	// Metrics
	tokensAdded    int64 // Total tokens added since creation
	tokensConsumed int64 // Total tokens consumed since creation
}

// NewTokenBucket creates a new token bucket with the specified parameters.
//
// Parameters:
//   - capacity: Maximum number of tokens the bucket can hold (burst size)
//   - refillRate: Number of tokens added per second (sustained rate)
//
// The bucket starts full, allowing immediate bursts.
func NewTokenBucket(capacity, refillRate int64) *TokenBucket {
	return &TokenBucket{
		capacity:     capacity,
		refillRate:   refillRate,
		refillPeriod: time.Second,
		tokens:       float64(capacity),
		lastRefill:   time.Now(),
	}
}

// Allow checks if the specified number of tokens can be consumed.
// Returns true if the request is allowed, false otherwise.
//
// This method is thread-safe and can be called concurrently.
func (tb *TokenBucket) Allow(tokens int64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()
	if tb.tokens >= float64(tokens) {
		tb.tokens -= float64(tokens)
		tb.tokensConsumed += tokens

		return true
	}

	return false
}

// AllowAt checks if tokens can be consumed at a specific time.
// This is useful for testing and simulation purposes.
func (tb *TokenBucket) AllowAt(tokens int64, at time.Time) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refillAt(at)
	if tb.tokens >= float64(tokens) {
		tb.tokens -= float64(tokens)
		tb.tokensConsumed += tokens

		return true
	}

	return false
}

// Available returns the number of tokens currently available.
func (tb *TokenBucket) Available() int64 {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	tb.refill()
	return int64(tb.tokens)
}

// Capacity returns the maximum capacity of the bucket.
func (tb *TokenBucket) Capacity() int64 {
	return tb.capacity
}

// RefillRate returns the refill rate in tokens per second.
func (tb *TokenBucket) RefillRate() int64 {
	return tb.refillRate
}

// Reset resets the bucket to its initial state (full).
func (tb *TokenBucket) Reset() {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.tokens = float64(tb.capacity)
	tb.lastRefill = time.Now()
}

// SetCapacity updates the bucket capacity.
// If the new capacity is smaller than current tokens, tokens are capped.
func (tb *TokenBucket) SetCapacity(capacity int64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.capacity = capacity
	if tb.tokens > float64(capacity) {
		tb.tokens = float64(capacity)
	}
}

// SetRefillRate updates the refill rate.
func (tb *TokenBucket) SetRefillRate(rate int64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refillRate = rate
}

// WaitTime returns how long to wait until the specified number of tokens
// will be available.
func (tb *TokenBucket) WaitTime(tokens int64) time.Duration {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	tb.refill()
	if tb.tokens >= float64(tokens) {
		return 0
	}

	tokensNeeded := float64(tokens) - tb.tokens
	if tb.refillRate == 0 {
		return time.Duration(-1)
	}

	waitSeconds := tokensNeeded / float64(tb.refillRate)
	return time.Duration(waitSeconds * float64(time.Second))
}

// GetMetrics returns current metrics for the token bucket.
type TokenBucketMetrics struct {
	Capacity        int64     `json:"capacity"`
	RefillRate      int64     `json:"refill_rate"`
	CurrentTokens   float64   `json:"current_tokens"`
	TokensAdded     int64     `json:"tokens_added"`
	TokensConsumed  int64     `json:"tokens_consumed"`
	LastRefill      time.Time `json:"last_refill"`
	UtilizationRate float64   `json:"utilization_rate"`
}

func (tb *TokenBucket) GetMetrics() *TokenBucketMetrics {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	tb.refill()

	var utilizationRate float64
	total := tb.tokensConsumed + int64(tb.tokens)
	if total > 0 {
		utilizationRate = float64(tb.tokensConsumed) / float64(total)
	}

	return &TokenBucketMetrics{
		Capacity:        tb.capacity,
		RefillRate:      tb.refillRate,
		CurrentTokens:   tb.tokens,
		TokensAdded:     tb.tokensAdded,
		TokensConsumed:  tb.tokensConsumed,
		LastRefill:      tb.lastRefill,
		UtilizationRate: utilizationRate,
	}
}

// refill adds tokens to the bucket based on elapsed time.
// This method must be called while holding the write lock.
func (tb *TokenBucket) refill() {
	tb.refillAt(time.Now())
}

// refillAt adds tokens to the bucket up to the specified time.
// This method must be called while holding the write lock.
func (tb *TokenBucket) refillAt(now time.Time) {
	if tb.refillRate == 0 {
		return
	}

	elapsed := now.Sub(tb.lastRefill)
	if elapsed <= 0 {
		return
	}

	tokensToAdd := float64(tb.refillRate) * elapsed.Seconds()
	oldTokens := tb.tokens
	tb.tokens = min(tb.tokens+tokensToAdd, float64(tb.capacity))

	actualTokensAdded := tb.tokens - oldTokens
	if actualTokensAdded > 0 {
		tb.tokensAdded += int64(actualTokensAdded)
	}

	tb.lastRefill = now
}

// Burst returns the current burst capacity (same as capacity for token bucket).
func (tb *TokenBucket) Burst() int64 {
	return tb.capacity
}

// Rate returns the sustained rate limit.
func (tb *TokenBucket) Rate() int64 {
	return tb.refillRate
}

// IsEmpty returns true if the bucket has no tokens.
func (tb *TokenBucket) IsEmpty() bool {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	tb.refill()
	return tb.tokens == 0
}

// IsFull returns true if the bucket is at capacity.
func (tb *TokenBucket) IsFull() bool {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	tb.refill()
	return tb.tokens >= float64(tb.capacity)
}

// TimeToFull returns the time until the bucket will be full.
func (tb *TokenBucket) TimeToFull() time.Duration {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	tb.refill()
	if tb.tokens >= float64(tb.capacity) {
		return 0
	}

	if tb.refillRate == 0 {
		return time.Duration(-1)
	}

	tokensNeeded := float64(tb.capacity) - tb.tokens
	secondsToFull := tokensNeeded / float64(tb.refillRate)
	return time.Duration(secondsToFull * float64(time.Second))
}

// Consume forcibly consumes tokens without checking availability.
// This can result in negative token count and should be used carefully.
// Returns the actual number of tokens consumed.
func (tb *TokenBucket) Consume(tokens int64) int64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	oldTokens := tb.tokens
	tb.tokens -= float64(tokens)
	tb.tokensConsumed += tokens

	if oldTokens >= float64(tokens) {
		return tokens
	}

	return int64(max(0, oldTokens))
}

// Add forcibly adds tokens to the bucket, potentially exceeding capacity.
// This should be used carefully as it can break rate limiting guarantees.
func (tb *TokenBucket) Add(tokens int64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.tokens += float64(tokens)
	tb.tokensAdded += tokens
}

// Clone creates a copy of the token bucket with the same configuration
// but reset state.
func (tb *TokenBucket) Clone() *TokenBucket {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	return NewTokenBucket(tb.capacity, tb.refillRate)
}

// String returns a string representation of the token bucket state.
func (tb *TokenBucket) String() string {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	tb.refill()
	return fmt.Sprintf("TokenBucket{capacity: %d, rate: %d/s, tokens: %.2f}",
		tb.capacity, tb.refillRate, tb.tokens)
}

// TokenBucketState represents the serializable state of a token bucket.
// This can be used for persistence or distributed rate limiting.
type TokenBucketState struct {
	Tokens     float64   `json:"tokens"`
	LastRefill time.Time `json:"last_refill"`
	Capacity   int64     `json:"capacity"`
	RefillRate int64     `json:"refill_rate"`
}

// GetState returns the current state for serialization.
func (tb *TokenBucket) GetState() *TokenBucketState {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	tb.refill()
	return &TokenBucketState{
		Tokens:     tb.tokens,
		LastRefill: tb.lastRefill,
		Capacity:   tb.capacity,
		RefillRate: tb.refillRate,
	}
}

// SetState restores the token bucket from a saved state.
func (tb *TokenBucket) SetState(state *TokenBucketState) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.tokens = state.Tokens
	tb.lastRefill = state.LastRefill
	tb.capacity = state.Capacity
	tb.refillRate = state.RefillRate
}

// NewTokenBucketFromState creates a token bucket from a saved state.
func NewTokenBucketFromState(state *TokenBucketState) *TokenBucket {
	tb := &TokenBucket{
		capacity:     state.Capacity,
		refillRate:   state.RefillRate,
		refillPeriod: time.Second,
		tokens:       state.Tokens,
		lastRefill:   state.LastRefill,
	}

	return tb
}
