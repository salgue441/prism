package algorithms

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// FixedWindow implements the fixed window rate limiting algorithm.
// This algorithm divides time into fixed windows and allows a maximum
// number of requests per window. It's simple, memory-efficient, and
// performs well under high load.
//
// The fixed window algorithm works by:
// 1. Dividing time into fixed-duration windows
// 2. Maintaining a counter for the current window
// 3. Resetting the counter when a new window begins
// 4. Allowing requests only if the counter is below the limit
//
// Trade-offs:
// - Pros: Simple, memory-efficient, high performance
// - Cons: Can allow bursts at window boundaries ("thundering herd")
type FixedWindow struct {
	// Configuration
	limit      int64         // Maximum requests per window
	windowSize time.Duration // Duration of each window

	// State (protected by mutex for window transitions)
	mu          sync.RWMutex
	windowStart time.Time // Start of the current window
	count       int64     // Current request count (atomic for performance)

	// Metrics
	totalRequests   int64 // Total requests processed
	allowedRequests int64 // Total requests allowed
	blockedRequests int64 // Total requests blocked
	windowResets    int64 // Number of window resets
	lastReset       time.Time
}

// NewFixedWindow creates a new fixed window rate limiter.
//
// Parameters:
//   - limit: Maximum number of requests allowed per window
//   - windowSize: Duration of each fixed window
func NewFixedWindow(limit int64, windowSize time.Duration) *FixedWindow {
	now := time.Now()

	return &FixedWindow{
		limit:       limit,
		windowSize:  windowSize,
		windowStart: now.Truncate(windowSize),
		lastReset:   now,
	}
}

// Allow checks if a request is allowed at the current time.
// Returns true if the request is within the rate limit, false otherwise.
func (fw *FixedWindow) Allow() bool {
	return fw.AllowAt(time.Now())
}

// AllowN checks if N requests are allowed at the current time.
// This is useful for bulk operations or when a single logical operation
// should consume multiple "request units".
func (fw *FixedWindow) AllowN(n int64) bool {
	return fw.AllowNAt(n, time.Now())
}

// AllowAt checks if a request is allowed at a specific time.
// This is useful for testing and simulation purposes.
func (fw *FixedWindow) AllowAt(at time.Time) bool {
	return fw.AllowNAt(1, at)
}

// AllowNAt checks if N requests are allowed at a specific time
func (fw *FixedWindow) AllowNAt(n int64, at time.Time) bool {
	atomic.AddInt64(&fw.totalRequests, n)
	fw.checkWindowReset(at)

	for {
		currentCount := atomic.LoadInt64(&fw.count)
		if currentCount+n > fw.limit {
			atomic.AddInt64(&fw.blockedRequests, n)
			return false
		}

		if atomic.CompareAndSwapInt64(&fw.count, currentCount, currentCount+n) {
			atomic.AddInt64(&fw.allowedRequests, n)
			return true
		}
	}
}

// Available returns the number of requests that can still be made
// within the current window.
func (fw *FixedWindow) Available() int64 {
	fw.checkWindowReset(time.Now())
	currentCount := atomic.LoadInt64(&fw.count)
	remaining := fw.limit - currentCount
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

// Count returns the current number of requests in the current window.
func (fw *FixedWindow) Count() int64 {
	fw.checkWindowReset(time.Now())
	return atomic.LoadInt64(&fw.count)
}

// Limit returns the configured request limit per window.
func (fw *FixedWindow) Limit() int64 {
	return fw.limit
}

// WindowSize returns the configured window size.
func (fw *FixedWindow) WindowSize() time.Duration {
	return fw.windowSize
}

// Reset manually resets the current window.
// This can be useful for testing or administrative purposes.
func (fw *FixedWindow) Reset() {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	now := time.Now()
	fw.windowStart = now.Truncate(fw.windowSize)
	atomic.StoreInt64(&fw.count, 0)
	fw.lastReset = now
	atomic.AddInt64(&fw.windowResets, 1)
}

// SetLimit updates the request limit per window.
// The change takes effect immediately.
func (fw *FixedWindow) SetLimit(limit int64) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.limit = limit
}

// SetWindowSize updates the window size.
// This will cause an immediate window reset.
func (fw *FixedWindow) SetWindowSize(windowSize time.Duration) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.windowSize = windowSize
	now := time.Now()
	fw.windowStart = now.Truncate(windowSize)
	atomic.StoreInt64(&fw.count, 0)
	fw.lastReset = now
	atomic.AddInt64(&fw.windowResets, 1)
}

// TimeToReset returns the time until the current window resets.
func (fw *FixedWindow) TimeToReset() time.Duration {
	fw.mu.RLock()
	windowStart := fw.windowStart
	fw.mu.RUnlock()

	nextWindow := windowStart.Add(fw.windowSize)
	now := time.Now()

	if nextWindow.Before(now) {
		return 0
	}

	return nextWindow.Sub(now)
}

// WindowStart returns the start time of the current window.
func (fw *FixedWindow) WindowStart() time.Time {
	fw.mu.RLock()
	defer fw.mu.RUnlock()
	return fw.windowStart
}

// WindowEnd returns the end time of the current window.
func (fw *FixedWindow) WindowEnd() time.Time {
	fw.mu.RLock()
	defer fw.mu.RUnlock()
	return fw.windowStart.Add(fw.windowSize)
}

// IsWindowActive checks if the current window is still active at the given time.
func (fw *FixedWindow) IsWindowActive(at time.Time) bool {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	windowEnd := fw.windowStart.Add(fw.windowSize)
	return at.Before(windowEnd) && !at.Before(fw.windowStart)
}

// GetMetrics returns current metrics for the fixed window.
type FixedWindowMetrics struct {
	Limit           int64         `json:"limit"`
	WindowSize      time.Duration `json:"window_size"`
	CurrentCount    int64         `json:"current_count"`
	Available       int64         `json:"available"`
	WindowStart     time.Time     `json:"window_start"`
	WindowEnd       time.Time     `json:"window_end"`
	TimeToReset     time.Duration `json:"time_to_reset"`
	TotalRequests   int64         `json:"total_requests"`
	AllowedRequests int64         `json:"allowed_requests"`
	BlockedRequests int64         `json:"blocked_requests"`
	WindowResets    int64         `json:"window_resets"`
	LastReset       time.Time     `json:"last_reset"`
	Utilization     float64       `json:"utilization"`
}

func (fw *FixedWindow) GetMetrics() *FixedWindowMetrics {
	fw.checkWindowReset(time.Now())

	fw.mu.RLock()
	windowStart := fw.windowStart
	windowEnd := fw.windowStart.Add(fw.windowSize)
	lastReset := fw.lastReset
	fw.mu.RUnlock()

	currentCount := atomic.LoadInt64(&fw.count)
	available := fw.limit - currentCount
	if available < 0 {
		available = 0
	}

	var utilization float64
	if fw.limit > 0 {
		utilization = float64(currentCount) / float64(fw.limit)
	}

	timeToReset := time.Until(windowEnd)
	if timeToReset < 0 {
		timeToReset = 0
	}

	return &FixedWindowMetrics{
		Limit:           fw.limit,
		WindowSize:      fw.windowSize,
		CurrentCount:    currentCount,
		Available:       available,
		WindowStart:     windowStart,
		WindowEnd:       windowEnd,
		TimeToReset:     timeToReset,
		TotalRequests:   atomic.LoadInt64(&fw.totalRequests),
		AllowedRequests: atomic.LoadInt64(&fw.allowedRequests),
		BlockedRequests: atomic.LoadInt64(&fw.blockedRequests),
		WindowResets:    atomic.LoadInt64(&fw.windowResets),
		LastReset:       lastReset,
		Utilization:     utilization,
	}
}

// Private methods

// checkWindowReset checks if the window needs to be reset and does so if necessary.
func (fw *FixedWindow) checkWindowReset(at time.Time) {
	fw.mu.RLock()
	windowEnd := fw.windowStart.Add(fw.windowSize)
	needsReset := at.After(windowEnd) || at.Equal(windowEnd)
	fw.mu.RUnlock()

	if !needsReset {
		return
	}

	fw.mu.Lock()
	defer fw.mu.Unlock()

	windowEnd = fw.windowStart.Add(fw.windowSize)
	if at.Before(windowEnd) && !at.Equal(windowEnd) {
		return
	}

	newWindowStart := at.Truncate(fw.windowSize)

	fw.windowStart = newWindowStart
	atomic.StoreInt64(&fw.count, 0)
	fw.lastReset = at
	atomic.AddInt64(&fw.windowResets, 1)
}

// Clone creates a copy of the fixed window with the same configuration
// but reset state.
func (fw *FixedWindow) Clone() *FixedWindow {
	fw.mu.RLock()
	limit := fw.limit
	windowSize := fw.windowSize
	fw.mu.RUnlock()

	return NewFixedWindow(limit, windowSize)
}

// String returns a string representation of the fixed window state.
func (fw *FixedWindow) String() string {
	fw.checkWindowReset(time.Now())

	fw.mu.RLock()
	windowStart := fw.windowStart
	fw.mu.RUnlock()

	currentCount := atomic.LoadInt64(&fw.count)
	available := fw.limit - currentCount
	if available < 0 {
		available = 0
	}

	return fmt.Sprintf(
		"FixedWindow{limit: %d, window: %v, count: %d, available: %d, start: %v}",
		fw.limit, fw.windowSize, currentCount, available,
		windowStart.Format(time.RFC3339))
}

// Advanced methods for specific use cases

// ForceIncrement forcibly increments the counter without checking the limit.
// This can be useful for penalty systems or administrative overrides.
// Returns the new count.
func (fw *FixedWindow) ForceIncrement(n int64) int64 {
	fw.checkWindowReset(time.Now())
	return atomic.AddInt64(&fw.count, n)
}

// ForceDecrement forcibly decrements the counter.
// This can be useful for compensating for failed requests or refunds.
// Returns the new count (won't go below 0).
func (fw *FixedWindow) ForceDecrement(n int64) int64 {
	fw.checkWindowReset(time.Now())

	for {
		currentCount := atomic.LoadInt64(&fw.count)
		newCount := currentCount - n
		if newCount < 0 {
			newCount = 0
		}

		if atomic.CompareAndSwapInt64(&fw.count, currentCount, newCount) {
			return newCount
		}
	}
}

// SetCount forcibly sets the counter to a specific value.
// This can be useful for testing or administrative purposes.
func (fw *FixedWindow) SetCount(count int64) {
	fw.checkWindowReset(time.Now())
	if count < 0 {
		count = 0
	}
	atomic.StoreInt64(&fw.count, count)
}

// PeekNextWindow returns information about what the next window will look like.
type NextWindowInfo struct {
	Start    time.Time     `json:"start"`
	End      time.Time     `json:"end"`
	Duration time.Duration `json:"duration"`
}

func (fw *FixedWindow) PeekNextWindow() *NextWindowInfo {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	nextStart := fw.windowStart.Add(fw.windowSize)
	nextEnd := nextStart.Add(fw.windowSize)

	return &NextWindowInfo{
		Start:    nextStart,
		End:      nextEnd,
		Duration: fw.windowSize,
	}
}

// FixedWindowState represents the serializable state of a fixed window.
type FixedWindowState struct {
	Count       int64         `json:"count"`
	WindowStart time.Time     `json:"window_start"`
	Limit       int64         `json:"limit"`
	WindowSize  time.Duration `json:"window_size"`
}

// GetState returns the current state for serialization.
func (fw *FixedWindow) GetState() *FixedWindowState {
	fw.checkWindowReset(time.Now())

	fw.mu.RLock()
	defer fw.mu.RUnlock()

	return &FixedWindowState{
		Count:       atomic.LoadInt64(&fw.count),
		WindowStart: fw.windowStart,
		Limit:       fw.limit,
		WindowSize:  fw.windowSize,
	}
}

// SetState restores the fixed window from a saved state.
func (fw *FixedWindow) SetState(state *FixedWindowState) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	atomic.StoreInt64(&fw.count, state.Count)
	fw.windowStart = state.WindowStart
	fw.limit = state.Limit
	fw.windowSize = state.WindowSize
}

// NewFixedWindowFromState creates a fixed window from a saved state.
func NewFixedWindowFromState(state *FixedWindowState) *FixedWindow {
	fw := &FixedWindow{
		limit:       state.Limit,
		windowSize:  state.WindowSize,
		windowStart: state.WindowStart,
		lastReset:   time.Now(),
	}

	atomic.StoreInt64(&fw.count, state.Count)
	return fw
}

// Batch operations for high-performance scenarios

// BatchAllow checks multiple requests at once for better performance.
// Returns a slice of booleans indicating which requests were allowed.
func (fw *FixedWindow) BatchAllow(requests []int64) []bool {
	return fw.BatchAllowAt(requests, time.Now())
}

// BatchAllowAt checks multiple requests at a specific time.
func (fw *FixedWindow) BatchAllowAt(requests []int64, at time.Time) []bool {
	if len(requests) == 0 {
		return nil
	}

	fw.checkWindowReset(at)
	results := make([]bool, len(requests))
	totalRequests := int64(0)

	for _, n := range requests {
		totalRequests += n
		atomic.AddInt64(&fw.totalRequests, n)
	}

	for {
		currentCount := atomic.LoadInt64(&fw.count)
		if currentCount+totalRequests > fw.limit {
			return fw.handleBatchIndividually(requests, at)
		}

		if atomic.CompareAndSwapInt64(&fw.count, currentCount,
			currentCount+totalRequests) {
			for i := range results {
				results[i] = true
				atomic.AddInt64(&fw.allowedRequests, requests[i])
			}

			return results
		}
	}
}

// handleBatchIndividually handles batch requests one by one when they can't
// all be allowed.
func (fw *FixedWindow) handleBatchIndividually(requests []int64, at time.Time) []bool {
	results := make([]bool, len(requests))

	for i, n := range requests {
		for {
			fw.checkWindowReset(at)
			currentCount := atomic.LoadInt64(&fw.count)

			if currentCount+n > fw.limit {
				results[i] = false
				atomic.AddInt64(&fw.blockedRequests, n)
				break
			}

			if atomic.CompareAndSwapInt64(&fw.count, currentCount, currentCount+n) {
				results[i] = true
				atomic.AddInt64(&fw.allowedRequests, n)
				break
			}
		}
	}

	return results
}
