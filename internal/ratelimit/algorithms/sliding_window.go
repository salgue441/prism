package algorithms

import (
	"container/ring"
	"fmt"
	"sync"
	"time"
)

// SlidingWindow implements the sliding window rate limiting algorithm.
// This algorithm maintains a precise count of requests within a sliding
// time window, providing smooth rate limiting without the "thundering herd"
// problem that can occur with fixed windows.
//
// The sliding window algorithm works by:
// 1. Maintaining a log of request timestamps
// 2. For each new request, removing timestamps older than the window
// 3. Checking if the remaining count is within the limit
// 4. Adding the new request timestamp if allowed
//
// This provides the most accurate rate limiting but uses more memory.
type SlidingWindow struct {
	// Configuration
	limit      int64         // Maximum requests per window
	windowSize time.Duration // Size of the sliding window

	// State (protected by mutex)
	mu       sync.RWMutex
	requests []time.Time // Request timestamps within the window

	// Optimization: use ring buffer for better performance with large limits
	useRingBuffer bool
	ringBuffer    *ring.Ring
	ringSize      int

	// Metrics
	totalRequests   int64 // Total requests processed
	allowedRequests int64 // Total requests allowed
	blockedRequests int64 // Total requests blocked
	windowRotations int64 // Number of times window was cleaned
	lastCleanup     time.Time
}

// NewSlidingWindow creates a new sliding window rate limiter.
//
// Parameters:
//   - limit: Maximum number of requests allowed within the window
//   - windowSize: Duration of the sliding window
//
// For high-throughput scenarios (limit > 1000), a ring buffer is used
// for better performance.
func NewSlidingWindow(limit int64, windowSize time.Duration) *SlidingWindow {
	initialCap := limit
	if initialCap > 1000 {
		initialCap = 1000
	}

	sw := &SlidingWindow{
		limit:       limit,
		windowSize:  windowSize,
		requests:    make([]time.Time, 0, int(initialCap)),
		lastCleanup: time.Now(),
	}

	if limit > 1000 {
		sw.useRingBuffer = true
		sw.ringSize = int(limit)
		sw.ringBuffer = ring.New(sw.ringSize)
	}

	return sw
}

// Allow checks if a request is allowed at the current time.
// Returns true if the request is within the rate limit, false otherwise.
func (sw *SlidingWindow) Allow() bool {
	return sw.AllowAt(time.Now())
}

// AllowN checks if N requests are allowed at the current time.
// This is useful for bulk operations or when a single logical operation
// should consume multiple "request units".
func (sw *SlidingWindow) AllowN(n int64) bool {
	return sw.AllowNAt(n, time.Now())
}

// AllowAt checks if a request is allowed at a specific time.
// This is useful for testing and simulation purposes.
func (sw *SlidingWindow) AllowAt(at time.Time) bool {
	return sw.AllowNAt(1, at)
}

// AllowNAt checks if N requests are allowed at a specific time.
func (sw *SlidingWindow) AllowNAt(n int64, at time.Time) bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	sw.totalRequests += n
	sw.cleanupAt(at)
	currentCount := sw.getCurrentCount()

	if currentCount+n > sw.limit {
		sw.blockedRequests += n
		return false
	}

	sw.addRequestsAt(n, at)
	sw.allowedRequests += n

	return true
}

// Available returns the number of requests that can still be made
// within the current window.
func (sw *SlidingWindow) Available() int64 {
	sw.mu.RLock()
	defer sw.mu.RUnlock()

	sw.cleanupAt(time.Now())
	return sw.limit - sw.getCurrentCount()
}

// Count returns the current number of requests in the window.
func (sw *SlidingWindow) Count() int64 {
	sw.mu.RLock()
	defer sw.mu.RUnlock()

	sw.cleanupAt(time.Now())
	return sw.getCurrentCount()
}

// Limit returns the configured request limit.
func (sw *SlidingWindow) Limit() int64 {
	return sw.limit
}

// WindowSize returns the configured window size.
func (sw *SlidingWindow) WindowSize() time.Duration {
	return sw.windowSize
}

// Reset clears all request history, effectively resetting the rate limiter.
func (sw *SlidingWindow) Reset() {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.useRingBuffer {
		sw.ringBuffer = ring.New(sw.ringSize)
	} else {
		sw.requests = sw.requests[:0]
	}

	sw.lastCleanup = time.Now()
}

// SetLimit updates the request limit.
// If the new limit is lower than the current count, no immediate action
// is taken, but future requests will be limited accordingly.
func (sw *SlidingWindow) SetLimit(limit int64) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	sw.limit = limit
	if limit > 1000 && !sw.useRingBuffer {
		sw.useRingBuffer = true
		sw.ringSize = int(limit)
		sw.ringBuffer = ring.New(sw.ringSize)

		for _, req := range sw.requests {
			sw.ringBuffer.Value = req
			sw.ringBuffer = sw.ringBuffer.Next()
		}
	}
}

// SetWindowSize updates the window size.
// This will trigger immediate cleanup of requests outside the new window.
func (sw *SlidingWindow) SetWindowSize(windowSize time.Duration) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	sw.windowSize = windowSize
	sw.cleanupAt(time.Now())
}

// TimeToReset returns the time until the oldest request expires
// and more requests become available.
func (sw *SlidingWindow) TimeToReset() time.Duration {
	sw.mu.RLock()
	defer sw.mu.RUnlock()

	if sw.getCurrentCount() == 0 {
		return 0
	}

	var oldestRequest time.Time
	if sw.useRingBuffer {
		oldestRequest = sw.getOldestFromRing()
	} else if len(sw.requests) > 0 {
		oldestRequest = sw.requests[0]
	}

	if oldestRequest.IsZero() {
		return 0
	}

	resetTime := oldestRequest.Add(sw.windowSize)
	now := time.Now()

	if resetTime.Before(now) {
		return 0
	}

	return resetTime.Sub(now)
}

// GetMetrics returns current metrics for the sliding window.
type SlidingWindowMetrics struct {
	Limit            int64         `json:"limit"`
	WindowSize       time.Duration `json:"window_size"`
	CurrentCount     int64         `json:"current_count"`
	Available        int64         `json:"available"`
	TotalRequests    int64         `json:"total_requests"`
	AllowedRequests  int64         `json:"allowed_requests"`
	BlockedRequests  int64         `json:"blocked_requests"`
	WindowRotations  int64         `json:"window_rotations"`
	LastCleanup      time.Time     `json:"last_cleanup"`
	UseRingBuffer    bool          `json:"use_ring_buffer"`
	MemoryEfficiency float64       `json:"memory_efficiency"` // used slots / allocated slots
}

func (sw *SlidingWindow) GetMetrics() *SlidingWindowMetrics {
	sw.mu.RLock()
	defer sw.mu.RUnlock()

	sw.cleanupAt(time.Now())

	currentCount := sw.getCurrentCount()
	available := sw.limit - currentCount

	var memoryEfficiency float64
	if sw.useRingBuffer {
		memoryEfficiency = float64(currentCount) / float64(sw.ringSize)
	} else {
		capacity := cap(sw.requests)
		if capacity > 0 {
			memoryEfficiency = float64(len(sw.requests)) / float64(capacity)
		}
	}

	return &SlidingWindowMetrics{
		Limit:            sw.limit,
		WindowSize:       sw.windowSize,
		CurrentCount:     currentCount,
		Available:        available,
		TotalRequests:    sw.totalRequests,
		AllowedRequests:  sw.allowedRequests,
		BlockedRequests:  sw.blockedRequests,
		WindowRotations:  sw.windowRotations,
		LastCleanup:      sw.lastCleanup,
		UseRingBuffer:    sw.useRingBuffer,
		MemoryEfficiency: memoryEfficiency,
	}
}

// Private methods

// cleanupAt removes requests older than the window at the specified time.
// This method must be called while holding the write lock.
func (sw *SlidingWindow) cleanupAt(at time.Time) {
	windowStart := at.Add(-sw.windowSize)

	if sw.useRingBuffer {
		sw.cleanupRingAt(windowStart)
	} else {
		sw.cleanupSliceAt(windowStart)
	}

	sw.lastCleanup = at
}

// cleanupSliceAt removes old requests from the slice-based storage.
func (sw *SlidingWindow) cleanupSliceAt(windowStart time.Time) {
	keepIndex := 0
	for i, req := range sw.requests {
		if req.After(windowStart) {
			keepIndex = i
			break
		}

		keepIndex = i + 1
	}

	if keepIndex > 0 {
		copy(sw.requests, sw.requests[keepIndex:])
		sw.requests = sw.requests[:len(sw.requests)-keepIndex]
		sw.windowRotations++
	}
}

// cleanupRingAt removes old requests from the ring buffer.
func (sw *SlidingWindow) cleanupRingAt(windowStart time.Time) {
	if sw.ringBuffer == nil {
		return
	}

	removed := 0
	sw.ringBuffer.Do(func(v interface{}) {
		if v != nil {
			if reqTime, ok := v.(time.Time); ok {
				if !reqTime.After(windowStart) {
					sw.ringBuffer.Value = nil
					removed++
				}
			}
		}
	})

	if removed > 0 {
		sw.windowRotations++
	}
}

// getCurrentCount returns the current number of requests in the window.
// This method must be called while holding at least a read lock.
func (sw *SlidingWindow) getCurrentCount() int64 {
	if sw.useRingBuffer {
		return sw.getRingCount()
	}

	return int64(len(sw.requests))
}

// getRingCount counts non-nil entries in the ring buffer.
func (sw *SlidingWindow) getRingCount() int64 {
	if sw.ringBuffer == nil {
		return 0
	}

	count := int64(0)
	sw.ringBuffer.Do(func(v interface{}) {
		if v != nil {
			count++
		}
	})

	return count
}

// addRequestsAt adds N request timestamps at the specified time.
// This method must be called while holding the write lock.
func (sw *SlidingWindow) addRequestsAt(n int64, at time.Time) {
	if sw.useRingBuffer {
		sw.addToRing(n, at)
	} else {
		for i := int64(0); i < n; i++ {
			sw.requests = append(sw.requests, at)
		}
	}
}

// addToRing adds N requests to the ring buffer.
func (sw *SlidingWindow) addToRing(n int64, at time.Time) {
	if sw.ringBuffer == nil {
		return
	}

	for i := int64(0); i < n; i++ {
		sw.ringBuffer.Value = at
		sw.ringBuffer = sw.ringBuffer.Next()
	}
}

// getOldestFromRing finds the oldest timestamp in the ring buffer.
func (sw *SlidingWindow) getOldestFromRing() time.Time {
	if sw.ringBuffer == nil {
		return time.Time{}
	}

	var oldest time.Time
	sw.ringBuffer.Do(func(v interface{}) {
		if v != nil {
			if reqTime, ok := v.(time.Time); ok {
				if oldest.IsZero() || reqTime.Before(oldest) {
					oldest = reqTime
				}
			}
		}
	})

	return oldest
}

// Clone creates a copy of the sliding window with the same configuration
// but reset state.
func (sw *SlidingWindow) Clone() *SlidingWindow {
	sw.mu.RLock()
	defer sw.mu.RUnlock()

	return NewSlidingWindow(sw.limit, sw.windowSize)
}

// String returns a string representation of the sliding window state.
func (sw *SlidingWindow) String() string {
	sw.mu.RLock()
	defer sw.mu.RUnlock()

	sw.cleanupAt(time.Now())
	currentCount := sw.getCurrentCount()

	return fmt.Sprintf(
		"SlidingWindow{limit: %d, window: %v, count: %d, available: %d}",
		sw.limit, sw.windowSize, currentCount, sw.limit-currentCount)
}

// SlidingWindowState represents the serializable state of a sliding window.
type SlidingWindowState struct {
	Requests   []time.Time   `json:"requests"`
	Limit      int64         `json:"limit"`
	WindowSize time.Duration `json:"window_size"`
}

// GetState returns the current state for serialization.
func (sw *SlidingWindow) GetState() *SlidingWindowState {
	sw.mu.RLock()
	defer sw.mu.RUnlock()

	sw.cleanupAt(time.Now())

	var requests []time.Time
	if sw.useRingBuffer {
		requests = sw.getRequestsFromRing()
	} else {
		requests = make([]time.Time, len(sw.requests))
		copy(requests, sw.requests)
	}

	return &SlidingWindowState{
		Requests:   requests,
		Limit:      sw.limit,
		WindowSize: sw.windowSize,
	}
}

// getRequestsFromRing extracts all non-nil timestamps from the ring buffer.
func (sw *SlidingWindow) getRequestsFromRing() []time.Time {
	if sw.ringBuffer == nil {
		return nil
	}

	var requests []time.Time
	sw.ringBuffer.Do(func(v interface{}) {
		if v != nil {
			if reqTime, ok := v.(time.Time); ok {
				requests = append(requests, reqTime)
			}
		}
	})

	return requests
}

// SetState restores the sliding window from a saved state.
func (sw *SlidingWindow) SetState(state *SlidingWindowState) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	sw.limit = state.Limit
	sw.windowSize = state.WindowSize

	if state.Limit > 1000 {
		sw.useRingBuffer = true
		sw.ringSize = int(state.Limit)
		sw.ringBuffer = ring.New(sw.ringSize)

		for _, req := range state.Requests {
			sw.ringBuffer.Value = req
			sw.ringBuffer = sw.ringBuffer.Next()
		}
	} else {
		sw.useRingBuffer = false
		sw.requests = make([]time.Time, len(state.Requests))
		copy(sw.requests, state.Requests)
	}
}

// NewSlidingWindowFromState creates a sliding window from a saved state.
func NewSlidingWindowFromState(state *SlidingWindowState) *SlidingWindow {
	sw := NewSlidingWindow(state.Limit, state.WindowSize)
	sw.SetState(state)
	return sw
}
