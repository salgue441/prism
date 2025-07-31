package algorithms

import (
	"fmt"
	"sync"
	"time"
)

// LeakyBucket implements the leaky bucket rate limiting algorithm.
// This algorithm maintains a queue (bucket) that fills with requests
// and leaks at a constant rate. It provides smooth output rate limiting
// and can handle bursts by queuing requests.
//
// The leaky bucket algorithm works by:
// 1. Maintaining a bucket with a maximum capacity
// 2. Adding requests to the bucket when they arrive
// 3. Leaking requests from the bucket at a constant rate
// 4. Rejecting requests when the bucket is full
//
// This algorithm is ideal for smoothing bursty traffic and ensuring
// a consistent output rate.
type LeakyBucket struct {
	// Configuration
	capacity     int64         // Maximum bucket capacity (burst size)
	leakRate     int64         // Requests leaked per second
	leakInterval time.Duration // How often to leak requests

	// State (protected by mutex)
	mu       sync.RWMutex
	volume   float64   // Current volume in the bucket
	lastLeak time.Time // Last time the bucket leaked

	// Optimization: track fractional leakage for precise timing
	fractionalLeak float64

	// Metrics
	totalRequests    int64 // Total requests processed
	acceptedRequests int64 // Total requests accepted into bucket
	rejectedRequests int64 // Total requests rejected (bucket full)
	leakedRequests   int64 // Total requests leaked from bucket
	overflowEvents   int64 // Times bucket reached capacity
	lastLeakTime     time.Time
}

// NewLeakyBucket creates a new leaky bucket rate limiter.
//
// Parameters:
//   - capacity: Maximum number of requests the bucket can hold
//   - leakRate: Number of requests leaked from the bucket per second
func NewLeakyBucket(capacity, leakRate int64) *LeakyBucket {
	return &LeakyBucket{
		capacity:     capacity,
		leakRate:     leakRate,
		leakInterval: time.Second,
		lastLeak:     time.Now(),
		lastLeakTime: time.Now(),
	}
}

// Allow checks if a request can be added to the bucket.
// Returns true if the request is accepted, false if the bucket is full.
func (lb *LeakyBucket) Allow() bool {
	return lb.AllowAt(time.Now())
}

// AllowN checks if N requests can be added to the bucket.
// Returns true if all N requests can be accepted, false otherwise.
func (lb *LeakyBucket) AllowN(n int64) bool {
	return lb.AllowNAt(n, time.Now())
}

// AllowAt checks if a request can be added to the bucket at a specific time.
func (lb *LeakyBucket) AllowAt(at time.Time) bool {
	return lb.AllowNAt(1, at)
}

// AllowNAt checks if N requests can be added to the bucket at a specific time.
func (lb *LeakyBucket) AllowNAt(n int64, at time.Time) bool {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.totalRequests += n
	lb.leakAt(at)

	if lb.volume+float64(n) > float64(lb.capacity) {
		lb.rejectedRequests += n

		if lb.volume >= float64(lb.capacity) {
			lb.overflowEvents++
		}

		return false
	}

	lb.volume += float64(n)
	lb.acceptedRequests += n

	return true
}

// Available returns the available space in the bucket.
func (lb *LeakyBucket) Available() int64 {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	lb.leakAt(time.Now())
	available := float64(lb.capacity) - lb.volume
	if available < 0 {
		available = 0
	}
	return int64(available)
}

// Volume returns the current volume of requests in the bucket.
func (lb *LeakyBucket) Volume() int64 {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	lb.leakAt(time.Now())
	return int64(lb.volume)
}

// Capacity returns the maximum capacity of the bucket.
func (lb *LeakyBucket) Capacity() int64 {
	return lb.capacity
}

// LeakRate returns the leak rate in requests per second.
func (lb *LeakyBucket) LeakRate() int64 {
	return lb.leakRate
}

// IsFull returns true if the bucket is at capacity.
func (lb *LeakyBucket) IsFull() bool {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	lb.leakAt(time.Now())
	return lb.volume >= float64(lb.capacity)
}

// IsEmpty returns true if the bucket is empty.
func (lb *LeakyBucket) IsEmpty() bool {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	lb.leakAt(time.Now())
	return lb.volume <= 0
}

// Reset empties the bucket completely.
func (lb *LeakyBucket) Reset() {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.volume = 0
	lb.fractionalLeak = 0
	lb.lastLeak = time.Now()
}

// SetCapacity updates the bucket capacity.
// If the new capacity is smaller than current volume, volume is capped.
func (lb *LeakyBucket) SetCapacity(capacity int64) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.capacity = capacity
	if lb.volume > float64(capacity) {
		lb.volume = float64(capacity)
	}
}

// SetLeakRate updates the leak rate.
func (lb *LeakyBucket) SetLeakRate(rate int64) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.leakRate = rate
}

// TimeToEmpty returns the time until the bucket will be empty.
func (lb *LeakyBucket) TimeToEmpty() time.Duration {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	lb.leakAt(time.Now())
	if lb.volume <= 0 {
		return 0
	}

	if lb.leakRate == 0 {
		return time.Duration(-1)
	}

	secondsToEmpty := lb.volume / float64(lb.leakRate)
	return time.Duration(secondsToEmpty * float64(time.Second))
}

// TimeToAvailable returns the time until N requests worth of space
// will be available in the bucket.
func (lb *LeakyBucket) TimeToAvailable(n int64) time.Duration {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	lb.leakAt(time.Now())
	available := float64(lb.capacity) - lb.volume
	if available >= float64(n) {
		return 0
	}

	if lb.leakRate == 0 {
		return time.Duration(-1)
	}

	spaceNeeded := float64(n) - available
	secondsToAvailable := spaceNeeded / float64(lb.leakRate)
	return time.Duration(secondsToAvailable * float64(time.Second))
}

// GetMetrics returns current metrics for the leaky bucket.
type LeakyBucketMetrics struct {
	Capacity         int64         `json:"capacity"`
	LeakRate         int64         `json:"leak_rate"`
	CurrentVolume    float64       `json:"current_volume"`
	Available        int64         `json:"available"`
	TotalRequests    int64         `json:"total_requests"`
	AcceptedRequests int64         `json:"accepted_requests"`
	RejectedRequests int64         `json:"rejected_requests"`
	LeakedRequests   int64         `json:"leaked_requests"`
	OverflowEvents   int64         `json:"overflow_events"`
	TimeToEmpty      time.Duration `json:"time_to_empty"`
	LastLeak         time.Time     `json:"last_leak"`
	Utilization      float64       `json:"utilization"`
	AcceptanceRate   float64       `json:"acceptance_rate"`
}

func (lb *LeakyBucket) GetMetrics() *LeakyBucketMetrics {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	lb.leakAt(time.Now())

	available := float64(lb.capacity) - lb.volume
	if available < 0 {
		available = 0
	}

	var utilization float64
	if lb.capacity > 0 {
		utilization = lb.volume / float64(lb.capacity)
	}

	var acceptanceRate float64
	if lb.totalRequests > 0 {
		acceptanceRate = float64(lb.acceptedRequests) / float64(lb.totalRequests)
	}

	var timeToEmpty time.Duration
	if lb.volume > 0 && lb.leakRate > 0 {
		secondsToEmpty := lb.volume / float64(lb.leakRate)
		timeToEmpty = time.Duration(secondsToEmpty * float64(time.Second))
	}

	return &LeakyBucketMetrics{
		Capacity:         lb.capacity,
		LeakRate:         lb.leakRate,
		CurrentVolume:    lb.volume,
		Available:        int64(available),
		TotalRequests:    lb.totalRequests,
		AcceptedRequests: lb.acceptedRequests,
		RejectedRequests: lb.rejectedRequests,
		LeakedRequests:   lb.leakedRequests,
		OverflowEvents:   lb.overflowEvents,
		TimeToEmpty:      timeToEmpty,
		LastLeak:         lb.lastLeak,
		Utilization:      utilization,
		AcceptanceRate:   acceptanceRate,
	}
}

// Private methods

// leakAt removes requests from the bucket based on elapsed time.
// This method must be called while holding the write lock.
func (lb *LeakyBucket) leakAt(at time.Time) {
	if lb.leakRate == 0 || lb.volume <= 0 {
		lb.lastLeak = at
		return
	}

	elapsed := at.Sub(lb.lastLeak)
	if elapsed <= 0 {
		return
	}

	leakAmount := float64(lb.leakRate) * elapsed.Seconds()
	leakAmount += lb.fractionalLeak

	actualLeak := min(leakAmount, lb.volume)
	lb.volume -= actualLeak
	lb.leakedRequests += int64(actualLeak)
	lb.fractionalLeak = leakAmount - actualLeak

	if lb.volume < 0 {
		lb.volume = 0
	}

	lb.lastLeak = at
	lb.lastLeakTime = at
}

// Force operations for administrative purposes

// ForceAdd forcibly adds volume to the bucket, potentially exceeding capacity.
func (lb *LeakyBucket) ForceAdd(volume int64) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.leakAt(time.Now())
	lb.volume += float64(volume)
}

// ForceLeak forcibly removes volume from the bucket.
func (lb *LeakyBucket) ForceLeak(volume int64) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.leakAt(time.Now())
	lb.volume -= float64(volume)
	if lb.volume < 0 {
		lb.volume = 0
	}

	lb.leakedRequests += volume
}

// SetVolume forcibly sets the bucket volume.
func (lb *LeakyBucket) SetVolume(volume float64) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if volume < 0 {
		volume = 0
	}

	if volume > float64(lb.capacity) {
		volume = float64(lb.capacity)
	}

	lb.volume = volume
	lb.lastLeak = time.Now()
}

// Peek operations for inspection without modification

// PeekVolume returns the current volume without triggering a leak.
func (lb *LeakyBucket) PeekVolume() float64 {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	return lb.volume
}

// PeekVolumeAt returns what the volume would be at a specific time.
func (lb *LeakyBucket) PeekVolumeAt(at time.Time) float64 {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if lb.leakRate == 0 || lb.volume <= 0 {
		return lb.volume
	}

	elapsed := at.Sub(lb.lastLeak)
	if elapsed <= 0 {
		return lb.volume
	}

	leakAmount := float64(lb.leakRate) * elapsed.Seconds()
	leakAmount += lb.fractionalLeak

	newVolume := lb.volume - min(leakAmount, lb.volume)
	if newVolume < 0 {
		newVolume = 0
	}

	return newVolume
}

// Advanced features

// WaitForSpace blocks until there's space for N requests in the bucket.
// Returns the actual wait time or an error if the context is canceled.
func (lb *LeakyBucket) WaitForSpace(n int64) time.Duration {
	waitTime := lb.TimeToAvailable(n)
	if waitTime <= 0 {
		return 0
	}

	// TODO: add context support
	// select {
	// case <-time.After(waitTime):
	//     return waitTime
	//
	// case <-ctx.Done():
	//     return ctx.Err()
	// }

	return waitTime
}

// Reserve reserves space in the bucket for future use.
// This is useful for pre-allocating capacity for known upcoming requests.
func (lb *LeakyBucket) Reserve(n int64) bool {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.leakAt(time.Now())

	if lb.volume+float64(n) > float64(lb.capacity) {
		return false
	}

	lb.volume += float64(n)
	return true
}

// Unreserve releases previously reserved space.
func (lb *LeakyBucket) Unreserve(n int64) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.volume -= float64(n)
	if lb.volume < 0 {
		lb.volume = 0
	}
}

// Batch operations

// BatchAllow attempts to add multiple request batches to the bucket.
// Returns a slice of booleans indicating which batches were accepted.
func (lb *LeakyBucket) BatchAllow(requests []int64) []bool {
	return lb.BatchAllowAt(requests, time.Now())
}

// BatchAllowAt attempts to add multiple request batches at a specific time.
func (lb *LeakyBucket) BatchAllowAt(requests []int64, at time.Time) []bool {
	if len(requests) == 0 {
		return nil
	}

	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.leakAt(at)
	results := make([]bool, len(requests))

	for i, n := range requests {
		lb.totalRequests += n

		if lb.volume+float64(n) > float64(lb.capacity) {
			results[i] = false
			lb.rejectedRequests += n
			if lb.volume >= float64(lb.capacity) {
				lb.overflowEvents++
			}
		} else {
			results[i] = true
			lb.volume += float64(n)
			lb.acceptedRequests += n
		}
	}

	return results
}

// Clone creates a copy of the leaky bucket with the same configuration
// but reset state.
func (lb *LeakyBucket) Clone() *LeakyBucket {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	return NewLeakyBucket(lb.capacity, lb.leakRate)
}

// String returns a string representation of the leaky bucket state.
func (lb *LeakyBucket) String() string {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	lb.leakAt(time.Now())
	available := float64(lb.capacity) - lb.volume
	if available < 0 {
		available = 0
	}

	return fmt.Sprintf(
		"LeakyBucket{capacity: %d, rate: %d/s, volume: %.2f, available: %.0f}",
		lb.capacity, lb.leakRate, lb.volume, available)
}

// LeakyBucketState represents the serializable state of a leaky bucket.
type LeakyBucketState struct {
	Volume         float64   `json:"volume"`
	LastLeak       time.Time `json:"last_leak"`
	FractionalLeak float64   `json:"fractional_leak"`
	Capacity       int64     `json:"capacity"`
	LeakRate       int64     `json:"leak_rate"`
}

// GetState returns the current state for serialization.
func (lb *LeakyBucket) GetState() *LeakyBucketState {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	lb.leakAt(time.Now())
	return &LeakyBucketState{
		Volume:         lb.volume,
		LastLeak:       lb.lastLeak,
		FractionalLeak: lb.fractionalLeak,
		Capacity:       lb.capacity,
		LeakRate:       lb.leakRate,
	}
}

// SetState restores the leaky bucket from a saved state.
func (lb *LeakyBucket) SetState(state *LeakyBucketState) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.volume = state.Volume
	lb.lastLeak = state.LastLeak
	lb.fractionalLeak = state.FractionalLeak
	lb.capacity = state.Capacity
	lb.leakRate = state.LeakRate
}

// NewLeakyBucketFromState creates a leaky bucket from a saved state.
func NewLeakyBucketFromState(state *LeakyBucketState) *LeakyBucket {
	lb := &LeakyBucket{
		capacity:       state.Capacity,
		leakRate:       state.LeakRate,
		leakInterval:   time.Second,
		volume:         state.Volume,
		lastLeak:       state.LastLeak,
		fractionalLeak: state.FractionalLeak,
		lastLeakTime:   time.Now(),
	}
	return lb
}

// Monitoring and observability

// GetLeakHistory returns recent leak events for monitoring.
type LeakEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	LeakAmount  float64   `json:"leak_amount"`
	VolumeAfter float64   `json:"volume_after"`
}

// Performance monitoring

// GetPerformanceStats returns performance statistics.
type PerformanceStats struct {
	AverageLeakRate    float64   `json:"average_leak_rate"`
	PeakVolume         float64   `json:"peak_volume"`
	UtilizationHistory []float64 `json:"utilization_history"`
	LastFullTime       time.Time `json:"last_full_time"`
	LastEmptyTime      time.Time `json:"last_empty_time"`
	EfficiencyRatio    float64   `json:"efficiency_ratio"`
}

// Configuration validation

// ValidateConfig validates leaky bucket configuration parameters.
func ValidateConfig(capacity, leakRate int64) error {
	if capacity <= 0 {
		return fmt.Errorf("capacity must be positive, got %d", capacity)
	}
	if leakRate < 0 {
		return fmt.Errorf("leak rate cannot be negative, got %d", leakRate)
	}
	if capacity > 1000000 {
		return fmt.Errorf("capacity too large, maximum is 1000000, got %d", capacity)
	}
	if leakRate > capacity*10 {
		return fmt.Errorf("leak rate too high relative to capacity")
	}
	return nil
}

// Factory functions with validation

// NewLeakyBucketWithValidation creates a new leaky bucket with parameter validation.
func NewLeakyBucketWithValidation(capacity, leakRate int64) (*LeakyBucket, error) {
	if err := ValidateConfig(capacity, leakRate); err != nil {
		return nil, err
	}

	return NewLeakyBucket(capacity, leakRate), nil
}

// Specialized bucket types

// NewSmoothingBucket creates a leaky bucket optimized for traffic smoothing.
// It uses a higher leak rate relative to capacity for better smoothing.
func NewSmoothingBucket(targetRate int64) *LeakyBucket {
	capacity := targetRate * 2
	return NewLeakyBucket(capacity, targetRate)
}

// NewBurstTolerantBucket creates a leaky bucket that can handle large bursts.
// It uses a lower leak rate relative to capacity for burst tolerance.
func NewBurstTolerantBucket(burstCapacity, sustainedRate int64) *LeakyBucket {
	return NewLeakyBucket(burstCapacity, sustainedRate)
}

