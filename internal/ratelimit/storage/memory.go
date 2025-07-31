package storage

import (
	"context"
	"fmt"
	"prism/internal/ratelimit"
	"prism/pkg/logger"
	"sort"
	"sync"
	"time"
)

// MemoryStorage implements in-memory storage for rate limiting data.
// This storage backend provides high performance with automatic cleanup
// of expired entries and is suitable for single-instance deployments.
type MemoryStorage struct {
	config *ratelimit.Config
	logger *logger.Logger

	// Storage map with TTL support
	mu      sync.RWMutex
	data    map[string]*memoryEntry
	indexes map[string]time.Time

	// Cleanup management
	cleanupTicker *time.Ticker
	cleanupDone   chan struct{}
	closed        bool

	// Metrics
	metrics *memoryMetrics
}

// memoryEntry represents a stored value with TTL information.
type memoryEntry struct {
	value      *ratelimit.StorageValue
	expiresAt  time.Time
	lastAccess time.Time
}

// memoryMetrics tracks storage performance metrics.
type memoryMetrics struct {
	mu            sync.RWMutex
	gets          int64
	sets          int64
	deletes       int64
	hits          int64
	misses        int64
	evictions     int64
	cleanupRuns   int64
	totalKeys     int64
	expiredKeys   int64
	memoryUsage   int64
	lastCleanup   time.Time
	avgAccessTime time.Duration
	accessTimeSum int64
	accessCount   int64
}

// NewMemoryStorage creates a new memory-based storage backend.
func NewMemoryStorage(config *ratelimit.Config, log *logger.Logger) (*MemoryStorage, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if log == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	ms := &MemoryStorage{
		config:      config,
		logger:      log,
		data:        make(map[string]*memoryEntry),
		indexes:     make(map[string]time.Time),
		cleanupDone: make(chan struct{}),
		metrics:     &memoryMetrics{lastCleanup: time.Now()},
	}

	if config.CleanupInterval > 0 {
		ms.cleanupTicker = time.NewTicker(config.CleanupInterval)
		go ms.cleanupLoop()
	}

	log.Info("Memory storage initialized",
		"max_keys", config.MaxKeys,
		"cleanup_interval", config.CleanupInterval)

	return ms, nil
}

// Get retrieves a value from memory storage.
func (ms *MemoryStorage) Get(ctx context.Context, key string) (*ratelimit.StorageValue, error) {
	start := time.Now()
	ms.recordAccessTime(time.Since(start))

	if ms.closed {
		return nil, ratelimit.ErrStorageUnavailable
	}

	ms.mu.RLock()

	entry, exists := ms.data[key]
	ms.mu.RUnlock()

	ms.metrics.mu.Lock()
	ms.metrics.gets++
	ms.metrics.mu.Unlock()

	if !exists {
		ms.metrics.mu.Lock()
		ms.metrics.misses++
		ms.metrics.mu.Unlock()

		return nil, nil
	}

	now := time.Now()
	if now.After(entry.expiresAt) {
		ms.mu.Lock()
		delete(ms.data, key)
		delete(ms.indexes, key)
		ms.mu.Unlock()

		ms.metrics.mu.Lock()
		ms.metrics.misses++
		ms.metrics.expiredKeys++
		ms.metrics.mu.Unlock()

		return nil, nil
	}

	ms.mu.Lock()
	entry.lastAccess = now
	ms.mu.Unlock()

	ms.metrics.mu.Lock()
	ms.metrics.hits++
	ms.metrics.mu.Unlock()

	return ms.copyStorageValue(entry.value), nil
}

// Set stores a value in memory storage with TTL.
func (ms *MemoryStorage) Set(ctx context.Context, key string,
	value *ratelimit.StorageValue, ttl time.Duration) error {
	start := time.Now()
	ms.recordAccessTime(time.Since(start))

	if ms.closed {
		return ratelimit.ErrStorageUnavailable
	}

	if value == nil {
		return fmt.Errorf("value cannot be nil")
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	if err := ms.ensureCapacity(); err != nil {
		return err
	}

	ms.mu.Lock()
	ms.data[key] = &memoryEntry{
		value:      ms.copyStorageValue(value),
		expiresAt:  expiresAt,
		lastAccess: now,
	}

	ms.indexes[key] = expiresAt
	ms.mu.Unlock()

	ms.metrics.mu.Lock()
	ms.metrics.sets++
	ms.metrics.totalKeys++
	ms.metrics.memoryUsage += ms.estimateEntrySize(key, value)
	ms.metrics.mu.Unlock()

	return nil
}

// Increment atomically increments a counter with TTL.
func (ms *MemoryStorage) Increment(ctx context.Context, key string,
	delta int64, ttl time.Duration) (int64, error) {
	start := time.Now()
	ms.recordAccessTime(time.Since(start))

	if ms.closed {
		return 0, ratelimit.ErrStorageUnavailable
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	ms.mu.Lock()
	defer ms.mu.Unlock()

	entry, exists := ms.data[key]
	var newCount int64

	if !exists || now.After(entry.expiresAt) {
		newCount = delta

		if len(ms.data) >= ms.config.MaxKeys {
			ms.mu.Unlock()
			if err := ms.ensureCapacity(); err != nil {
				ms.mu.Lock()
				return 0, err
			}

			ms.mu.Lock()
		}

		ms.data[key] = &memoryEntry{
			value: &ratelimit.StorageValue{
				Count: newCount,
			},
			expiresAt:  expiresAt,
			lastAccess: now,
		}

		ms.indexes[key] = expiresAt
		ms.metrics.sets++
		ms.metrics.totalKeys++
	} else {
		newCount = entry.value.Count + delta

		entry.value.Count = newCount
		entry.expiresAt = expiresAt
		entry.lastAccess = now
		ms.indexes[key] = expiresAt
	}

	ms.metrics.gets++
	ms.metrics.hits++

	return newCount, nil
}

// Delete removes a key from storage.
func (ms *MemoryStorage) Delete(ctx context.Context, key string) error {
	start := time.Now()
	ms.recordAccessTime(time.Since(start))

	if ms.closed {
		return ratelimit.ErrStorageUnavailable
	}

	ms.mu.Lock()
	entry, exists := ms.data[key]
	if exists {
		delete(ms.data, key)
		delete(ms.indexes, key)
	}

	ms.mu.Unlock()
	if exists {
		ms.metrics.mu.Lock()
		ms.metrics.deletes++
		ms.metrics.totalKeys--
		ms.metrics.memoryUsage -= ms.estimateEntrySize(key, entry.value)
		ms.metrics.mu.Unlock()
	}

	return nil
}

// Exists checks if a key exists in storage.
func (ms *MemoryStorage) Exists(ctx context.Context, key string) (bool, error) {
	start := time.Now()
	ms.recordAccessTime(time.Since(start))

	if ms.closed {
		return false, ratelimit.ErrStorageUnavailable
	}

	ms.mu.RLock()
	entry, exists := ms.data[key]
	ms.mu.RUnlock()

	if !exists {
		return false, nil
	}

	if time.Now().After(entry.expiresAt) {
		ms.Delete(ctx, key)
		return false, nil
	}

	return true, nil
}

// BatchGet retrieves multiple values efficiently.
func (ms *MemoryStorage) BatchGet(ctx context.Context, keys []string) (map[string]*ratelimit.StorageValue, error) {
	start := time.Now()
	ms.recordAccessTime(time.Since(start))

	if ms.closed {
		return nil, ratelimit.ErrStorageUnavailable
	}

	result := make(map[string]*ratelimit.StorageValue)
	now := time.Now()
	expiredKeys := make([]string, 0)

	ms.mu.RLock()
	for _, key := range keys {
		if entry, exists := ms.data[key]; exists {
			if now.After(entry.expiresAt) {
				expiredKeys = append(expiredKeys, key)
			} else {
				result[key] = ms.copyStorageValue(entry.value)
				entry.lastAccess = now
			}
		}
	}

	ms.mu.RUnlock()
	if len(expiredKeys) > 0 {
		ms.mu.Lock()
		for _, key := range expiredKeys {
			delete(ms.data, key)
			delete(ms.indexes, key)
		}

		ms.mu.Unlock()
		ms.metrics.mu.Lock()
		ms.metrics.expiredKeys += int64(len(expiredKeys))
		ms.metrics.mu.Unlock()
	}

	ms.metrics.mu.Lock()
	ms.metrics.gets += int64(len(keys))
	ms.metrics.hits += int64(len(result))
	ms.metrics.misses += int64(len(keys) - len(result))
	ms.metrics.mu.Unlock()

	return result, nil
}

// BatchSet stores multiple values efficiently.
func (ms *MemoryStorage) BatchSet(ctx context.Context, values map[string]*ratelimit.StorageValue, ttl time.Duration) error {
	start := time.Now()
	ms.recordAccessTime(time.Since(start))

	if ms.closed {
		return ratelimit.ErrStorageUnavailable
	}

	// Check capacity before batch operation
	if err := ms.ensureCapacityForBatch(len(values)); err != nil {
		return err
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	ms.mu.Lock()
	defer ms.mu.Unlock()

	for key, value := range values {
		if value == nil {
			continue
		}

		ms.data[key] = &memoryEntry{
			value:      ms.copyStorageValue(value),
			expiresAt:  expiresAt,
			lastAccess: now,
		}

		ms.indexes[key] = expiresAt
	}

	ms.metrics.sets += int64(len(values))
	ms.metrics.totalKeys += int64(len(values))

	return nil
}

// Close closes the storage backend and cleans up resources.
func (ms *MemoryStorage) Close() error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if ms.closed {
		return nil
	}

	ms.closed = true
	if ms.cleanupTicker != nil {
		ms.cleanupTicker.Stop()
		close(ms.cleanupDone)
	}

	ms.data = nil
	ms.indexes = nil
	ms.logger.Info("Memory storage closed")

	return nil
}

// Ping checks if the storage backend is available.
func (ms *MemoryStorage) Ping(ctx context.Context) error {
	if ms.closed {
		return ratelimit.ErrStorageUnavailable
	}

	return nil
}

// Private  methods

// cleanupLoop runs periodic cleanup of expired entries.
func (ms *MemoryStorage) cleanupLoop() {
	defer func() {
		if r := recover(); r != nil {
			ms.logger.Error("Memory storage cleanup panic", "error", r)
		}
	}()

	for {
		select {
		case <-ms.cleanupTicker.C:
			ms.cleanup()

		case <-ms.cleanupDone:
			return
		}
	}
}

// cleanup removes expired entries from storage
func (ms *MemoryStorage) cleanup() {
	start := time.Now()
	defer func() {
		ms.metrics.mu.Lock()

		ms.metrics.lastCleanup = time.Now()
		ms.metrics.cleanupRuns++

		ms.metrics.mu.Unlock()
	}()

	now := time.Now()
	expiredKeys := make([]string, 0)

	ms.mu.RLock()
	for key, expiresAt := range ms.indexes {
		if now.After(expiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	ms.mu.RUnlock()
	if len(expiredKeys) == 0 {
		return
	}

	ms.mu.Lock()
	memoryFreed := int64(0)

	for _, key := range expiredKeys {
		if entry, exists := ms.data[key]; exists {
			memoryFreed += ms.estimateEntrySize(key, entry.value)

			delete(ms.data, key)
			delete(ms.indexes, key)
		}
	}

	ms.mu.Unlock()
	ms.metrics.mu.Lock()
	ms.metrics.expiredKeys += int64(len(expiredKeys))
	ms.metrics.totalKeys -= int64(len(expiredKeys))
	ms.metrics.memoryUsage -= memoryFreed
	ms.metrics.mu.Unlock()

	ms.logger.Debug("Memory storage cleanup completed",
		"expired_keys", len(expiredKeys),
		"duration", time.Since(start),
		"memory_freed", memoryFreed)
}

// ensureCapacity ensures there's space for one more entry.
func (ms *MemoryStorage) ensureCapacity() error {
	return ms.ensureCapacityForBatch(1)
}

// ensureCapacityForBatch ensures there's space for N more entries.
func (ms *MemoryStorage) ensureCapacityForBatch(additionalEntries int) error {
	ms.mu.RLock()
	currentSize := len(ms.data)
	ms.mu.RUnlock()

	if currentSize+additionalEntries <= ms.config.MaxKeys {
		return nil
	}

	needed := currentSize + additionalEntries - ms.config.MaxKeys
	evicted := ms.evictLRU(needed)

	if evicted < needed {
		return fmt.Errorf("unable to free enough space: needed %d, evicted %d",
			needed, evicted)
	}

	return nil
}

// evictLRU evicts the least recently used entries.
func (ms *MemoryStorage) evictLRU(count int) int {
	if count <= 0 {
		return 0
	}

	// Collect entries with their last access times
	type lruEntry struct {
		key        string
		lastAccess time.Time
	}

	ms.mu.RLock()
	entries := make([]lruEntry, 0, len(ms.data))

	for key, entry := range ms.data {
		entries = append(entries, lruEntry{
			key:        key,
			lastAccess: entry.lastAccess,
		})
	}

	ms.mu.RUnlock()
	if len(entries) == 0 {
		return 0
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastAccess.Before(entries[j].lastAccess)
	})

	evictCount := min(count, len(entries))

	ms.mu.Lock()
	memoryFreed := int64(0)
	actuallyEvicted := 0

	for i := 0; i < evictCount; i++ {
		key := entries[i].key

		if entry, exists := ms.data[key]; exists {
			memoryFreed += ms.estimateEntrySize(key, entry.value)

			delete(ms.data, key)
			delete(ms.indexes, key)

			actuallyEvicted++
		}
	}

	ms.mu.Unlock()
	ms.metrics.mu.Lock()
	ms.metrics.evictions += int64(actuallyEvicted)
	ms.metrics.totalKeys -= int64(actuallyEvicted)
	ms.metrics.memoryUsage -= memoryFreed
	ms.metrics.mu.Unlock()

	ms.logger.Debug("LRU eviction completed",
		"requested", count,
		"evicted", actuallyEvicted,
		"memory_freed", memoryFreed)

	return actuallyEvicted
}

// copyStorageValue creates a deep copy of a storage value.
func (ms *MemoryStorage) copyStorageValue(value *ratelimit.StorageValue) *ratelimit.StorageValue {
	if value == nil {
		return nil
	}

	cpy := &ratelimit.StorageValue{
		Count:            value.Count,
		LastRefill:       value.LastRefill,
		WindowStart:      value.WindowStart,
		Tokens:           value.Tokens,
		Blacklisted:      value.Blacklisted,
		BlacklistedUntil: value.BlacklistedUntil,
	}

	if value.Requests != nil {
		cpy.Requests = make([]time.Time, len(value.Requests))
		copy(cpy.Requests, value.Requests)
	}

	if value.Metadata != nil {
		cpy.Metadata = make(map[string]any)
		for k, v := range value.Metadata {
			cpy.Metadata[k] = v
		}
	}

	return cpy
}

// estimateEntrySize estimates the memory usage of an entry.
func (ms *MemoryStorage) estimateEntrySize(key string,
	value *ratelimit.StorageValue) int64 {
	size := int64(len(key)) + 64

	if value != nil {
		size += 64

		if value.Requests != nil {
			size += int64(len(value.Requests)) * 24
		}

		if value.Metadata != nil {
			size += int64(len(value.Metadata)) * 32
		}
	}

	return size
}

// recordAccessTime records access time for performance metrics.
func (ms *MemoryStorage) recordAccessTime(duration time.Duration) {
	ms.metrics.mu.Lock()
	defer ms.metrics.mu.Unlock()

	ms.metrics.accessTimeSum += duration.Nanoseconds()
	ms.metrics.accessCount++

	if ms.metrics.accessCount > 0 {
		ms.metrics.avgAccessTime = time.Duration(ms.metrics.accessTimeSum / ms.metrics.accessCount)
	}
}

// GetMetrics returns current storage metrics.
type MemoryStorageMetrics struct {
	Gets          int64         `json:"gets"`
	Sets          int64         `json:"sets"`
	Deletes       int64         `json:"deletes"`
	Hits          int64         `json:"hits"`
	Misses        int64         `json:"misses"`
	HitRatio      float64       `json:"hit_ratio"`
	Evictions     int64         `json:"evictions"`
	CleanupRuns   int64         `json:"cleanup_runs"`
	TotalKeys     int64         `json:"total_keys"`
	ExpiredKeys   int64         `json:"expired_keys"`
	MemoryUsage   int64         `json:"memory_usage"`
	LastCleanup   time.Time     `json:"last_cleanup"`
	AvgAccessTime time.Duration `json:"avg_access_time"`
	MaxKeys       int           `json:"max_keys"`
	Utilization   float64       `json:"utilization"`
}

func (ms *MemoryStorage) GetMetrics() *MemoryStorageMetrics {
	ms.metrics.mu.RLock()
	defer ms.metrics.mu.RUnlock()

	var hitRatio float64
	totalRequests := ms.metrics.hits + ms.metrics.misses
	if totalRequests > 0 {
		hitRatio = float64(ms.metrics.hits) / float64(totalRequests)
	}

	var utilization float64
	if ms.config.MaxKeys > 0 {
		utilization = float64(ms.metrics.totalKeys) / float64(ms.config.MaxKeys)
	}

	return &MemoryStorageMetrics{
		Gets:          ms.metrics.gets,
		Sets:          ms.metrics.sets,
		Deletes:       ms.metrics.deletes,
		Hits:          ms.metrics.hits,
		Misses:        ms.metrics.misses,
		HitRatio:      hitRatio,
		Evictions:     ms.metrics.evictions,
		CleanupRuns:   ms.metrics.cleanupRuns,
		TotalKeys:     ms.metrics.totalKeys,
		ExpiredKeys:   ms.metrics.expiredKeys,
		MemoryUsage:   ms.metrics.memoryUsage,
		LastCleanup:   ms.metrics.lastCleanup,
		AvgAccessTime: ms.metrics.avgAccessTime,
		MaxKeys:       ms.config.MaxKeys,
		Utilization:   utilization,
	}
}

// Advanced features for debugging and monitoring

// GetAllKeys returns all currently stored keys (for debugging).
func (ms *MemoryStorage) GetAllKeys() []string {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	keys := make([]string, 0, len(ms.data))
	for key := range ms.data {
		keys = append(keys, key)
	}

	return keys
}

// GetKeyInfo returns detailed information about a specific key.
type KeyInfo struct {
	Key        string                  `json:"key"`
	Value      *ratelimit.StorageValue `json:"value"`
	ExpiresAt  time.Time               `json:"expires_at"`
	LastAccess time.Time               `json:"last_access"`
	TTL        time.Duration           `json:"ttl"`
	Size       int64                   `json:"size"`
}

func (ms *MemoryStorage) GetKeyInfo(key string) *KeyInfo {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	entry, exists := ms.data[key]
	if !exists {
		return nil
	}

	now := time.Now()
	var ttl time.Duration
	if now.Before(entry.expiresAt) {
		ttl = entry.expiresAt.Sub(now)
	}

	return &KeyInfo{
		Key:        key,
		Value:      ms.copyStorageValue(entry.value),
		ExpiresAt:  entry.expiresAt,
		LastAccess: entry.lastAccess,
		TTL:        ttl,
		Size:       ms.estimateEntrySize(key, entry.value),
	}
}

// GetExpiredKeys returns keys that have expired but haven't been cleaned up yet.
func (ms *MemoryStorage) GetExpiredKeys() []string {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	now := time.Now()
	expiredKeys := make([]string, 0)

	for key, expiresAt := range ms.indexes {
		if now.After(expiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	return expiredKeys
}

// ForceCleanup manually triggers cleanup of expired entries.
func (ms *MemoryStorage) ForceCleanup() int {
	before := len(ms.data)
	ms.cleanup()
	after := len(ms.data)

	return before - after
}

// SetTTL updates the TTL for an existing key.
func (ms *MemoryStorage) SetTTL(key string, ttl time.Duration) error {
	if ms.closed {
		return ratelimit.ErrStorageUnavailable
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()

	entry, exists := ms.data[key]
	if !exists {
		return fmt.Errorf("key not found: %s", key)
	}

	now := time.Now()
	if now.After(entry.expiresAt) {
		delete(ms.data, key)
		delete(ms.indexes, key)

		return fmt.Errorf("key has expired: %s", key)
	}

	newExpiresAt := now.Add(ttl)
	entry.expiresAt = newExpiresAt
	ms.indexes[key] = newExpiresAt

	return nil
}

// GetTTL returns the remaining TTL for a key.
func (ms *MemoryStorage) GetTTL(key string) (time.Duration, error) {
	if ms.closed {
		return 0, ratelimit.ErrStorageUnavailable
	}

	ms.mu.RLock()
	defer ms.mu.RUnlock()

	entry, exists := ms.data[key]
	if !exists {
		return 0, fmt.Errorf("key not found: %s", key)
	}

	now := time.Now()
	if now.After(entry.expiresAt) {
		return 0, nil
	}

	return entry.expiresAt.Sub(now), nil
}

// Persistence support (for graceful restarts)

// ExportData exports all current data for persistence.
type ExportEntry struct {
	Key       string                  `json:"key"`
	Value     *ratelimit.StorageValue `json:"value"`
	ExpiresAt time.Time               `json:"expires_at"`
}

func (ms *MemoryStorage) ExportData() []ExportEntry {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	now := time.Now()
	entries := make([]ExportEntry, 0, len(ms.data))

	for key, entry := range ms.data {
		if now.Before(entry.expiresAt) {
			entries = append(entries, ExportEntry{
				Key:       key,
				Value:     ms.copyStorageValue(entry.value),
				ExpiresAt: entry.expiresAt,
			})
		}
	}

	return entries
}

// ImportData imports previously exported data.
func (ms *MemoryStorage) ImportData(entries []ExportEntry) error {
	if ms.closed {
		return ratelimit.ErrStorageUnavailable
	}

	now := time.Now()
	imported := 0

	ms.mu.Lock()
	defer ms.mu.Unlock()

	for _, exportEntry := range entries {
		if now.After(exportEntry.ExpiresAt) {
			continue
		}

		if len(ms.data) >= ms.config.MaxKeys {
			break
		}

		ms.data[exportEntry.Key] = &memoryEntry{
			value:      ms.copyStorageValue(exportEntry.Value),
			expiresAt:  exportEntry.ExpiresAt,
			lastAccess: now,
		}

		ms.indexes[exportEntry.Key] = exportEntry.ExpiresAt
		imported++
	}

	ms.metrics.totalKeys += int64(imported)
	ms.logger.Info("Data imported",
		"total_entries", len(entries),
		"imported", imported,
		"skipped_expired", len(entries)-imported)

	return nil
}

// Configuration updates

// UpdateConfig updates the storage configuration.
func (ms *MemoryStorage) UpdateConfig(newConfig *ratelimit.Config) error {
	if newConfig == nil {
		return fmt.Errorf("config cannot be nil")
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()

	oldMaxKeys := ms.config.MaxKeys
	ms.config = newConfig

	if newConfig.MaxKeys < oldMaxKeys && len(ms.data) > newConfig.MaxKeys {
		excess := len(ms.data) - newConfig.MaxKeys
		ms.evictLRU(excess)
	}

	ms.logger.Info("Storage configuration updated",
		"old_max_keys", oldMaxKeys,
		"new_max_keys", newConfig.MaxKeys)

	return nil
}

// Health check support

// HealthCheck performs a basic health check on the storage.
func (ms *MemoryStorage) HealthCheck() error {
	if ms.closed {
		return ratelimit.ErrStorageUnavailable
	}

	testKey := "__health_check__"
	testValue := &ratelimit.StorageValue{Count: 1}

	ctx := context.Background()
	if err := ms.Set(ctx, testKey, testValue, time.Second); err != nil {
		return fmt.Errorf("health check set failed: %w", err)
	}

	if _, err := ms.Get(ctx, testKey); err != nil {
		return fmt.Errorf("health check get failed: %w", err)
	}

	if err := ms.Delete(ctx, testKey); err != nil {
		return fmt.Errorf("health check delete failed: %w", err)
	}

	return nil
}

// String returns a string representation of the storage state.
func (ms *MemoryStorage) String() string {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	return fmt.Sprintf("MemoryStorage{keys: %d, max: %d, closed: %v}",
		len(ms.data), ms.config.MaxKeys, ms.closed)
}
