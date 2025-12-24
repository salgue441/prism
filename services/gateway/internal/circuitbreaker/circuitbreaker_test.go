package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCircuitBreaker_InitialState(t *testing.T) {
	cb := New("test", DefaultConfig())

	assert.Equal(t, StateClosed, cb.State())
	assert.Equal(t, "test", cb.Name())
}

func TestCircuitBreaker_StateTransitions(t *testing.T) {
	config := Config{
		FailureThreshold:    3,
		SuccessThreshold:    2,
		Timeout:             100 * time.Millisecond,
		MaxHalfOpenRequests: 1,
	}

	t.Run("closed to open after failures", func(t *testing.T) {
		cb := New("test", config)

		// Record failures up to threshold
		for i := 0; i < config.FailureThreshold; i++ {
			assert.Equal(t, StateClosed, cb.State())
			cb.RecordFailure()
		}

		assert.Equal(t, StateOpen, cb.State())
	})

	t.Run("open to half-open after timeout", func(t *testing.T) {
		cb := New("test", config)

		// Trip the circuit
		for i := 0; i < config.FailureThreshold; i++ {
			cb.RecordFailure()
		}
		assert.Equal(t, StateOpen, cb.State())

		// Wait for timeout
		time.Sleep(config.Timeout + 10*time.Millisecond)

		assert.Equal(t, StateHalfOpen, cb.State())
	})

	t.Run("half-open to closed after successes", func(t *testing.T) {
		cb := New("test", config)

		// Trip the circuit
		for i := 0; i < config.FailureThreshold; i++ {
			cb.RecordFailure()
		}

		// Wait for timeout
		time.Sleep(config.Timeout + 10*time.Millisecond)
		assert.Equal(t, StateHalfOpen, cb.State())

		// Allow request and record successes
		require.NoError(t, cb.Allow())
		cb.RecordSuccess()

		require.NoError(t, cb.Allow())
		cb.RecordSuccess()

		assert.Equal(t, StateClosed, cb.State())
	})

	t.Run("half-open to open on failure", func(t *testing.T) {
		cb := New("test", config)

		// Trip the circuit
		for i := 0; i < config.FailureThreshold; i++ {
			cb.RecordFailure()
		}

		// Wait for timeout
		time.Sleep(config.Timeout + 10*time.Millisecond)
		assert.Equal(t, StateHalfOpen, cb.State())

		// Allow request and record failure
		require.NoError(t, cb.Allow())
		cb.RecordFailure()

		assert.Equal(t, StateOpen, cb.State())
	})
}

func TestCircuitBreaker_BlocksRequests_WhenOpen(t *testing.T) {
	config := Config{
		FailureThreshold: 2,
		Timeout:          time.Hour, // Long timeout so it stays open
	}
	cb := New("test", config)

	// Trip the circuit
	for i := 0; i < config.FailureThreshold; i++ {
		cb.RecordFailure()
	}

	err := cb.Allow()
	assert.ErrorIs(t, err, ErrCircuitOpen)
}

func TestCircuitBreaker_LimitsRequests_WhenHalfOpen(t *testing.T) {
	config := Config{
		FailureThreshold:    2,
		Timeout:             10 * time.Millisecond,
		MaxHalfOpenRequests: 1,
	}
	cb := New("test", config)

	// Trip the circuit
	for i := 0; i < config.FailureThreshold; i++ {
		cb.RecordFailure()
	}

	// Wait for timeout
	time.Sleep(config.Timeout + 5*time.Millisecond)

	// First request should be allowed (transitions to half-open)
	require.NoError(t, cb.Allow())

	// Don't record result yet - request is "in flight"
	// Second request should be blocked (too many in half-open)
	err := cb.Allow()
	assert.ErrorIs(t, err, ErrTooManyRequests)

	// Complete the first request to allow more
	cb.RecordSuccess()
}

func TestCircuitBreaker_Execute(t *testing.T) {
	cb := New("test", DefaultConfig())

	t.Run("successful execution", func(t *testing.T) {
		err := cb.Execute(context.Background(), func(ctx context.Context) error {
			return nil
		})
		assert.NoError(t, err)
	})

	t.Run("failed execution", func(t *testing.T) {
		expectedErr := errors.New("test error")
		err := cb.Execute(context.Background(), func(ctx context.Context) error {
			return expectedErr
		})
		assert.ErrorIs(t, err, expectedErr)
	})
}

func TestCircuitBreaker_Reset(t *testing.T) {
	config := Config{
		FailureThreshold: 2,
		Timeout:          time.Hour,
	}
	cb := New("test", config)

	// Trip the circuit
	for i := 0; i < config.FailureThreshold; i++ {
		cb.RecordFailure()
	}
	assert.Equal(t, StateOpen, cb.State())

	// Reset
	cb.Reset()
	assert.Equal(t, StateClosed, cb.State())
	assert.NoError(t, cb.Allow())
}

func TestCircuitBreaker_Stats(t *testing.T) {
	cb := New("test-stats", DefaultConfig())

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess()

	stats := cb.Stats()
	assert.Equal(t, "test-stats", stats.Name)
	assert.Equal(t, StateClosed, stats.State)
	assert.Equal(t, 0, stats.Failures) // Reset after success
	assert.False(t, stats.LastFailure.IsZero())
}

func TestCircuitBreaker_OnStateChange(t *testing.T) {
	stateChanges := make([]struct {
		name string
		from State
		to   State
	}, 0)
	var mu sync.Mutex

	config := Config{
		FailureThreshold: 2,
		Timeout:          10 * time.Millisecond,
		SuccessThreshold: 1,
		OnStateChange: func(name string, from, to State) {
			mu.Lock()
			stateChanges = append(stateChanges, struct {
				name string
				from State
				to   State
			}{name, from, to})
			mu.Unlock()
		},
	}
	cb := New("test", config)

	// Trip circuit
	cb.RecordFailure()
	cb.RecordFailure()

	// Wait for callback
	time.Sleep(20 * time.Millisecond)

	mu.Lock()
	assert.Len(t, stateChanges, 1)
	assert.Equal(t, StateClosed, stateChanges[0].from)
	assert.Equal(t, StateOpen, stateChanges[0].to)
	mu.Unlock()
}

func TestCircuitBreaker_Concurrent(t *testing.T) {
	cb := New("test", Config{
		FailureThreshold:    100,
		SuccessThreshold:    10,
		Timeout:             time.Second,
		MaxHalfOpenRequests: 10,
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cb.Allow(); err == nil {
				if i%2 == 0 {
					cb.RecordSuccess()
				} else {
					cb.RecordFailure()
				}
			}
		}()
	}
	wg.Wait()

	// Should not panic and state should be valid
	state := cb.State()
	assert.True(t, state == StateClosed || state == StateOpen || state == StateHalfOpen)
}

func TestRegistry(t *testing.T) {
	registry := NewRegistry(DefaultConfig())

	t.Run("get creates new breaker", func(t *testing.T) {
		cb1 := registry.Get("service1")
		assert.NotNil(t, cb1)
		assert.Equal(t, "service1", cb1.Name())
	})

	t.Run("get returns same breaker", func(t *testing.T) {
		cb1 := registry.Get("service2")
		cb2 := registry.Get("service2")
		assert.Same(t, cb1, cb2)
	})

	t.Run("all returns all breakers", func(t *testing.T) {
		registry.Get("a")
		registry.Get("b")
		registry.Get("c")

		all := registry.All()
		assert.GreaterOrEqual(t, len(all), 3)
	})

	t.Run("remove removes breaker", func(t *testing.T) {
		registry.Get("to-remove")
		registry.Remove("to-remove")

		// Getting again creates a new one
		cb := registry.Get("to-remove")
		assert.Equal(t, StateClosed, cb.State())
	})

	t.Run("all stats", func(t *testing.T) {
		stats := registry.AllStats()
		assert.NotEmpty(t, stats)
	})
}

func TestState_String(t *testing.T) {
	assert.Equal(t, "closed", StateClosed.String())
	assert.Equal(t, "open", StateOpen.String())
	assert.Equal(t, "half-open", StateHalfOpen.String())
	assert.Equal(t, "unknown", State(99).String())
}
