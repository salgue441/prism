// Package circuitbreaker implements the circuit breaker pattern for resilient
// communication with upstream services.
package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"time"
)

// State represents the circuit breaker state.
type State int

const (
	// StateClosed allows requests to pass through normally.
	StateClosed State = iota
	// StateOpen blocks all requests immediately.
	StateOpen
	// StateHalfOpen allows a limited number of test requests.
	StateHalfOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// ErrCircuitOpen is returned when the circuit breaker is open.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// ErrTooManyRequests is returned when too many requests are made in half-open state.
var ErrTooManyRequests = errors.New("too many requests in half-open state")

// Config holds circuit breaker configuration.
type Config struct {
	// FailureThreshold is the number of failures before opening the circuit.
	FailureThreshold int
	// SuccessThreshold is the number of successes needed to close the circuit.
	SuccessThreshold int
	// Timeout is the duration the circuit stays open before transitioning to half-open.
	Timeout time.Duration
	// MaxHalfOpenRequests is the max concurrent requests allowed in half-open state.
	MaxHalfOpenRequests int
	// OnStateChange is called when the circuit state changes.
	OnStateChange func(name string, from, to State)
}

// DefaultConfig returns a circuit breaker config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		FailureThreshold:    5,
		SuccessThreshold:    2,
		Timeout:             30 * time.Second,
		MaxHalfOpenRequests: 1,
	}
}

// CircuitBreaker implements the circuit breaker pattern.
type CircuitBreaker struct {
	name   string
	config Config

	mu                sync.RWMutex
	state             State
	failures          int
	successes         int
	lastFailure       time.Time
	halfOpenRequests  int
	consecutiveErrors int
}

// New creates a new circuit breaker with the given name and config.
func New(name string, config Config) *CircuitBreaker {
	if config.FailureThreshold <= 0 {
		config.FailureThreshold = 5
	}
	if config.SuccessThreshold <= 0 {
		config.SuccessThreshold = 2
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxHalfOpenRequests <= 0 {
		config.MaxHalfOpenRequests = 1
	}

	return &CircuitBreaker{
		name:   name,
		config: config,
		state:  StateClosed,
	}
}

// Name returns the circuit breaker name.
func (cb *CircuitBreaker) Name() string {
	return cb.name
}

// State returns the current circuit breaker state.
func (cb *CircuitBreaker) State() State {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.currentState()
}

// currentState returns the current state, checking for timeout transitions.
// Must be called with at least a read lock held.
func (cb *CircuitBreaker) currentState() State {
	if cb.state == StateOpen {
		if time.Since(cb.lastFailure) >= cb.config.Timeout {
			return StateHalfOpen
		}
	}
	return cb.state
}

// Execute runs the given function if the circuit allows it.
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(context.Context) error) error {
	if err := cb.beforeRequest(); err != nil {
		return err
	}

	// Execute the function
	err := fn(ctx)

	// Record the result
	cb.afterRequest(err == nil)

	return err
}

// Allow checks if a request should be allowed through.
func (cb *CircuitBreaker) Allow() error {
	return cb.beforeRequest()
}

// RecordSuccess records a successful request.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.afterRequest(true)
}

// RecordFailure records a failed request.
func (cb *CircuitBreaker) RecordFailure() {
	cb.afterRequest(false)
}

func (cb *CircuitBreaker) beforeRequest() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	state := cb.currentState()

	switch state {
	case StateClosed:
		return nil

	case StateOpen:
		return ErrCircuitOpen

	case StateHalfOpen:
		// Transition state if we were in open and timeout passed
		if cb.state == StateOpen {
			cb.state = StateHalfOpen
			cb.successes = 0
			cb.halfOpenRequests = 0
			if cb.config.OnStateChange != nil {
				go cb.config.OnStateChange(cb.name, StateOpen, StateHalfOpen)
			}
		}
		if cb.halfOpenRequests >= cb.config.MaxHalfOpenRequests {
			return ErrTooManyRequests
		}
		cb.halfOpenRequests++
		return nil
	}

	return nil
}

func (cb *CircuitBreaker) afterRequest(success bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	state := cb.currentState()

	if success {
		cb.onSuccess(state)
	} else {
		cb.onFailure(state)
	}
}

func (cb *CircuitBreaker) onSuccess(state State) {
	switch state {
	case StateClosed:
		cb.failures = 0
		cb.consecutiveErrors = 0

	case StateHalfOpen:
		cb.halfOpenRequests--
		cb.successes++
		cb.consecutiveErrors = 0
		if cb.successes >= cb.config.SuccessThreshold {
			cb.setState(StateClosed)
		}
	}
}

func (cb *CircuitBreaker) onFailure(state State) {
	switch state {
	case StateClosed:
		cb.consecutiveErrors++
		cb.failures++
		cb.lastFailure = time.Now()
		if cb.failures >= cb.config.FailureThreshold {
			cb.setState(StateOpen)
		}

	case StateHalfOpen:
		cb.halfOpenRequests--
		cb.lastFailure = time.Now()
		cb.setState(StateOpen)
	}
}

func (cb *CircuitBreaker) setState(newState State) {
	if cb.state == newState {
		return
	}

	oldState := cb.state
	cb.state = newState

	// Reset counters on state change
	switch newState {
	case StateClosed:
		cb.failures = 0
		cb.successes = 0
		cb.consecutiveErrors = 0
	case StateOpen:
		cb.successes = 0
	case StateHalfOpen:
		cb.successes = 0
		cb.halfOpenRequests = 0
	}

	// Call state change callback
	if cb.config.OnStateChange != nil {
		go cb.config.OnStateChange(cb.name, oldState, newState)
	}
}

// Stats returns circuit breaker statistics.
type Stats struct {
	Name              string
	State             State
	Failures          int
	Successes         int
	ConsecutiveErrors int
	LastFailure       time.Time
}

// Stats returns the current circuit breaker statistics.
func (cb *CircuitBreaker) Stats() Stats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return Stats{
		Name:              cb.name,
		State:             cb.currentState(),
		Failures:          cb.failures,
		Successes:         cb.successes,
		ConsecutiveErrors: cb.consecutiveErrors,
		LastFailure:       cb.lastFailure,
	}
}

// Reset resets the circuit breaker to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = StateClosed
	cb.failures = 0
	cb.successes = 0
	cb.consecutiveErrors = 0
	cb.halfOpenRequests = 0
}

// Registry manages multiple circuit breakers.
type Registry struct {
	mu       sync.RWMutex
	breakers map[string]*CircuitBreaker
	config   Config
}

// NewRegistry creates a new circuit breaker registry.
func NewRegistry(defaultConfig Config) *Registry {
	return &Registry{
		breakers: make(map[string]*CircuitBreaker),
		config:   defaultConfig,
	}
}

// Get returns the circuit breaker for the given name, creating one if needed.
func (r *Registry) Get(name string) *CircuitBreaker {
	r.mu.RLock()
	cb, ok := r.breakers[name]
	r.mu.RUnlock()

	if ok {
		return cb
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock
	if cb, ok = r.breakers[name]; ok {
		return cb
	}

	cb = New(name, r.config)
	r.breakers[name] = cb
	return cb
}

// Remove removes a circuit breaker from the registry.
func (r *Registry) Remove(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.breakers, name)
}

// All returns all circuit breakers in the registry.
func (r *Registry) All() []*CircuitBreaker {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*CircuitBreaker, 0, len(r.breakers))
	for _, cb := range r.breakers {
		result = append(result, cb)
	}
	return result
}

// AllStats returns statistics for all circuit breakers.
func (r *Registry) AllStats() []Stats {
	breakers := r.All()
	stats := make([]Stats, len(breakers))
	for i, cb := range breakers {
		stats[i] = cb.Stats()
	}
	return stats
}
