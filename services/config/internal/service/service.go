// Package service provides the business logic for the config service.
package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/carlossalguero/prism/services/config/internal/consul"
	"github.com/carlossalguero/prism/services/shared/errors"
)

// Route represents a gateway routing rule.
type Route struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Hosts       []string          `json:"hosts"`
	Paths       []string          `json:"paths"`
	Methods     []string          `json:"methods"`
	Headers     map[string]string `json:"headers,omitempty"`
	UpstreamID  string            `json:"upstream_id"`
	StripPath   bool              `json:"strip_path"`
	PathRewrite string            `json:"path_rewrite,omitempty"`
	Middleware  RouteMiddleware   `json:"middleware"`
	Priority    int               `json:"priority"`
	Enabled     bool              `json:"enabled"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// RouteMiddleware contains middleware configuration for a route.
type RouteMiddleware struct {
	AuthRequired   bool       `json:"auth_required"`
	RequiredRoles  []string   `json:"required_roles,omitempty"`
	RequiredScopes []string   `json:"required_scopes,omitempty"`
	RateLimitID    string     `json:"rate_limit_id,omitempty"`
	CORSEnabled    bool       `json:"cors_enabled"`
	CORSConfig     CORSConfig `json:"cors_config,omitempty"`
	TimeoutMs      int        `json:"timeout_ms"`
	Retries        int        `json:"retries"`
}

// CORSConfig holds CORS configuration.
type CORSConfig struct {
	AllowedOrigins   []string `json:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers"`
	ExposedHeaders   []string `json:"exposed_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
	MaxAge           int      `json:"max_age"`
}

// Upstream represents a backend service target pool.
type Upstream struct {
	ID             string               `json:"id"`
	Name           string               `json:"name"`
	Targets        []Target             `json:"targets"`
	LoadBalancer   LoadBalancerConfig   `json:"load_balancer"`
	HealthCheck    HealthCheckConfig    `json:"health_check"`
	CircuitBreaker CircuitBreakerConfig `json:"circuit_breaker"`
	CreatedAt      time.Time            `json:"created_at"`
	UpdatedAt      time.Time            `json:"updated_at"`
}

// Target represents a single backend instance.
type Target struct {
	ID       string            `json:"id"`
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	Weight   int               `json:"weight"`
	Healthy  bool              `json:"healthy"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// LoadBalancerConfig holds load balancer settings.
type LoadBalancerConfig struct {
	Algorithm string `json:"algorithm"` // round_robin, least_connections, random, weighted, ip_hash
}

// HealthCheckConfig holds health check settings.
type HealthCheckConfig struct {
	Enabled            bool   `json:"enabled"`
	Path               string `json:"path"`
	IntervalSeconds    int    `json:"interval_seconds"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	HealthyThreshold   int    `json:"healthy_threshold"`
	UnhealthyThreshold int    `json:"unhealthy_threshold"`
}

// CircuitBreakerConfig holds circuit breaker settings.
type CircuitBreakerConfig struct {
	Enabled          bool `json:"enabled"`
	FailureThreshold int  `json:"failure_threshold"`
	SuccessThreshold int  `json:"success_threshold"`
	TimeoutSeconds   int  `json:"timeout_seconds"`
}

// RateLimitRule represents a rate limiting rule.
type RateLimitRule struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Strategy          string    `json:"strategy"` // token_bucket, sliding_window, fixed_window
	RequestsPerSecond int64     `json:"requests_per_second"`
	BurstSize         int64     `json:"burst_size"`
	Scope             string    `json:"scope"` // global, ip, user, api_key
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// UpdateType represents the type of configuration update.
type UpdateType string

const (
	UpdateTypeCreated UpdateType = "created"
	UpdateTypeUpdated UpdateType = "updated"
	UpdateTypeDeleted UpdateType = "deleted"
)

// ConfigUpdate represents a configuration change notification.
type ConfigUpdate struct {
	Type     UpdateType
	Route    *Route
	Upstream *Upstream
	RateRule *RateLimitRule
}

// Service provides configuration management.
type Service struct {
	consul *consul.Client

	mu          sync.RWMutex
	subscribers []chan ConfigUpdate
}

// New creates a new config service.
func New(consulClient *consul.Client) *Service {
	return &Service{
		consul:      consulClient,
		subscribers: make([]chan ConfigUpdate, 0),
	}
}

// --- Route Operations ---

// CreateRoute creates a new route.
func (s *Service) CreateRoute(ctx context.Context, route *Route) (*Route, error) {
	if route.Name == "" {
		return nil, errors.InvalidInput("route name is required")
	}

	route.ID = uuid.New().String()
	route.CreatedAt = time.Now()
	route.UpdatedAt = route.CreatedAt

	if err := s.consul.PutJSON(ctx, "routes/"+route.ID, route); err != nil {
		return nil, fmt.Errorf("storing route: %w", err)
	}

	s.notify(ConfigUpdate{Type: UpdateTypeCreated, Route: route})
	return route, nil
}

// GetRoute retrieves a route by ID.
func (s *Service) GetRoute(ctx context.Context, id string) (*Route, error) {
	var route Route
	if err := s.consul.GetJSON(ctx, "routes/"+id, &route); err != nil {
		return nil, errors.NotFound(fmt.Sprintf("route not found: %s", id))
	}
	return &route, nil
}

// UpdateRoute updates an existing route.
func (s *Service) UpdateRoute(ctx context.Context, route *Route) (*Route, error) {
	existing, err := s.GetRoute(ctx, route.ID)
	if err != nil {
		return nil, err
	}

	route.CreatedAt = existing.CreatedAt
	route.UpdatedAt = time.Now()

	if err := s.consul.PutJSON(ctx, "routes/"+route.ID, route); err != nil {
		return nil, fmt.Errorf("updating route: %w", err)
	}

	s.notify(ConfigUpdate{Type: UpdateTypeUpdated, Route: route})
	return route, nil
}

// DeleteRoute deletes a route.
func (s *Service) DeleteRoute(ctx context.Context, id string) error {
	route, err := s.GetRoute(ctx, id)
	if err != nil {
		return err
	}

	if err := s.consul.Delete(ctx, "routes/"+id); err != nil {
		return fmt.Errorf("deleting route: %w", err)
	}

	s.notify(ConfigUpdate{Type: UpdateTypeDeleted, Route: route})
	return nil
}

// ListRoutes returns all routes.
func (s *Service) ListRoutes(ctx context.Context, enabledOnly bool, page, pageSize int) ([]*Route, int, error) {
	items, err := s.consul.ListJSON(ctx, "routes/", func() any { return &Route{} })
	if err != nil {
		return nil, 0, fmt.Errorf("listing routes: %w", err)
	}

	routes := make([]*Route, 0, len(items))
	for _, item := range items {
		route := item.(*Route)
		if enabledOnly && !route.Enabled {
			continue
		}
		routes = append(routes, route)
	}

	total := len(routes)

	// Apply pagination
	if page > 0 && pageSize > 0 {
		start := (page - 1) * pageSize
		if start >= len(routes) {
			return []*Route{}, total, nil
		}
		end := start + pageSize
		if end > len(routes) {
			end = len(routes)
		}
		routes = routes[start:end]
	}

	return routes, total, nil
}

// --- Upstream Operations ---

// RegisterUpstream creates or updates an upstream.
func (s *Service) RegisterUpstream(ctx context.Context, upstream *Upstream) (*Upstream, error) {
	if upstream.Name == "" {
		return nil, errors.InvalidInput("upstream name is required")
	}
	if len(upstream.Targets) == 0 {
		return nil, errors.InvalidInput("at least one target is required")
	}

	isNew := upstream.ID == ""
	if isNew {
		upstream.ID = uuid.New().String()
		upstream.CreatedAt = time.Now()
	}
	upstream.UpdatedAt = time.Now()

	// Assign IDs to targets if missing
	for i := range upstream.Targets {
		if upstream.Targets[i].ID == "" {
			upstream.Targets[i].ID = uuid.New().String()
		}
	}

	if err := s.consul.PutJSON(ctx, "upstreams/"+upstream.ID, upstream); err != nil {
		return nil, fmt.Errorf("storing upstream: %w", err)
	}

	updateType := UpdateTypeUpdated
	if isNew {
		updateType = UpdateTypeCreated
	}
	s.notify(ConfigUpdate{Type: updateType, Upstream: upstream})
	return upstream, nil
}

// GetUpstream retrieves an upstream by ID.
func (s *Service) GetUpstream(ctx context.Context, id string) (*Upstream, error) {
	var upstream Upstream
	if err := s.consul.GetJSON(ctx, "upstreams/"+id, &upstream); err != nil {
		return nil, errors.NotFound(fmt.Sprintf("upstream not found: %s", id))
	}
	return &upstream, nil
}

// DeregisterUpstream removes an upstream.
func (s *Service) DeregisterUpstream(ctx context.Context, id string) error {
	upstream, err := s.GetUpstream(ctx, id)
	if err != nil {
		return err
	}

	if err := s.consul.Delete(ctx, "upstreams/"+id); err != nil {
		return fmt.Errorf("deleting upstream: %w", err)
	}

	s.notify(ConfigUpdate{Type: UpdateTypeDeleted, Upstream: upstream})
	return nil
}

// ListUpstreams returns all upstreams.
func (s *Service) ListUpstreams(ctx context.Context, page, pageSize int) ([]*Upstream, int, error) {
	items, err := s.consul.ListJSON(ctx, "upstreams/", func() any { return &Upstream{} })
	if err != nil {
		return nil, 0, fmt.Errorf("listing upstreams: %w", err)
	}

	upstreams := make([]*Upstream, 0, len(items))
	for _, item := range items {
		upstreams = append(upstreams, item.(*Upstream))
	}

	total := len(upstreams)

	// Apply pagination
	if page > 0 && pageSize > 0 {
		start := (page - 1) * pageSize
		if start >= len(upstreams) {
			return []*Upstream{}, total, nil
		}
		end := start + pageSize
		if end > len(upstreams) {
			end = len(upstreams)
		}
		upstreams = upstreams[start:end]
	}

	return upstreams, total, nil
}

// --- Rate Limit Rule Operations ---

// CreateRateLimitRule creates a new rate limit rule.
func (s *Service) CreateRateLimitRule(ctx context.Context, rule *RateLimitRule) (*RateLimitRule, error) {
	if rule.Name == "" {
		return nil, errors.InvalidInput("rule name is required")
	}
	if rule.RequestsPerSecond <= 0 {
		return nil, errors.InvalidInput("requests per second must be positive")
	}

	rule.ID = uuid.New().String()
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = rule.CreatedAt

	if err := s.consul.PutJSON(ctx, "ratelimits/"+rule.ID, rule); err != nil {
		return nil, fmt.Errorf("storing rate limit rule: %w", err)
	}

	s.notify(ConfigUpdate{Type: UpdateTypeCreated, RateRule: rule})
	return rule, nil
}

// GetRateLimitRule retrieves a rate limit rule by ID.
func (s *Service) GetRateLimitRule(ctx context.Context, id string) (*RateLimitRule, error) {
	var rule RateLimitRule
	if err := s.consul.GetJSON(ctx, "ratelimits/"+id, &rule); err != nil {
		return nil, errors.NotFound(fmt.Sprintf("rate limit rule not found: %s", id))
	}
	return &rule, nil
}

// UpdateRateLimitRule updates an existing rate limit rule.
func (s *Service) UpdateRateLimitRule(ctx context.Context, rule *RateLimitRule) (*RateLimitRule, error) {
	existing, err := s.GetRateLimitRule(ctx, rule.ID)
	if err != nil {
		return nil, err
	}

	rule.CreatedAt = existing.CreatedAt
	rule.UpdatedAt = time.Now()

	if err := s.consul.PutJSON(ctx, "ratelimits/"+rule.ID, rule); err != nil {
		return nil, fmt.Errorf("updating rate limit rule: %w", err)
	}

	s.notify(ConfigUpdate{Type: UpdateTypeUpdated, RateRule: rule})
	return rule, nil
}

// DeleteRateLimitRule deletes a rate limit rule.
func (s *Service) DeleteRateLimitRule(ctx context.Context, id string) error {
	rule, err := s.GetRateLimitRule(ctx, id)
	if err != nil {
		return err
	}

	if err := s.consul.Delete(ctx, "ratelimits/"+id); err != nil {
		return fmt.Errorf("deleting rate limit rule: %w", err)
	}

	s.notify(ConfigUpdate{Type: UpdateTypeDeleted, RateRule: rule})
	return nil
}

// ListRateLimitRules returns all rate limit rules.
func (s *Service) ListRateLimitRules(ctx context.Context, page, pageSize int) ([]*RateLimitRule, int, error) {
	items, err := s.consul.ListJSON(ctx, "ratelimits/", func() any { return &RateLimitRule{} })
	if err != nil {
		return nil, 0, fmt.Errorf("listing rate limit rules: %w", err)
	}

	rules := make([]*RateLimitRule, 0, len(items))
	for _, item := range items {
		rules = append(rules, item.(*RateLimitRule))
	}

	total := len(rules)

	// Apply pagination
	if page > 0 && pageSize > 0 {
		start := (page - 1) * pageSize
		if start >= len(rules) {
			return []*RateLimitRule{}, total, nil
		}
		end := start + pageSize
		if end > len(rules) {
			end = len(rules)
		}
		rules = rules[start:end]
	}

	return rules, total, nil
}

// --- Subscription ---

// Subscribe returns a channel that receives configuration updates.
func (s *Service) Subscribe() <-chan ConfigUpdate {
	ch := make(chan ConfigUpdate, 100)
	s.mu.Lock()
	s.subscribers = append(s.subscribers, ch)
	s.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscription channel.
func (s *Service) Unsubscribe(ch <-chan ConfigUpdate) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, sub := range s.subscribers {
		if sub == ch {
			close(sub)
			s.subscribers = append(s.subscribers[:i], s.subscribers[i+1:]...)
			return
		}
	}
}

func (s *Service) notify(update ConfigUpdate) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, ch := range s.subscribers {
		select {
		case ch <- update:
		default:
			// Channel full, skip notification
		}
	}
}
