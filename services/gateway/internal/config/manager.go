// Package config provides configuration management for the gateway.
package config

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/carlossalguero/prism/services/gateway/internal/router"
	"github.com/carlossalguero/prism/services/shared/events"
	"github.com/carlossalguero/prism/services/shared/logger"
	pb "github.com/carlossalguero/prism/services/shared/proto/gen"
)

// Manager coordinates configuration loading and updates.
type Manager struct {
	client       *Client
	router       *router.Router
	rateLimiter  *RateLimitManager
	events       *events.Client
	logger       *logger.Logger

	mu            sync.RWMutex
	upstreamCache map[string]*router.Upstream // cache for route->upstream mapping

	watchCtx    context.Context
	watchCancel context.CancelFunc
}

// ManagerConfig holds configuration for the Manager.
type ManagerConfig struct {
	Client      ClientConfig
	Router      *router.Router
	RateLimiter *RateLimitManager
	Events      *events.Client
	Logger      *logger.Logger
}

// NewManager creates a new configuration manager.
func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		client:        NewClient(cfg.Client, cfg.Logger),
		router:        cfg.Router,
		rateLimiter:   cfg.RateLimiter,
		events:        cfg.Events,
		logger:        cfg.Logger,
		upstreamCache: make(map[string]*router.Upstream),
	}
}

// Start connects to the Config Service and loads initial configuration.
func (m *Manager) Start(ctx context.Context) error {
	m.logger.Info("starting config manager")

	// Connect to Config Service
	if err := m.client.Connect(ctx); err != nil {
		return fmt.Errorf("connecting to config service: %w", err)
	}

	// Load initial configuration
	if err := m.LoadAll(ctx); err != nil {
		return fmt.Errorf("loading initial config: %w", err)
	}

	return nil
}

// LoadAll loads all configuration from the Config Service.
func (m *Manager) LoadAll(ctx context.Context) error {
	m.publishEvent("prism.gateway.config.reload.started", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})

	start := time.Now()

	// Load upstreams first (routes depend on them)
	upstreams, err := m.client.ListUpstreams(ctx)
	if err != nil {
		return fmt.Errorf("loading upstreams: %w", err)
	}

	// Convert and store upstreams
	routerUpstreams := make([]*router.Upstream, 0, len(upstreams))
	m.mu.Lock()
	m.upstreamCache = make(map[string]*router.Upstream, len(upstreams))
	for _, pbUpstream := range upstreams {
		upstream, err := ProtoUpstreamToRouter(pbUpstream)
		if err != nil {
			m.logger.Warn("failed to convert upstream", "id", pbUpstream.Id, "error", err)
			continue
		}
		m.upstreamCache[upstream.ID] = upstream
		routerUpstreams = append(routerUpstreams, upstream)
	}
	m.mu.Unlock()

	m.router.ReplaceAllUpstreams(routerUpstreams)
	m.logger.Info("loaded upstreams", "count", len(routerUpstreams))

	// Load routes
	routes, err := m.client.ListRoutes(ctx)
	if err != nil {
		return fmt.Errorf("loading routes: %w", err)
	}

	// Convert routes
	routerRoutes := make([]*router.Route, 0, len(routes))
	for _, pbRoute := range routes {
		m.mu.RLock()
		upstream := m.upstreamCache[pbRoute.UpstreamId]
		m.mu.RUnlock()

		route := ProtoRouteToRouter(pbRoute, upstream)
		if route != nil {
			routerRoutes = append(routerRoutes, route)
		}
	}

	m.router.ReplaceAllRoutes(routerRoutes)
	m.logger.Info("loaded routes", "count", len(routerRoutes))

	// Load rate limit rules
	rules, err := m.client.ListRateLimitRules(ctx)
	if err != nil {
		return fmt.Errorf("loading rate limit rules: %w", err)
	}

	// Convert and apply rate limit rules
	rateLimitConfigs := make([]*RateLimitConfig, 0, len(rules))
	for _, pbRule := range rules {
		config := ProtoRateLimitRuleToConfig(pbRule)
		if config != nil {
			rateLimitConfigs = append(rateLimitConfigs, config)
		}
	}

	m.rateLimiter.ReplaceAllRules(rateLimitConfigs)
	m.logger.Info("loaded rate limit rules", "count", len(rateLimitConfigs))

	duration := time.Since(start)
	m.publishEvent("prism.gateway.config.reload.completed", map[string]interface{}{
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
		"duration_ms":     duration.Milliseconds(),
		"routes_count":    len(routerRoutes),
		"upstreams_count": len(routerUpstreams),
		"rules_count":     len(rateLimitConfigs),
	})

	m.logger.Info("config reload completed",
		"duration", duration,
		"routes", len(routerRoutes),
		"upstreams", len(routerUpstreams),
		"rate_limit_rules", len(rateLimitConfigs),
	)

	return nil
}

// StartWatching starts watching for configuration updates.
func (m *Manager) StartWatching(ctx context.Context) {
	m.watchCtx, m.watchCancel = context.WithCancel(ctx)

	go m.watchLoop()
}

func (m *Manager) watchLoop() {
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-m.watchCtx.Done():
			m.logger.Info("config watcher stopped")
			return
		default:
		}

		err := m.client.WatchConfig(m.watchCtx, m.handleUpdate)
		if err != nil {
			if m.watchCtx.Err() != nil {
				return // Context cancelled
			}

			m.logger.Warn("config watch stream error, reconnecting",
				"error", err,
				"backoff", backoff,
			)

			select {
			case <-m.watchCtx.Done():
				return
			case <-time.After(backoff):
			}

			// Exponential backoff
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}

			// Reconnect
			if reconnErr := m.client.Reconnect(m.watchCtx); reconnErr != nil {
				m.logger.Warn("failed to reconnect to config service", "error", reconnErr)
				continue
			}

			// Full sync after reconnect
			if loadErr := m.LoadAll(m.watchCtx); loadErr != nil {
				m.logger.Error("failed to reload config after reconnect", "error", loadErr)
			}

			backoff = time.Second // Reset backoff on successful reconnect
		}
	}
}

func (m *Manager) handleUpdate(update *pb.ConfigUpdate) {
	switch update.Type {
	case pb.ConfigUpdateType_CONFIG_UPDATE_TYPE_CREATED,
		pb.ConfigUpdateType_CONFIG_UPDATE_TYPE_UPDATED:
		m.handleUpsert(update)
	case pb.ConfigUpdateType_CONFIG_UPDATE_TYPE_DELETED:
		m.handleDelete(update)
	}
}

func (m *Manager) handleUpsert(update *pb.ConfigUpdate) {
	switch u := update.Update.(type) {
	case *pb.ConfigUpdate_Route:
		m.mu.RLock()
		upstream := m.upstreamCache[u.Route.UpstreamId]
		m.mu.RUnlock()

		route := ProtoRouteToRouter(u.Route, upstream)
		if route != nil {
			m.router.AddRoute(route)
			m.logger.Info("route updated", "id", route.ID, "name", route.Name)
			m.publishUpdateEvent("route", route.ID, update.Type.String())
		}

	case *pb.ConfigUpdate_Upstream:
		upstream, err := ProtoUpstreamToRouter(u.Upstream)
		if err != nil {
			m.logger.Warn("failed to convert upstream update", "id", u.Upstream.Id, "error", err)
			return
		}

		m.mu.Lock()
		m.upstreamCache[upstream.ID] = upstream
		m.mu.Unlock()

		m.router.AddUpstream(upstream)
		m.logger.Info("upstream updated", "id", upstream.ID, "name", upstream.Name)
		m.publishUpdateEvent("upstream", upstream.ID, update.Type.String())

	case *pb.ConfigUpdate_RateLimitRule:
		config := ProtoRateLimitRuleToConfig(u.RateLimitRule)
		if config != nil {
			m.rateLimiter.AddRule(config)
			m.logger.Info("rate limit rule updated", "id", config.ID, "name", config.Name)
			m.publishUpdateEvent("rate_limit_rule", config.ID, update.Type.String())
		}
	}
}

func (m *Manager) handleDelete(update *pb.ConfigUpdate) {
	switch u := update.Update.(type) {
	case *pb.ConfigUpdate_Route:
		m.router.RemoveRoute(u.Route.Id)
		m.logger.Info("route deleted", "id", u.Route.Id)
		m.publishUpdateEvent("route", u.Route.Id, "deleted")

	case *pb.ConfigUpdate_Upstream:
		m.mu.Lock()
		delete(m.upstreamCache, u.Upstream.Id)
		m.mu.Unlock()

		m.router.RemoveUpstream(u.Upstream.Id)
		m.logger.Info("upstream deleted", "id", u.Upstream.Id)
		m.publishUpdateEvent("upstream", u.Upstream.Id, "deleted")

	case *pb.ConfigUpdate_RateLimitRule:
		m.rateLimiter.RemoveRule(u.RateLimitRule.Id)
		m.logger.Info("rate limit rule deleted", "id", u.RateLimitRule.Id)
		m.publishUpdateEvent("rate_limit_rule", u.RateLimitRule.Id, "deleted")
	}
}

// TriggerReload forces a full configuration reload.
func (m *Manager) TriggerReload(ctx context.Context) error {
	m.logger.Info("manual config reload triggered")
	return m.LoadAll(ctx)
}

// Stop stops the config manager and closes connections.
func (m *Manager) Stop() error {
	if m.watchCancel != nil {
		m.watchCancel()
	}

	if m.rateLimiter != nil {
		m.rateLimiter.Stop()
	}

	if m.client != nil {
		return m.client.Close()
	}

	return nil
}

// IsConnected returns true if connected to the Config Service.
func (m *Manager) IsConnected() bool {
	return m.client.IsConnected()
}

func (m *Manager) publishEvent(eventType string, data map[string]interface{}) {
	if m.events == nil {
		return
	}

	// Convert map[string]interface{} to map[string]any
	anyData := make(map[string]any, len(data))
	for k, v := range data {
		anyData[k] = v
	}

	if err := m.events.PublishGatewayEvent(context.Background(), eventType, anyData); err != nil {
		m.logger.Warn("failed to publish config event",
			"event_type", eventType,
			"error", err,
		)
	}
}

func (m *Manager) publishUpdateEvent(resourceType, resourceID, action string) {
	m.publishEvent("prism.gateway.config.update.applied", map[string]interface{}{
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"resource_type": resourceType,
		"resource_id":   resourceID,
		"action":        action,
	})
}
