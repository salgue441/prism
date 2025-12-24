// Package config provides configuration management for the gateway.
package config

import (
	"fmt"
	"net/url"

	"github.com/carlossalguero/prism/services/gateway/internal/router"
	pb "github.com/carlossalguero/prism/services/shared/proto/gen"
)

// ProtoRouteToRouter converts a protobuf Route to a router.Route.
func ProtoRouteToRouter(pbRoute *pb.Route, upstream *router.Upstream) *router.Route {
	if pbRoute == nil {
		return nil
	}

	route := &router.Route{
		ID:          pbRoute.Id,
		Name:        pbRoute.Name,
		Priority:    int(pbRoute.Priority),
		Hosts:       pbRoute.Hosts,
		Paths:       pbRoute.Paths,
		Methods:     pbRoute.Methods,
		Headers:     pbRoute.Headers,
		Upstream:    upstream,
		StripPath:   pbRoute.StripPath,
		PathRewrite: pbRoute.PathRewrite,
		Enabled:     pbRoute.Enabled,
	}

	// Extract middleware configuration
	if pbRoute.Middleware != nil {
		route.AuthRequired = pbRoute.Middleware.AuthRequired
		route.RequiredRoles = pbRoute.Middleware.RequiredRoles
		route.RequiredScopes = pbRoute.Middleware.RequiredScopes
		route.RateLimitKey = pbRoute.Middleware.RateLimitRuleId
	}

	// Extract mirror configuration
	if pbRoute.Mirror != nil && pbRoute.Mirror.Enabled {
		route.MirrorEnabled = true
		route.MirrorUpstreamID = pbRoute.Mirror.UpstreamId
		route.MirrorSamplePct = pbRoute.Mirror.SamplePercentage
		route.MirrorTimeoutMs = int(pbRoute.Mirror.TimeoutMs)
		route.MirrorLogDiff = pbRoute.Mirror.LogResponseDiff
		route.MirrorHeaders = pbRoute.Mirror.HeadersToAdd
	}

	return route
}

// ProtoUpstreamToRouter converts a protobuf Upstream to a router.Upstream.
func ProtoUpstreamToRouter(pbUpstream *pb.Upstream) (*router.Upstream, error) {
	if pbUpstream == nil {
		return nil, nil
	}

	targets := make([]*router.Target, 0, len(pbUpstream.Targets))
	for _, t := range pbUpstream.Targets {
		target, err := ProtoTargetToRouter(t)
		if err != nil {
			return nil, fmt.Errorf("converting target %s: %w", t.Id, err)
		}
		targets = append(targets, target)
	}

	return &router.Upstream{
		ID:      pbUpstream.Id,
		Name:    pbUpstream.Name,
		Targets: targets,
	}, nil
}

// ProtoTargetToRouter converts a protobuf Target to a router.Target.
func ProtoTargetToRouter(pbTarget *pb.Target) (*router.Target, error) {
	if pbTarget == nil {
		return nil, nil
	}

	// Build URL from host and port
	scheme := "http"
	if pbTarget.Port == 443 {
		scheme = "https"
	}

	urlStr := fmt.Sprintf("%s://%s:%d", scheme, pbTarget.Host, pbTarget.Port)
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("parsing target URL %s: %w", urlStr, err)
	}

	weight := int(pbTarget.Weight)
	if weight <= 0 {
		weight = 1
	}

	return &router.Target{
		URL:    u,
		Weight: weight,
	}, nil
}

// LoadBalancerAlgorithmToProxy converts the proto load balancer algorithm to proxy type.
func LoadBalancerAlgorithmToProxy(algo pb.LoadBalancerAlgorithm) string {
	switch algo {
	case pb.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_ROUND_ROBIN:
		return "round_robin"
	case pb.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_LEAST_CONNECTIONS:
		return "least_connections"
	case pb.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_RANDOM:
		return "random"
	case pb.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_WEIGHTED:
		return "weighted"
	case pb.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_IP_HASH:
		return "ip_hash"
	default:
		return "round_robin"
	}
}

// RateLimitRuleToConfig converts a protobuf RateLimitRule to internal config.
type RateLimitConfig struct {
	ID                string
	Name              string
	Strategy          string
	RequestsPerSecond float64
	BurstSize         int
	Scope             string
}

// ProtoRateLimitRuleToConfig converts a protobuf RateLimitRule to RateLimitConfig.
func ProtoRateLimitRuleToConfig(rule *pb.RateLimitRule) *RateLimitConfig {
	if rule == nil {
		return nil
	}

	return &RateLimitConfig{
		ID:                rule.Id,
		Name:              rule.Name,
		Strategy:          rateLimitStrategyToString(rule.Strategy),
		RequestsPerSecond: float64(rule.RequestsPerSecond),
		BurstSize:         int(rule.BurstSize),
		Scope:             rateLimitScopeToString(rule.Scope),
	}
}

func rateLimitStrategyToString(s pb.RateLimitStrategy) string {
	switch s {
	case pb.RateLimitStrategy_RATE_LIMIT_STRATEGY_TOKEN_BUCKET:
		return "token_bucket"
	case pb.RateLimitStrategy_RATE_LIMIT_STRATEGY_SLIDING_WINDOW:
		return "sliding_window"
	case pb.RateLimitStrategy_RATE_LIMIT_STRATEGY_FIXED_WINDOW:
		return "fixed_window"
	default:
		return "token_bucket"
	}
}

func rateLimitScopeToString(s pb.RateLimitScope) string {
	switch s {
	case pb.RateLimitScope_RATE_LIMIT_SCOPE_GLOBAL:
		return "global"
	case pb.RateLimitScope_RATE_LIMIT_SCOPE_IP:
		return "ip"
	case pb.RateLimitScope_RATE_LIMIT_SCOPE_USER:
		return "user"
	case pb.RateLimitScope_RATE_LIMIT_SCOPE_API_KEY:
		return "api_key"
	default:
		return "ip"
	}
}
