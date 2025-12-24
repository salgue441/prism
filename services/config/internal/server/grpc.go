// Package server provides the gRPC server implementation for the config service.
package server

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/carlossalguero/prism/services/config/internal/service"
	"github.com/carlossalguero/prism/services/shared/errors"
	"github.com/carlossalguero/prism/services/shared/logger"
	pb "github.com/carlossalguero/prism/services/shared/proto/gen"
)

// ConfigServiceServer implements the ConfigService gRPC server.
type ConfigServiceServer struct {
	pb.UnimplementedConfigServiceServer
	service *service.Service
	logger  *logger.Logger
}

// NewConfigServer creates a new config gRPC server.
func NewConfigServer(svc *service.Service) *ConfigServiceServer {
	return &ConfigServiceServer{
		service: svc,
		logger:  logger.Default(),
	}
}

// RegisterConfigServer registers the config service with a gRPC server.
func RegisterConfigServer(s *grpc.Server, srv *ConfigServiceServer) {
	pb.RegisterConfigServiceServer(s, srv)
}

// --- Route Operations ---

// CreateRoute creates a new route.
func (s *ConfigServiceServer) CreateRoute(ctx context.Context, req *pb.CreateRouteRequest) (*pb.Route, error) {
	if req.Route == nil {
		return nil, status.Error(codes.InvalidArgument, "route is required")
	}

	route := protoToRoute(req.Route)
	created, err := s.service.CreateRoute(ctx, route)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return routeToProto(created), nil
}

// GetRoute retrieves a route by ID.
func (s *ConfigServiceServer) GetRoute(ctx context.Context, req *pb.GetRouteRequest) (*pb.Route, error) {
	route, err := s.service.GetRoute(ctx, req.Id)
	if err != nil {
		return nil, toGRPCError(err)
	}
	return routeToProto(route), nil
}

// UpdateRoute updates an existing route.
func (s *ConfigServiceServer) UpdateRoute(ctx context.Context, req *pb.UpdateRouteRequest) (*pb.Route, error) {
	if req.Route == nil {
		return nil, status.Error(codes.InvalidArgument, "route is required")
	}

	route := protoToRoute(req.Route)
	updated, err := s.service.UpdateRoute(ctx, route)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return routeToProto(updated), nil
}

// DeleteRoute deletes a route.
func (s *ConfigServiceServer) DeleteRoute(ctx context.Context, req *pb.DeleteRouteRequest) (*emptypb.Empty, error) {
	if err := s.service.DeleteRoute(ctx, req.Id); err != nil {
		return nil, toGRPCError(err)
	}
	return &emptypb.Empty{}, nil
}

// ListRoutes returns all routes.
func (s *ConfigServiceServer) ListRoutes(ctx context.Context, req *pb.ListRoutesRequest) (*pb.ListRoutesResponse, error) {
	routes, total, err := s.service.ListRoutes(ctx, req.EnabledOnly, int(req.Page), int(req.PageSize))
	if err != nil {
		return nil, toGRPCError(err)
	}

	pbRoutes := make([]*pb.Route, len(routes))
	for i, r := range routes {
		pbRoutes[i] = routeToProto(r)
	}

	return &pb.ListRoutesResponse{
		Routes: pbRoutes,
		Total:  int32(total),
	}, nil
}

// --- Upstream Operations ---

// RegisterUpstream creates or updates an upstream.
func (s *ConfigServiceServer) RegisterUpstream(ctx context.Context, req *pb.RegisterUpstreamRequest) (*pb.Upstream, error) {
	if req.Upstream == nil {
		return nil, status.Error(codes.InvalidArgument, "upstream is required")
	}

	upstream := protoToUpstream(req.Upstream)
	registered, err := s.service.RegisterUpstream(ctx, upstream)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return upstreamToProto(registered), nil
}

// DeregisterUpstream removes an upstream.
func (s *ConfigServiceServer) DeregisterUpstream(ctx context.Context, req *pb.DeregisterUpstreamRequest) (*emptypb.Empty, error) {
	if err := s.service.DeregisterUpstream(ctx, req.Id); err != nil {
		return nil, toGRPCError(err)
	}
	return &emptypb.Empty{}, nil
}

// ListUpstreams returns all upstreams.
func (s *ConfigServiceServer) ListUpstreams(ctx context.Context, req *pb.ListUpstreamsRequest) (*pb.ListUpstreamsResponse, error) {
	upstreams, total, err := s.service.ListUpstreams(ctx, int(req.Page), int(req.PageSize))
	if err != nil {
		return nil, toGRPCError(err)
	}

	pbUpstreams := make([]*pb.Upstream, len(upstreams))
	for i, u := range upstreams {
		pbUpstreams[i] = upstreamToProto(u)
	}

	return &pb.ListUpstreamsResponse{
		Upstreams: pbUpstreams,
		Total:     int32(total),
	}, nil
}

// GetUpstreamHealth returns health status for an upstream.
func (s *ConfigServiceServer) GetUpstreamHealth(ctx context.Context, req *pb.GetUpstreamHealthRequest) (*pb.UpstreamHealth, error) {
	upstream, err := s.service.GetUpstream(ctx, req.Id)
	if err != nil {
		return nil, toGRPCError(err)
	}

	targetHealth := make([]*pb.TargetHealth, len(upstream.Targets))
	for i, t := range upstream.Targets {
		targetHealth[i] = &pb.TargetHealth{
			TargetId: t.ID,
			Healthy:  t.Healthy,
		}
	}

	return &pb.UpstreamHealth{
		UpstreamId: upstream.ID,
		Targets:    targetHealth,
	}, nil
}

// --- Rate Limit Operations ---

// CreateRateLimitRule creates a new rate limit rule.
func (s *ConfigServiceServer) CreateRateLimitRule(ctx context.Context, req *pb.CreateRateLimitRuleRequest) (*pb.RateLimitRule, error) {
	if req.Rule == nil {
		return nil, status.Error(codes.InvalidArgument, "rule is required")
	}

	rule := protoToRateLimitRule(req.Rule)
	created, err := s.service.CreateRateLimitRule(ctx, rule)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return rateLimitRuleToProto(created), nil
}

// UpdateRateLimitRule updates an existing rate limit rule.
func (s *ConfigServiceServer) UpdateRateLimitRule(ctx context.Context, req *pb.UpdateRateLimitRuleRequest) (*pb.RateLimitRule, error) {
	if req.Rule == nil {
		return nil, status.Error(codes.InvalidArgument, "rule is required")
	}

	rule := protoToRateLimitRule(req.Rule)
	updated, err := s.service.UpdateRateLimitRule(ctx, rule)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return rateLimitRuleToProto(updated), nil
}

// DeleteRateLimitRule deletes a rate limit rule.
func (s *ConfigServiceServer) DeleteRateLimitRule(ctx context.Context, req *pb.DeleteRateLimitRuleRequest) (*emptypb.Empty, error) {
	if err := s.service.DeleteRateLimitRule(ctx, req.Id); err != nil {
		return nil, toGRPCError(err)
	}
	return &emptypb.Empty{}, nil
}

// ListRateLimitRules returns all rate limit rules.
func (s *ConfigServiceServer) ListRateLimitRules(ctx context.Context, req *pb.ListRateLimitRulesRequest) (*pb.ListRateLimitRulesResponse, error) {
	rules, total, err := s.service.ListRateLimitRules(ctx, int(req.Page), int(req.PageSize))
	if err != nil {
		return nil, toGRPCError(err)
	}

	pbRules := make([]*pb.RateLimitRule, len(rules))
	for i, r := range rules {
		pbRules[i] = rateLimitRuleToProto(r)
	}

	return &pb.ListRateLimitRulesResponse{
		Rules: pbRules,
		Total: int32(total),
	}, nil
}

// WatchConfig streams configuration updates to clients.
func (s *ConfigServiceServer) WatchConfig(req *pb.WatchConfigRequest, stream pb.ConfigService_WatchConfigServer) error {
	sub := s.service.Subscribe()
	defer s.service.Unsubscribe(sub)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case update, ok := <-sub:
			if !ok {
				return nil
			}

			pbUpdate := &pb.ConfigUpdate{
				Type: configUpdateTypeToProto(update.Type),
			}

			if update.Route != nil && req.WatchRoutes {
				pbUpdate.Update = &pb.ConfigUpdate_Route{Route: routeToProto(update.Route)}
			} else if update.Upstream != nil && req.WatchUpstreams {
				pbUpdate.Update = &pb.ConfigUpdate_Upstream{Upstream: upstreamToProto(update.Upstream)}
			} else if update.RateRule != nil && req.WatchRateLimits {
				pbUpdate.Update = &pb.ConfigUpdate_RateLimitRule{RateLimitRule: rateLimitRuleToProto(update.RateRule)}
			} else {
				continue
			}

			if err := stream.Send(pbUpdate); err != nil {
				return err
			}
		}
	}
}

// --- Conversion Helpers ---

func protoToRoute(p *pb.Route) *service.Route {
	r := &service.Route{
		ID:          p.Id,
		Name:        p.Name,
		Hosts:       p.Hosts,
		Paths:       p.Paths,
		Methods:     p.Methods,
		Headers:     p.Headers,
		UpstreamID:  p.UpstreamId,
		StripPath:   p.StripPath,
		PathRewrite: p.PathRewrite,
		Priority:    int(p.Priority),
		Enabled:     p.Enabled,
		Metadata:    p.Metadata,
	}

	if p.Middleware != nil {
		r.Middleware = service.RouteMiddleware{
			AuthRequired:   p.Middleware.AuthRequired,
			RequiredRoles:  p.Middleware.RequiredRoles,
			RequiredScopes: p.Middleware.RequiredScopes,
			RateLimitID:    p.Middleware.RateLimitRuleId,
			CORSEnabled:    p.Middleware.CorsEnabled,
			TimeoutMs:      int(p.Middleware.TimeoutMs),
			Retries:        int(p.Middleware.Retries),
		}
		if p.Middleware.CorsConfig != nil {
			r.Middleware.CORSConfig = service.CORSConfig{
				AllowedOrigins:   p.Middleware.CorsConfig.AllowedOrigins,
				AllowedMethods:   p.Middleware.CorsConfig.AllowedMethods,
				AllowedHeaders:   p.Middleware.CorsConfig.AllowedHeaders,
				ExposedHeaders:   p.Middleware.CorsConfig.ExposedHeaders,
				AllowCredentials: p.Middleware.CorsConfig.AllowCredentials,
				MaxAge:           int(p.Middleware.CorsConfig.MaxAge),
			}
		}
	}

	return r
}

func routeToProto(r *service.Route) *pb.Route {
	p := &pb.Route{
		Id:          r.ID,
		Name:        r.Name,
		Hosts:       r.Hosts,
		Paths:       r.Paths,
		Methods:     r.Methods,
		Headers:     r.Headers,
		UpstreamId:  r.UpstreamID,
		StripPath:   r.StripPath,
		PathRewrite: r.PathRewrite,
		Priority:    int32(r.Priority),
		Enabled:     r.Enabled,
		Metadata:    r.Metadata,
		CreatedAt:   timestamppb.New(r.CreatedAt),
		UpdatedAt:   timestamppb.New(r.UpdatedAt),
		Middleware: &pb.RouteMiddleware{
			AuthRequired:    r.Middleware.AuthRequired,
			RequiredRoles:   r.Middleware.RequiredRoles,
			RequiredScopes:  r.Middleware.RequiredScopes,
			RateLimitRuleId: r.Middleware.RateLimitID,
			CorsEnabled:     r.Middleware.CORSEnabled,
			TimeoutMs:       int32(r.Middleware.TimeoutMs),
			Retries:         int32(r.Middleware.Retries),
			CorsConfig: &pb.CORSConfig{
				AllowedOrigins:   r.Middleware.CORSConfig.AllowedOrigins,
				AllowedMethods:   r.Middleware.CORSConfig.AllowedMethods,
				AllowedHeaders:   r.Middleware.CORSConfig.AllowedHeaders,
				ExposedHeaders:   r.Middleware.CORSConfig.ExposedHeaders,
				AllowCredentials: r.Middleware.CORSConfig.AllowCredentials,
				MaxAge:           int32(r.Middleware.CORSConfig.MaxAge),
			},
		},
	}
	return p
}

func protoToUpstream(p *pb.Upstream) *service.Upstream {
	u := &service.Upstream{
		ID:   p.Id,
		Name: p.Name,
	}

	u.Targets = make([]service.Target, len(p.Targets))
	for i, t := range p.Targets {
		u.Targets[i] = service.Target{
			ID:       t.Id,
			Host:     t.Host,
			Port:     int(t.Port),
			Weight:   int(t.Weight),
			Healthy:  t.Healthy,
			Metadata: t.Metadata,
		}
	}

	if p.LoadBalancer != nil {
		u.LoadBalancer = service.LoadBalancerConfig{
			Algorithm: lbAlgorithmToString(p.LoadBalancer.Algorithm),
		}
	}

	if p.HealthCheck != nil {
		u.HealthCheck = service.HealthCheckConfig{
			Enabled:            p.HealthCheck.Enabled,
			Path:               p.HealthCheck.Path,
			IntervalSeconds:    int(p.HealthCheck.IntervalSeconds),
			TimeoutSeconds:     int(p.HealthCheck.TimeoutSeconds),
			HealthyThreshold:   int(p.HealthCheck.HealthyThreshold),
			UnhealthyThreshold: int(p.HealthCheck.UnhealthyThreshold),
		}
	}

	if p.CircuitBreaker != nil {
		u.CircuitBreaker = service.CircuitBreakerConfig{
			Enabled:          p.CircuitBreaker.Enabled,
			FailureThreshold: int(p.CircuitBreaker.FailureThreshold),
			SuccessThreshold: int(p.CircuitBreaker.SuccessThreshold),
			TimeoutSeconds:   int(p.CircuitBreaker.TimeoutSeconds),
		}
	}

	return u
}

func upstreamToProto(u *service.Upstream) *pb.Upstream {
	p := &pb.Upstream{
		Id:        u.ID,
		Name:      u.Name,
		CreatedAt: timestamppb.New(u.CreatedAt),
		UpdatedAt: timestamppb.New(u.UpdatedAt),
		LoadBalancer: &pb.LoadBalancerConfig{
			Algorithm: stringToLBAlgorithm(u.LoadBalancer.Algorithm),
		},
		HealthCheck: &pb.HealthCheckConfig{
			Enabled:            u.HealthCheck.Enabled,
			Path:               u.HealthCheck.Path,
			IntervalSeconds:    int32(u.HealthCheck.IntervalSeconds),
			TimeoutSeconds:     int32(u.HealthCheck.TimeoutSeconds),
			HealthyThreshold:   int32(u.HealthCheck.HealthyThreshold),
			UnhealthyThreshold: int32(u.HealthCheck.UnhealthyThreshold),
		},
		CircuitBreaker: &pb.CircuitBreakerConfig{
			Enabled:          u.CircuitBreaker.Enabled,
			FailureThreshold: int32(u.CircuitBreaker.FailureThreshold),
			SuccessThreshold: int32(u.CircuitBreaker.SuccessThreshold),
			TimeoutSeconds:   int32(u.CircuitBreaker.TimeoutSeconds),
		},
	}

	p.Targets = make([]*pb.Target, len(u.Targets))
	for i, t := range u.Targets {
		p.Targets[i] = &pb.Target{
			Id:       t.ID,
			Host:     t.Host,
			Port:     int32(t.Port),
			Weight:   int32(t.Weight),
			Healthy:  t.Healthy,
			Metadata: t.Metadata,
		}
	}

	return p
}

func protoToRateLimitRule(p *pb.RateLimitRule) *service.RateLimitRule {
	return &service.RateLimitRule{
		ID:                p.Id,
		Name:              p.Name,
		Strategy:          rateLimitStrategyToString(p.Strategy),
		RequestsPerSecond: p.RequestsPerSecond,
		BurstSize:         p.BurstSize,
		Scope:             rateLimitScopeToString(p.Scope),
	}
}

func rateLimitRuleToProto(r *service.RateLimitRule) *pb.RateLimitRule {
	return &pb.RateLimitRule{
		Id:                r.ID,
		Name:              r.Name,
		Strategy:          stringToRateLimitStrategy(r.Strategy),
		RequestsPerSecond: r.RequestsPerSecond,
		BurstSize:         r.BurstSize,
		Scope:             stringToRateLimitScope(r.Scope),
		CreatedAt:         timestamppb.New(r.CreatedAt),
		UpdatedAt:         timestamppb.New(r.UpdatedAt),
	}
}

func configUpdateTypeToProto(t service.UpdateType) pb.ConfigUpdateType {
	switch t {
	case service.UpdateTypeCreated:
		return pb.ConfigUpdateType_CONFIG_UPDATE_TYPE_CREATED
	case service.UpdateTypeUpdated:
		return pb.ConfigUpdateType_CONFIG_UPDATE_TYPE_UPDATED
	case service.UpdateTypeDeleted:
		return pb.ConfigUpdateType_CONFIG_UPDATE_TYPE_DELETED
	default:
		return pb.ConfigUpdateType_CONFIG_UPDATE_TYPE_UNSPECIFIED
	}
}

func lbAlgorithmToString(a pb.LoadBalancerAlgorithm) string {
	switch a {
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

func stringToLBAlgorithm(s string) pb.LoadBalancerAlgorithm {
	switch s {
	case "round_robin":
		return pb.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_ROUND_ROBIN
	case "least_connections":
		return pb.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_LEAST_CONNECTIONS
	case "random":
		return pb.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_RANDOM
	case "weighted":
		return pb.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_WEIGHTED
	case "ip_hash":
		return pb.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_IP_HASH
	default:
		return pb.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_ROUND_ROBIN
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

func stringToRateLimitStrategy(s string) pb.RateLimitStrategy {
	switch s {
	case "token_bucket":
		return pb.RateLimitStrategy_RATE_LIMIT_STRATEGY_TOKEN_BUCKET
	case "sliding_window":
		return pb.RateLimitStrategy_RATE_LIMIT_STRATEGY_SLIDING_WINDOW
	case "fixed_window":
		return pb.RateLimitStrategy_RATE_LIMIT_STRATEGY_FIXED_WINDOW
	default:
		return pb.RateLimitStrategy_RATE_LIMIT_STRATEGY_TOKEN_BUCKET
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

func stringToRateLimitScope(s string) pb.RateLimitScope {
	switch s {
	case "global":
		return pb.RateLimitScope_RATE_LIMIT_SCOPE_GLOBAL
	case "ip":
		return pb.RateLimitScope_RATE_LIMIT_SCOPE_IP
	case "user":
		return pb.RateLimitScope_RATE_LIMIT_SCOPE_USER
	case "api_key":
		return pb.RateLimitScope_RATE_LIMIT_SCOPE_API_KEY
	default:
		return pb.RateLimitScope_RATE_LIMIT_SCOPE_IP
	}
}

func toGRPCError(err error) error {
	if err == nil {
		return nil
	}

	var appErr *errors.Error
	if e, ok := err.(*errors.Error); ok {
		appErr = e
		return appErr.ToGRPCError()
	}

	return status.Error(codes.Internal, err.Error())
}
