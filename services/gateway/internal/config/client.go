// Package config provides configuration management for the gateway.
package config

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/carlossalguero/prism/services/shared/logger"
	pb "github.com/carlossalguero/prism/services/shared/proto/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// ClientConfig holds configuration for the Config Service client.
type ClientConfig struct {
	Address       string
	Timeout       time.Duration
	RetryInterval time.Duration
	MaxRetries    int
}

// Client wraps the gRPC client for the Config Service.
type Client struct {
	cfg    ClientConfig
	conn   *grpc.ClientConn
	client pb.ConfigServiceClient
	logger *logger.Logger
	mu     sync.RWMutex
}

// NewClient creates a new Config Service client.
func NewClient(cfg ClientConfig, log *logger.Logger) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.RetryInterval == 0 {
		cfg.RetryInterval = 2 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 10
	}

	return &Client{
		cfg:    cfg,
		logger: log,
	}
}

// Connect establishes a connection to the Config Service with retry logic.
func (c *Client) Connect(ctx context.Context) error {
	var lastErr error

	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			c.logger.Info("retrying connection to config service",
				"attempt", attempt,
				"max_retries", c.cfg.MaxRetries,
				"retry_interval", c.cfg.RetryInterval,
			)

			select {
			case <-ctx.Done():
				return fmt.Errorf("context cancelled while connecting: %w", ctx.Err())
			case <-time.After(c.cfg.RetryInterval):
			}
		}

		conn, err := grpc.NewClient(
			c.cfg.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			lastErr = fmt.Errorf("failed to create gRPC client: %w", err)
			c.logger.Warn("failed to create gRPC client",
				"error", err,
				"attempt", attempt,
			)
			continue
		}

		// Test the connection by making a simple request
		client := pb.NewConfigServiceClient(conn)
		testCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
		_, err = client.ListRoutes(testCtx, &pb.ListRoutesRequest{PageSize: 1})
		cancel()

		if err != nil {
			conn.Close()
			lastErr = fmt.Errorf("failed to verify connection: %w", err)
			c.logger.Warn("failed to verify config service connection",
				"error", err,
				"attempt", attempt,
			)
			continue
		}

		c.mu.Lock()
		c.conn = conn
		c.client = client
		c.mu.Unlock()

		c.logger.Info("connected to config service", "address", c.cfg.Address)
		return nil
	}

	return fmt.Errorf("failed to connect after %d retries: %w", c.cfg.MaxRetries, lastErr)
}

// Close closes the connection to the Config Service.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// IsConnected returns true if the client is connected.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.client != nil
}

// ListRoutes fetches all enabled routes from the Config Service.
func (c *Client) ListRoutes(ctx context.Context) ([]*pb.Route, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("client not connected")
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	var allRoutes []*pb.Route
	page := int32(1)
	pageSize := int32(100)

	for {
		resp, err := client.ListRoutes(ctx, &pb.ListRoutesRequest{
			Page:        page,
			PageSize:    pageSize,
			EnabledOnly: true,
		})
		if err != nil {
			return nil, fmt.Errorf("listing routes (page %d): %w", page, err)
		}

		allRoutes = append(allRoutes, resp.Routes...)

		if len(resp.Routes) < int(pageSize) {
			break
		}
		page++
	}

	return allRoutes, nil
}

// ListUpstreams fetches all upstreams from the Config Service.
func (c *Client) ListUpstreams(ctx context.Context) ([]*pb.Upstream, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("client not connected")
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	var allUpstreams []*pb.Upstream
	page := int32(1)
	pageSize := int32(100)

	for {
		resp, err := client.ListUpstreams(ctx, &pb.ListUpstreamsRequest{
			Page:     page,
			PageSize: pageSize,
		})
		if err != nil {
			return nil, fmt.Errorf("listing upstreams (page %d): %w", page, err)
		}

		allUpstreams = append(allUpstreams, resp.Upstreams...)

		if len(resp.Upstreams) < int(pageSize) {
			break
		}
		page++
	}

	return allUpstreams, nil
}

// ListRateLimitRules fetches all rate limit rules from the Config Service.
func (c *Client) ListRateLimitRules(ctx context.Context) ([]*pb.RateLimitRule, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("client not connected")
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	var allRules []*pb.RateLimitRule
	page := int32(1)
	pageSize := int32(100)

	for {
		resp, err := client.ListRateLimitRules(ctx, &pb.ListRateLimitRulesRequest{
			Page:     page,
			PageSize: pageSize,
		})
		if err != nil {
			return nil, fmt.Errorf("listing rate limit rules (page %d): %w", page, err)
		}

		allRules = append(allRules, resp.Rules...)

		if len(resp.Rules) < int(pageSize) {
			break
		}
		page++
	}

	return allRules, nil
}

// ConfigUpdateHandler is called when a configuration update is received.
type ConfigUpdateHandler func(update *pb.ConfigUpdate)

// WatchConfig subscribes to configuration updates from the Config Service.
// It returns a cancel function to stop watching and reconnects automatically on errors.
func (c *Client) WatchConfig(ctx context.Context, handler ConfigUpdateHandler) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("client not connected")
	}

	stream, err := client.WatchConfig(ctx, &pb.WatchConfigRequest{
		WatchRoutes:     true,
		WatchUpstreams:  true,
		WatchRateLimits: true,
	})
	if err != nil {
		return fmt.Errorf("starting watch stream: %w", err)
	}

	c.logger.Info("started watching config updates")

	for {
		update, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				c.logger.Info("config watch stream closed by server")
				return nil
			}
			if status.Code(err) == codes.Canceled {
				c.logger.Info("config watch stream cancelled")
				return nil
			}
			return fmt.Errorf("receiving config update: %w", err)
		}

		c.logger.Debug("received config update",
			"type", update.Type.String(),
		)

		handler(update)
	}
}

// Reconnect attempts to reconnect to the Config Service.
func (c *Client) Reconnect(ctx context.Context) error {
	c.mu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.client = nil
	}
	c.mu.Unlock()

	return c.Connect(ctx)
}
