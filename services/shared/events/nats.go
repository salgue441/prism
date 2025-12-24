// Package events provides a NATS client wrapper for event publishing and subscribing.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Common errors.
var (
	ErrNotConnected = errors.New("not connected to NATS")
	ErrTimeout      = errors.New("operation timed out")
)

// Config holds NATS client configuration.
type Config struct {
	URL            string        `mapstructure:"url"`
	Name           string        `mapstructure:"name"`
	MaxReconnects  int           `mapstructure:"max_reconnects"`
	ReconnectWait  time.Duration `mapstructure:"reconnect_wait"`
	Timeout        time.Duration `mapstructure:"timeout"`
	DrainTimeout   time.Duration `mapstructure:"drain_timeout"`
	EnableJetStream bool         `mapstructure:"enable_jetstream"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		URL:            "nats://localhost:4222",
		Name:           "prism-service",
		MaxReconnects:  10,
		ReconnectWait:  2 * time.Second,
		Timeout:        5 * time.Second,
		DrainTimeout:   30 * time.Second,
		EnableJetStream: true,
	}
}

// Client wraps the NATS client with additional functionality.
type Client struct {
	conn      *nats.Conn
	js        jetstream.JetStream
	config    Config
	mu        sync.RWMutex
	handlers  map[string]*nats.Subscription
	jsHandlers map[string]jetstream.ConsumeContext
}

// Event represents a generic event.
type Event struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Source    string         `json:"source"`
	Timestamp time.Time      `json:"timestamp"`
	TraceID   string         `json:"trace_id,omitempty"`
	Data      map[string]any `json:"data"`
}

// NewEvent creates a new event with the given type and source.
func NewEvent(eventType, source string, data map[string]any) Event {
	return Event{
		ID:        generateID(),
		Type:      eventType,
		Source:    source,
		Timestamp: time.Now().UTC(),
		Data:      data,
	}
}

// New creates a new NATS client.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		cfg.URL = "nats://localhost:4222"
	}
	if cfg.MaxReconnects == 0 {
		cfg.MaxReconnects = 10
	}
	if cfg.ReconnectWait == 0 {
		cfg.ReconnectWait = 2 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	opts := []nats.Option{
		nats.Name(cfg.Name),
		nats.MaxReconnects(cfg.MaxReconnects),
		nats.ReconnectWait(cfg.ReconnectWait),
		nats.Timeout(cfg.Timeout),
		nats.DrainTimeout(cfg.DrainTimeout),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			// Log reconnection
		}),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			// Log disconnection
		}),
	}

	conn, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	client := &Client{
		conn:       conn,
		config:     cfg,
		handlers:   make(map[string]*nats.Subscription),
		jsHandlers: make(map[string]jetstream.ConsumeContext),
	}

	// Initialize JetStream if enabled
	if cfg.EnableJetStream {
		js, err := jetstream.New(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to create JetStream context: %w", err)
		}
		client.js = js
	}

	return client, nil
}

// Close closes the NATS connection gracefully.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Stop all JetStream consumers
	for _, cc := range c.jsHandlers {
		cc.Stop()
	}

	// Drain and close connection
	if c.conn != nil {
		return c.conn.Drain()
	}
	return nil
}

// IsConnected returns whether the client is connected.
func (c *Client) IsConnected() bool {
	return c.conn != nil && c.conn.IsConnected()
}

// Conn returns the underlying NATS connection.
func (c *Client) Conn() *nats.Conn {
	return c.conn
}

// JetStream returns the JetStream context.
func (c *Client) JetStream() jetstream.JetStream {
	return c.js
}

// --- Publishing ---

// Publish publishes a message to a subject.
func (c *Client) Publish(ctx context.Context, subject string, data []byte) error {
	if !c.IsConnected() {
		return ErrNotConnected
	}
	return c.conn.Publish(subject, data)
}

// PublishJSON publishes a JSON-encoded message to a subject.
func (c *Client) PublishJSON(ctx context.Context, subject string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}
	return c.Publish(ctx, subject, data)
}

// PublishEvent publishes an event to a subject.
func (c *Client) PublishEvent(ctx context.Context, subject string, event Event) error {
	return c.PublishJSON(ctx, subject, event)
}

// Request sends a request and waits for a response.
func (c *Client) Request(ctx context.Context, subject string, data []byte) (*nats.Msg, error) {
	if !c.IsConnected() {
		return nil, ErrNotConnected
	}

	timeout := c.config.Timeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	return c.conn.Request(subject, data, timeout)
}

// RequestJSON sends a JSON request and decodes the response.
func (c *Client) RequestJSON(ctx context.Context, subject string, req any, resp any) error {
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	msg, err := c.Request(ctx, subject, data)
	if err != nil {
		return err
	}

	if resp != nil {
		if err := json.Unmarshal(msg.Data, resp); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// --- Subscribing ---

// Handler is a function that handles incoming messages.
type Handler func(ctx context.Context, msg *nats.Msg) error

// Subscribe subscribes to a subject with a handler.
func (c *Client) Subscribe(subject string, handler Handler) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	sub, err := c.conn.Subscribe(subject, func(msg *nats.Msg) {
		ctx := context.Background()
		if err := handler(ctx, msg); err != nil {
			// Log error
		}
	})
	if err != nil {
		return err
	}

	c.handlers[subject] = sub
	return nil
}

// QueueSubscribe subscribes to a subject with a queue group.
func (c *Client) QueueSubscribe(subject, queue string, handler Handler) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	sub, err := c.conn.QueueSubscribe(subject, queue, func(msg *nats.Msg) {
		ctx := context.Background()
		if err := handler(ctx, msg); err != nil {
			// Log error
		}
	})
	if err != nil {
		return err
	}

	c.handlers[subject+":"+queue] = sub
	return nil
}

// Unsubscribe unsubscribes from a subject.
func (c *Client) Unsubscribe(subject string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if sub, ok := c.handlers[subject]; ok {
		if err := sub.Unsubscribe(); err != nil {
			return err
		}
		delete(c.handlers, subject)
	}
	return nil
}

// --- JetStream Operations ---

// CreateStream creates a JetStream stream.
func (c *Client) CreateStream(ctx context.Context, cfg jetstream.StreamConfig) (jetstream.Stream, error) {
	if c.js == nil {
		return nil, errors.New("JetStream not enabled")
	}
	return c.js.CreateOrUpdateStream(ctx, cfg)
}

// JetStreamPublish publishes a message to a JetStream stream.
func (c *Client) JetStreamPublish(ctx context.Context, subject string, data []byte) (*jetstream.PubAck, error) {
	if c.js == nil {
		return nil, errors.New("JetStream not enabled")
	}
	return c.js.Publish(ctx, subject, data)
}

// JetStreamPublishJSON publishes a JSON message to a JetStream stream.
func (c *Client) JetStreamPublishJSON(ctx context.Context, subject string, v any) (*jetstream.PubAck, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message: %w", err)
	}
	return c.JetStreamPublish(ctx, subject, data)
}

// JetStreamHandler is a function that handles JetStream messages.
type JetStreamHandler func(ctx context.Context, msg jetstream.Msg) error

// JetStreamSubscribe creates a consumer and subscribes to messages.
func (c *Client) JetStreamSubscribe(ctx context.Context, stream, consumer string, handler JetStreamHandler) error {
	if c.js == nil {
		return errors.New("JetStream not enabled")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	cons, err := c.js.Consumer(ctx, stream, consumer)
	if err != nil {
		return fmt.Errorf("failed to get consumer: %w", err)
	}

	cc, err := cons.Consume(func(msg jetstream.Msg) {
		handlerCtx := context.Background()
		if err := handler(handlerCtx, msg); err != nil {
			// Negative ack on error
			msg.Nak()
			return
		}
		msg.Ack()
	})
	if err != nil {
		return fmt.Errorf("failed to consume: %w", err)
	}

	c.jsHandlers[stream+":"+consumer] = cc
	return nil
}

// --- Prism-specific Event Types ---

// Subject prefixes for Prism events.
const (
	SubjectPrefixAuth    = "prism.auth."
	SubjectPrefixGateway = "prism.gateway."
	SubjectPrefixConfig  = "prism.config."
	SubjectPrefixSystem  = "prism.system."
)

// Event types.
const (
	EventUserCreated   = "user.created"
	EventUserUpdated   = "user.updated"
	EventUserDeleted   = "user.deleted"
	EventUserLogin     = "user.login"
	EventUserLogout    = "user.logout"
	EventTokenRevoked  = "token.revoked"
	EventAPIKeyCreated = "apikey.created"
	EventAPIKeyRevoked = "apikey.revoked"
	EventRouteUpdated  = "route.updated"
	EventHealthCheck   = "health.check"
)

// PublishUserEvent publishes a user-related event.
func (c *Client) PublishUserEvent(ctx context.Context, eventType string, userID string, data map[string]any) error {
	if data == nil {
		data = make(map[string]any)
	}
	data["user_id"] = userID

	event := NewEvent(eventType, "auth", data)
	return c.PublishEvent(ctx, SubjectPrefixAuth+eventType, event)
}

// PublishGatewayEvent publishes a gateway-related event.
func (c *Client) PublishGatewayEvent(ctx context.Context, eventType string, data map[string]any) error {
	event := NewEvent(eventType, "gateway", data)
	return c.PublishEvent(ctx, SubjectPrefixGateway+eventType, event)
}

// PublishSystemEvent publishes a system-related event.
func (c *Client) PublishSystemEvent(ctx context.Context, eventType string, data map[string]any) error {
	event := NewEvent(eventType, "system", data)
	return c.PublishEvent(ctx, SubjectPrefixSystem+eventType, event)
}

// generateID generates a unique ID for events.
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// Global client instance.
var globalClient *Client

// Init initializes the global NATS client.
func Init(cfg Config) (*Client, error) {
	client, err := New(cfg)
	if err != nil {
		return nil, err
	}
	globalClient = client
	return client, nil
}

// Default returns the global NATS client.
func Default() *Client {
	return globalClient
}
