// Package consul provides a client wrapper for Consul KV operations.
package consul

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/consul/api"
)

// Client wraps the Consul API client for configuration management.
type Client struct {
	client    *api.Client
	kv        *api.KV
	keyPrefix string

	mu       sync.RWMutex
	watchers map[string]chan struct{}
}

// Config holds Consul client configuration.
type Config struct {
	Address    string
	Token      string
	Datacenter string
	KeyPrefix  string
}

// NewClient creates a new Consul client wrapper.
func NewClient(cfg Config) (*Client, error) {
	consulCfg := api.DefaultConfig()
	consulCfg.Address = cfg.Address
	if cfg.Token != "" {
		consulCfg.Token = cfg.Token
	}
	if cfg.Datacenter != "" {
		consulCfg.Datacenter = cfg.Datacenter
	}

	client, err := api.NewClient(consulCfg)
	if err != nil {
		return nil, fmt.Errorf("creating consul client: %w", err)
	}

	// Verify connection
	_, err = client.Status().Leader()
	if err != nil {
		return nil, fmt.Errorf("connecting to consul: %w", err)
	}

	keyPrefix := cfg.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "prism/"
	}

	return &Client{
		client:    client,
		kv:        client.KV(),
		keyPrefix: keyPrefix,
		watchers:  make(map[string]chan struct{}),
	}, nil
}

// Get retrieves a value from Consul KV store.
func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	fullKey := c.keyPrefix + key
	pair, _, err := c.kv.Get(fullKey, c.queryOptions(ctx))
	if err != nil {
		return nil, fmt.Errorf("getting key %s: %w", key, err)
	}
	if pair == nil {
		return nil, nil
	}
	return pair.Value, nil
}

// GetJSON retrieves and unmarshals a JSON value from Consul.
func (c *Client) GetJSON(ctx context.Context, key string, v any) error {
	data, err := c.Get(ctx, key)
	if err != nil {
		return err
	}
	if data == nil {
		return fmt.Errorf("key not found: %s", key)
	}
	return json.Unmarshal(data, v)
}

// Put stores a value in Consul KV store.
func (c *Client) Put(ctx context.Context, key string, value []byte) error {
	fullKey := c.keyPrefix + key
	p := &api.KVPair{
		Key:   fullKey,
		Value: value,
	}
	_, err := c.kv.Put(p, c.writeOptions(ctx))
	if err != nil {
		return fmt.Errorf("putting key %s: %w", key, err)
	}
	return nil
}

// PutJSON marshals and stores a value as JSON in Consul.
func (c *Client) PutJSON(ctx context.Context, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshaling value: %w", err)
	}
	return c.Put(ctx, key, data)
}

// Delete removes a key from Consul KV store.
func (c *Client) Delete(ctx context.Context, key string) error {
	fullKey := c.keyPrefix + key
	_, err := c.kv.Delete(fullKey, c.writeOptions(ctx))
	if err != nil {
		return fmt.Errorf("deleting key %s: %w", key, err)
	}
	return nil
}

// List returns all keys with the given prefix.
func (c *Client) List(ctx context.Context, prefix string) ([]string, error) {
	fullPrefix := c.keyPrefix + prefix
	pairs, _, err := c.kv.List(fullPrefix, c.queryOptions(ctx))
	if err != nil {
		return nil, fmt.Errorf("listing prefix %s: %w", prefix, err)
	}

	keys := make([]string, 0, len(pairs))
	prefixLen := len(c.keyPrefix)
	for _, pair := range pairs {
		if len(pair.Key) > prefixLen {
			keys = append(keys, pair.Key[prefixLen:])
		}
	}
	return keys, nil
}

// ListJSON retrieves all values under a prefix and unmarshals them.
func (c *Client) ListJSON(ctx context.Context, prefix string, newItem func() any) ([]any, error) {
	fullPrefix := c.keyPrefix + prefix
	pairs, _, err := c.kv.List(fullPrefix, c.queryOptions(ctx))
	if err != nil {
		return nil, fmt.Errorf("listing prefix %s: %w", prefix, err)
	}

	items := make([]any, 0, len(pairs))
	for _, pair := range pairs {
		item := newItem()
		if err := json.Unmarshal(pair.Value, item); err != nil {
			continue // Skip invalid entries
		}
		items = append(items, item)
	}
	return items, nil
}

// WatchResult contains the result of a watch operation.
type WatchResult struct {
	Key   string
	Value []byte
	Error error
}

// Watch watches for changes to keys with the given prefix.
// Returns a channel that receives updates when values change.
func (c *Client) Watch(ctx context.Context, prefix string) <-chan WatchResult {
	results := make(chan WatchResult, 10)
	fullPrefix := c.keyPrefix + prefix

	go func() {
		defer close(results)

		var lastIndex uint64
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			opts := &api.QueryOptions{
				WaitIndex: lastIndex,
				WaitTime:  30 * time.Second,
			}
			opts = opts.WithContext(ctx)

			pairs, meta, err := c.kv.List(fullPrefix, opts)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				results <- WatchResult{Error: err}
				time.Sleep(time.Second) // Back off on errors
				continue
			}

			if meta.LastIndex > lastIndex {
				lastIndex = meta.LastIndex
				prefixLen := len(c.keyPrefix)
				for _, pair := range pairs {
					key := ""
					if len(pair.Key) > prefixLen {
						key = pair.Key[prefixLen:]
					}
					results <- WatchResult{
						Key:   key,
						Value: pair.Value,
					}
				}
			}
		}
	}()

	return results
}

// RegisterService registers this service with Consul for discovery.
func (c *Client) RegisterService(id, name, address string, port int, tags []string) error {
	reg := &api.AgentServiceRegistration{
		ID:      id,
		Name:    name,
		Address: address,
		Port:    port,
		Tags:    tags,
		Check: &api.AgentServiceCheck{
			HTTP:                           fmt.Sprintf("http://%s:%d/health", address, port+1000),
			Interval:                       "10s",
			Timeout:                        "5s",
			DeregisterCriticalServiceAfter: "1m",
		},
	}
	return c.client.Agent().ServiceRegister(reg)
}

// DeregisterService removes this service from Consul.
func (c *Client) DeregisterService(id string) error {
	return c.client.Agent().ServiceDeregister(id)
}

// DiscoverService returns healthy instances of a service.
func (c *Client) DiscoverService(ctx context.Context, serviceName string) ([]*api.ServiceEntry, error) {
	entries, _, err := c.client.Health().Service(serviceName, "", true, c.queryOptions(ctx))
	if err != nil {
		return nil, fmt.Errorf("discovering service %s: %w", serviceName, err)
	}
	return entries, nil
}

// Health returns the Consul cluster leader address.
func (c *Client) Health() (string, error) {
	return c.client.Status().Leader()
}

func (c *Client) queryOptions(ctx context.Context) *api.QueryOptions {
	return (&api.QueryOptions{}).WithContext(ctx)
}

func (c *Client) writeOptions(ctx context.Context) *api.WriteOptions {
	return (&api.WriteOptions{}).WithContext(ctx)
}
