# Routing Guide

This guide covers route configuration and load balancing in Prism Gateway.

## Route Configuration

Routes define how incoming requests are proxied to upstream services.

### Basic Route

```yaml
routes:
  - path: "/api/v1/users"
    upstream: "users-service"
    methods: ["GET", "POST"]
```

### Route Properties

| Property | Type | Description |
|----------|------|-------------|
| `path` | string | URL path pattern to match |
| `upstream` | string | Name of upstream to route to |
| `methods` | []string | Allowed HTTP methods |
| `strip_prefix` | bool | Remove matched prefix before proxying |
| `auth_required` | bool | Require authentication |
| `required_roles` | []string | Required user roles |
| `required_scopes` | []string | Required API key scopes |
| `rate_limit` | object | Route-specific rate limiting |
| `timeout` | duration | Request timeout |
| `retry` | object | Retry configuration |

## Path Matching

### Exact Match

```yaml
- path: "/api/v1/users"
  # Matches only /api/v1/users
```

### Prefix Match

```yaml
- path: "/api/v1/*"
  # Matches /api/v1/anything
```

### Path Parameters

```yaml
- path: "/api/v1/users/:id"
  # Matches /api/v1/users/123
  # :id available as path parameter
```

### Match Priority

Routes are matched in order of specificity:

1. Exact matches
2. Path parameter matches (most specific first)
3. Prefix matches (longest prefix first)

## Upstreams

Upstreams define backend service pools.

### Basic Upstream

```yaml
upstreams:
  - name: "api-backend"
    targets:
      - address: "http://api1.internal:8080"
      - address: "http://api2.internal:8080"
```

### Weighted Targets

```yaml
upstreams:
  - name: "api-backend"
    targets:
      - address: "http://api1.internal:8080"
        weight: 3  # 75% of traffic
      - address: "http://api2.internal:8080"
        weight: 1  # 25% of traffic
```

## Load Balancing

### Algorithms

| Algorithm | Description |
|-----------|-------------|
| `round-robin` | Distribute evenly across targets |
| `weighted` | Distribute based on target weights |
| `least-conn` | Send to target with fewest connections |
| `random` | Random target selection |

### Configuration

```yaml
upstreams:
  - name: "api-backend"
    load_balancing:
      algorithm: "least-conn"
    targets:
      - address: "http://api1.internal:8080"
      - address: "http://api2.internal:8080"
```

## Health Checks

### Active Health Checks

```yaml
upstreams:
  - name: "api-backend"
    health_check:
      enabled: true
      path: "/health"
      interval: 10s
      timeout: 5s
      healthy_threshold: 2
      unhealthy_threshold: 3
    targets:
      - address: "http://api1.internal:8080"
```

### Health Check Properties

| Property | Description | Default |
|----------|-------------|---------|
| `enabled` | Enable health checks | false |
| `path` | Health check endpoint | /health |
| `interval` | Check frequency | 10s |
| `timeout` | Request timeout | 5s |
| `healthy_threshold` | Successes to mark healthy | 2 |
| `unhealthy_threshold` | Failures to mark unhealthy | 3 |

### Passive Health Checks

Targets are automatically marked unhealthy based on response errors:

```yaml
upstreams:
  - name: "api-backend"
    passive_health_check:
      enabled: true
      failure_threshold: 5
      recovery_timeout: 30s
```

## Path Rewriting

### Strip Prefix

Remove the matched prefix before forwarding:

```yaml
routes:
  - path: "/api/v1/*"
    upstream: "backend"
    strip_prefix: true

# /api/v1/users -> /users
```

### Path Replacement

Replace the matched path:

```yaml
routes:
  - path: "/old-api/*"
    upstream: "backend"
    rewrite: "/new-api/$1"

# /old-api/users -> /new-api/users
```

### Add Prefix

Add a prefix to the path:

```yaml
routes:
  - path: "/users/*"
    upstream: "backend"
    add_prefix: "/api/v2"

# /users/123 -> /api/v2/users/123
```

## Request Modification

### Header Injection

```yaml
routes:
  - path: "/api/*"
    upstream: "backend"
    headers:
      add:
        X-Request-Source: "gateway"
        X-Forwarded-Proto: "https"
      remove:
        - "X-Internal-Header"
```

### Host Header

```yaml
routes:
  - path: "/api/*"
    upstream: "backend"
    host_header: "api.internal.example.com"
```

## Timeouts and Retries

### Timeout Configuration

```yaml
routes:
  - path: "/api/slow/*"
    upstream: "slow-backend"
    timeout: 60s  # Override default timeout
```

### Retry Configuration

```yaml
routes:
  - path: "/api/*"
    upstream: "backend"
    retry:
      attempts: 3
      per_try_timeout: 10s
      retry_on:
        - "connection-error"
        - "reset"
        - "5xx"
      backoff:
        initial: 100ms
        max: 1s
        multiplier: 2
```

## Rate Limiting Per Route

```yaml
routes:
  - path: "/api/v1/search"
    upstream: "search-service"
    rate_limit:
      requests_per_second: 10
      burst_size: 20

  - path: "/api/v1/users"
    upstream: "users-service"
    rate_limit:
      requests_per_second: 100
      burst_size: 200
```

## Circuit Breaker Per Route

```yaml
routes:
  - path: "/api/external/*"
    upstream: "external-api"
    circuit_breaker:
      failure_threshold: 3
      success_threshold: 2
      timeout: 15s
```

## Dynamic Route Configuration

Routes can be updated dynamically via the Config Service:

### Create Route

```bash
grpcurl -plaintext -d '{
  "route": {
    "id": "users-route",
    "path": "/api/v1/users/*",
    "upstream_id": "users-service",
    "methods": ["GET", "POST"],
    "auth_required": true
  }
}' localhost:50052 config.ConfigService/CreateRoute
```

### Update Route

```bash
grpcurl -plaintext -d '{
  "route": {
    "id": "users-route",
    "path": "/api/v1/users/*",
    "upstream_id": "users-service",
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "auth_required": true
  }
}' localhost:50052 config.ConfigService/UpdateRoute
```

### Delete Route

```bash
grpcurl -plaintext -d '{"id": "users-route"}' \
  localhost:50052 config.ConfigService/DeleteRoute
```

### Watch for Changes

The Gateway subscribes to route changes:

```bash
grpcurl -plaintext localhost:50052 config.ConfigService/WatchRoutes
```

## CORS Configuration

```yaml
routes:
  - path: "/api/*"
    upstream: "backend"
    cors:
      enabled: true
      allowed_origins:
        - "https://app.example.com"
        - "https://admin.example.com"
      allowed_methods:
        - "GET"
        - "POST"
        - "PUT"
        - "DELETE"
      allowed_headers:
        - "Authorization"
        - "Content-Type"
      exposed_headers:
        - "X-Request-ID"
      max_age: 3600
      allow_credentials: true
```

## Example: Complete Configuration

```yaml
upstreams:
  - name: "users-service"
    load_balancing:
      algorithm: "round-robin"
    health_check:
      enabled: true
      path: "/health"
      interval: 10s
    targets:
      - address: "http://users-1.internal:8080"
      - address: "http://users-2.internal:8080"

  - name: "orders-service"
    load_balancing:
      algorithm: "least-conn"
    targets:
      - address: "http://orders-1.internal:8080"
      - address: "http://orders-2.internal:8080"

routes:
  # Public health check
  - path: "/health"
    upstream: "users-service"
    auth_required: false

  # User API
  - path: "/api/v1/users/*"
    upstream: "users-service"
    methods: ["GET", "POST", "PUT", "DELETE"]
    auth_required: true
    rate_limit:
      requests_per_second: 100
      burst_size: 200

  # Orders API (admin only)
  - path: "/api/v1/orders/*"
    upstream: "orders-service"
    methods: ["GET", "POST"]
    auth_required: true
    required_roles: ["admin", "operator"]
    timeout: 30s
    retry:
      attempts: 2
      retry_on: ["5xx"]
```
