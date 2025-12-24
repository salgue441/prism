# Configuration Guide

This guide covers all configuration options for Prism services.

## Configuration Sources

Prism services load configuration from multiple sources in order of precedence:

1. **Environment Variables** (highest priority)
2. **YAML Configuration Files**
3. **Default Values** (lowest priority)

## Gateway Configuration

### Basic Settings

```yaml
# configs/gateway.yaml
server:
  port: 8080
  host: "0.0.0.0"
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s
  shutdown_timeout: 30s
```

### TLS Configuration

```yaml
tls:
  enabled: true
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"
  min_version: "1.2"  # TLS 1.2 minimum
  client_auth: false  # Enable for mTLS
  client_ca_file: "/path/to/ca.pem"  # Required if client_auth is true
```

### Rate Limiting

```yaml
rate_limit:
  enabled: true
  requests_per_second: 100
  burst_size: 200
  cleanup_interval: 1m
```

### Circuit Breaker

```yaml
circuit_breaker:
  failure_threshold: 5      # Failures before opening
  success_threshold: 2      # Successes to close from half-open
  timeout: 30s              # Time before half-open
  max_half_open_requests: 1 # Concurrent requests in half-open
```

### Upstream Configuration

```yaml
upstreams:
  - name: "api-backend"
    targets:
      - address: "http://api1.internal:8080"
        weight: 1
      - address: "http://api2.internal:8080"
        weight: 1
    health_check:
      enabled: true
      path: "/health"
      interval: 10s
      timeout: 5s
```

### Route Configuration

```yaml
routes:
  - path: "/api/v1/*"
    upstream: "api-backend"
    methods: ["GET", "POST", "PUT", "DELETE"]
    strip_prefix: false
    auth_required: true
    rate_limit:
      requests_per_second: 50
      burst_size: 100
```

## Auth Service Configuration

### Basic Settings

```yaml
# configs/auth.yaml
server:
  grpc_port: 50051
  http_port: 8081
  shutdown_timeout: 30s
```

### JWT Configuration

```yaml
jwt:
  private_key_path: "./keys/private.pem"
  public_key_path: "./keys/public.pem"
  access_token_ttl: 15m
  refresh_token_ttl: 168h  # 7 days
  issuer: "prism-auth"
```

### OAuth 2.0 Providers

```yaml
oauth:
  google:
    client_id: "${GOOGLE_CLIENT_ID}"
    client_secret: "${GOOGLE_CLIENT_SECRET}"
    redirect_url: "http://localhost:8081/auth/google/callback"
    scopes:
      - "openid"
      - "email"
      - "profile"
  github:
    client_id: "${GITHUB_CLIENT_ID}"
    client_secret: "${GITHUB_CLIENT_SECRET}"
    redirect_url: "http://localhost:8081/auth/github/callback"
    scopes:
      - "user:email"
      - "read:user"
```

### Database Configuration

```yaml
database:
  host: "localhost"
  port: 5432
  name: "prism"
  user: "prism"
  password: "${DB_PASSWORD}"
  ssl_mode: "disable"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: 5m
```

### Password Policy

```yaml
password:
  min_length: 8
  require_uppercase: true
  require_lowercase: true
  require_number: true
  require_special: false
  bcrypt_cost: 12
```

## Config Service Configuration

### Basic Settings

```yaml
# configs/config.yaml
server:
  grpc_port: 50052
  shutdown_timeout: 30s
```

### Consul Configuration

```yaml
consul:
  address: "localhost:8500"
  scheme: "http"
  token: "${CONSUL_TOKEN}"
  datacenter: "dc1"
  key_prefix: "prism/"
```

## Environment Variables

All configuration values can be overridden with environment variables using the format:
`PRISM_<SECTION>_<KEY>`

| Variable | Description | Default |
|----------|-------------|---------|
| `PRISM_SERVER_PORT` | Gateway HTTP port | 8080 |
| `PRISM_SERVER_HOST` | Bind address | 0.0.0.0 |
| `PRISM_TLS_ENABLED` | Enable TLS | false |
| `PRISM_AUTH_GRPC_ADDRESS` | Auth service address | localhost:50051 |
| `PRISM_CONFIG_GRPC_ADDRESS` | Config service address | localhost:50052 |
| `PRISM_DB_HOST` | PostgreSQL host | localhost |
| `PRISM_DB_PORT` | PostgreSQL port | 5432 |
| `PRISM_DB_NAME` | Database name | prism |
| `PRISM_DB_USER` | Database user | prism |
| `PRISM_DB_PASSWORD` | Database password | - |
| `PRISM_JWT_PRIVATE_KEY_PATH` | JWT private key | ./keys/private.pem |
| `PRISM_JWT_PUBLIC_KEY_PATH` | JWT public key | ./keys/public.pem |
| `PRISM_CONSUL_ADDRESS` | Consul address | localhost:8500 |
| `PRISM_LOG_LEVEL` | Log level | info |
| `PRISM_LOG_FORMAT` | Log format (json/text) | json |

## Configuration Reloading

The Gateway supports hot-reloading of route configuration:

```bash
# Send SIGHUP to reload routes
kill -HUP $(pgrep gateway)
```

Or use the Config Service API to update routes dynamically without restart.

## Validation

Prism validates all configuration on startup. Invalid configuration will prevent the service from starting with a descriptive error message.

```bash
# Validate configuration without starting
./bin/gateway --validate-config
```
