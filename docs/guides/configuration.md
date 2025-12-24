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

### Redis Cache (Gateway)

```yaml
redis:
  address: "localhost:6379"
  password: "${REDIS_PASSWORD}"
  db: 0
  pool_size: 10
  min_idle_conns: 5
  dial_timeout: 5s
  read_timeout: 3s
  write_timeout: 3s
```

### NATS Events (Gateway)

```yaml
nats:
  url: "nats://localhost:4222"
  name: "prism-gateway"
  reconnect_wait: 2s
  max_reconnects: 60
  jetstream:
    enabled: true
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

### Database Configuration (Auth)

```yaml
database:
  host: "localhost"
  port: 5432
  name: "prism_auth"
  user: "prism"
  password: "${POSTGRES_AUTH_PASSWORD}"
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

### Redis Cache (Auth)

```yaml
redis:
  address: "localhost:6379"
  password: "${REDIS_PASSWORD}"
  db: 0
  pool_size: 10
  # Token cache settings
  token_cache_ttl: 5m
  session_ttl: 24h
```

### NATS Events (Auth)

```yaml
nats:
  url: "nats://localhost:4222"
  name: "prism-auth"
  # Event subjects
  user_created_subject: "prism.auth.user.created"
  user_login_subject: "prism.auth.user.login"
  token_revoked_subject: "prism.auth.token.revoked"
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

## DB Manager Service Configuration

### Basic Settings

```yaml
# configs/dbmanager.yaml
server:
  grpc_port: 50053
  shutdown_timeout: 30s
```

### Database Connections

```yaml
databases:
  auth:
    host: "localhost"
    port: 5432
    name: "prism_auth"
    user: "prism"
    password: "${POSTGRES_AUTH_PASSWORD}"
    ssl_mode: "disable"
    migrations_path: "./migrations/auth"

  ops:
    host: "localhost"
    port: 5433
    name: "prism_ops"
    user: "prism"
    password: "${POSTGRES_OPS_PASSWORD}"
    ssl_mode: "disable"
    migrations_path: "./migrations/ops"
```

### Migration Settings

```yaml
migration:
  run_on_startup: true
  lock_timeout: 30s
  statement_timeout: 5m
```

### Backup Configuration

```yaml
backup:
  enabled: true
  storage: "s3"  # local, s3

  # S3/MinIO settings
  s3:
    endpoint: "http://localhost:9000"
    bucket: "prism-backups"
    access_key: "${MINIO_ROOT_USER}"
    secret_key: "${MINIO_ROOT_PASSWORD}"
    region: "us-east-1"
    use_ssl: false

  # Local storage (development)
  local:
    path: "/var/lib/prism/backups"

  # Retention policy
  retention:
    full_backups: 7
    delta_backups: 30
    wal_files: 7d
```

### Scheduler Configuration

```yaml
scheduler:
  enabled: true
  jobs:
    - name: "full-backup-auth"
      schedule: "0 2 * * *"  # Daily at 2 AM
      database: "auth"
      type: "full"

    - name: "full-backup-ops"
      schedule: "0 3 * * *"  # Daily at 3 AM
      database: "ops"
      type: "full"

    - name: "health-check"
      schedule: "*/5 * * * *"  # Every 5 minutes
      type: "health"
```

## Redis Configuration

### Server Configuration

```ini
# deploy/redis/redis.conf
port 6379
bind 0.0.0.0

# Authentication
requirepass ${REDIS_PASSWORD}

# Memory management
maxmemory 256mb
maxmemory-policy allkeys-lru

# Persistence
appendonly yes
appendfsync everysec

# Connection limits
maxclients 10000
timeout 300
```

### Key Namespaces

| Prefix | Purpose | TTL |
|--------|---------|-----|
| `cache:` | General cache | Varies |
| `session:` | User sessions | 24h |
| `token:` | Token validation cache | 5m |
| `ratelimit:` | Rate limiting counters | 1s-1m |
| `lock:` | Distributed locks | 30s |

## NATS Configuration

### Server Configuration

```
# deploy/nats/nats-server.conf
port: 4222
http_port: 8222

# JetStream
jetstream {
  store_dir: /data/jetstream
  max_memory_store: 1G
  max_file_store: 10G
}

# Cluster (production)
cluster {
  name: prism-cluster
  port: 6222
}
```

### Event Subjects

| Subject | Description |
|---------|-------------|
| `prism.auth.user.created` | New user registration |
| `prism.auth.user.login` | User login event |
| `prism.auth.user.logout` | User logout event |
| `prism.auth.token.revoked` | Token revocation |
| `prism.gateway.request.logged` | Request audit log |
| `prism.system.health` | Health check events |
| `prism.dbmanager.backup.completed` | Backup completion |
| `prism.dbmanager.migration.applied` | Migration applied |

## Tracing Configuration

### OpenTelemetry

```yaml
tracing:
  enabled: true
  service_name: "prism-gateway"
  endpoint: "http://jaeger:4318"  # OTLP HTTP
  sample_rate: 1.0  # 0.0 to 1.0

  # Propagation
  propagators:
    - "tracecontext"
    - "baggage"
```

## Environment Variables

All configuration values can be overridden with environment variables using the format:
`PRISM_<SECTION>_<KEY>`

### Core Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PRISM_SERVER_PORT` | Gateway HTTP port | 8080 |
| `PRISM_SERVER_HOST` | Bind address | 0.0.0.0 |
| `PRISM_TLS_ENABLED` | Enable TLS | false |
| `PRISM_AUTH_GRPC_ADDRESS` | Auth service address | localhost:50051 |
| `PRISM_CONFIG_GRPC_ADDRESS` | Config service address | localhost:50052 |
| `PRISM_LOG_LEVEL` | Log level | info |
| `PRISM_LOG_FORMAT` | Log format (json/text) | json |

### Database Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PRISM_DB_HOST` | PostgreSQL host | localhost |
| `PRISM_DB_PORT` | PostgreSQL port | 5432 |
| `PRISM_DB_NAME` | Database name | prism_auth |
| `PRISM_DB_USER` | Database user | prism |
| `POSTGRES_AUTH_PASSWORD` | Auth DB password | - |
| `POSTGRES_OPS_PASSWORD` | Ops DB password | - |

### Redis Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PRISM_REDIS_ADDRESS` | Redis address | localhost:6379 |
| `REDIS_PASSWORD` | Redis password | - |
| `PRISM_REDIS_DB` | Redis database number | 0 |

### NATS Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PRISM_NATS_URL` | NATS URL | nats://localhost:4222 |
| `PRISM_NATS_NAME` | Client name | prism-service |

### JWT Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PRISM_JWT_PRIVATE_KEY_PATH` | JWT private key | ./keys/private.pem |
| `PRISM_JWT_PUBLIC_KEY_PATH` | JWT public key | ./keys/public.pem |

### OAuth Variables

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth secret |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth secret |

### Observability Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP endpoint | http://localhost:4318 |
| `OTEL_SERVICE_NAME` | Service name | varies |
| `OTEL_TRACES_SAMPLER_ARG` | Sample rate | 1.0 |

### Backup Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MINIO_ROOT_USER` | MinIO access key | - |
| `MINIO_ROOT_PASSWORD` | MinIO secret key | - |
| `PRISM_BACKUP_BUCKET` | Backup bucket | prism-backups |

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

## Configuration Files Location

```
configs/
├── gateway.yaml      # Gateway service
├── auth.yaml         # Auth service
├── config.yaml       # Config service
└── dbmanager.yaml    # DB Manager service

deploy/
├── redis/redis.conf           # Redis configuration
├── nats/nats-server.conf      # NATS configuration
└── docker-compose/.env        # Environment variables (not in git)
```

## Example .env File

```bash
# Database
POSTGRES_AUTH_PASSWORD=secure_auth_password
POSTGRES_OPS_PASSWORD=secure_ops_password

# Redis
REDIS_PASSWORD=secure_redis_password

# MinIO/S3
MINIO_ROOT_USER=prism
MINIO_ROOT_PASSWORD=secure_minio_password

# OAuth (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Observability
GRAFANA_ADMIN_PASSWORD=admin123
```
