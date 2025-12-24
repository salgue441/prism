# Observability Guide

This guide covers metrics, logging, tracing, and monitoring in Prism.

## Overview

Prism provides comprehensive observability through:

- **Prometheus Metrics** - Quantitative measurements
- **Jaeger Tracing** - Distributed request tracing
- **Structured Logging** - JSON logs with Loki integration
- **Health Checks** - Service health endpoints
- **Grafana Dashboards** - Unified visualization

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     Prism Services                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ Gateway  │  │   Auth   │  │  Config  │  │ DBManager│     │
│  │  :9080   │  │  :9081   │  │  :9052   │  │  :9053   │     │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘     │
│       │ metrics     │ metrics     │ metrics     │ metrics   │
│       │ traces      │ traces      │ traces      │ traces    │
│       │ logs        │ logs        │ logs        │ logs      │
└───────┼─────────────┼─────────────┼─────────────┼───────────┘
        │             │             │             │
        ▼             ▼             ▼             ▼
┌──────────────────────────────────────────────────────────────┐
│                   Observability Stack                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │Prometheus│  │  Jaeger  │  │   Loki   │  │ Grafana  │     │
│  │  :9090   │  │  :16686  │  │  :3100   │  │  :3000   │     │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘     │
└──────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Start observability stack
make docker-obs-up

# Access dashboards
# Grafana:    http://localhost:3000 (admin/admin)
# Prometheus: http://localhost:9090
# Jaeger:     http://localhost:16686
```

## Prometheus Metrics

### Available Metrics

#### HTTP Metrics (Gateway)

| Metric | Type | Description |
|--------|------|-------------|
| `prism_http_requests_total` | Counter | Total HTTP requests |
| `prism_http_request_duration_seconds` | Histogram | Request latency |
| `prism_http_request_size_bytes` | Histogram | Request body size |
| `prism_http_response_size_bytes` | Histogram | Response body size |
| `prism_http_requests_in_flight` | Gauge | Current active requests |

Labels: `method`, `path`, `status_code`

#### gRPC Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `prism_grpc_requests_total` | Counter | Total gRPC requests |
| `prism_grpc_request_duration_seconds` | Histogram | Request latency |
| `prism_grpc_requests_in_flight` | Gauge | Current active requests |

Labels: `method`, `service`, `code`

#### Upstream Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `prism_upstream_requests_total` | Counter | Total upstream requests |
| `prism_upstream_request_duration_seconds` | Histogram | Upstream latency |
| `prism_upstream_health_status` | Gauge | Health status (1=healthy) |

Labels: `upstream`, `target`, `status_code`

#### Circuit Breaker Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `prism_circuit_breaker_state` | Gauge | Current state (0=closed, 1=open, 2=half-open) |
| `prism_circuit_breaker_requests_total` | Counter | Requests through breaker |
| `prism_circuit_breaker_failures_total` | Counter | Failed requests |

Labels: `name`, `state`

#### Rate Limiter Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `prism_rate_limiter_requests_total` | Counter | Total rate limit checks |
| `prism_rate_limiter_limited_total` | Counter | Requests that were limited |
| `prism_rate_limiter_tokens_remaining` | Gauge | Available tokens |

Labels: `key`, `route`

#### Database Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `prism_db_connections_open` | Gauge | Open connections |
| `prism_db_connections_in_use` | Gauge | Active connections |
| `prism_db_connections_idle` | Gauge | Idle connections |

#### Redis Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `prism_redis_operations_total` | Counter | Total Redis operations |
| `prism_redis_operation_duration_seconds` | Histogram | Operation latency |
| `prism_redis_cache_hits_total` | Counter | Cache hits |
| `prism_redis_cache_misses_total` | Counter | Cache misses |

#### Infrastructure Exporters

The observability stack includes exporters for infrastructure components:

| Exporter | Port | Target |
|----------|------|--------|
| postgres-exporter | 9187 | PostgreSQL databases |
| redis-exporter | 9121 | Redis |
| nats-exporter | 7777 | NATS |

### Metrics Endpoints

Metrics are exposed at `/metrics` on the health check port:

```bash
# Gateway
curl http://localhost:9080/metrics

# Auth service
curl http://localhost:9081/metrics

# Infrastructure exporters
curl http://localhost:9187/metrics  # PostgreSQL
curl http://localhost:9121/metrics  # Redis
curl http://localhost:7777/metrics  # NATS
```

### Prometheus Configuration

```yaml
# deploy/observability/prometheus/prometheus.yml
scrape_configs:
  # Prism services
  - job_name: 'prism-gateway'
    static_configs:
      - targets: ['gateway:9080']

  - job_name: 'prism-auth'
    static_configs:
      - targets: ['auth:9081']

  # Infrastructure
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  - job_name: 'nats'
    static_configs:
      - targets: ['nats-exporter:7777']
```

### Example PromQL Queries

```promql
# Request rate
rate(prism_http_requests_total[5m])

# Error rate
sum(rate(prism_http_requests_total{status_code=~"5.."}[5m])) /
sum(rate(prism_http_requests_total[5m]))

# P99 latency
histogram_quantile(0.99, rate(prism_http_request_duration_seconds_bucket[5m]))

# Requests per upstream
sum by (upstream) (rate(prism_upstream_requests_total[5m]))

# Circuit breaker states
prism_circuit_breaker_state

# Rate limited requests
rate(prism_rate_limiter_limited_total[5m])

# Redis cache hit ratio
sum(rate(prism_redis_cache_hits_total[5m])) /
(sum(rate(prism_redis_cache_hits_total[5m])) + sum(rate(prism_redis_cache_misses_total[5m])))

# Database connection usage
prism_db_connections_in_use / prism_db_connections_open
```

## Distributed Tracing (Jaeger)

Prism uses OpenTelemetry for distributed tracing with Jaeger as the backend.

### Configuration

```yaml
# In service configuration
tracing:
  enabled: true
  service_name: "prism-gateway"
  endpoint: "http://jaeger:4318"  # OTLP HTTP endpoint
  sample_rate: 1.0                # 100% in development
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Jaeger OTLP endpoint | `http://localhost:4318` |
| `OTEL_SERVICE_NAME` | Service name for traces | Service-specific |
| `OTEL_TRACES_SAMPLER` | Sampling strategy | `parentbased_traceidratio` |
| `OTEL_TRACES_SAMPLER_ARG` | Sample rate (0.0-1.0) | `1.0` |

### Accessing Jaeger UI

1. Open http://localhost:16686
2. Select a service from the dropdown
3. Click "Find Traces"

### Trace Context Propagation

Traces are automatically propagated through:
- HTTP headers (`traceparent`, `tracestate`)
- gRPC metadata

### Span Attributes

Each span includes:

| Attribute | Description |
|-----------|-------------|
| `http.method` | HTTP method |
| `http.url` | Request URL |
| `http.status_code` | Response status |
| `db.name` | Database name |
| `db.operation` | Database operation type |
| `rpc.service` | gRPC service name |
| `rpc.method` | gRPC method name |

### Creating Custom Spans

```go
import "go.opentelemetry.io/otel"

func SomeFunction(ctx context.Context) {
    tracer := otel.Tracer("my-component")
    ctx, span := tracer.Start(ctx, "operation-name")
    defer span.End()

    // Add attributes
    span.SetAttributes(
        attribute.String("key", "value"),
    )

    // Record errors
    if err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, err.Error())
    }
}
```

## Structured Logging

### Log Format

All services output JSON-formatted logs:

```json
{
  "time": "2024-01-01T12:00:00.000Z",
  "level": "INFO",
  "msg": "Request completed",
  "request_id": "abc-123",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "method": "GET",
  "path": "/api/v1/users",
  "status": 200,
  "duration_ms": 45,
  "user_id": "user-456"
}
```

### Log Levels

| Level | Description |
|-------|-------------|
| `DEBUG` | Detailed debugging information |
| `INFO` | General operational messages |
| `WARN` | Warning conditions |
| `ERROR` | Error conditions |

### Configuration

```yaml
logging:
  level: "info"           # debug, info, warn, error
  format: "json"          # json or text
  output: "stdout"        # stdout, stderr, or file path
  add_source: true        # Include source file/line
```

### Request Logging

Each request is logged with:

- Request ID (correlation)
- Trace ID (distributed tracing correlation)
- Span ID
- Method and path
- Status code
- Duration
- User ID (if authenticated)
- Client IP
- User agent

### Loki Integration

Logs are collected by Promtail and sent to Loki:

```yaml
# deploy/observability/promtail/promtail.yml
scrape_configs:
  - job_name: prism
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
        refresh_interval: 5s
    relabel_configs:
      - source_labels: ['__meta_docker_container_name']
        target_label: 'container'
    pipeline_stages:
      - json:
          expressions:
            level: level
            request_id: request_id
            trace_id: trace_id
      - labels:
          level:
          request_id:
          trace_id:
```

### LogQL Queries

```logql
# All errors
{job="prism"} |= "ERROR"

# Requests by user
{job="prism"} | json | user_id="user-123"

# Slow requests (>1s)
{job="prism"} | json | duration_ms > 1000

# Auth failures
{job="prism"} | json | msg="authentication failed"

# Trace specific request
{job="prism"} | json | trace_id="4bf92f3577b34da6a3ce929d0e0e4736"

# Error rate by service
sum by (container) (rate({job="prism"} |= "ERROR" [5m]))
```

## Health Checks

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `/health` | Overall service health |
| `/health/live` | Liveness probe (is service running) |
| `/health/ready` | Readiness probe (is service ready) |

### Health Response

```json
{
  "status": "healthy",
  "checks": {
    "database": {
      "status": "healthy",
      "latency_ms": 2
    },
    "redis": {
      "status": "healthy",
      "latency_ms": 1
    },
    "auth_service": {
      "status": "healthy",
      "latency_ms": 5
    },
    "nats": {
      "status": "healthy",
      "latency_ms": 1
    }
  },
  "version": "1.0.0",
  "uptime_seconds": 3600
}
```

### Kubernetes Probes

```yaml
spec:
  containers:
    - name: gateway
      livenessProbe:
        httpGet:
          path: /health/live
          port: 9080
        initialDelaySeconds: 5
        periodSeconds: 10
      readinessProbe:
        httpGet:
          path: /health/ready
          port: 9080
        initialDelaySeconds: 5
        periodSeconds: 5
```

## Grafana Dashboards

### Pre-configured Dashboards

| Dashboard | Description |
|-----------|-------------|
| Infrastructure | PostgreSQL, Redis, NATS metrics |
| Services | Gateway, Auth, Config service metrics |
| Database | Connection pools, query performance |

### Dashboard Access

1. Open Grafana at http://localhost:3000
2. Default credentials: admin/admin (or from `.env`)
3. Dashboards are auto-provisioned from `deploy/observability/grafana/dashboards/`

### Data Sources

Pre-configured data sources:
- **Prometheus** - Metrics
- **Jaeger** - Traces
- **Loki** - Logs

### Key Panels

#### Gateway Dashboard

- Request Rate - Requests per second
- Error Rate - 4xx and 5xx errors
- Latency - P50, P95, P99 response times
- Upstream Health - Backend service status
- Circuit Breakers - State and transitions
- Rate Limiting - Limited vs allowed requests

#### Auth Service Dashboard

- Login Rate - Successful vs failed logins
- Token Generation - Access and refresh tokens
- OAuth - OAuth flow success rate
- Session Count - Active sessions
- API Key Usage - Requests per API key

#### Infrastructure Dashboard

- PostgreSQL connections, queries, locks
- Redis memory, operations, hit rates
- NATS message rates, subscriptions

### Importing Custom Dashboards

1. Go to Dashboards > Import
2. Upload JSON or paste dashboard ID
3. Select data sources

## Alerting

### Prometheus Alert Rules

```yaml
# deploy/observability/prometheus/alert-rules.yml
groups:
  - name: prism-alerts
    rules:
      - alert: HighErrorRate
        expr: |
          sum(rate(prism_http_requests_total{status_code=~"5.."}[5m])) /
          sum(rate(prism_http_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"

      - alert: CircuitBreakerOpen
        expr: prism_circuit_breaker_state == 1
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Circuit breaker {{ $labels.name }} is open"

      - alert: HighLatency
        expr: |
          histogram_quantile(0.99, rate(prism_http_request_duration_seconds_bucket[5m])) > 2
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "P99 latency above 2 seconds"

      - alert: DatabaseConnectionsExhausted
        expr: prism_db_connections_in_use / prism_db_connections_open > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database connection pool nearly exhausted"

      - alert: RedisHighMemory
        expr: redis_memory_used_bytes / redis_memory_max_bytes > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Redis memory usage above 90%"

      - alert: ServiceDown
        expr: up{job=~"prism-.*"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service {{ $labels.job }} is down"
```

### Alertmanager Integration

Configure Alertmanager for notifications:

```yaml
# alertmanager.yml
route:
  receiver: 'slack'
  group_wait: 30s

receivers:
  - name: 'slack'
    slack_configs:
      - channel: '#alerts'
        api_url: 'https://hooks.slack.com/services/...'
```

## Best Practices

1. **Use Request IDs** - Include `X-Request-ID` for correlation across services
2. **Correlate Traces and Logs** - Include trace_id in log messages
3. **Monitor Error Rates** - Alert on error rate spikes, not individual errors
4. **Track Latency Percentiles** - P99 is more meaningful than average
5. **Dashboard Granularity** - Have overview and detailed dashboards
6. **Log Context** - Include relevant context in log messages
7. **Retention Policies** - Configure appropriate metric/log retention
8. **Alert Fatigue** - Only alert on actionable conditions
9. **Sample Appropriately** - Use 100% sampling in dev, lower in production

## Debugging

### Enable Debug Logging

```bash
export PRISM_LOG_LEVEL=debug
./bin/gateway
```

### Request Tracing

```bash
# Find trace in Jaeger by request ID
# 1. Check logs for trace_id
docker logs gateway 2>&1 | grep "request_id=abc-123"

# 2. Search in Jaeger UI using trace_id
```

### Metrics Debugging

```bash
# Check if metrics are being collected
curl http://localhost:9080/metrics | grep prism_http

# Verify Prometheus is scraping
curl http://localhost:9090/api/v1/targets

# Query specific metric
curl 'http://localhost:9090/api/v1/query?query=prism_http_requests_total'
```

### Trace Debugging

```bash
# Check OTLP endpoint connectivity
curl http://localhost:4318/v1/traces

# View Jaeger internal metrics
curl http://localhost:14269/metrics
```
