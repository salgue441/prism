# Observability Guide

This guide covers metrics, logging, and monitoring in Prism.

## Overview

Prism provides comprehensive observability through:

- **Prometheus Metrics** - Quantitative measurements
- **Structured Logging** - JSON logs with Loki integration
- **Health Checks** - Service health endpoints
- **Grafana Dashboards** - Visualization

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

### Metrics Endpoint

Metrics are exposed at `/metrics` on the health check port:

```bash
curl http://localhost:9080/metrics
```

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'prism-gateway'
    static_configs:
      - targets: ['gateway:9080']

  - job_name: 'prism-auth'
    static_configs:
      - targets: ['auth:9081']

  - job_name: 'prism-config'
    static_configs:
      - targets: ['config:9052']
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
- Method and path
- Status code
- Duration
- User ID (if authenticated)
- Client IP
- User agent

### Loki Integration

Configure Promtail to ship logs to Loki:

```yaml
# promtail.yml
scrape_configs:
  - job_name: prism
    static_configs:
      - targets:
          - localhost
        labels:
          job: prism
          __path__: /var/log/prism/*.log
    pipeline_stages:
      - json:
          expressions:
            level: level
            request_id: request_id
      - labels:
          level:
          request_id:
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
    "auth_service": {
      "status": "healthy",
      "latency_ms": 5
    },
    "consul": {
      "status": "healthy",
      "latency_ms": 3
    }
  },
  "version": "1.0.0",
  "uptime_seconds": 3600
}
```

### Kubernetes Probes

```yaml
# Kubernetes deployment
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

### Gateway Dashboard

Key panels:

- **Request Rate** - Requests per second
- **Error Rate** - 4xx and 5xx errors
- **Latency** - P50, P95, P99 response times
- **Upstream Health** - Backend service status
- **Circuit Breakers** - State and transitions
- **Rate Limiting** - Limited vs allowed requests

### Auth Service Dashboard

Key panels:

- **Login Rate** - Successful vs failed logins
- **Token Generation** - Access and refresh tokens
- **OAuth** - OAuth flow success rate
- **Session Count** - Active sessions
- **API Key Usage** - Requests per API key

### Importing Dashboards

1. Access Grafana at `http://localhost:3000`
2. Go to Dashboards > Import
3. Import from `deploy/grafana/dashboards/`

### Alert Rules

```yaml
# Prometheus alert rules
groups:
  - name: prism
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
```

## Tracing (Future)

Distributed tracing with OpenTelemetry is planned:

```yaml
tracing:
  enabled: true
  exporter: "jaeger"
  endpoint: "http://jaeger:14268/api/traces"
  sample_rate: 0.1  # 10% of requests
```

## Best Practices

1. **Use Request IDs** - Include `X-Request-ID` for correlation
2. **Monitor Error Rates** - Alert on error rate spikes
3. **Track Latency Percentiles** - P99 is more meaningful than average
4. **Dashboard Granularity** - Have overview and detailed dashboards
5. **Log Context** - Include relevant context in log messages
6. **Retention Policies** - Configure appropriate metric/log retention
7. **Alert Fatigue** - Only alert on actionable conditions

## Debugging

### Enable Debug Logging

```bash
export PRISM_LOG_LEVEL=debug
./bin/gateway
```

### Request Tracing

Add verbose logging for specific requests:

```bash
curl -H "X-Debug: true" http://localhost:8080/api/v1/users
```

### Metrics Debugging

```bash
# Check if metrics are being collected
curl http://localhost:9080/metrics | grep prism_http

# Verify Prometheus is scraping
curl http://localhost:9090/api/v1/targets
```
