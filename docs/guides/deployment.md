# Deployment Guide

This guide covers deploying Prism to various environments.

## Prerequisites

- Docker and Docker Compose v2+
- Go 1.23+ (for local development)
- Make
- RSA key pair for JWT signing

## Quick Start (Development)

```bash
# Run automated development setup
make dev-setup

# This will:
# 1. Check prerequisites
# 2. Create .env from .env.example with generated passwords
# 3. Generate JWT RSA keys
# 4. Start infrastructure services
# 5. Run database migrations
# 6. Build services
```

## Docker Compose Architecture

Prism uses a modular Docker Compose architecture with separate files for different concerns:

```
deploy/docker-compose/
├── docker-compose.yml              # Core services (gateway, auth, config, dbmanager)
├── docker-compose.infra.yml        # Infrastructure (PostgreSQL, Redis, NATS, Consul, MinIO)
├── docker-compose.observability.yml # Monitoring (Prometheus, Jaeger, Loki, Grafana)
└── .env.example                    # Environment template
```

### Network Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        prism-frontend                           │
│  (External-facing: Traefik, Gateway)                           │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                        prism-backend                            │
│  (Internal services: Auth, Config, Gateway)                    │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                         prism-data                              │
│  (Data layer: PostgreSQL, Redis, NATS, Consul - isolated)      │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                     prism-observability                         │
│  (Monitoring: Prometheus, Jaeger, Loki, Grafana)               │
└─────────────────────────────────────────────────────────────────┘
```

## Environment Configuration

### Creating Environment File

```bash
# Copy template
cp deploy/docker-compose/.env.example deploy/docker-compose/.env

# Edit with your values
vim deploy/docker-compose/.env
```

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `POSTGRES_AUTH_PASSWORD` | Auth database password |
| `POSTGRES_OPS_PASSWORD` | Operational database password |
| `REDIS_PASSWORD` | Redis authentication password |
| `MINIO_ROOT_PASSWORD` | MinIO admin password |
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin password |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth secret |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth secret |

### Generate JWT Keys

```bash
make generate-keys
# Creates keys/private.pem and keys/public.pem
```

## Docker Compose Commands

### Start Services

```bash
# Infrastructure only (databases, cache, messaging)
make docker-infra-up

# Observability stack (monitoring, logging, tracing)
make docker-obs-up

# Core services (gateway, auth, config, dbmanager)
make docker-up

# Everything at once
make docker-full-up
```

### Stop Services

```bash
make docker-infra-down
make docker-obs-down
make docker-down
make docker-full-down
```

### View Logs

```bash
# Specific service
make docker-logs service=gateway
make docker-logs service=auth

# All services
docker compose -f deploy/docker-compose/docker-compose.yml logs -f
```

### Clean Up

```bash
# Stop and remove volumes
make docker-clean
```

## Infrastructure Components

### Dual PostgreSQL Databases

| Database | Port | Purpose |
|----------|------|---------|
| postgres-auth | 5432 | Users, sessions, API keys, OAuth |
| postgres-ops | 5433 | Audit logs, events, metrics, backups |

```bash
# Connect to auth database
docker exec -it postgres-auth psql -U prism -d prism_auth

# Connect to ops database
docker exec -it postgres-ops psql -U prism -d prism_ops
```

### Redis Cache

- **Port:** 6379
- **Features:** Token caching, rate limiting, sessions, distributed locks
- **Configuration:** `deploy/redis/redis.conf`

```bash
# Connect to Redis
docker exec -it redis redis-cli -a $REDIS_PASSWORD
```

### NATS Message Queue

- **Port:** 4222 (clients), 8222 (monitoring)
- **Features:** JetStream enabled, event streaming
- **Configuration:** `deploy/nats/nats-server.conf`

Topics:
- `prism.auth.user.>` - User events
- `prism.auth.token.>` - Token events
- `prism.gateway.request.>` - Request events
- `prism.system.>` - System events

### Consul Service Discovery

- **Port:** 8500
- **Features:** Service registration, key-value store, health checks

### MinIO (S3-Compatible Storage)

- **Port:** 9000 (API), 9001 (Console)
- **Features:** Backup storage, WAL archiving
- **Buckets:** `prism-backups`

## Database Operations

### Migrations

Migrations are managed by the DB Manager service:

```bash
# Migrations run automatically on startup
# Or trigger manually via gRPC API

# Using psql directly (development)
docker exec -it postgres-auth psql -U prism -d prism_auth \
  -f /migrations/001_initial_schema.sql
```

### Backups

```bash
# Create full backup of all databases
make backup-all

# Backup specific database
make backup-auth
make backup-ops

# List available backups
make backup-list
```

#### Backup Types

| Type | Command | Description |
|------|---------|-------------|
| Full | `./deploy/backup/backup.sh auth full` | Complete pg_basebackup |
| Delta | `./deploy/backup/backup.sh auth delta` | WAL-G delta backup |
| WAL | `./deploy/backup/backup.sh auth wal` | Archive WAL files |

#### Restore

```bash
# Restore with dry-run first
./deploy/backup/restore.sh auth FULL_BACKUP_NAME --dry-run

# Actual restore
./deploy/backup/restore.sh auth FULL_BACKUP_NAME
```

## Traefik Load Balancer

### Development Mode

```bash
# Start with Traefik
docker compose -f deploy/docker-compose/docker-compose.yml \
  -f deploy/traefik/docker-compose.traefik.yml up -d
```

### Configuration

- **Static config:** `deploy/traefik/traefik.yml` (production) or `traefik.dev.yml` (development)
- **Dynamic config:** `deploy/traefik/dynamic/`

### Features

- Rate limiting at edge
- TLS termination (Let's Encrypt in production)
- Health check integration
- Circuit breaker middleware

### Access Points with Traefik

| Path | Service |
|------|---------|
| `/api/*` | Gateway |
| `/auth/*` | Auth HTTP |
| `/health`, `/ready`, `/live` | Gateway health |

## Kubernetes Deployment

### Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: prism
```

### ConfigMaps

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gateway-config
  namespace: prism
data:
  gateway.yaml: |
    server:
      port: 8080
    rate_limit:
      enabled: true
      requests_per_second: 100
```

### Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: prism-secrets
  namespace: prism
type: Opaque
data:
  postgres-auth-password: <base64-encoded>
  postgres-ops-password: <base64-encoded>
  redis-password: <base64-encoded>
  jwt-private-key: <base64-encoded>
  jwt-public-key: <base64-encoded>
```

### Gateway Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gateway
  namespace: prism
spec:
  replicas: 3
  selector:
    matchLabels:
      app: gateway
  template:
    metadata:
      labels:
        app: gateway
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9080"
    spec:
      containers:
        - name: gateway
          image: prism-gateway:latest
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 9080
              name: metrics
          env:
            - name: PRISM_AUTH_GRPC_ADDRESS
              value: "auth:50051"
            - name: PRISM_CONFIG_GRPC_ADDRESS
              value: "config:50052"
            - name: PRISM_REDIS_ADDRESS
              value: "redis:6379"
            - name: PRISM_REDIS_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: prism-secrets
                  key: redis-password
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "256Mi"
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
---
apiVersion: v1
kind: Service
metadata:
  name: gateway
  namespace: prism
spec:
  selector:
    app: gateway
  ports:
    - port: 8080
      targetPort: 8080
      name: http
    - port: 9080
      targetPort: 9080
      name: metrics
```

### Horizontal Pod Autoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: gateway-hpa
  namespace: prism
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: gateway
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

### Ingress with TLS

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: prism-ingress
  namespace: prism
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts:
        - api.example.com
      secretName: prism-tls
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: gateway
                port:
                  number: 8080
```

## TLS Configuration

### Generate Self-Signed Certificates (Development)

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout key.pem -out cert.pem \
  -days 365 -nodes \
  -subj "/CN=localhost"
```

### Enable TLS in Gateway

```yaml
tls:
  enabled: true
  cert_file: "/certs/tls.crt"
  key_file: "/certs/tls.key"
  min_version: "1.2"
```

### mTLS Between Services

```yaml
tls:
  enabled: true
  client_auth: true
  client_ca_file: "/certs/ca.crt"
```

## Production Checklist

### Security

- [ ] TLS enabled on all endpoints
- [ ] JWT keys rotated and secured
- [ ] Database credentials in secrets management
- [ ] Redis password configured
- [ ] Network policies configured
- [ ] Rate limiting enabled at Traefik and Gateway
- [ ] OAuth secrets secured
- [ ] MinIO access policies configured

### Reliability

- [ ] Multiple replicas for each service
- [ ] Health checks configured
- [ ] Resource limits set
- [ ] PodDisruptionBudget configured
- [ ] Circuit breakers enabled
- [ ] Proper timeouts configured
- [ ] NATS JetStream configured for durability

### Observability

- [ ] Prometheus scraping enabled
- [ ] Grafana dashboards imported
- [ ] Loki log aggregation configured
- [ ] Jaeger tracing enabled
- [ ] Alerting rules set up
- [ ] Request tracing with correlation IDs

### Operations

- [ ] Automated backup schedule configured
- [ ] Backup verification process
- [ ] Disaster recovery plan documented
- [ ] Runbook documentation
- [ ] On-call rotation set up
- [ ] Incident response process

## Troubleshooting

### Service Not Starting

```bash
# Check logs
docker compose -f deploy/docker-compose/docker-compose.yml logs gateway

# Check container status
docker ps -a

# Check resource usage
docker stats
```

### Database Connection Issues

```bash
# Test connectivity
docker exec -it gateway nc -zv postgres-auth 5432

# Check PostgreSQL logs
docker logs postgres-auth

# Verify credentials
docker exec -it postgres-auth psql -U prism -d prism_auth -c "SELECT 1"
```

### Redis Connection Issues

```bash
# Test connection
docker exec -it redis redis-cli -a $REDIS_PASSWORD ping

# Check memory usage
docker exec -it redis redis-cli -a $REDIS_PASSWORD info memory
```

### NATS Connection Issues

```bash
# Check NATS monitoring
curl http://localhost:8222/varz

# View JetStream info
curl http://localhost:8222/jsz
```

### gRPC Connection Issues

```bash
# Test gRPC health
grpcurl -plaintext auth:50051 grpc.health.v1.Health/Check

# Check service endpoints
docker compose ps
```

### High Latency

1. Check circuit breaker states in Prometheus
2. Review upstream health checks
3. Analyze request traces in Jaeger
4. Check Redis cache hit rates
5. Review rate limiting configuration
6. Check database connection pool stats
