# Deployment Guide

This guide covers deploying Prism to various environments.

## Prerequisites

- Docker and Docker Compose
- PostgreSQL 14+
- Consul (for Config service)
- RSA key pair for JWT signing

## Docker Deployment

### Building Images

```bash
# Build all service images
make docker-build

# Or build individually
docker build -t prism-gateway -f deploy/docker/gateway.Dockerfile .
docker build -t prism-auth -f deploy/docker/auth.Dockerfile .
docker build -t prism-config -f deploy/docker/config.Dockerfile .
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  gateway:
    image: prism-gateway:latest
    ports:
      - "8080:8080"
      - "9080:9080"  # Health/metrics
    environment:
      - PRISM_AUTH_GRPC_ADDRESS=auth:50051
      - PRISM_CONFIG_GRPC_ADDRESS=config:50052
      - PRISM_LOG_LEVEL=info
    depends_on:
      - auth
      - config
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9080/health"]
      interval: 10s
      timeout: 5s
      retries: 3

  auth:
    image: prism-auth:latest
    ports:
      - "50051:50051"
      - "8081:8081"
      - "9081:9081"
    environment:
      - PRISM_DB_HOST=postgres
      - PRISM_DB_PASSWORD=${DB_PASSWORD}
      - PRISM_JWT_PRIVATE_KEY_PATH=/keys/private.pem
      - PRISM_JWT_PUBLIC_KEY_PATH=/keys/public.pem
    volumes:
      - ./keys:/keys:ro
    depends_on:
      - postgres
    healthcheck:
      test: ["CMD", "grpc_health_probe", "-addr=:50051"]
      interval: 10s
      timeout: 5s
      retries: 3

  config:
    image: prism-config:latest
    ports:
      - "50052:50052"
      - "9052:9052"
    environment:
      - PRISM_CONSUL_ADDRESS=consul:8500
    depends_on:
      - consul
    healthcheck:
      test: ["CMD", "grpc_health_probe", "-addr=:50052"]
      interval: 10s
      timeout: 5s
      retries: 3

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=prism
      - POSTGRES_USER=prism
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U prism"]
      interval: 10s
      timeout: 5s
      retries: 5

  consul:
    image: consul:1.15
    ports:
      - "8500:8500"
    command: agent -dev -client=0.0.0.0
    healthcheck:
      test: ["CMD", "consul", "members"]
      interval: 10s
      timeout: 5s
      retries: 3

  prometheus:
    image: prom/prometheus:v2.48.0
    ports:
      - "9090:9090"
    volumes:
      - ./deploy/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus

  grafana:
    image: grafana/grafana:10.2.0
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - ./deploy/grafana/provisioning:/etc/grafana/provisioning
      - grafana_data:/var/lib/grafana

  loki:
    image: grafana/loki:2.9.0
    ports:
      - "3100:3100"
    command: -config.file=/etc/loki/local-config.yaml

volumes:
  postgres_data:
  prometheus_data:
  grafana_data:
```

### Running

```bash
# Generate JWT keys
make generate-keys

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f gateway

# Stop all services
docker-compose down
```

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
  db-password: <base64-encoded>
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
          volumeMounts:
            - name: config
              mountPath: /etc/prism
      volumes:
        - name: config
          configMap:
            name: gateway-config
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

### Auth Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth
  namespace: prism
spec:
  replicas: 2
  selector:
    matchLabels:
      app: auth
  template:
    metadata:
      labels:
        app: auth
    spec:
      containers:
        - name: auth
          image: prism-auth:latest
          ports:
            - containerPort: 50051
              name: grpc
            - containerPort: 8081
              name: http
            - containerPort: 9081
              name: metrics
          env:
            - name: PRISM_DB_HOST
              value: "postgres"
            - name: PRISM_DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: prism-secrets
                  key: db-password
          volumeMounts:
            - name: jwt-keys
              mountPath: /keys
              readOnly: true
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "256Mi"
      volumes:
        - name: jwt-keys
          secret:
            secretName: prism-secrets
            items:
              - key: jwt-private-key
                path: private.pem
              - key: jwt-public-key
                path: public.pem
---
apiVersion: v1
kind: Service
metadata:
  name: auth
  namespace: prism
spec:
  selector:
    app: auth
  ports:
    - port: 50051
      targetPort: 50051
      name: grpc
    - port: 8081
      targetPort: 8081
      name: http
```

### Ingress

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
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

## Database Migrations

### Running Migrations

```bash
# Using make
make migrate-up

# Using migrate CLI
migrate -path migrations -database "postgres://user:pass@host:5432/prism?sslmode=disable" up

# In Kubernetes
kubectl exec -it deploy/auth -n prism -- /app/migrate -path /migrations up
```

### Rollback

```bash
# Rollback one migration
make migrate-down

# Rollback to specific version
migrate -path migrations -database "..." goto 3
```

## TLS Configuration

### Generate Certificates

```bash
# Development (self-signed)
openssl req -x509 -newkey rsa:4096 \
  -keyout key.pem -out cert.pem \
  -days 365 -nodes \
  -subj "/CN=localhost"

# Production - use cert-manager or similar
```

### Enable TLS

```yaml
# Gateway config
tls:
  enabled: true
  cert_file: "/certs/tls.crt"
  key_file: "/certs/tls.key"
  min_version: "1.2"
```

### mTLS Between Services

```yaml
# Enable client certificate validation
tls:
  enabled: true
  client_auth: true
  client_ca_file: "/certs/ca.crt"
```

## Production Checklist

### Security

- [ ] TLS enabled on all endpoints
- [ ] JWT keys rotated and secured
- [ ] Database credentials in secrets
- [ ] Network policies configured
- [ ] Rate limiting enabled
- [ ] OAuth secrets secured

### Reliability

- [ ] Multiple replicas for each service
- [ ] Health checks configured
- [ ] Resource limits set
- [ ] PodDisruptionBudget configured
- [ ] Circuit breakers enabled
- [ ] Proper timeouts configured

### Observability

- [ ] Prometheus scraping enabled
- [ ] Grafana dashboards imported
- [ ] Log aggregation configured
- [ ] Alerting rules set up
- [ ] Request tracing enabled

### Operations

- [ ] Backup strategy for PostgreSQL
- [ ] Disaster recovery plan
- [ ] Runbook documentation
- [ ] On-call rotation set up
- [ ] Incident response process

## Troubleshooting

### Service Not Starting

```bash
# Check logs
kubectl logs -f deploy/gateway -n prism

# Check events
kubectl describe pod gateway-xxx -n prism
```

### Database Connection Issues

```bash
# Test connectivity
kubectl exec -it deploy/auth -n prism -- nc -zv postgres 5432

# Check credentials
kubectl get secret prism-secrets -n prism -o yaml
```

### gRPC Connection Issues

```bash
# Test gRPC health
grpcurl -plaintext auth:50051 grpc.health.v1.Health/Check

# Check service discovery
kubectl get endpoints -n prism
```

### High Latency

1. Check circuit breaker states
2. Review upstream health
3. Analyze Prometheus metrics
4. Check resource utilization
5. Review rate limiting configuration
