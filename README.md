# Prism

A production-ready, microservices-based **Reverse Proxy API Gateway** built with Go. Prism provides authentication, rate limiting, dynamic routing, and comprehensive observability out of the box.

## Features

- **Reverse Proxy** - High-performance HTTP/HTTPS reverse proxy with load balancing
- **Authentication** - JWT (RS256) and OAuth 2.0 (Google, GitHub) support
- **API Keys** - Scoped API key management for service-to-service communication
- **Rate Limiting** - Token bucket algorithm with per-IP and per-user limits
- **Dynamic Routing** - Configuration-driven routing with hot-reload support
- **Service Discovery** - Consul integration for upstream service discovery
- **Observability** - Structured logging with Grafana + Loki stack
- **Production Ready** - Health checks, graceful shutdown, Docker support

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         Prism Gateway                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────┐    ┌─────────────┐    ┌──────────────────────────┐ │
│  │ Gateway │───▶│ Auth Service │───▶│ PostgreSQL (Users/Keys) │ │
│  │ :8080   │    │ :50051 gRPC  │    └──────────────────────────┘ │
│  └────┬────┘    └─────────────┘                                  │
│       │                                                          │
│       │         ┌──────────────┐    ┌──────────────────────────┐ │
│       └────────▶│Config Service│───▶│ Consul (Service Discovery)│ │
│                 │ :50052 gRPC  │    └──────────────────────────┘ │
│                 └──────────────┘                                  │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    Observability Stack                       │ │
│  │  Promtail ──▶ Loki ──▶ Grafana                              │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Go 1.23+
- Docker & Docker Compose
- OpenSSL (for key generation)

### Local Development

```bash
# Clone the repository
git clone https://github.com/carlossalguero/prism.git
cd prism

# Generate JWT signing keys
./scripts/generate-keys.sh

# Start infrastructure (PostgreSQL, Consul, Loki, Grafana)
make docker-up

# Run services locally
make run-auth   # Terminal 1
make run-gateway # Terminal 2
```

### Docker Compose (Full Stack)

```bash
# Start everything
cd deploy/docker-compose
docker compose up -d

# View logs
docker compose logs -f

# Access services
# Gateway:  http://localhost:8080
# Grafana:  http://localhost:3000 (admin/admin)
# Consul:   http://localhost:8500
```

## Project Structure

```
prism/
├── cmd/                    # Service entrypoints
│   ├── gateway/           # API Gateway service
│   ├── auth/              # Authentication service
│   └── config/            # Configuration service
├── internal/              # Private application code
│   ├── gateway/           # Gateway implementation
│   │   ├── proxy/         # Reverse proxy logic
│   │   ├── middleware/    # HTTP middleware
│   │   └── router/        # Request routing
│   ├── auth/              # Auth implementation
│   │   ├── jwt/           # JWT handling
│   │   ├── oauth/         # OAuth providers
│   │   ├── repository/    # Database operations
│   │   ├── service/       # Business logic
│   │   └── server/        # gRPC server
│   └── shared/            # Shared utilities
│       ├── logger/        # Structured logging
│       ├── errors/        # Error types
│       └── health/        # Health checks
├── api/proto/             # Protocol Buffer definitions
├── configs/               # Configuration files
├── deploy/                # Deployment configurations
│   ├── docker/            # Dockerfiles
│   ├── docker-compose/    # Docker Compose files
│   └── observability/     # Grafana, Loki, Promtail
├── migrations/            # Database migrations
└── scripts/               # Utility scripts
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GATEWAY_PORT` | Gateway HTTP port | `8080` |
| `AUTH_GRPC_PORT` | Auth service gRPC port | `50051` |
| `DATABASE_HOST` | PostgreSQL host | `localhost` |
| `DATABASE_PASSWORD` | PostgreSQL password | `prism_secret` |
| `JWT_PRIVATE_KEY_PATH` | Path to RSA private key | `./keys/private.pem` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | - |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID | - |

See `.env.example` for all available options.

### Route Configuration

Routes can be configured in `configs/gateway.yaml`:

```yaml
routes:
  - id: api-v1
    name: API v1
    paths:
      - /api/v1/
    targets:
      - http://backend:3000
    auth_required: true
    rate_limit_key: api-default
```

## API Reference

### Authentication

```bash
# Register
curl -X POST http://localhost:8081/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "secure123", "name": "User"}'

# Login
curl -X POST http://localhost:8081/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "secure123"}'

# OAuth (redirect user to)
http://localhost:8081/auth/google/login
http://localhost:8081/auth/github/login
```

### Using the Gateway

```bash
# With JWT token
curl http://localhost:8080/api/v1/resource \
  -H "Authorization: Bearer <access_token>"

# With API key
curl http://localhost:8080/api/v1/resource \
  -H "X-API-Key: prism_abc123..."
```

## Development

### Make Targets

```bash
make build          # Build all services
make test           # Run tests
make lint           # Run linter
make proto          # Generate protobuf code
make docker-build   # Build Docker images
make docker-up      # Start Docker Compose
make docker-down    # Stop Docker Compose
make generate-keys  # Generate JWT keys
```

### Running Tests

```bash
# All tests
make test

# With coverage
make test-coverage

# Integration tests
make test-integration
```

### Code Quality

```bash
# Install tools
make install-tools

# Format code
make fmt

# Run linter
make lint

# Security scan
make security-scan
```

## Observability

### Grafana Dashboards

Access Grafana at `http://localhost:3000` (default: admin/admin)

Pre-configured dashboards:
- **Prism Gateway** - Request rates, latencies, errors
- **Service Logs** - Aggregated logs from all services

### Log Queries (Loki)

```logql
# All gateway errors
{service="gateway"} |= "error"

# Slow requests (>1s)
{service="gateway"} | json | duration > 1s

# Requests by user
{service="gateway"} | json | user_id="<user-id>"
```

## Security

- JWT tokens use RS256 (asymmetric) signing
- Passwords are hashed with bcrypt
- API keys are stored as SHA256 hashes
- Rate limiting prevents abuse
- CORS and security headers configurable
- OAuth state parameter for CSRF protection

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Kong](https://github.com/Kong/kong) - Inspiration for gateway features
- [Traefik](https://github.com/traefik/traefik) - Dynamic configuration patterns
- [Grafana Loki](https://github.com/grafana/loki) - Log aggregation
