# Prism

![banner]()

**Prism** is a high-performance reverse API gateway written in **Go**, acting as a secure and intelligent entry point for external clients to access internal microservices.

## 🚀 Features

- 🔒 **Multi-Factor Authentication**: Supports API Keys, JWT tokens, OAuth 2.0 flows
- ⚡ **High Performance**: Designed for high-throughput, low-latency traffic
- 📊 **Real-Time Metrics & Analytics**: API usage patterns, performance tracking, and security event logging
- 🧠 **Intelligent Rate Limiting**: Redis-backed dynamic rate limiter
- 🔀 **Protocol Translation**: Converts between HTTP/REST ↔ gRPC / GraphQL seamlessly
- 🧩 **Request/Response Transformation**: Middleware-based transformation engine
- 🔁 **Load Balancing**: Smart routing and distribution across backend services
- 🧼 **Clean Architecture**: Built using Go best practices: Dependency Injection, Hexagonal Architecture, and modular design
- 🔍 **Logging & Monitoring**: Structured logs and pluggable observability

## 🏗️ Architecture

```plaintext
                   ┌────────────────────────────┐
                   │        External Client     │
                   └────────────┬───────────────┘
                                │
                     ┌──────────▼───────────┐
                     │      PRISM GATEWAY   │
                     │ - Auth & Security    │
                     │ - Rate Limiting      │
                     │ - Protocol Adapter   │
                     │ - Load Balancer      │
                     │ - Analytics & Logs   │
                     └──────────┬───────────┘
                                │
            ┌──────────┬────────┴─────────┬────────────┐
            ▼          ▼                  ▼            ▼
      gRPC Service   REST Service   GraphQL Service   etc...

```

## ⚙️ Tech Stack

- **Language**: Go (Golang)
- **Auth**: OAuth2, JWT, API Keys
- **Rate Limiting**: Redis
- **Protocols**: HTTP, gRPC, GraphQL
- **Architecture**: Clean Architecture, DI, Microservices
- **Monitoring**: Prometheus, Grafana, OpenTelemetry

## 📦 Installation

```bash
git clone https://github.com/salgue441/prism.git
cd prism

go mod tidy
go run cmd/main.go
```

## 🧪 Testing

```bash
go test ./...
```

## 📄 License

[MIT](./LICENSE)
