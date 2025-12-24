# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=${VERSION:-dev}" \
    -o /build/bin/config \
    ./cmd/config

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -S prism && adduser -S prism -G prism

# Create directories
RUN mkdir -p /etc/prism && chown -R prism:prism /etc/prism

# Copy binary from builder
COPY --from=builder /build/bin/config /usr/local/bin/config

# Switch to non-root user
USER prism

# Expose ports
EXPOSE 50052 51052

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:51052/health || exit 1

# Run the binary
ENTRYPOINT ["config"]
