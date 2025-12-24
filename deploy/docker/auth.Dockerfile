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
    -o /build/bin/auth \
    ./cmd/auth

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -S prism && adduser -S prism -G prism

# Create directories for keys
RUN mkdir -p /etc/prism /var/lib/prism/keys && \
    chown -R prism:prism /etc/prism /var/lib/prism

# Copy binary from builder
COPY --from=builder /build/bin/auth /usr/local/bin/auth

# Copy configuration (optional, can be mounted)
COPY --from=builder /build/configs/auth.yaml /etc/prism/auth.yaml

# Switch to non-root user
USER prism

# Expose ports
EXPOSE 50051 8081 51051

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:51051/health || exit 1

# Run the binary
ENTRYPOINT ["auth"]
