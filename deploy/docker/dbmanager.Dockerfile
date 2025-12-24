# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the service
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /app/bin/dbmanager \
    ./services/dbmanager/cmd

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    postgresql16-client \
    gzip

# Create non-root user
RUN addgroup -g 1000 prism && \
    adduser -u 1000 -G prism -s /bin/sh -D prism

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/bin/dbmanager /app/dbmanager

# Copy migrations
COPY --from=builder /app/migrations /app/migrations

# Create directories for backups
RUN mkdir -p /var/lib/prism/backups && \
    chown -R prism:prism /var/lib/prism

# Switch to non-root user
USER prism

# Expose ports
EXPOSE 50053 51053

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:51053/health || exit 1

# Run the service
ENTRYPOINT ["/app/dbmanager"]
