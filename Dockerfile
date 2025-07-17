# ================================
# Dockerfile - Multi-stage optimized build
# ================================
FROM golang:1.24-alpine AS builder

# Install git and ca-certificates (needed for go mod download)
RUN apk add --no-cache git ca-certificates tzdata

# Create appuser for security
RUN adduser -D -g '' appuser

# Set working directory
WORKDIR /build

# Copy go mod files first (for better caching)
COPY go.mod go.sum ./

# Download dependencies (cached if go.mod/go.sum haven't changed)
RUN go mod download
RUN go mod verify

# Copy source code
COPY . .

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags='-w -s -extldflags "-static"' \
  -a -installsuffix cgo \
  -o prism ./cmd/prism

# ================================
# Final stage - Minimal runtime image
# ================================
FROM scratch

# Environment Configuration
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /build/prism /prism
COPY --from=builder /build/configs /configs

# Use non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/prism", "-version"] || exit 1

# Expose port
EXPOSE 8080

# Set environment variables
ENV CONFIG_FILE=/configs/config.json
ENV LOG_LEVEL=info
ENV LOG_FORMAT=json

# Run the binary
ENTRYPOINT ["/prism"]