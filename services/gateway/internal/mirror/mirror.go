// Package mirror provides traffic mirroring functionality for the gateway.
package mirror

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/carlossalguero/prism/services/shared/events"
	"github.com/carlossalguero/prism/services/shared/logger"
	"github.com/carlossalguero/prism/services/shared/metrics"
)

// Config holds mirror configuration for a route.
type Config struct {
	Enabled       bool
	UpstreamID    string
	SamplePct     float64
	TimeoutMs     int
	LogDiff       bool
	HeadersToAdd  map[string]string
}

// UpstreamResolver returns the target URL for an upstream ID.
type UpstreamResolver func(upstreamID string) *url.URL

// Handler manages traffic mirroring.
type Handler struct {
	transport        http.RoundTripper
	logger           *logger.Logger
	metrics          *metrics.Metrics
	events           *events.Client
	upstreamResolver UpstreamResolver
	maxBodySize      int64
}

// HandlerConfig holds configuration for the Handler.
type HandlerConfig struct {
	Transport        http.RoundTripper
	Logger           *logger.Logger
	Metrics          *metrics.Metrics
	Events           *events.Client
	UpstreamResolver UpstreamResolver
	MaxBodySize      int64 // Max body size to mirror (default 10MB)
}

// NewHandler creates a new mirror handler.
func NewHandler(cfg HandlerConfig) *Handler {
	maxBodySize := cfg.MaxBodySize
	if maxBodySize <= 0 {
		maxBodySize = 10 * 1024 * 1024 // 10MB default
	}

	transport := cfg.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	return &Handler{
		transport:        transport,
		logger:           cfg.Logger,
		metrics:          cfg.Metrics,
		events:           cfg.Events,
		upstreamResolver: cfg.UpstreamResolver,
		maxBodySize:      maxBodySize,
	}
}

// ShouldMirror determines if a request should be mirrored based on sampling.
func (h *Handler) ShouldMirror(cfg *Config) bool {
	if cfg == nil || !cfg.Enabled {
		return false
	}

	if cfg.SamplePct >= 100.0 {
		return true
	}

	if cfg.SamplePct <= 0.0 {
		return false
	}

	return rand.Float64()*100.0 < cfg.SamplePct
}

// PrepareRequest clones the original request for mirroring.
// It returns the cloned request and body bytes for the mirror.
func (h *Handler) PrepareRequest(original *http.Request, bodyBytes []byte, cfg *Config) (*http.Request, error) {
	// Resolve mirror upstream URL
	targetURL := h.upstreamResolver(cfg.UpstreamID)
	if targetURL == nil {
		return nil, nil // No target, skip mirroring
	}

	// Create new request with cloned body
	var body io.Reader
	if len(bodyBytes) > 0 {
		body = bytes.NewReader(bodyBytes)
	}

	mirrorReq, err := http.NewRequest(original.Method, targetURL.String(), body)
	if err != nil {
		return nil, err
	}

	// Copy path and query from original
	mirrorReq.URL.Path = original.URL.Path
	mirrorReq.URL.RawQuery = original.URL.RawQuery

	// Deep copy headers
	mirrorReq.Header = make(http.Header)
	for k, vv := range original.Header {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		mirrorReq.Header[k] = vv2
	}

	// Set Host header to target
	mirrorReq.Host = targetURL.Host

	// Add mirror identification headers
	mirrorReq.Header.Set("X-Mirror-Request", "true")
	if requestID := original.Header.Get("X-Request-ID"); requestID != "" {
		mirrorReq.Header.Set("X-Original-Request-ID", requestID)
	}

	// Add custom headers from config
	for k, v := range cfg.HeadersToAdd {
		mirrorReq.Header.Set(k, v)
	}

	// Set content length if body exists
	if len(bodyBytes) > 0 {
		mirrorReq.ContentLength = int64(len(bodyBytes))
	}

	return mirrorReq, nil
}

// Execute sends the mirror request asynchronously.
// It discards the response body but logs and records metrics.
func (h *Handler) Execute(mirrorReq *http.Request, cfg *Config, primaryStatusCode int, requestID string) {
	if mirrorReq == nil {
		return
	}

	go func() {
		start := time.Now()

		// Set timeout
		timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = 5 * time.Second
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Execute request
		resp, err := h.transport.RoundTrip(mirrorReq.WithContext(ctx))

		duration := time.Since(start)
		var statusCode int
		var success bool

		if err != nil {
			h.logger.Warn("mirror request failed",
				"request_id", requestID,
				"upstream", cfg.UpstreamID,
				"error", err,
				"duration_ms", duration.Milliseconds(),
			)
			if h.metrics != nil {
				h.metrics.RecordMirrorRequest(cfg.UpstreamID, "error", duration)
			}
		} else {
			statusCode = resp.StatusCode
			success = true

			// Discard response body
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			// Record metrics
			statusStr := "2xx"
			if statusCode >= 400 && statusCode < 500 {
				statusStr = "4xx"
			} else if statusCode >= 500 {
				statusStr = "5xx"
			}

			if h.metrics != nil {
				h.metrics.RecordMirrorRequest(cfg.UpstreamID, statusStr, duration)
			}

			// Log response diff if enabled
			if cfg.LogDiff && primaryStatusCode != statusCode {
				h.logger.Info("mirror response status differs",
					"request_id", requestID,
					"upstream", cfg.UpstreamID,
					"primary_status", primaryStatusCode,
					"mirror_status", statusCode,
					"duration_ms", duration.Milliseconds(),
				)
			} else {
				h.logger.Debug("mirror request completed",
					"request_id", requestID,
					"upstream", cfg.UpstreamID,
					"status", statusCode,
					"duration_ms", duration.Milliseconds(),
				)
			}
		}

		// Publish NATS event
		if h.events != nil {
			h.publishEvent(requestID, cfg.UpstreamID, statusCode, duration, success, primaryStatusCode, err)
		}
	}()
}

func (h *Handler) publishEvent(requestID, upstreamID string, statusCode int, duration time.Duration, success bool, primaryStatus int, err error) {
	data := map[string]any{
		"request_id":       requestID,
		"mirror_upstream":  upstreamID,
		"mirror_status":    statusCode,
		"duration_ms":      duration.Milliseconds(),
		"success":          success,
		"primary_status":   primaryStatus,
		"status_match":     primaryStatus == statusCode,
	}

	if err != nil {
		data["error"] = err.Error()
	}

	if pubErr := h.events.PublishGatewayEvent(context.Background(), "mirror.completed", data); pubErr != nil {
		h.logger.Warn("failed to publish mirror event", "error", pubErr)
	}
}
