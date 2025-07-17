package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"prism/pkg/utils"
	"strings"
	"time"
)

// ReverseProxy wraps the standard library reverse proxy
type ReverseProxy struct {
	logger    *slog.Logger
	client    *http.Client
	transport *http.Transport
}

// Config holds proxy configuration
type Config struct {
	// Connection settings
	MaxIdleConns        int           `json:"max_idle_conns" default:"100"`
	MaxIdleConnsPerHost int           `json:"max_idle_conns_per_host" default:"10"`
	IdleConnTimeout     time.Duration `json:"idle_conn_timeout" default:"90s"`

	// Timeout settings
	RequestTimeout time.Duration `json:"request_timeout" default:"30s"`
	DialTimeout    time.Duration `json:"dial_timeout" default:"10s"`
	KeepAlive      time.Duration `json:"keep_alive" default:"30s"`

	// TLS settings
	TLSHandshakeTimeout time.Duration `json:"tls_handshake_timeout" default:"10s"`
	InsecureSkipVerify  bool          `json:"insecure_skip_verify" default:"false"`

	// Behavior settings
	DisableCompression bool `json:"disable_compression" default:"false"`
	DisableKeepAlives  bool `json:"disable_keep_alives" default:"false"`
}

// DefaultConfig returns a default proxy configuration
func DefaultConfig() *Config {
	return &Config{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		RequestTimeout:      30 * time.Second,
		DialTimeout:         10 * time.Second,
		KeepAlive:           30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		InsecureSkipVerify:  false,
		DisableCompression:  false,
		DisableKeepAlives:   false,
	}
}

// New creates a new reverse proxy instance with default configuration
func New(logger *slog.Logger) *ReverseProxy {
	return NewWithConfig(logger, DefaultConfig())
}

// NewWithConfig creates a new reverse proxy instance with custom configuration
func NewWithConfig(logger *slog.Logger, config *Config) *ReverseProxy {
	transport := &http.Transport{
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
		DisableCompression:  config.DisableCompression,
		DisableKeepAlives:   config.DisableKeepAlives,
		DialContext: (&net.Dialer{
			Timeout:   config.DialTimeout,
			KeepAlive: config.KeepAlive,
		}).DialContext,
		TLSHandshakeTimeout: config.TLSHandshakeTimeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.InsecureSkipVerify,
		},
	}

	client := &http.Client{
		Timeout:   config.RequestTimeout,
		Transport: transport,
	}

	return &ReverseProxy{
		logger:    logger,
		client:    client,
		transport: transport,
	}
}

// CreateHandler creates a proxy handler for the given target
func (rp *ReverseProxy) CreateHandler(target *url.URL, stripPath bool,
	routePath string) http.HandlerFunc {
	proxy := &httputil.ReverseProxy{
		Director:      rp.createDirector(target, stripPath, routePath),
		ErrorHandler:  rp.createErrorHandler(target),
		Transport:     rp.client.Transport,
		FlushInterval: 100 * time.Millisecond,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := rp.getOrGenerateRequestID(r)

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		r = r.WithContext(ctx)
		rp.setProxyHeaders(r)

		rp.logger.Debug("Proxying request",
			slog.String("request_id", requestID),
			slog.String("method", r.Method),
			slog.String("original_path", r.URL.Path),
			slog.String("target", target.String()),
			slog.String("remote_addr", utils.GetClientIP(r)),
		)

		proxy.ServeHTTP(w, r)
		duration := time.Since(start)
		rp.logger.Debug("Request proxied",
			slog.String("request_id", requestID),
			slog.String("method", r.Method),
			slog.String("target", target.String()),
			slog.Duration("duration", duration),
		)
	}
}

// createDirector creates a request director function
func (rp *ReverseProxy) createDirector(target *url.URL, stripPath bool,
	routePath string) func(*http.Request) {
	return func(req *http.Request) {
		originalURL := req.URL.String()

		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host

		if stripPath {
			req.URL.Path = rp.stripPathPrefix(req.URL.Path, routePath)
		} else {
			if target.Path != "" && target.Path != "/" {
				req.URL.Path = strings.TrimSuffix(target.Path, "/") + req.URL.Path
			}
		}

		if req.URL.Path == "" || req.URL.Path[0] != '/' {
			req.URL.Path = "/" + req.URL.Path
		}

		rp.setForwardingHeaders(req)
		if originalURL != req.URL.String() {
			rp.logger.Debug("Path transformed",
				slog.String("original", originalURL),
				slog.String("transformed", req.URL.String()),
				slog.Bool("strip_path", stripPath),
			)
		}
	}
}

// createErrorHandler creates an error handler for proxy failures
func (rp *ReverseProxy) createErrorHandler(target *url.URL) func(
	http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		requestID := rp.getOrGenerateRequestID(r)
		rp.logger.Error("Proxy request failed",
			slog.String("request_id", requestID),
			slog.String("target", target.String()),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("remote_addr", utils.GetClientIP(r)),
			slog.String("error", err.Error()),
		)

		statusCode := rp.getErrorStatusCode(err)
		message := rp.getErrorMessage(statusCode)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Proxy-Error", "true")
		w.WriteHeader(statusCode)

		errorResponse := map[string]any{
			"error":      message,
			"status":     statusCode,
			"request_id": requestID,
		}

		if jsonBytes, err := json.Marshal(errorResponse); err == nil {
			w.Write(jsonBytes)
		} else {
			w.Write([]byte(`{"error":"Internal Server Error"}`))
		}
	}
}

// getErrorStatusCode determines the appropriate HTTP status code for an error
func (rp *ReverseProxy) getErrorStatusCode(err error) int {
	errStr := strings.ToLower(err.Error())

	switch {
	case strings.Contains(errStr, "timeout"):
		return http.StatusGatewayTimeout

	case strings.Contains(errStr, "connection refused"):
		return http.StatusServiceUnavailable

	case strings.Contains(errStr, "no such host"):
		return http.StatusBadGateway

	case strings.Contains(errStr, "context deadline exceeded"):
		return http.StatusGatewayTimeout

	case strings.Contains(errStr, "connection reset"):
		return http.StatusBadGateway

	default:
		return http.StatusBadGateway
	}
}

// getErrorMessage returns a user-friendly error message for a status code
func (rp *ReverseProxy) getErrorMessage(statusCode int) string {
	switch statusCode {
	case http.StatusBadGateway:
		return "Backend service unavailable"

	case http.StatusServiceUnavailable:
		return "Service temporarily unavailable"

	case http.StatusGatewayTimeout:
		return "Backend service timeout"

	default:
		return "Proxy error"
	}
}

// stripPathPrefix removes the routing prefix from the request path
func (rp *ReverseProxy) stripPathPrefix(requestPath, routePath string) string {
	if requestPath == routePath {
		return "/"
	}

	if strings.HasPrefix(requestPath, routePath) {
		stripped := strings.TrimPrefix(requestPath, routePath)
		if stripped == "" || stripped[0] != '/' {
			return "/" + stripped
		}

		return stripped
	}

	return requestPath
}

// setProxyHeaders sets headers on the incoming request before proxying
func (rp *ReverseProxy) setProxyHeaders(req *http.Request) {
	hopHeaders := []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, header := range hopHeaders {
		req.Header.Del(header)
	}

	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Forwarded-Proto")
	req.Header.Del("X-Forwarded-Host")
	req.Header.Del("X-Real-IP")
}

// setForwardingHeaders sets headers for backend services
func (rp *ReverseProxy) setForwardingHeaders(req *http.Request) {
	clientIP := utils.GetClientIP(req)

	req.Header.Set("X-Real-IP", clientIP)
	req.Header.Set("X-Forwarded-For", clientIP)
	req.Header.Set("X-Forwarded-Proto", utils.GetScheme(req))
	req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
	req.Header.Set("X-Forwarded-By", "api-gateway/1.0.0")
	req.Header.Set("X-Request-Start", time.Now().UTC().Format(time.RFC3339))
}

// getOrGenerateRequestID gets or generates a request ID
func (rp *ReverseProxy) getOrGenerateRequestID(req *http.Request) string {
	if requestID := req.Header.Get("X-Request-ID"); requestID != "" {
		return requestID
	}

	if requestID := req.Context().Value("requestID"); requestID != nil {
		if id, ok := requestID.(string); ok {
			return id
		}
	}

	return generateRequestID()
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int63())
}

// GetStats returns proxy statistics
func (rp *ReverseProxy) GetStats() ProxyStats {
	return ProxyStats{
		MaxIdleConns:        rp.transport.MaxIdleConns,
		MaxIdleConnsPerHost: rp.transport.MaxIdleConnsPerHost,
		IdleConnTimeout:     rp.transport.IdleConnTimeout.String(),
	}
}

// ProxyStats contains proxy statistics
type ProxyStats struct {
	MaxIdleConns        int    `json:"max_idle_conns"`
	MaxIdleConnsPerHost int    `json:"max_idle_conns_per_host"`
	IdleConnTimeout     string `json:"idle_conn_timeout"`
}

// Close gracefully closes the proxy and its connections
func (rp *ReverseProxy) Close() error {
	if rp.transport != nil {
		rp.transport.CloseIdleConnections()
	}
	
	return nil
}
