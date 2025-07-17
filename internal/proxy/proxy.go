package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"prism/pkg/utils"
	"strings"
	"time"
)

// ReverseProxy wraps the standard library reverse proxy
type ReverseProxy struct {
	logger *slog.Logger
	client *http.Client
}

// New creates a new reverse proxy instance
func New(logger *slog.Logger) *ReverseProxy {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
		},
	}

	return &ReverseProxy{
		logger: logger,
		client: client,
	}
}

// CreateHandler creates a proxy handler for the given target
func (rp *ReverseProxy) CreateHandler(target *url.URL, stripPath bool,
	routePath string) http.HandlerFunc {
	proxy := &httputil.ReverseProxy{
		Director:     rp.createDirector(target, stripPath, routePath),
		ErrorHandler: rp.createErrorHandler(target),
		Transport:    rp.client.Transport,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rp.setProxyHeaders(r)
		proxy.ServeHTTP(w, r)

		rp.logger.Debug("Request proxied",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("target", target.String()),
			slog.Duration("duration", time.Since(start)),
		)
	}
}

// createDirector creates a request director function
func (rp *ReverseProxy) createDirector(target *url.URL, stripPath bool,
	routePath string) func(*http.Request) {
	return func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host

		if stripPath {
			req.URL.Path = rp.stripPathPrefix(req.URL.Path, routePath)
		} else {
			if target.Path != "" && target.Path != "/" {
				req.URL.Path = strings.TrimSuffix(target.Path, "/") + req.URL.Path
			}
		}

		if req.URL.Path == "" {
			req.URL.Path = "/"
		}

		rp.setForwardingHeaders(req)
	}
}

// createErrorHandler creates an error handler for proxy failures
func (rp *ReverseProxy) createErrorHandler(target *url.URL) func(
	http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		rp.logger.Error("Proxy request failed",
			slog.String("target", target.String()),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("remote_addr", utils.GetClientIP(r)),
			slog.String("error", err.Error()),
		)

		switch {
		case strings.Contains(err.Error(), "timeout"):
			http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)

		case strings.Contains(err.Error(), "connection refused"):
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)

		default:
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}
	}
}

// stripPathPrefix removes the routing prefix from the request path
func (rp *ReverseProxy) stripPathPrefix(requestPath, routePath string) string {
	if !strings.HasPrefix(requestPath, routePath) {
		return requestPath
	}

	stripped := strings.TrimPrefix(requestPath, routePath)
	if stripped == "" {
		return "/"
	}

	return stripped
}

// setProxyHeaders sets headers on the incoming request
func (rp *ReverseProxy) setProxyHeaders(req *http.Request) {
	req.Header.Del("Connection")
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Te")
	req.Header.Del("Trailer")
	req.Header.Del("Upgrade")
}

// setForwardingHeaders sets headers for backend services
func (rp *ReverseProxy) setForwardingHeaders(req *http.Request) {
	clientIP := utils.GetClientIP(req)
	req.Header.Set("X-Real-IP", clientIP)

	if existingXFF := req.Header.Get("X-Forwarded-For"); existingXFF != "" {
		req.Header.Set("X-Forwarded-For", existingXFF+", "+clientIP)
	} else {
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	req.Header.Set("X-Forwarded-Proto", utils.GetScheme(req))
	req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
	req.Header.Set("X-Forwarded-By", "api-gateway/1.0.0")
}
