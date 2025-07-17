package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"prism/pkg/utils"
	"strings"
)

// ReverseProxy wraps the standard library reverse proxy
type ReverseProxy struct {
	logger *slog.Logger
}

// New creates a new reverse proxy instance
func New(logger *slog.Logger) *ReverseProxy {
	return &ReverseProxy{
		logger: logger,
	}
}

// CreateHandler creates a proxy handler for the given target
func (rp *ReverseProxy) CreateHandler(target *url.URL, stripPath bool,
	routePath string) http.HandlerFunc {
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director

	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		if stripPath {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, routePath)

			if req.URL.Path == "" {
				req.URL.Path = "/"
			}
		}

		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		req.Header.Set("X-Forwarded-Proto", utils.GetScheme(req))
		req.Header.Set("X-Real-IP", utils.GetClientIP(req))
		req.Header.Set("X-Forwarded-For", utils.GetClientIP(req))
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		rp.logger.Error("Proxy error",
			slog.String("target", target.String()),
			slog.String("path", r.URL.Path),
			slog.String("method", r.Method),
			slog.String("error", err.Error()),
		)

		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}
}
