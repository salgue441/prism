// Package proxy provides the core reverse proxy functionality.
package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/carlossalguero/prism/services/gateway/internal/circuitbreaker"
	"github.com/carlossalguero/prism/services/gateway/internal/mirror"
	"github.com/carlossalguero/prism/services/shared/errors"
	"github.com/carlossalguero/prism/services/shared/logger"
)

// Config holds proxy configuration.
type Config struct {
	Transport              http.RoundTripper
	FlushInterval          time.Duration
	BufferPool             httputil.BufferPool
	ErrorHandler           func(http.ResponseWriter, *http.Request, error)
	ModifyResponse         func(*http.Response) error
	RequestTimeout         time.Duration
	PreserveHost           bool
	TrustXForwarded        bool
	MaxIdleConns           int
	IdleConnTimeout        time.Duration
	CircuitBreakerRegistry *circuitbreaker.Registry
	MirrorHandler          *mirror.Handler
}

// Proxy is a reverse proxy that forwards requests to upstream targets.
type Proxy struct {
	transport       http.RoundTripper
	flushInterval   time.Duration
	bufferPool      httputil.BufferPool
	errorHandler    func(http.ResponseWriter, *http.Request, error)
	modifyResponse  func(*http.Response) error
	requestTimeout  time.Duration
	preserveHost    bool
	trustXForwarded bool
	cbRegistry      *circuitbreaker.Registry
	mirrorHandler   *mirror.Handler
	logger          *logger.Logger
}

// New creates a new reverse proxy.
func New(cfg Config) *Proxy {
	transport := cfg.Transport
	if transport == nil {
		transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		}
	}

	flushInterval := cfg.FlushInterval
	if flushInterval == 0 {
		flushInterval = -1 // Disable auto-flush for better performance
	}

	requestTimeout := cfg.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = 30 * time.Second
	}

	p := &Proxy{
		transport:       transport,
		flushInterval:   flushInterval,
		bufferPool:      cfg.BufferPool,
		modifyResponse:  cfg.ModifyResponse,
		requestTimeout:  requestTimeout,
		preserveHost:    cfg.PreserveHost,
		trustXForwarded: cfg.TrustXForwarded,
		cbRegistry:      cfg.CircuitBreakerRegistry,
		mirrorHandler:   cfg.MirrorHandler,
		logger:          logger.Default().WithComponent("proxy"),
	}

	p.errorHandler = cfg.ErrorHandler
	if p.errorHandler == nil {
		p.errorHandler = p.defaultErrorHandler
	}

	return p
}

// Target represents an upstream target.
type Target struct {
	URL    *url.URL
	Weight int
}

// contextKey is used for context values.
type contextKey string

const (
	// TargetKey is the context key for the target URL.
	TargetKey contextKey = "proxy_target"
	// MirrorConfigKey is the context key for mirror configuration.
	MirrorConfigKey contextKey = "proxy_mirror_config"
)

// MirrorConfig holds mirror configuration passed via context.
type MirrorConfig struct {
	Enabled      bool
	UpstreamID   string
	SamplePct    float64
	TimeoutMs    int
	LogDiff      bool
	HeadersToAdd map[string]string
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get target from context
	target, ok := r.Context().Value(TargetKey).(*url.URL)
	if !ok || target == nil {
		p.errorHandler(w, r, errors.RouteNotFound("no upstream target configured"))
		return
	}

	// Check for mirror configuration
	var mirrorCfg *mirror.Config
	var mirrorReq *http.Request
	var clonedBody []byte

	if p.mirrorHandler != nil {
		if mc, ok := r.Context().Value(MirrorConfigKey).(*MirrorConfig); ok && mc != nil && mc.Enabled {
			mirrorCfg = &mirror.Config{
				Enabled:      mc.Enabled,
				UpstreamID:   mc.UpstreamID,
				SamplePct:    mc.SamplePct,
				TimeoutMs:    mc.TimeoutMs,
				LogDiff:      mc.LogDiff,
				HeadersToAdd: mc.HeadersToAdd,
			}

			// Check if we should mirror this request based on sampling
			if p.mirrorHandler.ShouldMirror(mirrorCfg) {
				// Clone body before forwarding
				var err error
				r.Body, clonedBody, err = mirror.CloneBody(r.Body, 10*1024*1024) // 10MB max
				if err != nil {
					p.logger.Warn("failed to clone body for mirroring", "error", err)
				} else if len(clonedBody) > 0 || r.ContentLength == 0 {
					// Prepare mirror request
					mirrorReq, err = p.mirrorHandler.PrepareRequest(r, clonedBody, mirrorCfg)
					if err != nil {
						p.logger.Warn("failed to prepare mirror request", "error", err)
					}
				}
			}
		}
	}

	// Apply request timeout
	ctx := r.Context()
	if p.requestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.requestTimeout)
		defer cancel()
		r = r.WithContext(ctx)
	}

	// Wrap response writer to capture status code for mirroring
	wrappedWriter := &statusCapturingWriter{ResponseWriter: w, status: http.StatusOK}

	// Check circuit breaker if registry is configured
	if p.cbRegistry != nil {
		cb := p.cbRegistry.Get(target.Host)
		if err := cb.Allow(); err != nil {
			if err == circuitbreaker.ErrCircuitOpen {
				p.errorHandler(w, r, errors.Unavailable("upstream service unavailable (circuit open)"))
				return
			}
			if err == circuitbreaker.ErrTooManyRequests {
				p.errorHandler(w, r, errors.RateLimited("too many requests to upstream"))
				return
			}
			p.errorHandler(w, r, errors.Unavailable(err.Error()))
			return
		}

		// Wrap transport to record circuit breaker result
		wrappedTransport := &circuitBreakerTransport{
			transport: p.transport,
			cb:        cb,
		}

		// Create the reverse proxy for this request with circuit breaker transport
		proxy := &httputil.ReverseProxy{
			Director:       p.director(target),
			Transport:      wrappedTransport,
			FlushInterval:  p.flushInterval,
			BufferPool:     p.bufferPool,
			ModifyResponse: p.modifyResponse,
			ErrorHandler:   p.errorHandler,
		}

		proxy.ServeHTTP(wrappedWriter, r)
	} else {
		// Create the reverse proxy for this request (no circuit breaker)
		proxy := &httputil.ReverseProxy{
			Director:       p.director(target),
			Transport:      p.transport,
			FlushInterval:  p.flushInterval,
			BufferPool:     p.bufferPool,
			ModifyResponse: p.modifyResponse,
			ErrorHandler:   p.errorHandler,
		}

		proxy.ServeHTTP(wrappedWriter, r)
	}

	// Fire mirror request asynchronously after primary request completes
	if mirrorReq != nil && mirrorCfg != nil {
		requestID := r.Header.Get("X-Request-ID")
		p.mirrorHandler.Execute(mirrorReq, mirrorCfg, wrappedWriter.status, requestID)
	}
}

// statusCapturingWriter wraps http.ResponseWriter to capture status code.
type statusCapturingWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusCapturingWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCapturingWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusCapturingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// circuitBreakerTransport wraps an http.RoundTripper to record results for circuit breaker.
type circuitBreakerTransport struct {
	transport http.RoundTripper
	cb        *circuitbreaker.CircuitBreaker
}

func (t *circuitBreakerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		t.cb.RecordFailure()
		return resp, err
	}

	// Consider 5xx responses as failures for circuit breaker
	if resp.StatusCode >= 500 {
		t.cb.RecordFailure()
	} else {
		t.cb.RecordSuccess()
	}

	return resp, nil
}

// director returns the director function for the reverse proxy.
func (p *Proxy) director(target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		// Set target URL
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host

		// Handle path
		targetPath := target.Path
		if targetPath == "" {
			targetPath = "/"
		}

		// Join paths
		if req.URL.Path != "" {
			if strings.HasSuffix(targetPath, "/") {
				req.URL.Path = targetPath + strings.TrimPrefix(req.URL.Path, "/")
			} else {
				req.URL.Path = singleJoiningSlash(targetPath, req.URL.Path)
			}
		} else {
			req.URL.Path = targetPath
		}

		// Preserve query string
		if target.RawQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = target.RawQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
		}

		// Set Host header
		if !p.preserveHost {
			req.Host = target.Host
		}

		// Handle X-Forwarded headers
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
				if p.trustXForwarded {
					clientIP = prior + ", " + clientIP
				}
			}
			req.Header.Set("X-Forwarded-For", clientIP)
		}

		if req.TLS != nil {
			req.Header.Set("X-Forwarded-Proto", "https")
		} else {
			if proto := req.Header.Get("X-Forwarded-Proto"); proto == "" || !p.trustXForwarded {
				req.Header.Set("X-Forwarded-Proto", "http")
			}
		}

		req.Header.Set("X-Forwarded-Host", req.Host)

		// Remove hop-by-hop headers
		removeHopByHopHeaders(req.Header)
	}
}

func (p *Proxy) defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	p.logger.WithContext(r.Context()).Error("proxy error",
		"error", err,
		"method", r.Method,
		"path", r.URL.Path,
	)

	var appErr *errors.Error
	if e, ok := err.(*errors.Error); ok {
		appErr = e
	} else {
		appErr = errors.UpstreamError(err.Error())
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(appErr.HTTPStatusCode())

	// Simple JSON error response
	response := `{"error":"` + appErr.Message + `","code":"` + string(appErr.Code) + `"}`
	io.WriteString(w, response)
}

// Helper functions

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// Hop-by-hop headers that should not be forwarded
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(header http.Header) {
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

// LoadBalancer provides load balancing across multiple targets.
type LoadBalancer struct {
	mu       sync.RWMutex
	targets  []*Target
	current  int
	strategy LoadBalanceStrategy
}

// LoadBalanceStrategy defines the load balancing algorithm.
type LoadBalanceStrategy int

const (
	// RoundRobin distributes requests evenly across targets.
	RoundRobin LoadBalanceStrategy = iota
	// Random selects a random target.
	Random
	// LeastConnections selects the target with fewest active connections.
	LeastConnections
	// Weighted selects targets based on their weight.
	Weighted
)

// NewLoadBalancer creates a new load balancer.
func NewLoadBalancer(targets []*Target, strategy LoadBalanceStrategy) *LoadBalancer {
	return &LoadBalancer{
		targets:  targets,
		strategy: strategy,
	}
}

// Next returns the next target according to the load balancing strategy.
func (lb *LoadBalancer) Next() *Target {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if len(lb.targets) == 0 {
		return nil
	}

	switch lb.strategy {
	case RoundRobin:
		target := lb.targets[lb.current]
		lb.current = (lb.current + 1) % len(lb.targets)
		return target
	case Random:
		// In production, use crypto/rand for better randomness
		return lb.targets[time.Now().UnixNano()%int64(len(lb.targets))]
	case Weighted:
		return lb.weightedSelect()
	default:
		return lb.targets[0]
	}
}

func (lb *LoadBalancer) weightedSelect() *Target {
	totalWeight := 0
	for _, t := range lb.targets {
		totalWeight += t.Weight
	}

	if totalWeight == 0 {
		return lb.targets[0]
	}

	// Simple weighted selection
	r := int(time.Now().UnixNano() % int64(totalWeight))
	for _, t := range lb.targets {
		r -= t.Weight
		if r < 0 {
			return t
		}
	}

	return lb.targets[0]
}

// AddTarget adds a target to the load balancer.
func (lb *LoadBalancer) AddTarget(target *Target) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.targets = append(lb.targets, target)
}

// RemoveTarget removes a target from the load balancer.
func (lb *LoadBalancer) RemoveTarget(targetURL string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for i, t := range lb.targets {
		if t.URL.String() == targetURL {
			lb.targets = append(lb.targets[:i], lb.targets[i+1:]...)
			return
		}
	}
}

// Targets returns a copy of the current targets.
func (lb *LoadBalancer) Targets() []*Target {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	result := make([]*Target, len(lb.targets))
	copy(result, lb.targets)
	return result
}
