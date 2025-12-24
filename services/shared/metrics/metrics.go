// Package metrics provides Prometheus metrics collection for all services.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Common labels used across metrics.
const (
	LabelService   = "service"
	LabelMethod    = "method"
	LabelPath      = "path"
	LabelStatus    = "status"
	LabelUpstream  = "upstream"
	LabelComponent = "component"
)

// Metrics contains all Prometheus metrics for a service.
type Metrics struct {
	serviceName string
	registry    *prometheus.Registry

	// HTTP metrics
	httpRequestsTotal    *prometheus.CounterVec
	httpRequestDuration  *prometheus.HistogramVec
	httpRequestsInFlight prometheus.Gauge
	httpResponseSize     *prometheus.HistogramVec

	// gRPC metrics
	grpcRequestsTotal   *prometheus.CounterVec
	grpcRequestDuration *prometheus.HistogramVec

	// Upstream/proxy metrics
	upstreamRequestsTotal   *prometheus.CounterVec
	upstreamRequestDuration *prometheus.HistogramVec
	upstreamHealthy         *prometheus.GaugeVec

	// Circuit breaker metrics
	circuitBreakerState *prometheus.GaugeVec
	circuitBreakerTrips *prometheus.CounterVec

	// Rate limiter metrics
	rateLimitHits    *prometheus.CounterVec
	rateLimitDropped *prometheus.CounterVec

	// Traffic mirroring metrics
	mirrorRequestsTotal   *prometheus.CounterVec
	mirrorRequestDuration *prometheus.HistogramVec

	// Connection pool metrics
	dbConnectionsActive *prometheus.GaugeVec
	dbConnectionsIdle   *prometheus.GaugeVec

	// Custom metrics
	customCounters   map[string]*prometheus.CounterVec
	customGauges     map[string]*prometheus.GaugeVec
	customHistograms map[string]*prometheus.HistogramVec
}

// Config holds metrics configuration.
type Config struct {
	ServiceName string
	Namespace   string
	Subsystem   string
}

// New creates a new Metrics instance.
func New(cfg Config) *Metrics {
	if cfg.Namespace == "" {
		cfg.Namespace = "prism"
	}

	registry := prometheus.NewRegistry()

	// Register default Go metrics
	registry.MustRegister(prometheus.NewGoCollector())
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	m := &Metrics{
		serviceName:      cfg.ServiceName,
		registry:         registry,
		customCounters:   make(map[string]*prometheus.CounterVec),
		customGauges:     make(map[string]*prometheus.GaugeVec),
		customHistograms: make(map[string]*prometheus.HistogramVec),
	}

	factory := promauto.With(registry)

	// HTTP metrics
	m.httpRequestsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests.",
		},
		[]string{LabelService, LabelMethod, LabelPath, LabelStatus},
	)

	m.httpRequestDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{LabelService, LabelMethod, LabelPath, LabelStatus},
	)

	m.httpRequestsInFlight = factory.NewGauge(
		prometheus.GaugeOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "http_requests_in_flight",
			Help:      "Current number of HTTP requests being processed.",
		},
	)

	m.httpResponseSize = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "http_response_size_bytes",
			Help:      "HTTP response size in bytes.",
			Buckets:   prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{LabelService, LabelMethod, LabelPath},
	)

	// gRPC metrics
	m.grpcRequestsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "grpc_requests_total",
			Help:      "Total number of gRPC requests.",
		},
		[]string{LabelService, LabelMethod, LabelStatus},
	)

	m.grpcRequestDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "grpc_request_duration_seconds",
			Help:      "gRPC request latency in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{LabelService, LabelMethod},
	)

	// Upstream metrics
	m.upstreamRequestsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "upstream_requests_total",
			Help:      "Total number of upstream requests.",
		},
		[]string{LabelUpstream, LabelMethod, LabelStatus},
	)

	m.upstreamRequestDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "upstream_request_duration_seconds",
			Help:      "Upstream request latency in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{LabelUpstream, LabelMethod},
	)

	m.upstreamHealthy = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "upstream_healthy",
			Help:      "Whether the upstream is healthy (1) or not (0).",
		},
		[]string{LabelUpstream},
	)

	// Circuit breaker metrics
	m.circuitBreakerState = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "circuit_breaker_state",
			Help:      "Circuit breaker state (0=closed, 1=open, 2=half-open).",
		},
		[]string{LabelComponent},
	)

	m.circuitBreakerTrips = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "circuit_breaker_trips_total",
			Help:      "Total number of circuit breaker trips.",
		},
		[]string{LabelComponent},
	)

	// Rate limiter metrics
	m.rateLimitHits = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "rate_limit_hits_total",
			Help:      "Total number of rate limit checks.",
		},
		[]string{LabelPath},
	)

	m.rateLimitDropped = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "rate_limit_dropped_total",
			Help:      "Total number of requests dropped due to rate limiting.",
		},
		[]string{LabelPath},
	)

	// Traffic mirroring metrics
	m.mirrorRequestsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "mirror_requests_total",
			Help:      "Total number of mirror requests.",
		},
		[]string{LabelUpstream, LabelStatus},
	)

	m.mirrorRequestDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "mirror_request_duration_seconds",
			Help:      "Mirror request latency in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{LabelUpstream},
	)

	// Database connection pool metrics
	m.dbConnectionsActive = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "db_connections_active",
			Help:      "Number of active database connections.",
		},
		[]string{LabelComponent},
	)

	m.dbConnectionsIdle = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "db_connections_idle",
			Help:      "Number of idle database connections.",
		},
		[]string{LabelComponent},
	)

	return m
}

// Handler returns an HTTP handler for the metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// Registry returns the Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// --- HTTP Metrics ---

// RecordHTTPRequest records an HTTP request.
func (m *Metrics) RecordHTTPRequest(method, path string, status int, duration time.Duration, responseSize int64) {
	statusStr := strconv.Itoa(status)
	m.httpRequestsTotal.WithLabelValues(m.serviceName, method, path, statusStr).Inc()
	m.httpRequestDuration.WithLabelValues(m.serviceName, method, path, statusStr).Observe(duration.Seconds())
	m.httpResponseSize.WithLabelValues(m.serviceName, method, path).Observe(float64(responseSize))
}

// HTTPRequestsInFlight increments/decrements in-flight request counter.
func (m *Metrics) HTTPRequestsInFlight(delta float64) {
	m.httpRequestsInFlight.Add(delta)
}

// --- gRPC Metrics ---

// RecordGRPCRequest records a gRPC request.
func (m *Metrics) RecordGRPCRequest(method, status string, duration time.Duration) {
	m.grpcRequestsTotal.WithLabelValues(m.serviceName, method, status).Inc()
	m.grpcRequestDuration.WithLabelValues(m.serviceName, method).Observe(duration.Seconds())
}

// --- Upstream Metrics ---

// RecordUpstreamRequest records an upstream request.
func (m *Metrics) RecordUpstreamRequest(upstream, method string, status int, duration time.Duration) {
	statusStr := strconv.Itoa(status)
	m.upstreamRequestsTotal.WithLabelValues(upstream, method, statusStr).Inc()
	m.upstreamRequestDuration.WithLabelValues(upstream, method).Observe(duration.Seconds())
}

// SetUpstreamHealthy sets the health status of an upstream.
func (m *Metrics) SetUpstreamHealthy(upstream string, healthy bool) {
	val := 0.0
	if healthy {
		val = 1.0
	}
	m.upstreamHealthy.WithLabelValues(upstream).Set(val)
}

// --- Circuit Breaker Metrics ---

// SetCircuitBreakerState sets the circuit breaker state.
func (m *Metrics) SetCircuitBreakerState(component string, state int) {
	m.circuitBreakerState.WithLabelValues(component).Set(float64(state))
}

// RecordCircuitBreakerTrip records a circuit breaker trip.
func (m *Metrics) RecordCircuitBreakerTrip(component string) {
	m.circuitBreakerTrips.WithLabelValues(component).Inc()
}

// --- Rate Limiter Metrics ---

// RecordRateLimitHit records a rate limit check.
func (m *Metrics) RecordRateLimitHit(path string) {
	m.rateLimitHits.WithLabelValues(path).Inc()
}

// RecordRateLimitDrop records a dropped request due to rate limiting.
func (m *Metrics) RecordRateLimitDrop(path string) {
	m.rateLimitDropped.WithLabelValues(path).Inc()
}

// --- Traffic Mirroring Metrics ---

// RecordMirrorRequest records a mirror request.
func (m *Metrics) RecordMirrorRequest(upstream, status string, duration time.Duration) {
	m.mirrorRequestsTotal.WithLabelValues(upstream, status).Inc()
	m.mirrorRequestDuration.WithLabelValues(upstream).Observe(duration.Seconds())
}

// --- Database Metrics ---

// SetDBConnections sets the database connection counts.
func (m *Metrics) SetDBConnections(component string, active, idle int) {
	m.dbConnectionsActive.WithLabelValues(component).Set(float64(active))
	m.dbConnectionsIdle.WithLabelValues(component).Set(float64(idle))
}

// --- Middleware ---

// HTTPMiddleware returns an HTTP middleware that records request metrics.
func (m *Metrics) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.HTTPRequestsInFlight(1)
		defer m.HTTPRequestsInFlight(-1)

		// Wrap response writer to capture status and size
		wrapped := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		m.RecordHTTPRequest(r.Method, r.URL.Path, wrapped.status, duration, int64(wrapped.size))
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	return n, err
}

// Flush implements http.Flusher.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Global metrics instance for convenience.
var globalMetrics *Metrics

// Init initializes the global metrics instance.
func Init(cfg Config) *Metrics {
	globalMetrics = New(cfg)
	return globalMetrics
}

// Default returns the global metrics instance.
func Default() *Metrics {
	return globalMetrics
}
