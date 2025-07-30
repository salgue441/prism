package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"prism/internal/config"
	"prism/pkg/logger"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// New creates a new high-performance HTTP server instance with comprehensive
// security, observability, and lifecycle management features.
//
// The server implements:
//   - High-performance request handling with connection pooling
//   - Comprehensive security controls and headers
//   - Real-time metrics collection and health monitoring
//   - Graceful lifecycle management with proper cleanup
//   - Enhanced context with request correlation and tracing
//   - Flexible middleware system with ordering
//
// Parameters:
//   - config: Server configuration with validation
//   - logger: Structured logger instance
//   - opts: Optional server configuration (can be nil)
//
// Returns:
//   - *Server: Configured server instance ready for use
//   - error: Configuration validation or initialization error
func New(cfg *config.Config, log *logger.Logger, opts *ServerOptions) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}

	if log == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	if opts == nil {
		opts = &ServerOptions{}
	}

	if cfg.IsDebugMode() {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	if len(opts.TrustedProxies) > 0 {
		if err := router.SetTrustedProxies(opts.TrustedProxies); err != nil {
			return nil, fmt.Errorf("failed to set trusted proxies: %w", err)
		}
	}

	server := &Server{
		config:          cfg,
		logger:          log,
		router:          router,
		middleware:      make([]gin.HandlerFunc, 0),
		shutdownChan:    make(chan struct{}),
		doneChan:        make(chan struct{}),
		shutdownTimeout: cfg.Server.ShutdownTimeout,
		connTracker:     newConnectionTracker(),
		healthStatus:    newHealthStatus(),
		errorHandlers:   make(map[int]gin.HandlerFunc),
	}

	if err := server.initHTTPServer(opts); err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP server: %w", err)
	}

	if cfg.Metrics.Enabled && cfg.Metrics.Port > 0 {
		if err := server.initMetricsServer(); err != nil {
			return nil, fmt.Errorf("failed to initialize metrics server: %w", err)
		}
	}

	if cfg.Development.PProf && cfg.Development.PprofPort > 0 {
		if err := server.initPprofServer(); err != nil {
			return nil, fmt.Errorf("failed to initialize pprof server: %w", err)
		}
	}

	if !opts.DisableDefaultMiddleware {
		server.setupDefaultMiddleware()
	}

	for _, middleware := range opts.CustomMiddleware {
		server.router.Use(middleware)
	}

	server.setupRouteGroups()
	server.setupDefaultRoutes()

	for code, handler := range opts.ErrorHandlers {
		server.errorHandlers[code] = handler
	}

	if opts.HealthCheckers != nil {
		for name, _ := range opts.HealthCheckers {
			server.healthStatus.dependencies[name] = &DependencyHealth{
				Name:   name,
				Status: HealthStateStarting,
			}
		}
	}

	return server, nil
}

// initHTTPServer initializes the main HTTP server with optimized settings.
func (s *Server) initHTTPServer(opts *ServerOptions) error {
	s.httpServer = &http.Server{
		Addr:           s.config.GetAddress(),
		Handler:        s.router,
		ReadTimeout:    s.config.Server.ReadTimeout,
		WriteTimeout:   s.config.Server.WriteTimeout,
		IdleTimeout:    s.config.Server.IdleTimeout,
		MaxHeaderBytes: s.config.Server.MaxHeaderBytes,
		ConnState:      s.trackConnection,
		ErrorLog:       s.createErrorLogger(),
	}

	if s.config.IsTLSEnabled() {
		tlsConfig, err := s.createTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to create TLS configuration: %w", err)
		}

		s.httpServer.TLSConfig = tlsConfig
	}

	return nil
}

func (s *Server) createErrorLogger() *log.Logger {
	return log.New(s.logger.Logger.Out, "[HTTP-ERROR] ", log.LstdFlags)
}

// initMetricsServer initializes a separate metrics server for security isolation.
func (s *Server) initMetricsServer() error {
	metricsRouter := gin.New()

	metricsRouter.Use(gin.Recovery())
	metricsRouter.Use(s.createLoggingMiddleware("metrics"))
	metricsRouter.GET(s.config.Metrics.Path, gin.WrapH(promhttp.Handler()))

	s.metricsServer = &http.Server{
		Addr:           s.config.GetMetricsAddress(),
		Handler:        metricsRouter,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	return nil
}

// initPprofServer initializes the pprof server for development profiling.
func (s *Server) initPprofServer() error {
	pprofRouter := gin.New()

	pprofRouter.Use(gin.Recovery())
	pprofRouter.Use(s.createLoggingMiddleware("pprof"))

	s.registerPprofRoutes(pprofRouter)
	s.pprofServer = &http.Server{
		Addr:         s.config.GetPprofAddress(),
		Handler:      pprofRouter,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return nil
}

// createTLSConfig creates a secure TLS configuration based on server config.
func (s *Server) createTLSConfig() (*tls.Config, error) {
	cfg := s.config.Server.TLS
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	if cfg.MinVersion != "" {
		switch cfg.MinVersion {
		case "1.2":
			tlsConfig.MinVersion = tls.VersionTLS12

		case "1.3":
			tlsConfig.MinVersion = tls.VersionTLS13

		default:
			return nil, fmt.Errorf("unsupported TLS minimum version: %s",
				cfg.MinVersion)
		}
	}

	if cfg.MaxVersion != "" {
		switch cfg.MaxVersion {
		case "1.2":
			tlsConfig.MaxVersion = tls.VersionTLS12

		case "1.3":
			tlsConfig.MaxVersion = tls.VersionTLS13

		default:
			return nil, fmt.Errorf("unsupported TLS maximum version: %s",
				cfg.MaxVersion)
		}
	}

	switch cfg.ClientAuth {
	case "NoClientCert":
		tlsConfig.ClientAuth = tls.NoClientCert

	case "RequestClientCert":
		tlsConfig.ClientAuth = tls.RequestClientCert

	case "RequireAnyClientCert":
		tlsConfig.ClientAuth = tls.RequireAnyClientCert

	case "VerifyClientCertIfGiven":
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven

	case "RequireAndVerifyClientCert":
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

// setupDefaultMiddleware configures the default middleware chain.
func (s *Server) setupDefaultMiddleware() {
	s.router.Use(gin.CustomRecovery(s.createRecoveryHandler()))
	s.router.Use(s.createRequestIDMiddleware())
	s.router.Use(s.createLoggingMiddleware("main"))
	s.router.Use(s.createSecurityHeadersMiddleware())

	if s.config.IsCORSEnabled() {
		s.router.Use(s.createCORSMiddleware())
	}

	if s.config.IsRateLimitingEnabled() {
		s.router.Use(s.createRateLimitMiddleware())
	}

	if s.config.IsMetricsEnabled() {
		s.router.Use(s.createMetricsMiddleware())
	}

	s.router.Use(s.createCompressionMiddleware())
}

// setupRouteGroups creates organized route groups for different functionalities.
func (s *Server) setupRouteGroups() {
	s.apiGroup = s.router.Group("/api")
	s.adminGroup = s.router.Group("/admin")
	s.adminGroup.Use(s.createAdminAuthMiddleware())
	s.healthGroup = s.router.Group("")
}

// setupDefaultRoutes registers essential server routes.
func (s *Server) setupDefaultRoutes() {
	if s.config.IsHealthEnabled() {
		s.healthGroup.GET(s.config.Health.Path, s.handleHealthCheck)

		if s.config.Health.ReadinessPath != "" {
			s.healthGroup.GET(s.config.Health.ReadinessPath, s.handleReadinessCheck)
		}
	}

	if s.config.IsMetricsEnabled() && s.config.Metrics.Port == 0 {
		s.router.GET(s.config.Metrics.Path, gin.WrapH(promhttp.Handler()))
	}

	s.router.GET("/", s.handleRoot)
	s.router.NoRoute(s.handleNotFound)
	s.router.NoMethod(s.handleMethodNotAllowed)
}

// Start starts the HTTP server and all auxiliary servers.
func (s *Server) Start() error {
	if !atomic.CompareAndSwapInt32(&s.started, 0, 1) {
		return ErrServerAlreadyStarted
	}

	s.startTime = time.Now()
	s.healthStatus.startTime = s.startTime
	s.healthStatus.status = HealthStateStarting
	s.logger.LogStartup("server", "1.0.0", s.config.GetAddress())

	if err := s.startAuxiliaryServers(); err != nil {
		atomic.StoreInt32(&s.started, 0)
		return fmt.Errorf("failed to start auxiliary servers: %w", err)
	}

	listener, err := s.createListener()
	if err != nil {
		atomic.StoreInt32(&s.started, 0)
		return fmt.Errorf("failed to create listener: %w", err)
	}

	s.healthStatus.mu.Lock()
	s.healthStatus.status = HealthStateHealthy
	s.healthStatus.mu.Unlock()

	go func() {
		defer close(s.doneChan)

		var err error
		if s.config.IsTLSEnabled() {
			s.logger.Info("Starting HTTPS server", "address", s.config.GetAddress())
			err = s.httpServer.ServeTLS(listener, "", "")
		} else {
			s.logger.Info("Starting HTTP server", "address", s.config.GetAddress())
			err = s.httpServer.Serve(listener)
		}

		if err != nil && err != http.ErrServerClosed {
			s.logger.Error("Server error", "error", err)
		}
	}()

	s.logger.Info("Server started successfully",
		"address", s.config.GetAddress(),
		"tls_enabled", s.config.IsTLSEnabled(),
		"debug_mode", s.config.IsDebugMode())

	return nil
}

// startAuxiliaryServers starts metrics and pprof servers if configured.
func (s *Server) startAuxiliaryServers() error {
	if s.metricsServer != nil {
		go func() {
			s.logger.Info("Starting metrics server", "address", s.config.GetMetricsAddress())

			if err := s.metricsServer.ListenAndServe(); err != nil &&
				err != http.ErrServerClosed {
				s.logger.Error("Metrics server error", "error", err)
			}
		}()
	}

	if s.pprofServer != nil {
		go func() {
			s.logger.Info("Starting pprof server", "address",
				s.config.GetPprofAddress())

			if err := s.pprofServer.ListenAndServe(); err != nil &&
				err != http.ErrServerClosed {
				s.logger.Error("Pprof server error", "error", err)
			}
		}()
	}

	return nil
}

// createListener creates an optimized network listener.
func (s *Server) createListener() (net.Listener, error) {
	listener, err := net.Listen("tcp", s.config.GetAddress())
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	if tcpListener, ok := listener.(*net.TCPListener); ok {
		return &tcpKeepAliveListener{
			TCPListener: tcpListener,
			period:      3 * time.Minute,
		}, nil
	}

	return listener, nil
}

// Shutdown gracefully shuts down the server and all auxiliary servers.
func (s *Server) Shutdown(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&s.started, 1, 0) {
		return ErrServerNotStarted
	}

	s.healthStatus.mu.Lock()
	s.healthStatus.status = HealthStateStopping
	s.healthStatus.mu.Unlock()

	s.logger.Info("Starting graceful shutdown")

	shutdownCtx, cancel := context.WithTimeout(ctx, s.shutdownTimeout)
	defer cancel()
	close(s.shutdownChan)

	errChan := make(chan error, 3)
	go func() {
		errChan <- s.httpServer.Shutdown(shutdownCtx)
	}()

	if s.metricsServer != nil {
		go func() {
			errChan <- s.metricsServer.Shutdown(shutdownCtx)
		}()
	} else {
		errChan <- nil
	}

	if s.pprofServer != nil {
		go func() {
			errChan <- s.pprofServer.Shutdown(shutdownCtx)
		}()
	} else {
		errChan <- nil
	}

	var shutdownErrors []error
	for i := 0; i < 3; i++ {
		if err := <-errChan; err != nil {
			shutdownErrors = append(shutdownErrors, err)
		}
	}

	select {
	case <-s.doneChan:
		s.logger.Info("Server shutdown completed")

	case <-shutdownCtx.Done():
		s.logger.Warn("Server shutdown timed out")
		shutdownErrors = append(shutdownErrors, ErrShutdownTimeout)
	}

	s.healthStatus.mu.Lock()
	s.healthStatus.status = HealthStateStopped
	s.healthStatus.mu.Unlock()

	uptime := time.Since(s.startTime)
	s.logger.LogShutdown("server", "graceful", uptime, len(shutdownErrors) == 0)

	if len(shutdownErrors) > 0 {
		return fmt.Errorf("shutdown errors: %v", shutdownErrors)
	}

	return nil
}

// Close forcefully closes the server without graceful shutdown.
func (s *Server) Close() error {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return ErrServerClosed
	}

	s.logger.Warn("Forcefully closing server")

	var errors []error
	if err := s.httpServer.Close(); err != nil {
		errors = append(errors, err)
	}

	if s.metricsServer != nil {
		if err := s.metricsServer.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if s.pprofServer != nil {
		if err := s.pprofServer.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("close errors: %v", errors)
	}

	return nil
}

// Route registration methods

// GET registers a GET route with enhanced context.
func (s *Server) GET(path string, handlers ...HandlerFunc) {
	s.addRoute(MethodGET, path, handlers...)
}

// POST registers a POST route with enhanced context.
func (s *Server) POST(path string, handlers ...HandlerFunc) {
	s.addRoute(MethodPOST, path, handlers...)
}

// PUT registers a PUT route with enhanced context.
func (s *Server) PUT(path string, handlers ...HandlerFunc) {
	s.addRoute(MethodPUT, path, handlers...)
}

// PATCH registers a PATCH route with enhanced context.
func (s *Server) PATCH(path string, handlers ...HandlerFunc) {
	s.addRoute(MethodPATCH, path, handlers...)
}

// DELETE registers a DELETE route with enhanced context.
func (s *Server) DELETE(path string, handlers ...HandlerFunc) {
	s.addRoute(MethodDELETE, path, handlers...)
}

// HEAD registers a HEAD route with enhanced context.
func (s *Server) HEAD(path string, handlers ...HandlerFunc) {
	s.addRoute(MethodHEAD, path, handlers...)
}

// OPTIONS registers an OPTIONS route with enhanced context.
func (s *Server) OPTIONS(path string, handlers ...HandlerFunc) {
	s.addRoute(MethodOPTIONS, path, handlers...)
}

// Any registers a route for all HTTP methods.
func (s *Server) Any(path string, handlers ...HandlerFunc) {
	methods := []string{
		MethodGET,
		MethodPOST,
		MethodPUT,
		MethodPATCH,
		MethodDELETE,
		MethodHEAD,
		MethodOPTIONS,
	}

	for _, method := range methods {
		s.addRoute(method, path, handlers...)
	}
}

// addRoute adds a route with enhanced context wrapping.
func (s *Server) addRoute(method, path string, handlers ...HandlerFunc) {
	ginHandlers := make([]gin.HandlerFunc, len(handlers))
	for i, handler := range handlers {
		ginHandlers[i] = s.wrapHandler(handler)
	}

	switch method {
	case MethodGET:

		s.router.GET(path, ginHandlers...)
	case MethodPOST:
		s.router.POST(path, ginHandlers...)

	case MethodPUT:
		s.router.PUT(path, ginHandlers...)

	case MethodPATCH:
		s.router.PATCH(path, ginHandlers...)

	case MethodDELETE:
		s.router.DELETE(path, ginHandlers...)

	case MethodHEAD:
		s.router.HEAD(path, ginHandlers...)

	case MethodOPTIONS:
		s.router.OPTIONS(path, ginHandlers...)
	}

	s.logger.Debug("Route registered",
		"method", method,
		"path", path,
		"handlers", len(handlers))
}

// Group creates a new route group with enhanced context.
func (s *Server) Group(path string, handlers ...HandlerFunc) *RouteGroup {
	ginGroup := s.router.Group(path)
	for _, handler := range handlers {
		ginGroup.Use(s.wrapHandler(handler))
	}

	return &RouteGroup{
		group:  ginGroup,
		server: s,
	}
}

// Use adds middleware to the server.
func (s *Server) Use(handlers ...HandlerFunc) {
	for _, handler := range handlers {
		s.router.Use(s.wrapHandler(handler))
	}
}

// wrapHandler wraps an enhanced handler function for use with Gin.
func (s *Server) wrapHandler(handler HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := s.createEnhancedContext(c)
		handler(ctx)

		if !ctx.aborted && !c.Writer.Written() {
			ctx.handleAutoResponse()
		}
	}
}

// createEnhancedContext creates an enhanced context from Gin context.
func (s *Server) createEnhancedContext(c *gin.Context) *Context {
	now := time.Now()
	requestID := c.GetHeader(HeaderRequestID)
	if requestID == "" {
		requestID = generateRequestID()
		c.Header(HeaderRequestID, requestID)
	}

	traceID := c.GetHeader(HeaderTraceID)
	requestCtx := &RequestContext{
		RequestID:   requestID,
		TraceID:     traceID,
		StartTime:   now,
		Method:      c.Request.Method,
		Path:        c.Request.URL.Path,
		RemoteAddr:  c.ClientIP(),
		UserAgent:   c.GetHeader(HeaderUserAgent),
		Headers:     extractHeaders(c.Request.Header),
		QueryParams: extractQueryParams(c.Request.URL.Query()),
	}

	responseCtx := &ResponseContext{}
	securityCtx := &SecurityContext{
		ClientIP:     c.ClientIP(),
		ForwardedFor: c.GetHeader(HeaderForwardedFor),
		TLSEnabled:   c.Request.TLS != nil,
	}

	if c.Request.TLS != nil {
		securityCtx.TLSVersion = getTLSVersion(c.Request.TLS.Version)
		securityCtx.CipherSuite = getCipherSuite(c.Request.TLS.CipherSuite)
	}

	loggerEntry := s.logger.
		WithField("request_id", requestID).
		WithField("component", "server")
		
	if traceID != "" {
		loggerEntry = loggerEntry.WithField("trace_id", traceID)
	}

	return &Context{
		Context:     c,
		RequestCtx:  requestCtx,
		ResponseCtx: responseCtx,
		SecurityCtx: securityCtx,
		Logger:      loggerEntry,
		server:      s,
		startTime:   now,
		data:        make(map[string]interface{}),
	}
}

// Connection tracking for graceful shutdown

// trackConnection tracks HTTP connection state changes.
func (s *Server) trackConnection(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		atomic.AddInt64(&s.activeConns, 1)
		atomic.AddInt64(&s.totalConns, 1)
	case http.StateClosed:
		atomic.AddInt64(&s.activeConns, -1)
	}
}

// newConnectionTracker creates a new connection tracker.
func newConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		conns: make(map[*http.Server]map[*http.Request]*ConnectionState),
	}
}

// Health status management

// newHealthStatus creates a new health status tracker.
func newHealthStatus() *HealthStatus {
	return &HealthStatus{
		status:       HealthStateStarting,
		lastCheck:    time.Now(),
		dependencies: make(map[string]*DependencyHealth),
		startTime:    time.Now(),
	}
}

// GetHealthStatus returns the current health status.
func (s *Server) GetHealthStatus() *HealthCheckResult {
	s.healthStatus.mu.RLock()
	defer s.healthStatus.mu.RUnlock()

	return &HealthCheckResult{
		Status:       s.healthStatus.status,
		Timestamp:    time.Now(),
		Uptime:       time.Since(s.healthStatus.startTime),
		Dependencies: s.healthStatus.dependencies,
		Metrics:      s.GetMetrics(),
	}
}

// GetMetrics returns current server metrics.
func (s *Server) GetMetrics() *ServerMetrics {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return &ServerMetrics{
		RequestCount:      atomic.LoadInt64(&s.requestCount),
		ErrorCount:        atomic.LoadInt64(&s.errorCount),
		ActiveConnections: atomic.LoadInt64(&s.activeConns),
		TotalConnections:  atomic.LoadInt64(&s.totalConns),
		MemoryUsage:       memStats.Alloc,
		GoroutineCount:    runtime.NumGoroutine(),
		Uptime:            time.Since(s.startTime),
		StartTime:         s.startTime,
	}
}

// tcpKeepAliveListener implements TCP keep-alive for better connection management.
type tcpKeepAliveListener struct {
	*net.TCPListener
	period time.Duration
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}

	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(ln.period)
	return tc, nil
}

// RouteGroup represents an enhanced route group with server context.
type RouteGroup struct {
	group  *gin.RouterGroup
	server *Server
}

// GET registers a GET route in the group.
func (rg *RouteGroup) GET(path string, handlers ...HandlerFunc) {
	rg.addRoute(MethodGET, path, handlers...)
}

// POST registers a POST route in the group.
func (rg *RouteGroup) POST(path string, handlers ...HandlerFunc) {
	rg.addRoute(MethodPOST, path, handlers...)
}

// PUT registers a PUT route in the group.
func (rg *RouteGroup) PUT(path string, handlers ...HandlerFunc) {
	rg.addRoute(MethodPUT, path, handlers...)
}

// PATCH registers a PATCH route in the group.
func (rg *RouteGroup) PATCH(path string, handlers ...HandlerFunc) {
	rg.addRoute(MethodPATCH, path, handlers...)
}

// DELETE registers a DELETE route in the group.
func (rg *RouteGroup) DELETE(path string, handlers ...HandlerFunc) {
	rg.addRoute(MethodDELETE, path, handlers...)
}

// Use adds middleware to the route group.
func (rg *RouteGroup) Use(handlers ...HandlerFunc) {
	for _, handler := range handlers {
		rg.group.Use(rg.server.wrapHandler(handler))
	}
}

// Group creates a sub-group.
func (rg *RouteGroup) Group(path string, handlers ...HandlerFunc) *RouteGroup {
	subGroup := rg.group.Group(path)
	for _, handler := range handlers {
		subGroup.Use(rg.server.wrapHandler(handler))
	}

	return &RouteGroup{
		group:  subGroup,
		server: rg.server,
	}
}

// addRoute adds a route to the group.
func (rg *RouteGroup) addRoute(method, path string, handlers ...HandlerFunc) {
	ginHandlers := make([]gin.HandlerFunc, len(handlers))
	for i, handler := range handlers {
		ginHandlers[i] = rg.server.wrapHandler(handler)
	}

	switch method {
	case MethodGET:
		rg.group.GET(path, ginHandlers...)

	case MethodPOST:
		rg.group.POST(path, ginHandlers...)

	case MethodPUT:
		rg.group.PUT(path, ginHandlers...)

	case MethodPATCH:
		rg.group.PATCH(path, ginHandlers...)

	case MethodDELETE:
		rg.group.DELETE(path, ginHandlers...)
	}
}
