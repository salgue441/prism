// Package middleware provides request events middleware for publishing to NATS.
package middleware

import (
	"context"
	"net/http"
	"time"
)

// EventPublisher defines the interface for publishing events.
type EventPublisher interface {
	PublishJSON(ctx context.Context, subject string, v any) error
	IsConnected() bool
}

// RequestEvent represents a logged request event.
type RequestEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	RequestID    string    `json:"request_id"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	StatusCode   int       `json:"status_code"`
	Duration     int64     `json:"duration_ms"`
	UserID       string    `json:"user_id,omitempty"`
	RemoteAddr   string    `json:"remote_addr"`
	UserAgent    string    `json:"user_agent"`
	ContentType  string    `json:"content_type,omitempty"`
	RequestSize  int64     `json:"request_size"`
	ResponseSize int64     `json:"response_size"`
}

// EventsConfig holds events middleware configuration.
type EventsConfig struct {
	Publisher EventPublisher
	Subject   string
}

// responseRecorder wraps ResponseWriter to capture status code and size.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	size       int64
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.size += int64(n)
	return n, err
}

// Events returns middleware that publishes request events to NATS.
func Events(cfg EventsConfig) func(http.Handler) http.Handler {
	if cfg.Subject == "" {
		cfg.Subject = "prism.gateway.request.logged"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if publisher is not available
			if cfg.Publisher == nil || !cfg.Publisher.IsConnected() {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()

			// Wrap response writer to capture status and size
			recorder := &responseRecorder{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Process request
			next.ServeHTTP(recorder, r)

			// Build event asynchronously (fire and forget)
			go func() {
				event := RequestEvent{
					Timestamp:    start,
					RequestID:    GetRequestID(r.Context()),
					Method:       r.Method,
					Path:         r.URL.Path,
					StatusCode:   recorder.statusCode,
					Duration:     time.Since(start).Milliseconds(),
					RemoteAddr:   r.RemoteAddr,
					UserAgent:    r.UserAgent(),
					ContentType:  r.Header.Get("Content-Type"),
					RequestSize:  r.ContentLength,
					ResponseSize: recorder.size,
				}

				// Add user ID if authenticated
				if userInfo := GetUserInfo(r.Context()); userInfo != nil {
					event.UserID = userInfo.ID
				}

				// Publish event (fire and forget)
				_ = cfg.Publisher.PublishJSON(context.Background(), cfg.Subject, event)
			}()
		})
	}
}
