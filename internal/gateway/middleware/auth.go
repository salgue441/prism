// Package middleware provides authentication middleware for the gateway.
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/carlossalguero/prism/internal/shared/errors"
	"github.com/carlossalguero/prism/internal/shared/logger"
)

// userContextKey is the context key for authenticated user info.
type userContextKey struct{}

// UserInfo represents authenticated user information.
type UserInfo struct {
	ID        string
	Email     string
	Roles     []string
	SessionID string
}

// TokenValidator defines the interface for token validation.
type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) (*UserInfo, error)
	ValidateAPIKey(ctx context.Context, key string) (*UserInfo, []string, error) // returns user info and scopes
}

// AuthConfig holds authentication middleware configuration.
type AuthConfig struct {
	Validator       TokenValidator
	RequiredRoles   []string
	RequiredScopes  []string
	SkipPaths       []string
	Logger          *logger.Logger
}

// Auth returns middleware that validates JWT tokens or API keys.
func Auth(cfg AuthConfig) func(http.Handler) http.Handler {
	skipPaths := make(map[string]bool)
	for _, p := range cfg.SkipPaths {
		skipPaths[p] = true
	}

	log := cfg.Logger
	if log == nil {
		log = logger.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip paths that don't require auth
			if skipPaths[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			// Try to extract token
			var userInfo *UserInfo
			var scopes []string
			var err error

			// Check Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				if strings.HasPrefix(authHeader, "Bearer ") {
					// JWT token
					token := strings.TrimPrefix(authHeader, "Bearer ")
					userInfo, err = cfg.Validator.ValidateToken(r.Context(), token)
				} else if strings.HasPrefix(authHeader, "ApiKey ") {
					// API key
					key := strings.TrimPrefix(authHeader, "ApiKey ")
					userInfo, scopes, err = cfg.Validator.ValidateAPIKey(r.Context(), key)
				} else {
					err = errors.Unauthorized("invalid authorization header format")
				}
			} else {
				// Check X-API-Key header
				apiKey := r.Header.Get("X-API-Key")
				if apiKey != "" {
					userInfo, scopes, err = cfg.Validator.ValidateAPIKey(r.Context(), apiKey)
				} else {
					err = errors.Unauthorized("missing authorization")
				}
			}

			if err != nil {
				log.WithContext(r.Context()).Warn("authentication failed",
					"error", err,
					"path", r.URL.Path,
				)
				writeAuthError(w, err)
				return
			}

			// Check required roles
			if len(cfg.RequiredRoles) > 0 && !hasAnyRole(userInfo.Roles, cfg.RequiredRoles) {
				log.WithContext(r.Context()).Warn("insufficient roles",
					"user_id", userInfo.ID,
					"required", cfg.RequiredRoles,
					"has", userInfo.Roles,
				)
				writeAuthError(w, errors.Forbidden("insufficient permissions"))
				return
			}

			// Check required scopes (for API keys)
			if len(cfg.RequiredScopes) > 0 && len(scopes) > 0 {
				if !hasAllScopes(scopes, cfg.RequiredScopes) {
					log.WithContext(r.Context()).Warn("insufficient scopes",
						"user_id", userInfo.ID,
						"required", cfg.RequiredScopes,
						"has", scopes,
					)
					writeAuthError(w, errors.InsufficientScope("insufficient API key scopes"))
					return
				}
			}

			// Add user info to context
			ctx := context.WithValue(r.Context(), userContextKey{}, userInfo)
			ctx = context.WithValue(ctx, logger.UserIDKey, userInfo.ID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserInfo extracts user information from the request context.
func GetUserInfo(ctx context.Context) *UserInfo {
	if info, ok := ctx.Value(userContextKey{}).(*UserInfo); ok {
		return info
	}
	return nil
}

// OptionalAuth returns middleware that validates tokens but doesn't require them.
func OptionalAuth(validator TokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var userInfo *UserInfo

			// Check Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				if strings.HasPrefix(authHeader, "Bearer ") {
					token := strings.TrimPrefix(authHeader, "Bearer ")
					userInfo, _ = validator.ValidateToken(r.Context(), token)
				} else if strings.HasPrefix(authHeader, "ApiKey ") {
					key := strings.TrimPrefix(authHeader, "ApiKey ")
					userInfo, _, _ = validator.ValidateAPIKey(r.Context(), key)
				}
			} else {
				apiKey := r.Header.Get("X-API-Key")
				if apiKey != "" {
					userInfo, _, _ = validator.ValidateAPIKey(r.Context(), apiKey)
				}
			}

			if userInfo != nil {
				ctx := context.WithValue(r.Context(), userContextKey{}, userInfo)
				ctx = context.WithValue(ctx, logger.UserIDKey, userInfo.ID)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RoleRequired returns middleware that checks for required roles.
func RoleRequired(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userInfo := GetUserInfo(r.Context())
			if userInfo == nil {
				writeAuthError(w, errors.Unauthorized("authentication required"))
				return
			}

			if !hasAnyRole(userInfo.Roles, roles) {
				writeAuthError(w, errors.Forbidden("insufficient permissions"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Helper functions

func hasAnyRole(userRoles, requiredRoles []string) bool {
	roleMap := make(map[string]bool)
	for _, r := range userRoles {
		roleMap[r] = true
	}

	for _, required := range requiredRoles {
		if roleMap[required] {
			return true
		}
	}
	return false
}

func hasAllScopes(userScopes, requiredScopes []string) bool {
	scopeMap := make(map[string]bool)
	for _, s := range userScopes {
		scopeMap[s] = true
	}

	for _, required := range requiredScopes {
		if !scopeMap[required] {
			return false
		}
	}
	return true
}

func writeAuthError(w http.ResponseWriter, err error) {
	var appErr *errors.Error
	if e, ok := err.(*errors.Error); ok {
		appErr = e
	} else {
		appErr = errors.Unauthorized(err.Error())
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(appErr.HTTPStatusCode())

	response := `{"error":"` + appErr.Message + `","code":"` + string(appErr.Code) + `"}`
	w.Write([]byte(response))
}
