// Package auth provides authentication validation with caching support.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/carlossalguero/prism/services/gateway/internal/middleware"
	pb "github.com/carlossalguero/prism/services/shared/proto/gen"
)

// CacheClient defines the interface for caching operations.
type CacheClient interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, expiration time.Duration) error
	Delete(ctx context.Context, keys ...string) error
}

// Config holds validator configuration.
type Config struct {
	AuthServiceAddress string
	Cache              CacheClient
	TokenCacheTTL      time.Duration
	APIKeyCacheTTL     time.Duration
}

// Validator validates tokens and API keys using the Auth service.
type Validator struct {
	authClient     pb.AuthServiceClient
	conn           *grpc.ClientConn
	cache          CacheClient
	tokenCacheTTL  time.Duration
	apiKeyCacheTTL time.Duration
}

// CachedUserInfo is the cached version of user info.
type CachedUserInfo struct {
	ID        string   `json:"id"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	SessionID string   `json:"session_id"`
}

// CachedAPIKeyInfo is the cached version of API key validation.
type CachedAPIKeyInfo struct {
	UserInfo CachedUserInfo `json:"user_info"`
	Scopes   []string       `json:"scopes"`
}

// NewValidator creates a new validator.
func NewValidator(cfg Config) (*Validator, error) {
	conn, err := grpc.NewClient(
		cfg.AuthServiceAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}

	tokenTTL := cfg.TokenCacheTTL
	if tokenTTL == 0 {
		tokenTTL = 5 * time.Minute
	}

	apiKeyTTL := cfg.APIKeyCacheTTL
	if apiKeyTTL == 0 {
		apiKeyTTL = 10 * time.Minute
	}

	return &Validator{
		authClient:     pb.NewAuthServiceClient(conn),
		conn:           conn,
		cache:          cfg.Cache,
		tokenCacheTTL:  tokenTTL,
		apiKeyCacheTTL: apiKeyTTL,
	}, nil
}

// Close closes the gRPC connection.
func (v *Validator) Close() error {
	if v.conn != nil {
		return v.conn.Close()
	}
	return nil
}

// ValidateToken validates a JWT token.
func (v *Validator) ValidateToken(ctx context.Context, token string) (*middleware.UserInfo, error) {
	cacheKey := "token:" + hashToken(token)

	// Check cache first
	if v.cache != nil {
		cached, err := v.cache.Get(ctx, cacheKey)
		if err == nil && cached != "" {
			var info CachedUserInfo
			if err := json.Unmarshal([]byte(cached), &info); err == nil {
				return &middleware.UserInfo{
					ID:        info.ID,
					Email:     info.Email,
					Roles:     info.Roles,
					SessionID: info.SessionID,
				}, nil
			}
		}
	}

	// Call Auth service
	resp, err := v.authClient.ValidateToken(ctx, &pb.ValidateTokenRequest{
		Token: token,
	})
	if err != nil {
		return nil, err
	}

	if !resp.Valid || resp.Claims == nil {
		return nil, fmt.Errorf("invalid token: %s", resp.Error)
	}

	userInfo := &middleware.UserInfo{
		ID:        resp.Claims.UserId,
		Email:     resp.Claims.Email,
		Roles:     resp.Claims.Roles,
		SessionID: resp.Claims.SessionId,
	}

	// Cache the result
	if v.cache != nil {
		cached := CachedUserInfo{
			ID:        userInfo.ID,
			Email:     userInfo.Email,
			Roles:     userInfo.Roles,
			SessionID: userInfo.SessionID,
		}
		data, _ := json.Marshal(cached)
		_ = v.cache.Set(ctx, cacheKey, string(data), v.tokenCacheTTL)
	}

	return userInfo, nil
}

// ValidateAPIKey validates an API key.
func (v *Validator) ValidateAPIKey(ctx context.Context, key string) (*middleware.UserInfo, []string, error) {
	cacheKey := "apikey:" + hashToken(key)

	// Check cache first
	if v.cache != nil {
		cached, err := v.cache.Get(ctx, cacheKey)
		if err == nil && cached != "" {
			var info CachedAPIKeyInfo
			if err := json.Unmarshal([]byte(cached), &info); err == nil {
				return &middleware.UserInfo{
					ID:        info.UserInfo.ID,
					Email:     info.UserInfo.Email,
					Roles:     info.UserInfo.Roles,
					SessionID: info.UserInfo.SessionID,
				}, info.Scopes, nil
			}
		}
	}

	// Call Auth service
	resp, err := v.authClient.ValidateAPIKey(ctx, &pb.ValidateAPIKeyRequest{
		Key: key,
	})
	if err != nil {
		return nil, nil, err
	}

	if !resp.Valid || resp.ApiKey == nil {
		return nil, nil, fmt.Errorf("invalid API key: %s", resp.Error)
	}

	userInfo := &middleware.UserInfo{
		ID:    resp.ApiKey.UserId,
		Roles: resp.ApiKey.Scopes, // API keys use scopes as roles for authorization
	}

	// Cache the result
	if v.cache != nil {
		cached := CachedAPIKeyInfo{
			UserInfo: CachedUserInfo{
				ID:    userInfo.ID,
				Roles: userInfo.Roles,
			},
			Scopes: resp.ApiKey.Scopes,
		}
		data, _ := json.Marshal(cached)
		_ = v.cache.Set(ctx, cacheKey, string(data), v.apiKeyCacheTTL)
	}

	return userInfo, resp.ApiKey.Scopes, nil
}

// hashToken creates a hash of the token for cache key.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:16]) // Use first 16 bytes
}
