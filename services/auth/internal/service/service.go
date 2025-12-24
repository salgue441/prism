// Package service provides the business logic for the auth service.
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/carlossalguero/prism/services/auth/internal/jwt"
	"github.com/carlossalguero/prism/services/auth/internal/oauth"
	"github.com/carlossalguero/prism/services/auth/internal/repository"
	"github.com/carlossalguero/prism/services/shared/errors"
)

// Config holds the auth service configuration.
type Config struct {
	Repository     repository.Repository
	JWTManager     *jwt.Manager
	OAuthProviders map[string]oauth.Provider
	Cache          CacheClient
	Events         EventClient
}

// CacheClient defines the interface for caching operations.
type CacheClient interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, expiration time.Duration) error
	GetJSON(ctx context.Context, key string, dest any) error
	SetJSON(ctx context.Context, key string, value any, expiration time.Duration) error
	Delete(ctx context.Context, keys ...string) error
	Exists(ctx context.Context, key string) (bool, error)
	SAdd(ctx context.Context, key string, members ...any) error
	SIsMember(ctx context.Context, key string, member any) (bool, error)
	SRem(ctx context.Context, key string, members ...any) error
	Ping(ctx context.Context) error
}

// EventClient defines the interface for event publishing.
type EventClient interface {
	PublishUserEvent(ctx context.Context, eventType string, userID string, data map[string]any) error
	PublishJSON(ctx context.Context, subject string, v any) error
	IsConnected() bool
}

// Cache key prefixes.
const (
	cacheKeyToken         = "token:"
	cacheKeyAPIKey        = "apikey:"
	cacheKeyRevokedTokens = "revoked:"
	cacheKeySession       = "session:"
)

// Cache TTLs.
const (
	tokenCacheTTL    = 5 * time.Minute
	apiKeyCacheTTL   = 10 * time.Minute
	revokedCacheTTL  = 24 * time.Hour
)

// Service provides authentication business logic.
type Service struct {
	repo           repository.Repository
	jwt            *jwt.Manager
	oauthProviders map[string]oauth.Provider
	cache          CacheClient
	events         EventClient
}

// New creates a new auth service.
func New(cfg Config) *Service {
	return &Service{
		repo:           cfg.Repository,
		jwt:            cfg.JWTManager,
		oauthProviders: cfg.OAuthProviders,
		cache:          cfg.Cache,
		events:         cfg.Events,
	}
}

// TokenPair represents an access and refresh token pair.
type TokenPair struct {
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
}

// User represents a user.
type User struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Provider      string
	Roles         []string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// RegisterInput holds the input for user registration.
type RegisterInput struct {
	Email    string
	Password string
	Name     string
}

// Register creates a new user account.
func (s *Service) Register(ctx context.Context, input RegisterInput) (*User, *TokenPair, error) {
	// Validate password strength
	if len(input.Password) < 8 {
		return nil, nil, errors.New(errors.CodePasswordTooWeak, "password must be at least 8 characters")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, errors.InternalWrap("hashing password", err)
	}

	passwordHash := string(hashedPassword)

	// Create user
	user := &repository.User{
		Email:         input.Email,
		EmailVerified: false,
		PasswordHash:  &passwordHash,
		Name:          input.Name,
		Provider:      "local",
		Roles:         []string{"user"},
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, nil, err
	}

	// Generate tokens
	tokens, err := s.createTokens(ctx, user, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	// Publish user created event
	s.publishEvent(ctx, "user.created", user.ID.String(), map[string]any{
		"email":    user.Email,
		"name":     user.Name,
		"provider": user.Provider,
	})

	return userFromRepo(user), tokens, nil
}

// LoginInput holds the input for user login.
type LoginInput struct {
	Email     string
	Password  string
	UserAgent string
	IPAddress string
}

// Login authenticates a user with email and password.
func (s *Service) Login(ctx context.Context, input LoginInput) (*User, *TokenPair, error) {
	user, err := s.repo.GetUserByEmail(ctx, input.Email)
	if err != nil {
		if errors.IsCode(err, errors.CodeNotFound) {
			return nil, nil, errors.InvalidCredentials("invalid email or password")
		}
		return nil, nil, err
	}

	if user.Disabled {
		return nil, nil, errors.New(errors.CodeUserDisabled, "account is disabled")
	}

	if user.PasswordHash == nil {
		return nil, nil, errors.InvalidCredentials("invalid email or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(input.Password)); err != nil {
		return nil, nil, errors.InvalidCredentials("invalid email or password")
	}

	tokens, err := s.createTokens(ctx, user, &input.UserAgent, &input.IPAddress)
	if err != nil {
		return nil, nil, err
	}

	// Publish user login event
	s.publishEvent(ctx, "user.login", user.ID.String(), map[string]any{
		"email":      user.Email,
		"ip_address": input.IPAddress,
		"user_agent": input.UserAgent,
	})

	return userFromRepo(user), tokens, nil
}

// Logout revokes a refresh token.
func (s *Service) Logout(ctx context.Context, refreshToken string, revokeAll bool) error {
	tokenHash := hashRefreshToken(refreshToken)
	session, err := s.repo.GetSessionByRefreshToken(ctx, tokenHash)
	if err != nil {
		return err
	}

	if revokeAll {
		return s.repo.RevokeAllUserSessions(ctx, session.UserID)
	}

	return s.repo.RevokeSession(ctx, session.ID)
}

// RefreshToken refreshes an access token using a refresh token.
func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error) {
	tokenHash := hashRefreshToken(refreshToken)
	session, err := s.repo.GetSessionByRefreshToken(ctx, tokenHash)
	if err != nil {
		if errors.IsCode(err, errors.CodeNotFound) {
			return nil, errors.New(errors.CodeInvalidRefreshToken, "invalid or expired refresh token")
		}
		return nil, err
	}

	user, err := s.repo.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, err
	}

	if user.Disabled {
		return nil, errors.New(errors.CodeUserDisabled, "account is disabled")
	}

	// Update session last used
	if err := s.repo.UpdateSessionLastUsed(ctx, session.ID); err != nil {
		return nil, err
	}

	// Generate new access token (keep same session)
	accessToken, expiresAt, err := s.jwt.GenerateAccessToken(
		user.ID.String(), user.Email, user.Roles, session.ID.String(),
	)
	if err != nil {
		return nil, errors.InternalWrap("generating access token", err)
	}

	return &TokenPair{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken, // Return same refresh token
		AccessTokenExpiresAt:  expiresAt,
		RefreshTokenExpiresAt: session.ExpiresAt,
	}, nil
}

// ValidateToken validates an access token.
func (s *Service) ValidateToken(ctx context.Context, token string) (*jwt.Claims, error) {
	claims, err := s.jwt.ValidateToken(token)
	if err != nil {
		return nil, err
	}

	// Check if token is revoked (check cache first)
	jti, err := uuid.Parse(claims.ID)
	if err == nil {
		revoked, err := s.isTokenRevoked(ctx, jti)
		if err != nil {
			return nil, errors.InternalWrap("checking token revocation", err)
		}
		if revoked {
			return nil, errors.New(errors.CodeTokenRevoked, "token has been revoked")
		}
	}

	return claims, nil
}

// isTokenRevoked checks if a token is revoked, using cache when available.
func (s *Service) isTokenRevoked(ctx context.Context, jti uuid.UUID) (bool, error) {
	cacheKey := cacheKeyRevokedTokens + jti.String()

	// Check cache first
	if s.cache != nil {
		exists, err := s.cache.Exists(ctx, cacheKey)
		if err == nil && exists {
			return true, nil
		}
	}

	// Check database
	revoked, err := s.repo.IsTokenRevoked(ctx, jti)
	if err != nil {
		return false, err
	}

	// Cache the result if revoked
	if revoked && s.cache != nil {
		_ = s.cache.Set(ctx, cacheKey, "1", revokedCacheTTL)
	}

	return revoked, nil
}

// RevokeToken revokes an access token.
func (s *Service) RevokeToken(ctx context.Context, token string, revokeAllSessions bool) error {
	claims, err := s.jwt.ValidateToken(token)
	if err != nil {
		// Still try to extract token ID for revocation
		jti, extractErr := s.jwt.ExtractTokenID(token)
		if extractErr != nil {
			return err
		}
		// Revoke even if expired
		userID, _ := uuid.Parse(claims.UserID)
		jtiUUID, _ := uuid.Parse(jti)
		if err := s.repo.RevokeToken(ctx, jtiUUID, userID, time.Now().Add(24*time.Hour)); err != nil {
			return err
		}
		// Cache the revocation
		s.cacheTokenRevocation(ctx, jtiUUID)
		return nil
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return errors.InvalidInput("invalid user ID in token")
	}

	jti, err := uuid.Parse(claims.ID)
	if err != nil {
		return errors.InvalidInput("invalid token ID")
	}

	if err := s.repo.RevokeToken(ctx, jti, userID, claims.ExpiresAt.Time); err != nil {
		return err
	}

	// Cache the revocation
	s.cacheTokenRevocation(ctx, jti)

	// Publish token revoked event
	s.publishEvent(ctx, "token.revoked", claims.UserID, map[string]any{
		"token_id": jti.String(),
	})

	if revokeAllSessions {
		return s.repo.RevokeAllUserSessions(ctx, userID)
	}

	return nil
}

// cacheTokenRevocation caches a token revocation.
func (s *Service) cacheTokenRevocation(ctx context.Context, jti uuid.UUID) {
	if s.cache != nil {
		cacheKey := cacheKeyRevokedTokens + jti.String()
		_ = s.cache.Set(ctx, cacheKey, "1", revokedCacheTTL)
	}
}

// GetOAuthURL returns the OAuth authorization URL for a provider.
func (s *Service) GetOAuthURL(ctx context.Context, providerName, redirectURI string) (string, string, error) {
	provider, ok := s.oauthProviders[providerName]
	if !ok {
		return "", "", errors.InvalidInput(fmt.Sprintf("unsupported OAuth provider: %s", providerName))
	}

	state, err := generateRandomString(32)
	if err != nil {
		return "", "", errors.InternalWrap("generating state", err)
	}

	// Store state for CSRF protection
	oauthState := &repository.OAuthState{
		State:       state,
		Provider:    providerName,
		RedirectURI: &redirectURI,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	if err := s.repo.CreateOAuthState(ctx, oauthState); err != nil {
		return "", "", errors.InternalWrap("storing OAuth state", err)
	}

	url := provider.GetAuthURL(state)
	return url, state, nil
}

// HandleOAuthCallback handles the OAuth callback.
func (s *Service) HandleOAuthCallback(ctx context.Context, providerName, code, state string) (*User, *TokenPair, error) {
	// Validate state
	oauthState, err := s.repo.GetAndDeleteOAuthState(ctx, state)
	if err != nil {
		return nil, nil, errors.OAuthError("invalid or expired OAuth state")
	}

	if oauthState.Provider != providerName {
		return nil, nil, errors.OAuthError("OAuth provider mismatch")
	}

	provider, ok := s.oauthProviders[providerName]
	if !ok {
		return nil, nil, errors.InvalidInput(fmt.Sprintf("unsupported OAuth provider: %s", providerName))
	}

	// Exchange code for user info
	userInfo, err := provider.Exchange(ctx, code)
	if err != nil {
		return nil, nil, errors.OAuthError(fmt.Sprintf("OAuth exchange failed: %v", err))
	}

	// Find or create user
	user, err := s.repo.GetUserByProvider(ctx, providerName, userInfo.ID)
	if err != nil {
		if !errors.IsCode(err, errors.CodeNotFound) {
			return nil, nil, err
		}

		// Check if user exists with same email
		existingUser, err := s.repo.GetUserByEmail(ctx, userInfo.Email)
		if err != nil && !errors.IsCode(err, errors.CodeNotFound) {
			return nil, nil, err
		}

		if existingUser != nil {
			// Link OAuth to existing account
			existingUser.Provider = providerName
			existingUser.ProviderID = &userInfo.ID
			if existingUser.Picture == nil && userInfo.Picture != "" {
				existingUser.Picture = &userInfo.Picture
			}
			if err := s.repo.UpdateUser(ctx, existingUser); err != nil {
				return nil, nil, err
			}
			user = existingUser
		} else {
			// Create new user
			user = &repository.User{
				Email:         userInfo.Email,
				EmailVerified: userInfo.EmailVerified,
				Name:          userInfo.Name,
				Picture:       &userInfo.Picture,
				Provider:      providerName,
				ProviderID:    &userInfo.ID,
				Roles:         []string{"user"},
			}
			if err := s.repo.CreateUser(ctx, user); err != nil {
				return nil, nil, err
			}
		}
	}

	if user.Disabled {
		return nil, nil, errors.New(errors.CodeUserDisabled, "account is disabled")
	}

	tokens, err := s.createTokens(ctx, user, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	return userFromRepo(user), tokens, nil
}

// APIKeyInput holds the input for creating an API key.
type APIKeyInput struct {
	UserID        string
	Name          string
	Scopes        []string
	ExpiresInDays int64
}

// APIKey represents an API key.
type APIKey struct {
	ID         string
	Name       string
	Prefix     string
	UserID     string
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
}

// CreateAPIKey creates a new API key.
func (s *Service) CreateAPIKey(ctx context.Context, input APIKeyInput) (*APIKey, string, error) {
	userID, err := uuid.Parse(input.UserID)
	if err != nil {
		return nil, "", errors.InvalidInput("invalid user ID")
	}

	// Generate API key
	key, err := generateAPIKey()
	if err != nil {
		return nil, "", errors.InternalWrap("generating API key", err)
	}

	var expiresAt *time.Time
	if input.ExpiresInDays > 0 {
		t := time.Now().Add(time.Duration(input.ExpiresInDays) * 24 * time.Hour)
		expiresAt = &t
	}

	apiKey := &repository.APIKey{
		UserID:    userID,
		Name:      input.Name,
		KeyHash:   repository.HashAPIKey(key),
		KeyPrefix: key[:8],
		Scopes:    input.Scopes,
		ExpiresAt: expiresAt,
	}

	if err := s.repo.CreateAPIKey(ctx, apiKey); err != nil {
		return nil, "", err
	}

	// Publish API key created event
	s.publishEvent(ctx, "apikey.created", input.UserID, map[string]any{
		"key_id":   apiKey.ID.String(),
		"key_name": input.Name,
		"scopes":   input.Scopes,
	})

	return apiKeyFromRepo(apiKey), key, nil
}

// ValidateAPIKey validates an API key.
func (s *Service) ValidateAPIKey(ctx context.Context, key string) (*APIKey, error) {
	keyHash := repository.HashAPIKey(key)
	cacheKey := cacheKeyAPIKey + keyHash[:16] // Use first 16 chars of hash for cache key

	// Check cache first
	if s.cache != nil {
		var cachedKey APIKey
		if err := s.cache.GetJSON(ctx, cacheKey, &cachedKey); err == nil {
			// Update last used asynchronously
			go func() {
				keyID, _ := uuid.Parse(cachedKey.ID)
				_ = s.repo.UpdateAPIKeyLastUsed(context.Background(), keyID)
			}()
			return &cachedKey, nil
		}
	}

	// Fetch from database
	apiKey, err := s.repo.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		if errors.IsCode(err, errors.CodeNotFound) {
			return nil, errors.APIKeyInvalid("invalid API key")
		}
		return nil, err
	}

	result := apiKeyFromRepo(apiKey)

	// Cache the result
	if s.cache != nil {
		_ = s.cache.SetJSON(ctx, cacheKey, result, apiKeyCacheTTL)
	}

	// Update last used
	_ = s.repo.UpdateAPIKeyLastUsed(ctx, apiKey.ID)

	return result, nil
}

// RevokeAPIKey revokes an API key.
func (s *Service) RevokeAPIKey(ctx context.Context, id string) error {
	keyID, err := uuid.Parse(id)
	if err != nil {
		return errors.InvalidInput("invalid API key ID")
	}

	// Get the API key to find user ID for event
	apiKey, err := s.repo.GetAPIKeyByID(ctx, keyID)
	if err != nil {
		return err
	}

	if err := s.repo.RevokeAPIKey(ctx, keyID); err != nil {
		return err
	}

	// Invalidate cache
	if s.cache != nil {
		cacheKey := cacheKeyAPIKey + apiKey.KeyHash[:16]
		_ = s.cache.Delete(ctx, cacheKey)
	}

	// Publish API key revoked event
	s.publishEvent(ctx, "apikey.revoked", apiKey.UserID.String(), map[string]any{
		"key_id":   id,
		"key_name": apiKey.Name,
	})

	return nil
}

// ListAPIKeys lists API keys for a user.
func (s *Service) ListAPIKeys(ctx context.Context, userID string, page, pageSize int) ([]APIKey, int, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, 0, errors.InvalidInput("invalid user ID")
	}

	if pageSize <= 0 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100
	}
	offset := page * pageSize

	keys, total, err := s.repo.ListAPIKeys(ctx, uid, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}

	result := make([]APIKey, len(keys))
	for i, k := range keys {
		result[i] = *apiKeyFromRepo(&k)
	}

	return result, total, nil
}

// GetUser retrieves a user by ID.
func (s *Service) GetUser(ctx context.Context, id string) (*User, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.InvalidInput("invalid user ID")
	}

	user, err := s.repo.GetUserByID(ctx, uid)
	if err != nil {
		return nil, err
	}

	return userFromRepo(user), nil
}

// UpdateUser updates a user.
func (s *Service) UpdateUser(ctx context.Context, id string, name, picture *string) (*User, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.InvalidInput("invalid user ID")
	}

	user, err := s.repo.GetUserByID(ctx, uid)
	if err != nil {
		return nil, err
	}

	if name != nil {
		user.Name = *name
	}
	if picture != nil {
		user.Picture = picture
	}

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	return userFromRepo(user), nil
}

// DeleteUser deletes a user.
func (s *Service) DeleteUser(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return errors.InvalidInput("invalid user ID")
	}

	return s.repo.DeleteUser(ctx, uid)
}

// Helper functions

func (s *Service) createTokens(ctx context.Context, user *repository.User, userAgent, ipAddress *string) (*TokenPair, error) {
	jwtTokens, err := s.jwt.GenerateTokenPair(user.ID.String(), user.Email, user.Roles)
	if err != nil {
		return nil, errors.InternalWrap("generating tokens", err)
	}

	// Store session
	session := &repository.Session{
		UserID:           user.ID,
		RefreshTokenHash: hashRefreshToken(jwtTokens.RefreshToken),
		UserAgent:        userAgent,
		IPAddress:        ipAddress,
		ExpiresAt:        jwtTokens.RefreshTokenExpiresAt,
	}

	if err := s.repo.CreateSession(ctx, session); err != nil {
		return nil, errors.InternalWrap("creating session", err)
	}

	return &TokenPair{
		AccessToken:           jwtTokens.AccessToken,
		RefreshToken:          jwtTokens.RefreshToken,
		AccessTokenExpiresAt:  jwtTokens.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: jwtTokens.RefreshTokenExpiresAt,
	}, nil
}

func userFromRepo(u *repository.User) *User {
	user := &User{
		ID:            u.ID.String(),
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Provider:      u.Provider,
		Roles:         u.Roles,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
	if u.Picture != nil {
		user.Picture = *u.Picture
	}
	return user
}

func apiKeyFromRepo(k *repository.APIKey) *APIKey {
	apiKey := &APIKey{
		ID:        k.ID.String(),
		Name:      k.Name,
		Prefix:    k.KeyPrefix,
		UserID:    k.UserID.String(),
		Scopes:    k.Scopes,
		CreatedAt: k.CreatedAt,
	}
	if k.ExpiresAt != nil {
		apiKey.ExpiresAt = k.ExpiresAt
	}
	if k.LastUsedAt != nil {
		apiKey.LastUsedAt = k.LastUsedAt
	}
	return apiKey
}

func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

func generateAPIKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("prism_%s", base64.URLEncoding.EncodeToString(bytes)[:40]), nil
}

func hashRefreshToken(token string) string {
	return repository.HashAPIKey(token) // Reuse the same hashing function
}

// publishEvent publishes an event if the events client is available.
func (s *Service) publishEvent(ctx context.Context, eventType, userID string, data map[string]any) {
	if s.events == nil || !s.events.IsConnected() {
		return
	}
	// Fire and forget - don't block on event publishing
	go func() {
		_ = s.events.PublishUserEvent(context.Background(), eventType, userID, data)
	}()
}
