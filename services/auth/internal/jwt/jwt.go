// Package jwt provides JWT token generation and validation using RS256.
package jwt

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/carlossalguero/prism/services/shared/errors"
)

// Claims represents the JWT claims.
type Claims struct {
	jwt.RegisteredClaims
	UserID    string   `json:"user_id"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	SessionID string   `json:"session_id"`
}

// Config holds JWT configuration.
type Config struct {
	PrivateKeyPath  string
	PublicKeyPath   string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	Issuer          string
}

// Manager handles JWT operations.
type Manager struct {
	privateKey      *rsa.PrivateKey
	publicKey       *rsa.PublicKey
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	issuer          string
}

// NewManager creates a new JWT manager.
func NewManager(cfg Config) (*Manager, error) {
	privateKey, err := LoadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading private key: %w", err)
	}

	publicKey, err := LoadPublicKey(cfg.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading public key: %w", err)
	}

	return &Manager{
		privateKey:      privateKey,
		publicKey:       publicKey,
		accessTokenTTL:  cfg.AccessTokenTTL,
		refreshTokenTTL: cfg.RefreshTokenTTL,
		issuer:          cfg.Issuer,
	}, nil
}

// NewManagerWithKeys creates a JWT manager with provided keys.
func NewManagerWithKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, cfg Config) *Manager {
	return &Manager{
		privateKey:      privateKey,
		publicKey:       publicKey,
		accessTokenTTL:  cfg.AccessTokenTTL,
		refreshTokenTTL: cfg.RefreshTokenTTL,
		issuer:          cfg.Issuer,
	}
}

// TokenPair represents an access and refresh token pair.
type TokenPair struct {
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
	SessionID             string
}

// GenerateTokenPair generates a new access and refresh token pair.
func (m *Manager) GenerateTokenPair(userID, email string, roles []string) (*TokenPair, error) {
	sessionID := uuid.New().String()
	now := time.Now()

	// Generate access token
	accessToken, accessExp, err := m.generateToken(userID, email, roles, sessionID, m.accessTokenTTL, now)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	// Generate refresh token
	refreshToken, refreshExp, err := m.generateToken(userID, email, roles, sessionID, m.refreshTokenTTL, now)
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessExp,
		RefreshTokenExpiresAt: refreshExp,
		SessionID:             sessionID,
	}, nil
}

// GenerateAccessToken generates a new access token for an existing session.
func (m *Manager) GenerateAccessToken(userID, email string, roles []string, sessionID string) (string, time.Time, error) {
	return m.generateToken(userID, email, roles, sessionID, m.accessTokenTTL, time.Now())
}

func (m *Manager) generateToken(userID, email string, roles []string, sessionID string, ttl time.Duration, now time.Time) (string, time.Time, error) {
	expiresAt := now.Add(ttl)
	jti := uuid.New().String()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   userID,
			Issuer:    m.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
		UserID:    userID,
		Email:     email,
		Roles:     roles,
		SessionID: sessionID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signing token: %w", err)
	}

	return signedToken, expiresAt, nil
}

// ValidateToken validates a JWT token and returns its claims.
func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	})

	if err != nil {
		if err == jwt.ErrTokenExpired {
			return nil, errors.TokenExpired("token has expired")
		}
		return nil, errors.TokenInvalid("invalid token").Wrap(err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.TokenInvalid("invalid token claims")
	}

	return claims, nil
}

// GetPublicKey returns the public key for external verification.
func (m *Manager) GetPublicKey() *rsa.PublicKey {
	return m.publicKey
}

// GetAccessTokenTTL returns the access token TTL.
func (m *Manager) GetAccessTokenTTL() time.Duration {
	return m.accessTokenTTL
}

// GetRefreshTokenTTL returns the refresh token TTL.
func (m *Manager) GetRefreshTokenTTL() time.Duration {
	return m.refreshTokenTTL
}

// ExtractTokenID extracts the JTI from a token without full validation.
// Useful for token revocation where we need to blacklist even expired tokens.
func (m *Manager) ExtractTokenID(tokenString string) (string, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return "", fmt.Errorf("parsing token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return "", fmt.Errorf("invalid claims type")
	}

	return claims.ID, nil
}

// HashToken creates a SHA256 hash of a token for secure storage.
// This is used for refresh tokens and API keys to avoid storing plaintext.
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
