package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

func TestManager_GenerateTokenPair(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)

	manager := NewManagerWithKeys(privateKey, publicKey, Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "test-issuer",
	})

	tokenPair, err := manager.GenerateTokenPair("user-123", "test@example.com", []string{"admin"})
	require.NoError(t, err)

	assert.NotEmpty(t, tokenPair.AccessToken)
	assert.NotEmpty(t, tokenPair.RefreshToken)
	assert.NotEmpty(t, tokenPair.SessionID)
	assert.True(t, tokenPair.AccessTokenExpiresAt.After(time.Now()))
	assert.True(t, tokenPair.RefreshTokenExpiresAt.After(time.Now()))
	assert.True(t, tokenPair.RefreshTokenExpiresAt.After(tokenPair.AccessTokenExpiresAt))
}

func TestManager_ValidateToken(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)

	manager := NewManagerWithKeys(privateKey, publicKey, Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "test-issuer",
	})

	t.Run("valid token", func(t *testing.T) {
		tokenPair, err := manager.GenerateTokenPair("user-123", "test@example.com", []string{"admin", "user"})
		require.NoError(t, err)

		claims, err := manager.ValidateToken(tokenPair.AccessToken)
		require.NoError(t, err)

		assert.Equal(t, "user-123", claims.UserID)
		assert.Equal(t, "test@example.com", claims.Email)
		assert.Equal(t, []string{"admin", "user"}, claims.Roles)
		assert.Equal(t, tokenPair.SessionID, claims.SessionID)
		assert.Equal(t, "test-issuer", claims.Issuer)
	})

	t.Run("invalid token format", func(t *testing.T) {
		_, err := manager.ValidateToken("invalid-token")
		assert.Error(t, err)
	})

	t.Run("wrong signing key", func(t *testing.T) {
		otherPrivate, _ := generateTestKeys(t)
		otherManager := NewManagerWithKeys(otherPrivate, publicKey, Config{
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
			Issuer:          "test-issuer",
		})

		tokenPair, err := otherManager.GenerateTokenPair("user-123", "test@example.com", nil)
		require.NoError(t, err)

		// Validating with different public key should fail
		_, err = manager.ValidateToken(tokenPair.AccessToken)
		assert.Error(t, err)
	})
}

func TestManager_GenerateAccessToken(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)

	manager := NewManagerWithKeys(privateKey, publicKey, Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "test-issuer",
	})

	token, expiresAt, err := manager.GenerateAccessToken("user-123", "test@example.com", []string{"user"}, "session-abc")
	require.NoError(t, err)

	assert.NotEmpty(t, token)
	assert.True(t, expiresAt.After(time.Now()))

	claims, err := manager.ValidateToken(token)
	require.NoError(t, err)

	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "session-abc", claims.SessionID)
}

func TestManager_ExtractTokenID(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)

	manager := NewManagerWithKeys(privateKey, publicKey, Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "test-issuer",
	})

	tokenPair, err := manager.GenerateTokenPair("user-123", "test@example.com", nil)
	require.NoError(t, err)

	jti, err := manager.ExtractTokenID(tokenPair.AccessToken)
	require.NoError(t, err)
	assert.NotEmpty(t, jti)
}

func TestManager_GetPublicKey(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)

	manager := NewManagerWithKeys(privateKey, publicKey, Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "test-issuer",
	})

	assert.Equal(t, publicKey, manager.GetPublicKey())
}

func TestManager_GetTTLs(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)

	accessTTL := 15 * time.Minute
	refreshTTL := 7 * 24 * time.Hour

	manager := NewManagerWithKeys(privateKey, publicKey, Config{
		AccessTokenTTL:  accessTTL,
		RefreshTokenTTL: refreshTTL,
		Issuer:          "test-issuer",
	})

	assert.Equal(t, accessTTL, manager.GetAccessTokenTTL())
	assert.Equal(t, refreshTTL, manager.GetRefreshTokenTTL())
}

func TestHashToken(t *testing.T) {
	t.Run("produces consistent hash", func(t *testing.T) {
		token := "test-token-12345"
		hash1 := HashToken(token)
		hash2 := HashToken(token)

		assert.Equal(t, hash1, hash2)
		assert.Len(t, hash1, 64) // SHA256 produces 32 bytes = 64 hex chars
	})

	t.Run("different tokens produce different hashes", func(t *testing.T) {
		hash1 := HashToken("token-1")
		hash2 := HashToken("token-2")

		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("hash is deterministic", func(t *testing.T) {
		// Known test vector for SHA256
		token := "hello"
		hash := HashToken(token)

		// SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
		assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hash)
	})
}
