// Package repository provides database operations for the auth service.
package repository

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/carlossalguero/prism/internal/shared/errors"
)

// User represents a user in the database.
type User struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
	PasswordHash  *string
	Name          string
	Picture       *string
	Provider      string
	ProviderID    *string
	Roles         []string
	Disabled      bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Session represents a user session in the database.
type Session struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	RefreshTokenHash string
	UserAgent        *string
	IPAddress        *string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	LastUsedAt       time.Time
}

// APIKey represents an API key in the database.
type APIKey struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Name       string
	KeyHash    string
	KeyPrefix  string
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
}

// OAuthState represents an OAuth state for CSRF protection.
type OAuthState struct {
	State       string
	Provider    string
	RedirectURI *string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// Repository defines the interface for auth data operations.
type Repository interface {
	// User operations
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByProvider(ctx context.Context, provider, providerID string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id uuid.UUID) error

	// Session operations
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByRefreshToken(ctx context.Context, tokenHash string) (*Session, error)
	UpdateSessionLastUsed(ctx context.Context, id uuid.UUID) error
	RevokeSession(ctx context.Context, id uuid.UUID) error
	RevokeAllUserSessions(ctx context.Context, userID uuid.UUID) error

	// API Key operations
	CreateAPIKey(ctx context.Context, apiKey *APIKey) error
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)
	GetAPIKeyByID(ctx context.Context, id uuid.UUID) (*APIKey, error)
	ListAPIKeys(ctx context.Context, userID uuid.UUID, limit, offset int) ([]APIKey, int, error)
	UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error
	RevokeAPIKey(ctx context.Context, id uuid.UUID) error

	// OAuth state operations
	CreateOAuthState(ctx context.Context, state *OAuthState) error
	GetAndDeleteOAuthState(ctx context.Context, state string) (*OAuthState, error)

	// Token revocation
	RevokeToken(ctx context.Context, jti uuid.UUID, userID uuid.UUID, expiresAt time.Time) error
	IsTokenRevoked(ctx context.Context, jti uuid.UUID) (bool, error)
}

// Postgres implements Repository using PostgreSQL.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres creates a new PostgreSQL repository.
func NewPostgres(pool *pgxpool.Pool) *Postgres {
	return &Postgres{pool: pool}
}

// CreateUser creates a new user.
func (r *Postgres) CreateUser(ctx context.Context, user *User) error {
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	query := `
		INSERT INTO users (id, email, email_verified, password_hash, name, picture, provider, provider_id, roles, disabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.pool.Exec(ctx, query,
		user.ID, user.Email, user.EmailVerified, user.PasswordHash,
		user.Name, user.Picture, user.Provider, user.ProviderID,
		user.Roles, user.Disabled, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return errors.AlreadyExists("user with this email already exists")
		}
		return fmt.Errorf("creating user: %w", err)
	}

	return nil
}

// GetUserByID retrieves a user by ID.
func (r *Postgres) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	query := `
		SELECT id, email, email_verified, password_hash, name, picture, provider, provider_id, roles, disabled, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	var user User
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.EmailVerified, &user.PasswordHash,
		&user.Name, &user.Picture, &user.Provider, &user.ProviderID,
		&user.Roles, &user.Disabled, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("user not found")
		}
		return nil, fmt.Errorf("getting user: %w", err)
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email.
func (r *Postgres) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, email, email_verified, password_hash, name, picture, provider, provider_id, roles, disabled, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	var user User
	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.EmailVerified, &user.PasswordHash,
		&user.Name, &user.Picture, &user.Provider, &user.ProviderID,
		&user.Roles, &user.Disabled, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("user not found")
		}
		return nil, fmt.Errorf("getting user: %w", err)
	}

	return &user, nil
}

// GetUserByProvider retrieves a user by OAuth provider and provider ID.
func (r *Postgres) GetUserByProvider(ctx context.Context, provider, providerID string) (*User, error) {
	query := `
		SELECT id, email, email_verified, password_hash, name, picture, provider, provider_id, roles, disabled, created_at, updated_at
		FROM users
		WHERE provider = $1 AND provider_id = $2
	`

	var user User
	err := r.pool.QueryRow(ctx, query, provider, providerID).Scan(
		&user.ID, &user.Email, &user.EmailVerified, &user.PasswordHash,
		&user.Name, &user.Picture, &user.Provider, &user.ProviderID,
		&user.Roles, &user.Disabled, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("user not found")
		}
		return nil, fmt.Errorf("getting user: %w", err)
	}

	return &user, nil
}

// UpdateUser updates a user.
func (r *Postgres) UpdateUser(ctx context.Context, user *User) error {
	user.UpdatedAt = time.Now()

	query := `
		UPDATE users
		SET email = $2, email_verified = $3, password_hash = $4, name = $5,
		    picture = $6, roles = $7, disabled = $8, updated_at = $9
		WHERE id = $1
	`

	result, err := r.pool.Exec(ctx, query,
		user.ID, user.Email, user.EmailVerified, user.PasswordHash,
		user.Name, user.Picture, user.Roles, user.Disabled, user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("updating user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.NotFound("user not found")
	}

	return nil
}

// DeleteUser deletes a user.
func (r *Postgres) DeleteUser(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("deleting user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.NotFound("user not found")
	}

	return nil
}

// CreateSession creates a new session.
func (r *Postgres) CreateSession(ctx context.Context, session *Session) error {
	if session.ID == uuid.Nil {
		session.ID = uuid.New()
	}
	session.CreatedAt = time.Now()
	session.LastUsedAt = session.CreatedAt

	query := `
		INSERT INTO sessions (id, user_id, refresh_token_hash, user_agent, ip_address, created_at, expires_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.pool.Exec(ctx, query,
		session.ID, session.UserID, session.RefreshTokenHash,
		session.UserAgent, session.IPAddress, session.CreatedAt,
		session.ExpiresAt, session.LastUsedAt,
	)
	if err != nil {
		return fmt.Errorf("creating session: %w", err)
	}

	return nil
}

// GetSessionByRefreshToken retrieves a session by refresh token hash.
func (r *Postgres) GetSessionByRefreshToken(ctx context.Context, tokenHash string) (*Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, user_agent, ip_address, created_at, expires_at, revoked_at, last_used_at
		FROM sessions
		WHERE refresh_token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
	`

	var session Session
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&session.ID, &session.UserID, &session.RefreshTokenHash,
		&session.UserAgent, &session.IPAddress, &session.CreatedAt,
		&session.ExpiresAt, &session.RevokedAt, &session.LastUsedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("session not found")
		}
		return nil, fmt.Errorf("getting session: %w", err)
	}

	return &session, nil
}

// UpdateSessionLastUsed updates the last used timestamp of a session.
func (r *Postgres) UpdateSessionLastUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE sessions SET last_used_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

// RevokeSession revokes a session.
func (r *Postgres) RevokeSession(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE sessions SET revoked_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

// RevokeAllUserSessions revokes all sessions for a user.
func (r *Postgres) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`
	_, err := r.pool.Exec(ctx, query, userID)
	return err
}

// CreateAPIKey creates a new API key.
func (r *Postgres) CreateAPIKey(ctx context.Context, apiKey *APIKey) error {
	if apiKey.ID == uuid.Nil {
		apiKey.ID = uuid.New()
	}
	apiKey.CreatedAt = time.Now()

	query := `
		INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, scopes, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.pool.Exec(ctx, query,
		apiKey.ID, apiKey.UserID, apiKey.Name, apiKey.KeyHash,
		apiKey.KeyPrefix, apiKey.Scopes, apiKey.CreatedAt, apiKey.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("creating API key: %w", err)
	}

	return nil
}

// GetAPIKeyByHash retrieves an API key by its hash.
func (r *Postgres) GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, key_prefix, scopes, created_at, expires_at, revoked_at, last_used_at
		FROM api_keys
		WHERE key_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())
	`

	var apiKey APIKey
	err := r.pool.QueryRow(ctx, query, keyHash).Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.Name, &apiKey.KeyHash,
		&apiKey.KeyPrefix, &apiKey.Scopes, &apiKey.CreatedAt,
		&apiKey.ExpiresAt, &apiKey.RevokedAt, &apiKey.LastUsedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("API key not found")
		}
		return nil, fmt.Errorf("getting API key: %w", err)
	}

	return &apiKey, nil
}

// GetAPIKeyByID retrieves an API key by ID.
func (r *Postgres) GetAPIKeyByID(ctx context.Context, id uuid.UUID) (*APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, key_prefix, scopes, created_at, expires_at, revoked_at, last_used_at
		FROM api_keys
		WHERE id = $1
	`

	var apiKey APIKey
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.Name, &apiKey.KeyHash,
		&apiKey.KeyPrefix, &apiKey.Scopes, &apiKey.CreatedAt,
		&apiKey.ExpiresAt, &apiKey.RevokedAt, &apiKey.LastUsedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("API key not found")
		}
		return nil, fmt.Errorf("getting API key: %w", err)
	}

	return &apiKey, nil
}

// ListAPIKeys lists API keys for a user.
func (r *Postgres) ListAPIKeys(ctx context.Context, userID uuid.UUID, limit, offset int) ([]APIKey, int, error) {
	countQuery := `SELECT COUNT(*) FROM api_keys WHERE user_id = $1`
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, userID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting API keys: %w", err)
	}

	query := `
		SELECT id, user_id, name, key_hash, key_prefix, scopes, created_at, expires_at, revoked_at, last_used_at
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.pool.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("listing API keys: %w", err)
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var key APIKey
		if err := rows.Scan(
			&key.ID, &key.UserID, &key.Name, &key.KeyHash,
			&key.KeyPrefix, &key.Scopes, &key.CreatedAt,
			&key.ExpiresAt, &key.RevokedAt, &key.LastUsedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning API key: %w", err)
		}
		keys = append(keys, key)
	}

	return keys, total, nil
}

// UpdateAPIKeyLastUsed updates the last used timestamp of an API key.
func (r *Postgres) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

// RevokeAPIKey revokes an API key.
func (r *Postgres) RevokeAPIKey(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE api_keys SET revoked_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

// CreateOAuthState creates an OAuth state for CSRF protection.
func (r *Postgres) CreateOAuthState(ctx context.Context, state *OAuthState) error {
	state.CreatedAt = time.Now()

	query := `
		INSERT INTO oauth_states (state, provider, redirect_uri, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.pool.Exec(ctx, query,
		state.State, state.Provider, state.RedirectURI,
		state.CreatedAt, state.ExpiresAt,
	)
	return err
}

// GetAndDeleteOAuthState retrieves and deletes an OAuth state.
func (r *Postgres) GetAndDeleteOAuthState(ctx context.Context, state string) (*OAuthState, error) {
	query := `
		DELETE FROM oauth_states
		WHERE state = $1 AND expires_at > NOW()
		RETURNING state, provider, redirect_uri, created_at, expires_at
	`

	var s OAuthState
	err := r.pool.QueryRow(ctx, query, state).Scan(
		&s.State, &s.Provider, &s.RedirectURI, &s.CreatedAt, &s.ExpiresAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("OAuth state not found or expired")
		}
		return nil, fmt.Errorf("getting OAuth state: %w", err)
	}

	return &s, nil
}

// RevokeToken adds a token to the revocation list.
func (r *Postgres) RevokeToken(ctx context.Context, jti uuid.UUID, userID uuid.UUID, expiresAt time.Time) error {
	query := `
		INSERT INTO revoked_tokens (jti, user_id, expires_at, revoked_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (jti) DO NOTHING
	`
	_, err := r.pool.Exec(ctx, query, jti, userID, expiresAt)
	return err
}

// IsTokenRevoked checks if a token has been revoked.
func (r *Postgres) IsTokenRevoked(ctx context.Context, jti uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1)`
	var exists bool
	err := r.pool.QueryRow(ctx, query, jti).Scan(&exists)
	return exists, err
}

// HashAPIKey hashes an API key for storage.
func HashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", hash)
}

// isUniqueViolation checks if an error is a unique constraint violation.
func isUniqueViolation(err error) bool {
	// pgx returns errors that can be checked for postgres error codes
	// Code 23505 is unique_violation
	return err != nil && (contains(err.Error(), "unique") || contains(err.Error(), "23505"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
