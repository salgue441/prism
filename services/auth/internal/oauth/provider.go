// Package oauth provides OAuth 2.0 provider implementations.
package oauth

import (
	"context"
)

// Provider defines the interface for OAuth providers.
type Provider interface {
	// Name returns the provider name (e.g., "google", "github").
	Name() string

	// GetAuthURL returns the URL to redirect users for authentication.
	GetAuthURL(state string) string

	// Exchange exchanges an authorization code for tokens and user info.
	Exchange(ctx context.Context, code string) (*UserInfo, error)
}

// UserInfo represents the user information returned by OAuth providers.
type UserInfo struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Provider      string
}

// Config is the base configuration for OAuth providers.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}
