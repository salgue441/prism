// Package oauth provides Google OAuth 2.0 implementation.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"

// GoogleConfig holds Google OAuth configuration.
type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// GoogleProvider implements OAuth for Google.
type GoogleProvider struct {
	config *oauth2.Config
}

// googleUserInfo represents the Google user info response.
type googleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// NewGoogleProvider creates a new Google OAuth provider.
func NewGoogleProvider(cfg GoogleConfig) *GoogleProvider {
	return &GoogleProvider{
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes: []string{
				"openid",
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
	}
}

// Name returns the provider name.
func (p *GoogleProvider) Name() string {
	return "google"
}

// GetAuthURL returns the Google OAuth authorization URL.
func (p *GoogleProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// Exchange exchanges an authorization code for user information.
func (p *GoogleProvider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
	// Exchange code for token
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}

	// Fetch user info
	client := p.config.Client(ctx, token)
	resp, err := client.Get(googleUserInfoURL)
	if err != nil {
		return nil, fmt.Errorf("fetching user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google API error: %s", string(body))
	}

	var gUser googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&gUser); err != nil {
		return nil, fmt.Errorf("decoding user info: %w", err)
	}

	return &UserInfo{
		ID:            gUser.ID,
		Email:         gUser.Email,
		EmailVerified: gUser.VerifiedEmail,
		Name:          gUser.Name,
		Picture:       gUser.Picture,
		Provider:      "google",
	}, nil
}
