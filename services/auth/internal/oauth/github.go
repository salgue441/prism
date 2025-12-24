// Package oauth provides GitHub OAuth 2.0 implementation.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const (
	githubUserURL   = "https://api.github.com/user"
	githubEmailsURL = "https://api.github.com/user/emails"
)

// GitHubConfig holds GitHub OAuth configuration.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// GitHubProvider implements OAuth for GitHub.
type GitHubProvider struct {
	config *oauth2.Config
}

// githubUser represents the GitHub user response.
type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// githubEmail represents a GitHub email response.
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// NewGitHubProvider creates a new GitHub OAuth provider.
func NewGitHubProvider(cfg GitHubConfig) *GitHubProvider {
	return &GitHubProvider{
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{"user:email", "read:user"},
			Endpoint:     github.Endpoint,
		},
	}
}

// Name returns the provider name.
func (p *GitHubProvider) Name() string {
	return "github"
}

// GetAuthURL returns the GitHub OAuth authorization URL.
func (p *GitHubProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

// Exchange exchanges an authorization code for user information.
func (p *GitHubProvider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
	// Exchange code for token
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}

	client := p.config.Client(ctx, token)

	// Fetch user info
	user, err := p.fetchUser(client)
	if err != nil {
		return nil, err
	}

	// Fetch primary email if not in user profile
	email := user.Email
	emailVerified := false
	if email == "" {
		email, emailVerified, err = p.fetchPrimaryEmail(client)
		if err != nil {
			return nil, err
		}
	}

	name := user.Name
	if name == "" {
		name = user.Login
	}

	return &UserInfo{
		ID:            fmt.Sprintf("%d", user.ID),
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		Picture:       user.AvatarURL,
		Provider:      "github",
	}, nil
}

func (p *GitHubProvider) fetchUser(client *http.Client) (*githubUser, error) {
	req, err := http.NewRequest(http.MethodGet, githubUserURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github API error: %s", string(body))
	}

	var user githubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("decoding user: %w", err)
	}

	return &user, nil
}

func (p *GitHubProvider) fetchPrimaryEmail(client *http.Client) (string, bool, error) {
	req, err := http.NewRequest(http.MethodGet, githubEmailsURL, nil)
	if err != nil {
		return "", false, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("fetching emails: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", false, fmt.Errorf("github API error: %s", string(body))
	}

	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", false, fmt.Errorf("decoding emails: %w", err)
	}

	// Find primary verified email
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, true, nil
		}
	}

	// Fall back to first verified email
	for _, email := range emails {
		if email.Verified {
			return email.Email, true, nil
		}
	}

	// Fall back to first email
	if len(emails) > 0 {
		return emails[0].Email, emails[0].Verified, nil
	}

	return "", false, fmt.Errorf("no email found")
}
