// Package server provides the gRPC server implementation for the auth service.
package server

import (
	"context"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/carlossalguero/prism/internal/auth/service"
	"github.com/carlossalguero/prism/internal/shared/errors"
	"github.com/carlossalguero/prism/internal/shared/logger"
)

// AuthServiceServer implements the AuthService gRPC server.
// Note: In production, this would implement the generated protobuf interface.
// For now, we define the methods that match our proto definition.
type AuthServiceServer struct {
	service *service.Service
	logger  *logger.Logger
}

// NewAuthServer creates a new auth gRPC server.
func NewAuthServer(svc *service.Service) *AuthServiceServer {
	return &AuthServiceServer{
		service: svc,
		logger:  logger.Default().WithComponent("auth-grpc"),
	}
}

// RegisterAuthServer registers the auth server with a gRPC server.
// Note: In production, use the generated registration function.
func RegisterAuthServer(s *grpc.Server, srv *AuthServiceServer) {
	// This would be: authpb.RegisterAuthServiceServer(s, srv)
	// For now, we register it manually or use reflection
	_ = s
	_ = srv
}

// ValidateToken validates a JWT token.
func (s *AuthServiceServer) ValidateToken(ctx context.Context, req *ValidateTokenRequest) (*ValidateTokenResponse, error) {
	claims, err := s.service.ValidateToken(ctx, req.Token)
	if err != nil {
		appErr, ok := err.(*errors.Error)
		if ok {
			return &ValidateTokenResponse{
				Valid: false,
				Error: appErr.Message,
			}, nil
		}
		return &ValidateTokenResponse{
			Valid: false,
			Error: "invalid token",
		}, nil
	}

	return &ValidateTokenResponse{
		Valid: true,
		Claims: &TokenClaims{
			UserID:    claims.UserID,
			Email:     claims.Email,
			Roles:     claims.Roles,
			SessionID: claims.SessionID,
			IssuedAt:  claims.IssuedAt.Unix(),
			ExpiresAt: claims.ExpiresAt.Unix(),
		},
	}, nil
}

// RefreshToken refreshes an access token.
func (s *AuthServiceServer) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*TokenPairResponse, error) {
	tokens, err := s.service.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &TokenPairResponse{
		AccessToken:          tokens.AccessToken,
		RefreshToken:         tokens.RefreshToken,
		AccessTokenExpiresAt: tokens.AccessTokenExpiresAt.Unix(),
		RefreshExpiresAt:     tokens.RefreshTokenExpiresAt.Unix(),
		TokenType:            "Bearer",
	}, nil
}

// RevokeToken revokes a token.
func (s *AuthServiceServer) RevokeToken(ctx context.Context, req *RevokeTokenRequest) (*emptypb.Empty, error) {
	err := s.service.RevokeToken(ctx, req.Token, req.RevokeAllSessions)
	if err != nil {
		return nil, toGRPCError(err)
	}
	return &emptypb.Empty{}, nil
}

// Login authenticates a user.
func (s *AuthServiceServer) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	user, tokens, err := s.service.Login(ctx, service.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &LoginResponse{
		User:   userToProto(user),
		Tokens: tokensToProto(tokens),
	}, nil
}

// Logout logs out a user.
func (s *AuthServiceServer) Logout(ctx context.Context, req *LogoutRequest) (*emptypb.Empty, error) {
	err := s.service.Logout(ctx, req.RefreshToken, req.LogoutAllSessions)
	if err != nil {
		return nil, toGRPCError(err)
	}
	return &emptypb.Empty{}, nil
}

// Register registers a new user.
func (s *AuthServiceServer) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	user, tokens, err := s.service.Register(ctx, service.RegisterInput{
		Email:    req.Email,
		Password: req.Password,
		Name:     req.Name,
	})
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &RegisterResponse{
		User:   userToProto(user),
		Tokens: tokensToProto(tokens),
	}, nil
}

// GetOAuthURL returns the OAuth authorization URL.
func (s *AuthServiceServer) GetOAuthURL(ctx context.Context, req *GetOAuthURLRequest) (*GetOAuthURLResponse, error) {
	url, state, err := s.service.GetOAuthURL(ctx, req.Provider, req.RedirectURI)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &GetOAuthURLResponse{
		URL:   url,
		State: state,
	}, nil
}

// HandleOAuthCallback handles the OAuth callback.
func (s *AuthServiceServer) HandleOAuthCallback(ctx context.Context, req *OAuthCallbackRequest) (*LoginResponse, error) {
	user, tokens, err := s.service.HandleOAuthCallback(ctx, req.Provider, req.Code, req.State)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &LoginResponse{
		User:   userToProto(user),
		Tokens: tokensToProto(tokens),
	}, nil
}

// CreateAPIKey creates a new API key.
func (s *AuthServiceServer) CreateAPIKey(ctx context.Context, req *CreateAPIKeyRequest) (*CreateAPIKeyResponse, error) {
	// Note: userID should come from authenticated context
	apiKey, key, err := s.service.CreateAPIKey(ctx, service.APIKeyInput{
		UserID:        req.UserID,
		Name:          req.Name,
		Scopes:        req.Scopes,
		ExpiresInDays: req.ExpiresInDays,
	})
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &CreateAPIKeyResponse{
		APIKey: apiKeyToProto(apiKey),
		Key:    key,
	}, nil
}

// ValidateAPIKey validates an API key.
func (s *AuthServiceServer) ValidateAPIKey(ctx context.Context, req *ValidateAPIKeyRequest) (*ValidateAPIKeyResponse, error) {
	apiKey, err := s.service.ValidateAPIKey(ctx, req.Key)
	if err != nil {
		appErr, ok := err.(*errors.Error)
		if ok {
			return &ValidateAPIKeyResponse{
				Valid: false,
				Error: appErr.Message,
			}, nil
		}
		return &ValidateAPIKeyResponse{
			Valid: false,
			Error: "invalid API key",
		}, nil
	}

	return &ValidateAPIKeyResponse{
		Valid:  true,
		APIKey: apiKeyToProto(apiKey),
	}, nil
}

// RevokeAPIKey revokes an API key.
func (s *AuthServiceServer) RevokeAPIKey(ctx context.Context, req *RevokeAPIKeyRequest) (*emptypb.Empty, error) {
	err := s.service.RevokeAPIKey(ctx, req.ID)
	if err != nil {
		return nil, toGRPCError(err)
	}
	return &emptypb.Empty{}, nil
}

// ListAPIKeys lists API keys for a user.
func (s *AuthServiceServer) ListAPIKeys(ctx context.Context, req *ListAPIKeysRequest) (*ListAPIKeysResponse, error) {
	keys, total, err := s.service.ListAPIKeys(ctx, req.UserID, int(req.Page), int(req.PageSize))
	if err != nil {
		return nil, toGRPCError(err)
	}

	protoKeys := make([]*APIKeyProto, len(keys))
	for i, k := range keys {
		protoKeys[i] = apiKeyToProto(&k)
	}

	return &ListAPIKeysResponse{
		APIKeys: protoKeys,
		Total:   int32(total),
	}, nil
}

// GetUser retrieves a user by ID.
func (s *AuthServiceServer) GetUser(ctx context.Context, req *GetUserRequest) (*UserProto, error) {
	user, err := s.service.GetUser(ctx, req.ID)
	if err != nil {
		return nil, toGRPCError(err)
	}
	return userToProto(user), nil
}

// UpdateUser updates a user.
func (s *AuthServiceServer) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*UserProto, error) {
	user, err := s.service.UpdateUser(ctx, req.ID, req.Name, req.Picture)
	if err != nil {
		return nil, toGRPCError(err)
	}
	return userToProto(user), nil
}

// DeleteUser deletes a user.
func (s *AuthServiceServer) DeleteUser(ctx context.Context, req *DeleteUserRequest) (*emptypb.Empty, error) {
	err := s.service.DeleteUser(ctx, req.ID)
	if err != nil {
		return nil, toGRPCError(err)
	}
	return &emptypb.Empty{}, nil
}

// HTTP handlers for OAuth callbacks

// HandleGoogleCallback handles the Google OAuth callback via HTTP.
func (s *AuthServiceServer) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	s.handleOAuthCallback(w, r, "google")
}

// HandleGitHubCallback handles the GitHub OAuth callback via HTTP.
func (s *AuthServiceServer) HandleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	s.handleOAuthCallback(w, r, "github")
}

func (s *AuthServiceServer) handleOAuthCallback(w http.ResponseWriter, r *http.Request, provider string) {
	ctx := r.Context()

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	user, tokens, err := s.service.HandleOAuthCallback(ctx, provider, code, state)
	if err != nil {
		s.logger.Error("OAuth callback failed", "provider", provider, "error", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	// In production, you'd redirect to frontend with tokens or set cookies
	// For now, return JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Simple JSON response (in production, use proper JSON encoding)
	response := `{"user_id":"` + user.ID + `","access_token":"` + tokens.AccessToken + `"}`
	w.Write([]byte(response))
}

// Interceptors

// LoggingInterceptor logs gRPC requests.
func LoggingInterceptor(log *logger.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		duration := time.Since(start)

		log.LogGRPCRequest(ctx, info.FullMethod, duration, err)
		return resp, err
	}
}

// RecoveryInterceptor recovers from panics.
func RecoveryInterceptor(log *logger.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.LogPanic(ctx, r)
				err = status.Error(codes.Internal, "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}

// Helper types and functions

// Request/Response types (these would normally be generated from protobuf)

type ValidateTokenRequest struct {
	Token string
}

type ValidateTokenResponse struct {
	Valid  bool
	Claims *TokenClaims
	Error  string
}

type TokenClaims struct {
	UserID    string
	Email     string
	Roles     []string
	SessionID string
	IssuedAt  int64
	ExpiresAt int64
}

type RefreshTokenRequest struct {
	RefreshToken string
}

type TokenPairResponse struct {
	AccessToken          string
	RefreshToken         string
	AccessTokenExpiresAt int64
	RefreshExpiresAt     int64
	TokenType            string
}

type RevokeTokenRequest struct {
	Token             string
	RevokeAllSessions bool
}

type LoginRequest struct {
	Email    string
	Password string
}

type LoginResponse struct {
	User   *UserProto
	Tokens *TokenPairResponse
}

type LogoutRequest struct {
	RefreshToken      string
	LogoutAllSessions bool
}

type RegisterRequest struct {
	Email    string
	Password string
	Name     string
}

type RegisterResponse struct {
	User   *UserProto
	Tokens *TokenPairResponse
}

type GetOAuthURLRequest struct {
	Provider    string
	RedirectURI string
}

type GetOAuthURLResponse struct {
	URL   string
	State string
}

type OAuthCallbackRequest struct {
	Provider string
	Code     string
	State    string
}

type CreateAPIKeyRequest struct {
	UserID        string
	Name          string
	Scopes        []string
	ExpiresInDays int64
}

type CreateAPIKeyResponse struct {
	APIKey *APIKeyProto
	Key    string
}

type ValidateAPIKeyRequest struct {
	Key string
}

type ValidateAPIKeyResponse struct {
	Valid  bool
	APIKey *APIKeyProto
	Error  string
}

type RevokeAPIKeyRequest struct {
	ID string
}

type ListAPIKeysRequest struct {
	UserID   string
	Page     int32
	PageSize int32
}

type ListAPIKeysResponse struct {
	APIKeys []*APIKeyProto
	Total   int32
}

type GetUserRequest struct {
	ID string
}

type UpdateUserRequest struct {
	ID      string
	Name    *string
	Picture *string
}

type DeleteUserRequest struct {
	ID string
}

type UserProto struct {
	ID            string
	Email         string
	Name          string
	Picture       string
	Roles         []string
	EmailVerified bool
	Provider      string
	CreatedAt     *timestamppb.Timestamp
	UpdatedAt     *timestamppb.Timestamp
}

type APIKeyProto struct {
	ID         string
	Name       string
	Prefix     string
	UserID     string
	Scopes     []string
	CreatedAt  *timestamppb.Timestamp
	ExpiresAt  *timestamppb.Timestamp
	LastUsedAt *timestamppb.Timestamp
}

func userToProto(u *service.User) *UserProto {
	return &UserProto{
		ID:            u.ID,
		Email:         u.Email,
		Name:          u.Name,
		Picture:       u.Picture,
		Roles:         u.Roles,
		EmailVerified: u.EmailVerified,
		Provider:      u.Provider,
		CreatedAt:     timestamppb.New(u.CreatedAt),
		UpdatedAt:     timestamppb.New(u.UpdatedAt),
	}
}

func tokensToProto(t *service.TokenPair) *TokenPairResponse {
	return &TokenPairResponse{
		AccessToken:          t.AccessToken,
		RefreshToken:         t.RefreshToken,
		AccessTokenExpiresAt: t.AccessTokenExpiresAt.Unix(),
		RefreshExpiresAt:     t.RefreshTokenExpiresAt.Unix(),
		TokenType:            "Bearer",
	}
}

func apiKeyToProto(k *service.APIKey) *APIKeyProto {
	proto := &APIKeyProto{
		ID:        k.ID,
		Name:      k.Name,
		Prefix:    k.Prefix,
		UserID:    k.UserID,
		Scopes:    k.Scopes,
		CreatedAt: timestamppb.New(k.CreatedAt),
	}
	if k.ExpiresAt != nil {
		proto.ExpiresAt = timestamppb.New(*k.ExpiresAt)
	}
	if k.LastUsedAt != nil {
		proto.LastUsedAt = timestamppb.New(*k.LastUsedAt)
	}
	return proto
}

func toGRPCError(err error) error {
	appErr, ok := err.(*errors.Error)
	if !ok {
		return status.Error(codes.Internal, err.Error())
	}
	return appErr.ToGRPCError()
}
