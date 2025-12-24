package errors

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
)

func TestError_Error(t *testing.T) {
	t.Run("without underlying error", func(t *testing.T) {
		err := New(CodeNotFound, "resource not found")
		assert.Equal(t, "NOT_FOUND: resource not found", err.Error())
	})

	t.Run("with underlying error", func(t *testing.T) {
		underlying := errors.New("connection refused")
		err := Wrap(CodeInternal, "database error", underlying)
		assert.Contains(t, err.Error(), "INTERNAL: database error")
		assert.Contains(t, err.Error(), "connection refused")
	})
}

func TestError_Unwrap(t *testing.T) {
	underlying := errors.New("original error")
	err := Wrap(CodeInternal, "wrapped", underlying)

	assert.True(t, errors.Is(err, underlying))
}

func TestError_Is(t *testing.T) {
	err1 := New(CodeNotFound, "not found 1")
	err2 := New(CodeNotFound, "not found 2")
	err3 := New(CodeInternal, "internal")

	assert.True(t, errors.Is(err1, err2))
	assert.False(t, errors.Is(err1, err3))
}

func TestError_WithDetails(t *testing.T) {
	err := New(CodeInvalidInput, "validation failed")
	details := map[string]string{"field": "email", "reason": "invalid format"}

	withDetails := err.WithDetails(details)

	assert.Equal(t, err.Code, withDetails.Code)
	assert.Equal(t, err.Message, withDetails.Message)
	assert.Equal(t, details, withDetails.Details)
}

func TestError_Wrap(t *testing.T) {
	underlying := errors.New("underlying")
	err := New(CodeInternal, "wrapper")

	wrapped := err.Wrap(underlying)

	assert.Equal(t, err.Code, wrapped.Code)
	assert.Equal(t, err.Message, wrapped.Message)
	assert.Equal(t, underlying, wrapped.Err)
}

func TestError_HTTPStatusCode(t *testing.T) {
	tests := []struct {
		code     Code
		expected int
	}{
		{CodeInvalidInput, http.StatusBadRequest},
		{CodePasswordTooWeak, http.StatusBadRequest},
		{CodeUnauthorized, http.StatusUnauthorized},
		{CodeInvalidCredentials, http.StatusUnauthorized},
		{CodeTokenExpired, http.StatusUnauthorized},
		{CodeTokenInvalid, http.StatusUnauthorized},
		{CodeForbidden, http.StatusForbidden},
		{CodeInsufficientScope, http.StatusForbidden},
		{CodeNotFound, http.StatusNotFound},
		{CodeRouteNotFound, http.StatusNotFound},
		{CodeAlreadyExists, http.StatusConflict},
		{CodeConflict, http.StatusConflict},
		{CodeRateLimited, http.StatusTooManyRequests},
		{CodeTimeout, http.StatusGatewayTimeout},
		{CodeUnavailable, http.StatusServiceUnavailable},
		{CodeInternal, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			err := New(tt.code, "test")
			assert.Equal(t, tt.expected, err.HTTPStatusCode())
		})
	}
}

func TestError_GRPCStatus(t *testing.T) {
	tests := []struct {
		code     Code
		expected codes.Code
	}{
		{CodeInvalidInput, codes.InvalidArgument},
		{CodeUnauthorized, codes.Unauthenticated},
		{CodeForbidden, codes.PermissionDenied},
		{CodeNotFound, codes.NotFound},
		{CodeAlreadyExists, codes.AlreadyExists},
		{CodeRateLimited, codes.ResourceExhausted},
		{CodeTimeout, codes.DeadlineExceeded},
		{CodeUnavailable, codes.Unavailable},
		{CodeCanceled, codes.Canceled},
		{CodeInternal, codes.Internal},
	}

	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			err := New(tt.code, "test")
			status := err.GRPCStatus()
			assert.Equal(t, tt.expected, status.Code())
		})
	}
}

func TestError_ToGRPCError(t *testing.T) {
	err := NotFound("resource not found")
	grpcErr := err.ToGRPCError()

	assert.Error(t, grpcErr)
}

func TestFromGRPCError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		assert.Nil(t, FromGRPCError(nil))
	})

	t.Run("non-grpc error", func(t *testing.T) {
		err := errors.New("regular error")
		appErr := FromGRPCError(err)
		assert.Equal(t, CodeInternal, appErr.Code)
	})

	t.Run("grpc error", func(t *testing.T) {
		original := NotFound("test")
		grpcErr := original.ToGRPCError()
		recovered := FromGRPCError(grpcErr)

		assert.Equal(t, CodeNotFound, recovered.Code)
		assert.Equal(t, "test", recovered.Message)
	})
}

func TestErrorConstructors(t *testing.T) {
	t.Run("Internal", func(t *testing.T) {
		err := Internal("internal error")
		assert.Equal(t, CodeInternal, err.Code)
		assert.Equal(t, "internal error", err.Message)
	})

	t.Run("InternalWrap", func(t *testing.T) {
		underlying := errors.New("db error")
		err := InternalWrap("failed", underlying)
		assert.Equal(t, CodeInternal, err.Code)
		assert.Equal(t, underlying, err.Err)
	})

	t.Run("InvalidInput", func(t *testing.T) {
		err := InvalidInput("bad request")
		assert.Equal(t, CodeInvalidInput, err.Code)
	})

	t.Run("NotFound", func(t *testing.T) {
		err := NotFound("not found")
		assert.Equal(t, CodeNotFound, err.Code)
	})

	t.Run("AlreadyExists", func(t *testing.T) {
		err := AlreadyExists("exists")
		assert.Equal(t, CodeAlreadyExists, err.Code)
	})

	t.Run("Unauthorized", func(t *testing.T) {
		err := Unauthorized("not authorized")
		assert.Equal(t, CodeUnauthorized, err.Code)
	})

	t.Run("Forbidden", func(t *testing.T) {
		err := Forbidden("forbidden")
		assert.Equal(t, CodeForbidden, err.Code)
	})

	t.Run("RateLimited", func(t *testing.T) {
		err := RateLimited("too many requests")
		assert.Equal(t, CodeRateLimited, err.Code)
	})

	t.Run("Unavailable", func(t *testing.T) {
		err := Unavailable("service unavailable")
		assert.Equal(t, CodeUnavailable, err.Code)
	})

	t.Run("Timeout", func(t *testing.T) {
		err := Timeout("request timeout")
		assert.Equal(t, CodeTimeout, err.Code)
	})

	t.Run("TokenExpired", func(t *testing.T) {
		err := TokenExpired("token expired")
		assert.Equal(t, CodeTokenExpired, err.Code)
	})

	t.Run("TokenInvalid", func(t *testing.T) {
		err := TokenInvalid("invalid token")
		assert.Equal(t, CodeTokenInvalid, err.Code)
	})

	t.Run("APIKeyInvalid", func(t *testing.T) {
		err := APIKeyInvalid("invalid key")
		assert.Equal(t, CodeAPIKeyInvalid, err.Code)
	})

	t.Run("RouteNotFound", func(t *testing.T) {
		err := RouteNotFound("route not found")
		assert.Equal(t, CodeRouteNotFound, err.Code)
	})
}

func TestIsCode(t *testing.T) {
	err := NotFound("test")

	assert.True(t, IsCode(err, CodeNotFound))
	assert.False(t, IsCode(err, CodeInternal))
	assert.False(t, IsCode(errors.New("regular error"), CodeNotFound))
}
