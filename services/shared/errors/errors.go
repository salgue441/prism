// Package errors provides custom error types with error codes for the Prism gateway.
package errors

import (
	"errors"
	"fmt"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Code represents an application error code.
type Code string

// Error codes for the application.
const (
	// General errors
	CodeInternal       Code = "INTERNAL"
	CodeInvalidInput   Code = "INVALID_INPUT"
	CodeNotFound       Code = "NOT_FOUND"
	CodeAlreadyExists  Code = "ALREADY_EXISTS"
	CodeUnauthorized   Code = "UNAUTHORIZED"
	CodeForbidden      Code = "FORBIDDEN"
	CodeRateLimited    Code = "RATE_LIMITED"
	CodeUnavailable    Code = "UNAVAILABLE"
	CodeTimeout        Code = "TIMEOUT"
	CodeCanceled       Code = "CANCELED"
	CodeFailedPrecond  Code = "FAILED_PRECONDITION"
	CodeConflict       Code = "CONFLICT"
	CodeResourceExaust Code = "RESOURCE_EXHAUSTED"

	// Auth-specific errors
	CodeInvalidCredentials  Code = "INVALID_CREDENTIALS"
	CodeTokenExpired        Code = "TOKEN_EXPIRED"
	CodeTokenInvalid        Code = "TOKEN_INVALID"
	CodeTokenRevoked        Code = "TOKEN_REVOKED"
	CodeSessionExpired      Code = "SESSION_EXPIRED"
	CodeOAuthError          Code = "OAUTH_ERROR"
	CodeAPIKeyInvalid       Code = "API_KEY_INVALID"
	CodeAPIKeyExpired       Code = "API_KEY_EXPIRED"
	CodeInsufficientScope   Code = "INSUFFICIENT_SCOPE"
	CodePasswordTooWeak     Code = "PASSWORD_TOO_WEAK"
	CodeEmailNotVerified    Code = "EMAIL_NOT_VERIFIED"
	CodeUserDisabled        Code = "USER_DISABLED"
	CodeInvalidRefreshToken Code = "INVALID_REFRESH_TOKEN"

	// Gateway-specific errors
	CodeUpstreamError    Code = "UPSTREAM_ERROR"
	CodeCircuitOpen      Code = "CIRCUIT_OPEN"
	CodeNoHealthyTargets Code = "NO_HEALTHY_TARGETS"
	CodeRouteNotFound    Code = "ROUTE_NOT_FOUND"
	CodeInvalidRoute     Code = "INVALID_ROUTE"
)

// Error is the application's custom error type with code and details.
type Error struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
	Err     error  `json:"-"` // Underlying error, not serialized
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *Error) Unwrap() error {
	return e.Err
}

// Is checks if the target error has the same code.
func (e *Error) Is(target error) bool {
	var t *Error
	if errors.As(target, &t) {
		return e.Code == t.Code
	}
	return false
}

// WithDetails returns a copy of the error with additional details.
func (e *Error) WithDetails(details any) *Error {
	return &Error{
		Code:    e.Code,
		Message: e.Message,
		Details: details,
		Err:     e.Err,
	}
}

// Wrap wraps an underlying error.
func (e *Error) Wrap(err error) *Error {
	return &Error{
		Code:    e.Code,
		Message: e.Message,
		Details: e.Details,
		Err:     err,
	}
}

// New creates a new Error with the given code and message.
func New(code Code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

// Wrap creates a new Error wrapping an existing error.
func Wrap(code Code, message string, err error) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// Common error constructors

// Internal creates an internal error.
func Internal(message string) *Error {
	return New(CodeInternal, message)
}

// InternalWrap creates an internal error wrapping another error.
func InternalWrap(message string, err error) *Error {
	return Wrap(CodeInternal, message, err)
}

// InvalidInput creates an invalid input error.
func InvalidInput(message string) *Error {
	return New(CodeInvalidInput, message)
}

// NotFound creates a not found error.
func NotFound(message string) *Error {
	return New(CodeNotFound, message)
}

// AlreadyExists creates an already exists error.
func AlreadyExists(message string) *Error {
	return New(CodeAlreadyExists, message)
}

// Unauthorized creates an unauthorized error.
func Unauthorized(message string) *Error {
	return New(CodeUnauthorized, message)
}

// Forbidden creates a forbidden error.
func Forbidden(message string) *Error {
	return New(CodeForbidden, message)
}

// RateLimited creates a rate limited error.
func RateLimited(message string) *Error {
	return New(CodeRateLimited, message)
}

// Unavailable creates an unavailable error.
func Unavailable(message string) *Error {
	return New(CodeUnavailable, message)
}

// Timeout creates a timeout error.
func Timeout(message string) *Error {
	return New(CodeTimeout, message)
}

// Auth-specific error constructors

// InvalidCredentials creates an invalid credentials error.
func InvalidCredentials(message string) *Error {
	return New(CodeInvalidCredentials, message)
}

// TokenExpired creates a token expired error.
func TokenExpired(message string) *Error {
	return New(CodeTokenExpired, message)
}

// TokenInvalid creates a token invalid error.
func TokenInvalid(message string) *Error {
	return New(CodeTokenInvalid, message)
}

// SessionExpired creates a session expired error.
func SessionExpired(message string) *Error {
	return New(CodeSessionExpired, message)
}

// OAuthError creates an OAuth error.
func OAuthError(message string) *Error {
	return New(CodeOAuthError, message)
}

// APIKeyInvalid creates an invalid API key error.
func APIKeyInvalid(message string) *Error {
	return New(CodeAPIKeyInvalid, message)
}

// InsufficientScope creates an insufficient scope error.
func InsufficientScope(message string) *Error {
	return New(CodeInsufficientScope, message)
}

// Gateway-specific error constructors

// UpstreamError creates an upstream error.
func UpstreamError(message string) *Error {
	return New(CodeUpstreamError, message)
}

// CircuitOpen creates a circuit open error.
func CircuitOpen(message string) *Error {
	return New(CodeCircuitOpen, message)
}

// NoHealthyTargets creates a no healthy targets error.
func NoHealthyTargets(message string) *Error {
	return New(CodeNoHealthyTargets, message)
}

// RouteNotFound creates a route not found error.
func RouteNotFound(message string) *Error {
	return New(CodeRouteNotFound, message)
}

// HTTPStatusCode returns the appropriate HTTP status code for the error.
func (e *Error) HTTPStatusCode() int {
	switch e.Code {
	case CodeInvalidInput, CodePasswordTooWeak:
		return http.StatusBadRequest
	case CodeUnauthorized, CodeInvalidCredentials, CodeTokenExpired,
		CodeTokenInvalid, CodeTokenRevoked, CodeSessionExpired,
		CodeAPIKeyInvalid, CodeAPIKeyExpired, CodeInvalidRefreshToken:
		return http.StatusUnauthorized
	case CodeForbidden, CodeInsufficientScope, CodeEmailNotVerified, CodeUserDisabled:
		return http.StatusForbidden
	case CodeNotFound, CodeRouteNotFound:
		return http.StatusNotFound
	case CodeAlreadyExists, CodeConflict:
		return http.StatusConflict
	case CodeRateLimited, CodeResourceExaust:
		return http.StatusTooManyRequests
	case CodeFailedPrecond:
		return http.StatusPreconditionFailed
	case CodeTimeout:
		return http.StatusGatewayTimeout
	case CodeUnavailable, CodeUpstreamError, CodeCircuitOpen, CodeNoHealthyTargets:
		return http.StatusServiceUnavailable
	case CodeCanceled:
		return 499 // Client Closed Request
	default:
		return http.StatusInternalServerError
	}
}

// GRPCStatus returns the appropriate gRPC status for the error.
func (e *Error) GRPCStatus() *status.Status {
	var code codes.Code
	switch e.Code {
	case CodeInvalidInput, CodePasswordTooWeak:
		code = codes.InvalidArgument
	case CodeUnauthorized, CodeInvalidCredentials, CodeTokenExpired,
		CodeTokenInvalid, CodeTokenRevoked, CodeSessionExpired,
		CodeAPIKeyInvalid, CodeAPIKeyExpired, CodeInvalidRefreshToken:
		code = codes.Unauthenticated
	case CodeForbidden, CodeInsufficientScope, CodeEmailNotVerified, CodeUserDisabled:
		code = codes.PermissionDenied
	case CodeNotFound, CodeRouteNotFound:
		code = codes.NotFound
	case CodeAlreadyExists, CodeConflict:
		code = codes.AlreadyExists
	case CodeRateLimited, CodeResourceExaust:
		code = codes.ResourceExhausted
	case CodeFailedPrecond:
		code = codes.FailedPrecondition
	case CodeTimeout:
		code = codes.DeadlineExceeded
	case CodeUnavailable, CodeUpstreamError, CodeCircuitOpen, CodeNoHealthyTargets:
		code = codes.Unavailable
	case CodeCanceled:
		code = codes.Canceled
	default:
		code = codes.Internal
	}

	return status.New(code, e.Message)
}

// ToGRPCError converts the error to a gRPC error.
func (e *Error) ToGRPCError() error {
	return e.GRPCStatus().Err()
}

// FromGRPCError converts a gRPC error to an Error.
func FromGRPCError(err error) *Error {
	if err == nil {
		return nil
	}

	st, ok := status.FromError(err)
	if !ok {
		return InternalWrap("unknown error", err)
	}

	var code Code
	switch st.Code() {
	case codes.InvalidArgument:
		code = CodeInvalidInput
	case codes.Unauthenticated:
		code = CodeUnauthorized
	case codes.PermissionDenied:
		code = CodeForbidden
	case codes.NotFound:
		code = CodeNotFound
	case codes.AlreadyExists:
		code = CodeAlreadyExists
	case codes.ResourceExhausted:
		code = CodeRateLimited
	case codes.FailedPrecondition:
		code = CodeFailedPrecond
	case codes.DeadlineExceeded:
		code = CodeTimeout
	case codes.Unavailable:
		code = CodeUnavailable
	case codes.Canceled:
		code = CodeCanceled
	default:
		code = CodeInternal
	}

	return New(code, st.Message())
}

// IsCode checks if an error has a specific code.
func IsCode(err error, code Code) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Code == code
	}
	return false
}

// GetCode extracts the error code from an error, or CodeInternal if not found.
func GetCode(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeInternal
}
