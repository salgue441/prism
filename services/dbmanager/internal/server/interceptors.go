// Package server provides gRPC interceptors for the DB Manager service.
package server

import (
	"context"
	"runtime/debug"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/carlossalguero/prism/services/shared/logger"
	"github.com/carlossalguero/prism/services/shared/metrics"
)

// LoggingInterceptor logs gRPC requests and responses.
func LoggingInterceptor(log *logger.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		resp, err := handler(ctx, req)

		duration := time.Since(start)

		if err != nil {
			log.Error("gRPC request failed",
				"method", info.FullMethod,
				"duration", duration,
				"error", err.Error(),
			)
		} else {
			log.Info("gRPC request",
				"method", info.FullMethod,
				"duration", duration,
			)
		}

		return resp, err
	}
}

// RecoveryInterceptor recovers from panics in gRPC handlers.
func RecoveryInterceptor(log *logger.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic recovered in gRPC handler",
					"method", info.FullMethod,
					"panic", r,
					"stack", string(debug.Stack()),
				)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		return handler(ctx, req)
	}
}

// MetricsInterceptor records metrics for gRPC requests.
func MetricsInterceptor(m *metrics.Metrics) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		resp, err := handler(ctx, req)

		duration := time.Since(start)

		statusCode := "OK"
		if err != nil {
			if s, ok := status.FromError(err); ok {
				statusCode = s.Code().String()
			} else {
				statusCode = "Unknown"
			}
		}

		m.RecordGRPCRequest(info.FullMethod, statusCode, duration)

		return resp, err
	}
}
