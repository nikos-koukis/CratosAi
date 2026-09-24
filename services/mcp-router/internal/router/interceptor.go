package router

import (
	"context"
	"log/slog"
	"path"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"jarvis.internal/libs/go/mtls"
	"jarvis.internal/mcp-router/internal/metrics"
)

type requestIDKey struct{}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// RequestID returns the id of the current RPC (the caller's x-request-id,
// else a new UUID). It is sent to the Vault for audit correlation.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// WithRequestID sets the request id (for tests and non-gRPC callers).
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// Interceptor assigns request ids, turns panics into INTERNAL errors, and
// logs and counts every call. Install it before the authorization
// interceptor so refused callers are logged too.
func Interceptor(log *slog.Logger, m *metrics.Metrics) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		start := time.Now()
		id := incomingRequestID(ctx)
		ctx = WithRequestID(ctx, id)
		_ = grpc.SetHeader(ctx, metadata.Pairs("x-request-id", id))
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic in RPC handler", "method", info.FullMethod, "request_id", id,
					"panic", r, "stack", string(debug.Stack()))
				resp, err = nil, status.Errorf(codes.Internal, "internal error (request %s)", id)
			}
			code := status.Code(err)
			m.RPCs.WithLabelValues(path.Base(info.FullMethod), code.String()).Inc()
			level := slog.LevelInfo
			switch {
			case code == codes.Internal || code == codes.Unknown || code == codes.DataLoss:
				level = slog.LevelError
			case strings.HasPrefix(info.FullMethod, "/grpc.health."):
				level = slog.LevelDebug
			}
			principal, _ := mtls.PeerPrincipal(ctx)
			log.Log(ctx, level, "rpc", "method", info.FullMethod, "principal", principal, "code", code.String(),
				"duration_ms", float64(time.Since(start).Microseconds())/1000, "request_id", id)
		}()
		return handler(ctx, req)
	}
}

func incomingRequestID(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get("x-request-id"); len(values) == 1 && requestIDPattern.MatchString(values[0]) {
			return values[0]
		}
	}
	return uuid.NewString()
}

func codeOf(err error) codes.Code { return status.Code(err) }
