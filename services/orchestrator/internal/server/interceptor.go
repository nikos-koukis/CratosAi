package server

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
	"jarvis.internal/orchestrator/internal/engine"
	"jarvis.internal/orchestrator/internal/metrics"
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func incomingRequestID(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get("x-request-id"); len(values) == 1 && requestIDPattern.MatchString(values[0]) {
			return values[0]
		}
	}
	return uuid.NewString()
}

func logCall(log *slog.Logger, m *metrics.Metrics, ctx context.Context, method, id string, err error, started time.Time) {
	code := status.Code(err)
	m.RPCs.WithLabelValues(path.Base(method), code.String()).Inc()
	level := slog.LevelInfo
	switch {
	case code == codes.Internal || code == codes.Unknown || code == codes.DataLoss:
		level = slog.LevelError
	case strings.HasPrefix(method, "/grpc.health."):
		level = slog.LevelDebug
	}
	principal, _ := mtls.PeerPrincipal(ctx)
	log.Log(ctx, level, "rpc", "method", method, "principal", principal, "code", code.String(),
		"duration_ms", float64(time.Since(started).Microseconds())/1000, "request_id", id)
}

// UnaryInterceptor assigns request ids, turns panics into INTERNAL, and logs
// and counts every call. Install it before the authorization interceptor.
func UnaryInterceptor(log *slog.Logger, m *metrics.Metrics) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		started := time.Now()
		id := incomingRequestID(ctx)
		ctx = engine.WithRequestID(ctx, id)
		_ = grpc.SetHeader(ctx, metadata.Pairs("x-request-id", id))
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic in RPC handler", "method", info.FullMethod, "request_id", id, "panic", r,
					"stack", string(debug.Stack()))
				resp, err = nil, status.Errorf(codes.Internal, "internal error (request %s)", id)
			}
			logCall(log, m, ctx, info.FullMethod, id, err, started)
		}()
		return handler(ctx, req)
	}
}

type idStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *idStream) Context() context.Context { return s.ctx }

// StreamInterceptor is UnaryInterceptor for streams.
func StreamInterceptor(log *slog.Logger, m *metrics.Metrics) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		started := time.Now()
		id := incomingRequestID(ss.Context())
		ctx := engine.WithRequestID(ss.Context(), id)
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic in stream handler", "method", info.FullMethod, "request_id", id, "panic", r,
					"stack", string(debug.Stack()))
				err = status.Errorf(codes.Internal, "internal error (request %s)", id)
			}
			logCall(log, m, ctx, info.FullMethod, id, err, started)
		}()
		return handler(srv, &idStream{ServerStream: ss, ctx: ctx})
	}
}
