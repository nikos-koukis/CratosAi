// Package admin is the app API's internal side: AppAdminService over gRPC
// with mutual TLS, for the dashboard backend. It issues pairing codes for
// signed-in users and manages their app sessions.
package admin

import (
	"context"
	"log/slog"
	"net/url"
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
	"google.golang.org/protobuf/types/known/timestamppb"

	"jarvis.internal/app-api/internal/metrics"
	"jarvis.internal/app-api/internal/secret"
	"jarvis.internal/app-api/internal/store"
	appv1 "jarvis.internal/gen/go/jarvis/app/v1"
	"jarvis.internal/libs/go/mtls"
)

var (
	userPattern      = regexp.MustCompile(`^[\x21-\x7e]{1,128}$`)
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
)

// Store is what the admin service needs from the database.
type Store interface {
	CreatePairingCode(ctx context.Context, codeHash []byte, tenant uuid.UUID, user string, expires time.Time) error
	Sessions(ctx context.Context, tenant uuid.UUID, user string) ([]store.Session, error)
	Revoke(ctx context.Context, tenant uuid.UUID, user string, id uuid.UUID, reason string) (bool, error)
}

// Service implements appv1.AppAdminServiceServer.
type Service struct {
	appv1.UnimplementedAppAdminServiceServer
	Store      Store
	Metrics    *metrics.Metrics
	Log        *slog.Logger
	PublicURL  string
	PairingTTL time.Duration
}

func owner(tenantID, userID string) (uuid.UUID, error) {
	tenant, err := uuid.Parse(tenantID)
	if err != nil {
		return uuid.Nil, status.Error(codes.InvalidArgument, "tenant_id must be a UUID")
	}
	if !userPattern.MatchString(userID) {
		return uuid.Nil, status.Error(codes.InvalidArgument, "user_id must be 1 to 128 printable ASCII characters")
	}
	return tenant, nil
}

func (s *Service) internal(ctx context.Context, what string, err error) error {
	id := requestID(ctx)
	s.Log.Error(what+" failed", "request_id", id, "error", err)
	return status.Errorf(codes.Internal, "internal error (request %s)", id)
}

// CreatePairingCode implements AppAdminServiceServer.
func (s *Service) CreatePairingCode(ctx context.Context, req *appv1.CreatePairingCodeRequest) (*appv1.CreatePairingCodeResponse, error) {
	tenant, err := owner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	code, err := secret.NewPairingCode()
	if err != nil {
		return nil, s.internal(ctx, "make pairing code", err)
	}
	normalized, err := secret.NormalizeCode(code)
	if err != nil {
		return nil, s.internal(ctx, "normalize pairing code", err)
	}
	expires := time.Now().Add(s.PairingTTL)
	if err := s.Store.CreatePairingCode(ctx, secret.Hash(normalized), tenant, req.GetUserId(), expires); err != nil {
		return nil, s.internal(ctx, "store pairing code", err)
	}
	s.Metrics.Pairings.WithLabelValues("issued").Inc()
	s.Log.Info("pairing code issued", "request_id", requestID(ctx), "tenant_id", tenant)
	link := url.URL{Scheme: "jarvis", Host: "pair",
		RawQuery: url.Values{"server": {s.PublicURL}, "code": {code}}.Encode()}
	return &appv1.CreatePairingCodeResponse{Code: code, PairingUrl: link.String(), ExpireTime: timestamppb.New(expires)}, nil
}

// ListSessions implements AppAdminServiceServer.
func (s *Service) ListSessions(ctx context.Context, req *appv1.ListSessionsRequest) (*appv1.ListSessionsResponse, error) {
	tenant, err := owner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	sessions, err := s.Store.Sessions(ctx, tenant, req.GetUserId())
	if err != nil {
		return nil, s.internal(ctx, "list sessions", err)
	}
	out := &appv1.ListSessionsResponse{}
	for _, session := range sessions {
		out.Sessions = append(out.Sessions, &appv1.AppSession{
			SessionId: session.ID.String(), DeviceName: session.DeviceName, DeviceModel: session.DeviceModel,
			CreateTime: timestamppb.New(session.CreatedAt), LastUseTime: timestamppb.New(session.LastUsedAt),
		})
	}
	return out, nil
}

// RevokeSession implements AppAdminServiceServer.
func (s *Service) RevokeSession(ctx context.Context, req *appv1.RevokeSessionRequest) (*appv1.RevokeSessionResponse, error) {
	tenant, err := owner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.GetSessionId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "session_id must be a UUID")
	}
	revoked, err := s.Store.Revoke(ctx, tenant, req.GetUserId(), id, store.ReasonRevoked)
	if err != nil {
		return nil, s.internal(ctx, "revoke session", err)
	}
	if revoked {
		s.Metrics.Revoked.WithLabelValues("revoked").Inc()
		s.Log.Info("app session revoked", "request_id", requestID(ctx), "session_id", id, "tenant_id", tenant)
	}
	return &appv1.RevokeSessionResponse{}, nil
}

// --- interceptor -----------------------------------------------------------------------

type requestIDKey struct{}

func requestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// UnaryInterceptor assigns request ids, turns panics into INTERNAL, and logs
// and counts every call. Install it before the authorization interceptor.
func UnaryInterceptor(log *slog.Logger, m *metrics.Metrics) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		started := time.Now()
		id := ""
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if values := md.Get("x-request-id"); len(values) == 1 && requestIDPattern.MatchString(values[0]) {
				id = values[0]
			}
		}
		if id == "" {
			id = uuid.NewString()
		}
		ctx = context.WithValue(ctx, requestIDKey{}, id)
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic in RPC handler", "method", info.FullMethod, "request_id", id, "panic", r,
					"stack", string(debug.Stack()))
				resp, err = nil, status.Errorf(codes.Internal, "internal error (request %s)", id)
			}
			code := status.Code(err)
			m.RPCs.WithLabelValues(path.Base(info.FullMethod), code.String()).Inc()
			m.RPCSeconds.WithLabelValues(path.Base(info.FullMethod)).Observe(time.Since(started).Seconds())
			level := slog.LevelInfo
			switch {
			case code == codes.Internal || code == codes.Unknown:
				level = slog.LevelError
			case strings.HasPrefix(info.FullMethod, "/grpc.health."):
				level = slog.LevelDebug
			}
			principal, _ := mtls.PeerPrincipal(ctx)
			log.Log(ctx, level, "admin rpc", "method", info.FullMethod, "principal", principal, "code", code.String(),
				"duration_ms", float64(time.Since(started).Microseconds())/1000, "request_id", id)
		}()
		return handler(ctx, req)
	}
}

var _ appv1.AppAdminServiceServer = (*Service)(nil)
