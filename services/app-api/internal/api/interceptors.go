package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"path"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"jarvis.internal/app-api/internal/metrics"
	"jarvis.internal/app-api/internal/ratelimit"
	"jarvis.internal/app-api/internal/store"
	"jarvis.internal/gen/go/jarvis/app/v1/appv1connect"
)

type contextKey struct{}

// call is per-request state shared by the interceptors and handlers.
type call struct {
	requestID string
	caller    Caller
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// Caller is the authenticated user of a request.
type Caller struct {
	TenantID  uuid.UUID
	UserID    string
	SessionID uuid.UUID
}

func callOf(ctx context.Context) *call {
	c, _ := ctx.Value(contextKey{}).(*call)
	return c
}

func requestID(ctx context.Context) string {
	if c := callOf(ctx); c != nil {
		return c.requestID
	}
	return ""
}

func callerOf(ctx context.Context) Caller {
	if c := callOf(ctx); c != nil {
		return c.caller
	}
	return Caller{}
}

// anonymous procedures take a secret instead of an access token; they are
// rate limited per client address.
var anonymous = map[string]bool{
	appv1connect.AppServiceRedeemPairingCodeProcedure: true,
	appv1connect.AppServiceRefreshSessionProcedure:    true,
	appv1connect.AppServiceSignOutProcedure:           true,
}

// Logging assigns request ids, and logs and counts every call.
func Logging(log *slog.Logger, m *metrics.Metrics) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			started := time.Now()
			id := req.Header().Get("X-Request-Id")
			if !requestIDPattern.MatchString(id) {
				id = uuid.NewString()
			}
			ctx = context.WithValue(ctx, contextKey{}, &call{requestID: id})
			resp, err := next(ctx, req)
			if resp != nil {
				resp.Header().Set("X-Request-Id", id)
			}
			procedure := path.Base(req.Spec().Procedure)
			code, level := "ok", slog.LevelInfo
			if err != nil {
				// CodeOf(nil) is CodeUnknown, so only real errors get here.
				c := connect.CodeOf(err)
				code = c.String()
				if c == connect.CodeInternal || c == connect.CodeUnknown {
					level = slog.LevelError
				}
			}
			m.RPCs.WithLabelValues(procedure, code).Inc()
			m.RPCSeconds.WithLabelValues(procedure).Observe(time.Since(started).Seconds())
			attrs := []any{"procedure", procedure, "code", code,
				"duration_ms", float64(time.Since(started).Microseconds()) / 1000, "request_id", id}
			if c := callerOf(ctx); c.SessionID != uuid.Nil {
				attrs = append(attrs, "session_id", c.SessionID, "tenant_id", c.TenantID)
			}
			log.Log(ctx, level, "rpc", attrs...)
			return resp, err
		}
	}
}

// Recover turns a handler panic into INTERNAL (connect.WithRecover).
func Recover(log *slog.Logger) func(context.Context, connect.Spec, http.Header, any) error {
	return func(ctx context.Context, spec connect.Spec, _ http.Header, panicked any) error {
		log.Error("panic in handler", "procedure", spec.Procedure, "request_id", requestID(ctx),
			"panic", panicked, "stack", string(debug.Stack()))
		return connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
}

// RateLimit limits anonymous procedures per client address.
func RateLimit(limiter *ratelimit.Limiter, m *metrics.Metrics, log *slog.Logger) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if anonymous[req.Spec().Procedure] && !limiter.Allow(clientAddress(req.Peer().Addr)) {
				procedure := path.Base(req.Spec().Procedure)
				m.Limited.WithLabelValues(procedure).Inc()
				log.Warn("rate limited", "procedure", procedure, "request_id", requestID(ctx))
				return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many attempts; wait a minute"))
			}
			return next(ctx, req)
		}
	}
}

// clientAddress is the IP of the peer (the port changes per connection).
func clientAddress(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// SessionChecker loads a session to check it is still active.
type SessionChecker interface {
	Session(ctx context.Context, id uuid.UUID) (store.Session, error)
}

// Auth requires a valid access token of an active session on every
// procedure except the anonymous ones, and puts the Caller in the context.
// A signed-out or revoked session's tokens stop working at once here.
func Auth(minter *Minter, sessions SessionChecker, log *slog.Logger) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if anonymous[req.Spec().Procedure] {
				return next(ctx, req)
			}
			scheme, token, ok := strings.Cut(req.Header().Get("Authorization"), " ")
			if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
				return nil, unauthenticated()
			}
			identity, err := minter.Verify(token)
			if err != nil {
				log.Debug("access token rejected", "request_id", requestID(ctx), "error", err)
				return nil, unauthenticated()
			}
			sessionID, err := uuid.Parse(identity.SessionID)
			if err != nil {
				return nil, unauthenticated() // not an app session's token
			}
			session, err := sessions.Session(ctx, sessionID)
			switch {
			case errors.Is(err, store.ErrNotFound):
				return nil, sessionEnded()
			case err != nil:
				return nil, internal(ctx, log, "load session", err)
			case !session.Active(time.Now()) || session.TenantID.String() != identity.TenantID || session.UserID != identity.UserID:
				return nil, sessionEnded()
			}
			c := callOf(ctx)
			if c == nil {
				c = &call{requestID: uuid.NewString()}
				ctx = context.WithValue(ctx, contextKey{}, c)
			}
			c.caller = Caller{TenantID: session.TenantID, UserID: session.UserID, SessionID: session.ID}
			return next(ctx, req)
		}
	}
}
