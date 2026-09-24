package api_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"

	"jarvis.internal/app-api/internal/api"
	"jarvis.internal/app-api/internal/metrics"
)

// levels records the level of every log record.
type levels struct {
	mu   sync.Mutex
	seen []slog.Level
}

func (l *levels) Enabled(context.Context, slog.Level) bool { return true }
func (l *levels) WithAttrs([]slog.Attr) slog.Handler       { return l }
func (l *levels) WithGroup(string) slog.Handler            { return l }
func (l *levels) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = append(l.seen, r.Level)
	return nil
}

func TestOnlyServerFaultsAreLoggedAsErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want slog.Level
	}{
		{"success", nil, slog.LevelInfo},
		{"client mistake", connect.NewError(connect.CodeInvalidArgument, errors.New("bad")), slog.LevelInfo},
		{"refused", connect.NewError(connect.CodeUnauthenticated, errors.New("no")), slog.LevelInfo},
		{"internal", connect.NewError(connect.CodeInternal, errors.New("boom")), slog.LevelError},
		{"unknown", errors.New("plain"), slog.LevelError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &levels{}
			interceptor := api.Logging(slog.New(h), metrics.New())
			call := interceptor(func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return connect.NewResponse(&emptypb.Empty{}), nil
			})
			_, _ = call(context.Background(), connect.NewRequest(&emptypb.Empty{}))
			if len(h.seen) != 1 || h.seen[0] != tc.want {
				t.Fatalf("logged at %v, want %v", h.seen, tc.want)
			}
		})
	}
}
