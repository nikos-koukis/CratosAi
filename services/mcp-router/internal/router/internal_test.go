package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	mcpv1 "jarvis.internal/gen/go/jarvis/mcp/v1"
	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/mcp-router/internal/metrics"
	"jarvis.internal/mcp-router/internal/netguard"
	"jarvis.internal/mcp-router/internal/oauthflow"
	"jarvis.internal/mcp-router/internal/store"
	"jarvis.internal/mcp-router/internal/upstream"
)

func TestClassify(t *testing.T) {
	ctx := context.Background()
	expired, cancel := context.WithTimeout(ctx, 0)
	defer cancel()
	cases := []struct {
		name   string
		ctx    context.Context
		err    error
		code   codes.Code
		reason mcpv1.ErrorReason
	}{
		{"refresh refused", ctx, fmt.Errorf("x: %w", oauthflow.ErrNeedsReauth), codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_NEEDS_REAUTHORIZATION},
		{"server refused", ctx, fmt.Errorf("x: %w", upstream.ErrNeedsReauth), codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_NEEDS_REAUTHORIZATION},
		{"guard", ctx, fmt.Errorf("dial: %w", netguard.ErrNotAllowed), codes.PermissionDenied, mcpv1.ErrorReason_ERROR_REASON_SERVER_NOT_ALLOWED},
		{"deadline", expired, errors.New("anything"), codes.DeadlineExceeded, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED},
		{"server error", ctx, fmt.Errorf("calling: %w", &jsonrpc.Error{Code: -32602, Message: "unknown tool"}), codes.Aborted, mcpv1.ErrorReason_ERROR_REASON_UPSTREAM_ERROR},
		{"transport rejection", ctx, fmt.Errorf("calling: %w", &jsonrpc.Error{Code: -32005, Message: "rejected by transport"}), codes.Unavailable, mcpv1.ErrorReason_ERROR_REASON_UPSTREAM_UNAVAILABLE},
		{"vault down", ctx, fmt.Errorf("open: %w", status.Error(codes.Unavailable, "refused")), codes.Unavailable, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED},
		{"vault refused", ctx, fmt.Errorf("open: %w", status.Error(codes.PermissionDenied, "no")), codes.Internal, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED},
		{"tampered credentials", ctx, vaultclient.ErrSealedDataInvalid, codes.Internal, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED},
		{"network", ctx, errors.New("connection reset"), codes.Unavailable, mcpv1.ErrorReason_ERROR_REASON_UPSTREAM_UNAVAILABLE},
	}
	for _, c := range cases {
		f := classify(c.ctx, c.err)
		if f.code != c.code || f.reason != c.reason {
			t.Errorf("%s: got %v/%v, want %v/%v", c.name, f.code, f.reason, c.code, c.reason)
		}
	}
}

func TestSanitizeAndTruncate(t *testing.T) {
	if got := sanitize("line1\nline2\x00\u0085end\xff"); strings.ContainsAny(got, "\n\x00\u0085") || !utf8.ValidString(got) {
		t.Fatalf("sanitize = %q", got)
	}
	if got := sanitize(strings.Repeat("ω", 1000)); len(got) > maxMessageBytes || !utf8.ValidString(got) {
		t.Fatalf("sanitize length %d", len(got))
	}
	for n := range 8 {
		if got := truncateUTF8("aωb€c", n); len(got) > n || !utf8.ValidString(got) {
			t.Fatalf("truncateUTF8(%d) = %q", n, got)
		}
	}
}

func TestConvertContentBudget(t *testing.T) {
	budget := 10
	blocks := []mcp.Content{
		&mcp.TextContent{Text: "12345"},
		&mcp.ImageContent{MIMEType: "image/png", Data: []byte("0123456789")}, // does not fit
		&mcp.TextContent{Text: "abcdefgh"},                                   // cut to 5
		&mcp.ResourceLink{URI: "x"},                                          // no budget left
	}
	out, truncated := convertContent(blocks, &budget)
	if !truncated || len(out) != 2 || out[1].GetText().GetText() != "abcde" || budget != 0 {
		t.Fatalf("out = %v, truncated = %v, budget = %d", out, truncated, budget)
	}
	budget = 100
	if _, truncated := structured(map[string]any{"k": strings.Repeat("v", 200)}, &budget); !truncated || budget != 100 {
		t.Fatal("oversized structured content kept")
	}
}

func TestConvertToolRejectsUnsafeNames(t *testing.T) {
	integration := store.Integration{DisplayName: "X"}
	for _, name := range []string{"", "has space", "new\nline", "ünïcode", strings.Repeat("a", 129)} {
		if _, ok := convertTool(integration, &mcp.Tool{Name: name}); ok {
			t.Errorf("tool name %q accepted", name)
		}
	}
	tool, ok := convertTool(integration, &mcp.Tool{Name: "get_issue"})
	if !ok || tool.GetInputSchemaJson() != defaultInputSchema || !tool.GetAnnotations().GetDestructive() || !tool.GetAnnotations().GetOpenWorld() {
		t.Fatalf("defaults: %v", tool)
	}
}

func TestInterceptor(t *testing.T) {
	intercept := Interceptor(slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.New())
	info := &grpc.UnaryServerInfo{FullMethod: "/jarvis.mcp.v1.McpRouterService/CallTool"}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", "req-42"))
	var seen string
	_, err := intercept(ctx, nil, info, func(ctx context.Context, _ any) (any, error) {
		seen = RequestID(ctx)
		return "ok", nil
	})
	if err != nil || seen != "req-42" {
		t.Fatalf("request id = %q, err = %v", seen, err)
	}

	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", "bad id\n"))
	_, _ = intercept(ctx, nil, info, func(ctx context.Context, _ any) (any, error) {
		seen = RequestID(ctx)
		return nil, nil
	})
	if seen == "bad id\n" || len(seen) != 36 {
		t.Fatalf("unsafe request id kept: %q", seen)
	}

	resp, err := intercept(context.Background(), nil, info, func(context.Context, any) (any, error) {
		panic("boom")
	})
	if resp != nil || status.Code(err) != codes.Internal || strings.Contains(err.Error(), "boom") {
		t.Fatalf("panic → %v, %v", resp, err)
	}
}
