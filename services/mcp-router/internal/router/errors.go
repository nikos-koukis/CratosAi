package router

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	mcpv1 "jarvis.internal/gen/go/jarvis/mcp/v1"
	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/mcp-router/internal/netguard"
	"jarvis.internal/mcp-router/internal/oauthflow"
	"jarvis.internal/mcp-router/internal/upstream"
)

// ErrorDomain is the google.rpc.ErrorInfo domain of router errors.
const ErrorDomain = "mcp.jarvis"

const maxMessageBytes = 512

// JSON-RPC codes the SDK uses for its own transport failures (client or
// server closing, request rejected by the transport): not server answers.
var localWireCodes = []int64{-32003, -32004, -32005}

// reasonError is a status error with an ErrorInfo detail.
func reasonError(code codes.Code, reason mcpv1.ErrorReason, message string) error {
	st := status.New(code, message)
	if detailed, err := st.WithDetails(&errdetails.ErrorInfo{Domain: ErrorDomain, Reason: reason.String()}); err == nil {
		st = detailed
	}
	return st.Err()
}

func rateLimited(retryAfter time.Duration) error {
	st := status.New(codes.ResourceExhausted, "too many tool calls; retry later")
	detailed, err := st.WithDetails(
		&errdetails.ErrorInfo{Domain: ErrorDomain, Reason: mcpv1.ErrorReason_ERROR_REASON_RATE_LIMITED.String()},
		&errdetails.RetryInfo{RetryDelay: durationpb.New(retryAfter)},
	)
	if err == nil {
		st = detailed
	}
	return st.Err()
}

func invalid(message string) error { return status.Error(codes.InvalidArgument, message) }

func notFound() error {
	return reasonError(codes.NotFound, mcpv1.ErrorReason_ERROR_REASON_INTEGRATION_NOT_FOUND, "integration not found")
}

// failure is how an upstream problem is reported, both as an RPC error
// (CallTool) and as an IntegrationError (ListTools).
type failure struct {
	code    codes.Code
	reason  mcpv1.ErrorReason
	message string
	// internal failures are logged with their cause and reported vaguely.
	internal bool
}

func (f failure) err() error {
	if f.reason == mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED {
		return status.Error(f.code, f.message)
	}
	return reasonError(f.code, f.reason, f.message)
}

// classify maps an error from connecting to or calling an MCP server.
func classify(ctx context.Context, err error) failure {
	var wire *jsonrpc.Error
	var grpcErr interface{ GRPCStatus() *status.Status }
	switch {
	case errors.Is(err, oauthflow.ErrNeedsReauth), errors.Is(err, upstream.ErrNeedsReauth):
		return failure{codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_NEEDS_REAUTHORIZATION,
			"the server no longer accepts the stored authorization; reauthorize the integration", false}
	case errors.Is(err, netguard.ErrNotAllowed):
		return failure{codes.PermissionDenied, mcpv1.ErrorReason_ERROR_REASON_SERVER_NOT_ALLOWED,
			"the server resolves to an address that is not allowed", false}
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return failure{codes.DeadlineExceeded, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED, "the server did not answer in time", false}
	case errors.Is(ctx.Err(), context.Canceled):
		return failure{codes.Canceled, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED, "the call was cancelled", false}
	case errors.As(err, &wire) && !slices.Contains(localWireCodes, wire.Code):
		return failure{codes.Aborted, mcpv1.ErrorReason_ERROR_REASON_UPSTREAM_ERROR,
			"the server returned an error: " + sanitize(wire.Message), false}
	case errors.Is(err, vaultclient.ErrSealedDataInvalid):
		return failure{codes.Internal, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED, "stored credentials could not be opened", true}
	case errors.As(err, &grpcErr): // only the Vault is reached over gRPC
		if code := grpcErr.GRPCStatus().Code(); code == codes.Unavailable || code == codes.DeadlineExceeded {
			return failure{codes.Unavailable, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED, "the key vault is unavailable", true}
		}
		return failure{codes.Internal, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED, "internal error", true}
	default:
		return failure{codes.Unavailable, mcpv1.ErrorReason_ERROR_REASON_UPSTREAM_UNAVAILABLE, "the server could not be reached", false}
	}
}

// sanitize makes remote text safe to pass on: printable, single line, bounded.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
	return truncateUTF8(strings.TrimSpace(s), maxMessageBytes)
}

// truncateUTF8 cuts s to at most n bytes without splitting a character.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// --- validation ----------------------------------------------------------------

type owner struct {
	tenant uuid.UUID
	user   string
}

func parseOwner(tenantID, userID string) (owner, error) {
	tenant, err := uuid.Parse(tenantID)
	if err != nil || tenant == uuid.Nil || tenantID != tenant.String() {
		return owner{}, invalid("tenant_id must be a canonical lowercase UUID")
	}
	if !printableASCII(userID, 1, 128) {
		return owner{}, invalid("user_id must be 1 to 128 printable ASCII characters")
	}
	return owner{tenant: tenant, user: userID}, nil
}

func parseIntegrationID(id string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(id)
	if err != nil || id != parsed.String() {
		return uuid.Nil, invalid("integration_id must be a canonical lowercase UUID")
	}
	return parsed, nil
}

func printableASCII(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// validToolName accepts the MCP recommendation (1-128 characters) loosely:
// any visible ASCII, so both what ListTools returns and what CallTool
// accepts stay safe to log and to map to model function names.
func validToolName(name string) bool {
	return printableASCII(name, 1, 128) && !strings.ContainsRune(name, ' ')
}

var displayNameForbidden = regexp.MustCompile(`[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]`)

func validDisplayName(name string) bool {
	n := utf8.RuneCountInString(name)
	return utf8.ValidString(name) && n >= 1 && n <= 64 && strings.TrimSpace(name) == name &&
		!displayNameForbidden.MatchString(name)
}

// validBearerToken accepts RFC 6750 token characters (visible ASCII).
func validBearerToken(token []byte) bool {
	if len(token) == 0 || len(token) > 8192 {
		return false
	}
	for _, b := range token {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}
