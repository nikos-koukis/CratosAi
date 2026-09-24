// Package server implements AuditService over gRPC: it validates events,
// stamps them with the caller's identity and appends them to the trail.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"path"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"jarvis.internal/audit/internal/chain"
	"jarvis.internal/audit/internal/metrics"
	"jarvis.internal/audit/internal/store"
	auditv1 "jarvis.internal/gen/go/jarvis/audit/v1"
	"jarvis.internal/libs/go/mtls"
)

const (
	maxBatch       = 500
	maxDetails     = 16
	maxDetailValue = 256
	defaultPage    = 50
	maxPage        = 200
	// Producers' clocks may run a little ahead.
	maxClockSkew = 5 * time.Minute
)

var (
	actionPattern    = regexp.MustCompile(`^[a-z0-9_.]{3,64}$`)
	detailKeyPattern = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	printable        = regexp.MustCompile(`^[\x21-\x7e]*$`)
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	prefixPattern    = regexp.MustCompile(`^[a-z0-9_.]{1,64}$`)
)

// Store is what the service needs from the database.
type Store interface {
	Append(ctx context.Context, source string, events []chain.Event) (recorded, duplicates int, err error)
	List(ctx context.Context, f store.Filter) ([]store.Record, *store.Cursor, error)
	Verify(ctx context.Context, tenant uuid.UUID) (store.Verification, error)
}

// Service implements auditv1.AuditServiceServer.
type Service struct {
	auditv1.UnimplementedAuditServiceServer
	Store   Store
	Metrics *metrics.Metrics
	Log     *slog.Logger
	Now     func() time.Time
}

func invalid(format string, args ...any) error {
	return status.Errorf(codes.InvalidArgument, format, args...)
}

func (s *Service) internal(ctx context.Context, what string, err error) error {
	id := requestID(ctx)
	s.Log.Error(what+" failed", "request_id", id, "error", err)
	return status.Errorf(codes.Internal, "internal error (request %s)", id)
}

func canonicalUUID(field, value string) (string, error) {
	id, err := uuid.Parse(value)
	if err != nil {
		return "", invalid("%s must be a UUID", field)
	}
	return id.String(), nil
}

func bounded(field, value string, max int) error {
	if len(value) > max || !printable.MatchString(value) {
		return invalid("%s must be at most %d printable ASCII characters", field, max)
	}
	return nil
}

// event checks one incoming event and converts it for the chain.
func (s *Service) event(i int, e *auditv1.Event) (chain.Event, error) {
	wrap := func(err error) error {
		st, _ := status.FromError(err)
		return invalid("event %d: %s", i, st.Message())
	}
	eventID, err := canonicalUUID("event_id", e.GetEventId())
	if err != nil {
		return chain.Event{}, wrap(err)
	}
	tenantID, err := canonicalUUID("tenant_id", e.GetTenantId())
	if err != nil {
		return chain.Event{}, wrap(err)
	}
	if e.GetOccurTime() == nil || e.GetOccurTime().CheckValid() != nil {
		return chain.Event{}, wrap(invalid("occur_time is required"))
	}
	occur := e.GetOccurTime().AsTime().UTC().Truncate(chain.Precision)
	if occur.After(s.Now().Add(maxClockSkew)) {
		return chain.Event{}, wrap(invalid("occur_time is in the future"))
	}
	actor := e.GetActor()
	if actor.GetKind() == auditv1.ActorKind_ACTOR_KIND_UNSPECIFIED || actor.GetId() == "" {
		return chain.Event{}, wrap(invalid("actor kind and id are required"))
	}
	checks := []struct {
		field, value string
		max          int
	}{
		{"actor.id", actor.GetId(), 128},
		{"on_behalf_of", e.GetOnBehalfOf(), 128},
		{"target_type", e.GetTargetType(), 64},
		{"target_id", e.GetTargetId(), 128},
		{"reason", e.GetReason(), 64},
		{"request_id", e.GetRequestId(), 128},
	}
	for _, c := range checks {
		if err := bounded(c.field, c.value, c.max); err != nil {
			return chain.Event{}, wrap(err)
		}
	}
	if !actionPattern.MatchString(e.GetAction()) {
		return chain.Event{}, wrap(invalid("action must be 3 to 64 of a-z 0-9 . _"))
	}
	if e.GetOutcome() == auditv1.Outcome_OUTCOME_UNSPECIFIED {
		return chain.Event{}, wrap(invalid("outcome is required"))
	}
	if len(e.GetDetails()) > maxDetails {
		return chain.Event{}, wrap(invalid("at most %d details", maxDetails))
	}
	for k, v := range e.GetDetails() {
		if !detailKeyPattern.MatchString(k) {
			return chain.Event{}, wrap(invalid("detail keys must be 1 to 32 of a-z 0-9 _"))
		}
		if utf8.RuneCountInString(v) > maxDetailValue || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return chain.Event{}, wrap(invalid("detail %q must be at most %d characters, without control characters",
				k, maxDetailValue))
		}
	}
	return chain.Event{
		TenantID: tenantID, EventID: eventID, OccurTime: occur,
		ActorKind: actor.GetKind().String(), ActorID: actor.GetId(), OnBehalfOf: e.GetOnBehalfOf(),
		Action: e.GetAction(), TargetType: e.GetTargetType(), TargetID: e.GetTargetId(),
		Outcome: e.GetOutcome().String(), Reason: e.GetReason(), RequestID: e.GetRequestId(),
		Details: e.GetDetails(),
	}, nil
}

// Record implements AuditServiceServer.
func (s *Service) Record(ctx context.Context, req *auditv1.RecordRequest) (*auditv1.RecordResponse, error) {
	if n := len(req.GetEvents()); n == 0 || n > maxBatch {
		return nil, invalid("a batch has 1 to %d events", maxBatch)
	}
	events := make([]chain.Event, len(req.GetEvents()))
	for i, e := range req.GetEvents() {
		converted, err := s.event(i, e)
		if err != nil {
			return nil, err
		}
		events[i] = converted
	}
	// The source is who the caller proved to be, never a request field.
	source := mtls.Principal(ctx)
	recorded, duplicates, err := s.Store.Append(ctx, source, events)
	if err != nil {
		return nil, s.internal(ctx, "append events", err)
	}
	for _, e := range events {
		s.Metrics.Recorded.WithLabelValues(source, e.Outcome).Inc()
	}
	if duplicates > 0 {
		s.Metrics.Duplicates.WithLabelValues(source).Add(float64(duplicates))
	}
	return &auditv1.RecordResponse{Recorded: int32(recorded), Duplicates: int32(duplicates)}, nil
}

type pageToken struct {
	T int64 `json:"t"` // occur time, Unix microseconds
	S int64 `json:"s"` // sequence
}

func encodeToken(c *store.Cursor) string {
	if c == nil {
		return ""
	}
	data, _ := json.Marshal(pageToken{T: c.OccurTime.UnixMicro(), S: c.Sequence})
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeToken(token string) (*store.Cursor, error) {
	if token == "" {
		return nil, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(token)
	var t pageToken
	if err != nil || len(token) > 256 || json.Unmarshal(data, &t) != nil || t.S < 1 {
		return nil, invalid("page_token is not valid")
	}
	return &store.Cursor{OccurTime: time.UnixMicro(t.T).UTC(), Sequence: t.S}, nil
}

// ListEvents implements AuditServiceServer.
func (s *Service) ListEvents(ctx context.Context, req *auditv1.ListEventsRequest) (*auditv1.ListEventsResponse, error) {
	tenant, err := uuid.Parse(req.GetTenantId())
	if err != nil {
		return nil, invalid("tenant_id must be a UUID")
	}
	if err := bounded("user_id", req.GetUserId(), 128); err != nil {
		return nil, err
	}
	if p := req.GetActionPrefix(); p != "" && !prefixPattern.MatchString(p) {
		return nil, invalid("action_prefix must be 1 to 64 of a-z 0-9 . _")
	}
	size := int(req.GetPageSize())
	switch {
	case size == 0:
		size = defaultPage
	case size < 0 || size > maxPage:
		return nil, invalid("page_size must be 1 to %d", maxPage)
	}
	after, err := decodeToken(req.GetPageToken())
	if err != nil {
		return nil, err
	}
	f := store.Filter{TenantID: tenant, UserID: req.GetUserId(), ActionPrefix: req.GetActionPrefix(),
		PageSize: size, After: after}
	if req.GetSince() != nil {
		f.Since = req.GetSince().AsTime()
	}
	if req.GetUntil() != nil {
		f.Until = req.GetUntil().AsTime()
	}
	records, next, err := s.Store.List(ctx, f)
	if err != nil {
		return nil, s.internal(ctx, "list events", err)
	}
	out := make([]*auditv1.Event, len(records))
	for i, r := range records {
		out[i] = toProto(r)
	}
	return &auditv1.ListEventsResponse{Events: out, NextPageToken: encodeToken(next)}, nil
}

func toProto(r store.Record) *auditv1.Event {
	return &auditv1.Event{
		EventId:    r.EventID,
		TenantId:   r.TenantID,
		OccurTime:  timestamppb.New(r.OccurTime),
		Actor:      &auditv1.Actor{Kind: auditv1.ActorKind(auditv1.ActorKind_value[r.ActorKind]), Id: r.ActorID},
		OnBehalfOf: r.OnBehalfOf,
		Action:     r.Action,
		TargetType: r.TargetType,
		TargetId:   r.TargetID,
		Outcome:    auditv1.Outcome(auditv1.Outcome_value[r.Outcome]),
		Reason:     r.Reason,
		RequestId:  r.RequestID,
		Details:    r.Details,
		Source:     r.Source,
		Sequence:   r.Sequence,
		Hash:       r.Hash,
		RecordTime: timestamppb.New(r.RecordTime),
	}
}

// VerifyChain implements AuditServiceServer.
func (s *Service) VerifyChain(ctx context.Context, req *auditv1.VerifyChainRequest) (*auditv1.VerifyChainResponse, error) {
	tenant, err := uuid.Parse(req.GetTenantId())
	if err != nil {
		return nil, invalid("tenant_id must be a UUID")
	}
	v, err := s.Store.Verify(ctx, tenant)
	if err != nil {
		return nil, s.internal(ctx, "verify chain", err)
	}
	result := "intact"
	if !v.Intact {
		result = "broken"
		s.Log.Error("AUDIT CHAIN BROKEN: stored events were changed or removed",
			"tenant_id", tenant, "first_broken_sequence", v.FirstBroken, "events", v.Events)
	}
	s.Metrics.Verifications.WithLabelValues(result).Inc()
	return &auditv1.VerifyChainResponse{Intact: v.Intact, Events: v.Events, FirstBrokenSequence: v.FirstBroken,
		HeadHash: v.Head}, nil
}

type requestIDKey struct{}

func requestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// UnaryInterceptor assigns request ids, recovers from panics, and logs and
// counts every call. It runs before the policy interceptor.
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
		method := path.Base(info.FullMethod)
		// The policy interceptor runs after this one; read the caller from its certificate.
		caller, _ := mtls.PeerPrincipal(ctx)
		defer func() {
			if p := recover(); p != nil {
				log.Error("panic", "method", method, "request_id", id, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
				resp, err = nil, status.Errorf(codes.Internal, "internal error (request %s)", id)
			}
			code := status.Code(err)
			m.RPCs.WithLabelValues(method, code.String()).Inc()
			level := slog.LevelInfo
			if code == codes.Internal || code == codes.Unknown {
				level = slog.LevelError
			}
			log.Log(ctx, level, "rpc", "method", method, "code", code.String(), "request_id", id,
				"caller", caller, "ms", time.Since(started).Milliseconds())
		}()
		return handler(ctx, req)
	}
}
