// Package api is the app API's public side: the AppService (Connect, gRPC
// and gRPC-Web over HTTPS) for the iPhone app and, later, the web dashboard.
//
// Apps pair with a one-time code and then hold a session: a refresh token
// that rotates on every use and short-lived access and voice tokens. Task and
// approval calls go to the orchestrator on the caller's behalf; the tenant
// and user always come from the verified session, never from the request.
package api

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"jarvis.internal/app-api/internal/metrics"
	"jarvis.internal/app-api/internal/secret"
	"jarvis.internal/app-api/internal/store"
	appv1 "jarvis.internal/gen/go/jarvis/app/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
)

// RefreshGrace is how long a just-rotated refresh token still works, so an
// app that lost the response to its refresh can retry.
const RefreshGrace = time.Minute

const orchestratorTimeout = 30 * time.Second

var (
	approverPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	// APNs device tokens are 32 bytes today; Apple says the length may grow.
	deviceTokenPattern = regexp.MustCompile(`^(?:[0-9a-f]{2}){32,200}$`)
)

// Store is what the service needs from the database.
type Store interface {
	SessionChecker
	RedeemPairingCode(ctx context.Context, codeHash []byte, n store.NewSession) (store.Session, error)
	Refresh(ctx context.Context, presented, next []byte, idleTTL, grace time.Duration) (store.Session, store.RefreshOutcome, error)
	SignOut(ctx context.Context, presented []byte) (uuid.NullUUID, error)
	SetPushToken(ctx context.Context, session uuid.UUID, token, environment string) error
	DeletePushToken(ctx context.Context, session uuid.UUID) error
}

// Service implements appv1connect.AppServiceHandler.
type Service struct {
	Store        Store
	Minter       *Minter
	Orchestrator orchv1.OrchestratorServiceClient
	Metrics      *metrics.Metrics
	Log          *slog.Logger
	VoiceURL     string
	RefreshTTL   time.Duration
}

// --- sessions ------------------------------------------------------------------------

// RedeemPairingCode implements AppServiceHandler.
func (s *Service) RedeemPairingCode(ctx context.Context, req *connect.Request[appv1.RedeemPairingCodeRequest]) (*connect.Response[appv1.RedeemPairingCodeResponse], error) {
	name, model := strings.TrimSpace(req.Msg.GetDeviceName()), strings.TrimSpace(req.Msg.GetDeviceModel())
	switch {
	case !displayText(name, 64):
		return nil, invalid("device_name must be 1 to 64 printable characters")
	case !displayText(model, 64):
		return nil, invalid("device_model must be 1 to 64 printable characters")
	}
	code, err := secret.NormalizeCode(req.Msg.GetCode())
	if err != nil {
		s.Metrics.Pairings.WithLabelValues("invalid").Inc()
		return nil, pairingInvalid()
	}
	refresh, err := secret.NewRefreshToken()
	if err != nil {
		return nil, internal(ctx, s.Log, "make refresh token", err)
	}
	session, err := s.Store.RedeemPairingCode(ctx, secret.Hash(code), store.NewSession{
		ID: uuid.New(), DeviceName: name, DeviceModel: model, RefreshHash: secret.Hash(refresh),
		RefreshExpiresAt: time.Now().Add(s.RefreshTTL),
	})
	if errors.Is(err, store.ErrNotFound) {
		s.Metrics.Pairings.WithLabelValues("invalid").Inc()
		s.Log.Warn("pairing code refused", "request_id", requestID(ctx))
		return nil, pairingInvalid()
	}
	if err != nil {
		return nil, internal(ctx, s.Log, "redeem pairing code", err)
	}
	out, err := s.session(session, refresh)
	if err != nil {
		return nil, internal(ctx, s.Log, "mint tokens", err)
	}
	s.Metrics.Pairings.WithLabelValues("paired").Inc()
	s.Log.Info("app paired", "request_id", requestID(ctx), "session_id", session.ID, "tenant_id", session.TenantID,
		"device_model", model)
	return connect.NewResponse(&appv1.RedeemPairingCodeResponse{Session: out}), nil
}

// RefreshSession implements AppServiceHandler.
func (s *Service) RefreshSession(ctx context.Context, req *connect.Request[appv1.RefreshSessionRequest]) (*connect.Response[appv1.RefreshSessionResponse], error) {
	presented := req.Msg.GetRefreshToken()
	if secret.CheckRefreshToken(presented) != nil {
		s.Metrics.Refreshes.WithLabelValues("ended").Inc()
		return nil, sessionEnded()
	}
	next, err := secret.NewRefreshToken()
	if err != nil {
		return nil, internal(ctx, s.Log, "make refresh token", err)
	}
	session, outcome, err := s.Store.Refresh(ctx, secret.Hash(presented), secret.Hash(next), s.RefreshTTL, RefreshGrace)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.Metrics.Refreshes.WithLabelValues("ended").Inc()
		return nil, sessionEnded()
	case err != nil:
		return nil, internal(ctx, s.Log, "refresh session", err)
	case outcome == store.Reused:
		s.Metrics.Refreshes.WithLabelValues("reused").Inc()
		s.Metrics.Revoked.WithLabelValues("reused").Inc()
		s.Log.Warn("refresh token reused after rotation: session ended (the token was probably copied)",
			"request_id", requestID(ctx), "session_id", session.ID, "tenant_id", session.TenantID)
		return nil, sessionEnded()
	}
	label := "rotated"
	if outcome == store.Retried {
		label = "retried"
	}
	s.Metrics.Refreshes.WithLabelValues(label).Inc()
	out, err := s.session(session, next)
	if err != nil {
		return nil, internal(ctx, s.Log, "mint tokens", err)
	}
	return connect.NewResponse(&appv1.RefreshSessionResponse{Session: out}), nil
}

// SignOut implements AppServiceHandler.
func (s *Service) SignOut(ctx context.Context, req *connect.Request[appv1.SignOutRequest]) (*connect.Response[appv1.SignOutResponse], error) {
	if secret.CheckRefreshToken(req.Msg.GetRefreshToken()) == nil {
		id, err := s.Store.SignOut(ctx, secret.Hash(req.Msg.GetRefreshToken()))
		if err != nil {
			return nil, internal(ctx, s.Log, "sign out", err)
		}
		if id.Valid {
			s.Metrics.Revoked.WithLabelValues("signed_out").Inc()
			s.Log.Info("app signed out", "request_id", requestID(ctx), "session_id", id.UUID)
		}
	}
	return connect.NewResponse(&appv1.SignOutResponse{}), nil
}

func (s *Service) session(session store.Session, refresh string) (*appv1.Session, error) {
	access, voice, expires, err := s.Minter.Mint(session)
	if err != nil {
		return nil, err
	}
	return &appv1.Session{
		SessionId:              session.ID.String(),
		TenantId:               session.TenantID.String(),
		UserId:                 session.UserID,
		AccessToken:            access,
		AccessTokenExpireTime:  timestamppb.New(expires),
		VoiceToken:             voice,
		VoiceUrl:               s.VoiceURL,
		RefreshToken:           refresh,
		RefreshTokenExpireTime: timestamppb.New(session.RefreshExpiresAt),
	}, nil
}

func pairingInvalid() *connect.Error {
	return reasoned(connect.CodeUnauthenticated, appv1.ErrorReason_ERROR_REASON_PAIRING_CODE_INVALID,
		"the pairing code is not valid; ask for a new one")
}

// displayText: 1 to max characters, valid UTF-8 without control characters.
func displayText(s string, max int) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

// --- tasks and approvals -------------------------------------------------------------------

// orchestrator returns a context for an orchestrator call on the caller's behalf.
func (s *Service) orchestrator(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx = metadata.AppendToOutgoingContext(ctx, "x-request-id", requestID(ctx))
	return context.WithTimeout(ctx, orchestratorTimeout)
}

// ListTasks implements AppServiceHandler.
func (s *Service) ListTasks(ctx context.Context, req *connect.Request[appv1.ListTasksRequest]) (*connect.Response[appv1.ListTasksResponse], error) {
	limit := req.Msg.GetLimit()
	if limit < 0 || limit > 100 {
		return nil, invalid("limit must be 0 to 100")
	}
	if limit == 0 {
		limit = 20
	}
	c := callerOf(ctx)
	octx, cancel := s.orchestrator(ctx)
	defer cancel()
	resp, err := s.Orchestrator.ListTasks(octx, &orchv1.ListTasksRequest{TenantId: c.TenantID.String(), UserId: c.UserID,
		Limit: limit})
	if err != nil {
		return nil, fromOrchestrator(ctx, s.Log, "list tasks", err)
	}
	out := &appv1.ListTasksResponse{}
	for _, t := range resp.GetTasks() {
		out.Tasks = append(out.Tasks, taskProto(t))
	}
	return connect.NewResponse(out), nil
}

// CancelTask implements AppServiceHandler.
func (s *Service) CancelTask(ctx context.Context, req *connect.Request[appv1.CancelTaskRequest]) (*connect.Response[appv1.CancelTaskResponse], error) {
	if _, err := uuid.Parse(req.Msg.GetTaskId()); err != nil {
		return nil, invalid("task_id must be a UUID")
	}
	c := callerOf(ctx)
	octx, cancel := s.orchestrator(ctx)
	defer cancel()
	resp, err := s.Orchestrator.CancelTask(octx, &orchv1.CancelTaskRequest{TenantId: c.TenantID.String(),
		UserId: c.UserID, TaskId: req.Msg.GetTaskId()})
	if status.Code(err) == codes.NotFound {
		return nil, reasoned(connect.CodeNotFound, appv1.ErrorReason_ERROR_REASON_TASK_NOT_FOUND, "no such task")
	}
	if err != nil {
		return nil, fromOrchestrator(ctx, s.Log, "cancel task", err)
	}
	s.Log.Info("task cancelled from the app", "request_id", requestID(ctx), "task_id", req.Msg.GetTaskId())
	return connect.NewResponse(&appv1.CancelTaskResponse{Task: taskProto(resp.GetTask())}), nil
}

// ListApprovals implements AppServiceHandler.
func (s *Service) ListApprovals(ctx context.Context, _ *connect.Request[appv1.ListApprovalsRequest]) (*connect.Response[appv1.ListApprovalsResponse], error) {
	c := callerOf(ctx)
	octx, cancel := s.orchestrator(ctx)
	defer cancel()
	resp, err := s.Orchestrator.ListTasks(octx, &orchv1.ListTasksRequest{TenantId: c.TenantID.String(), UserId: c.UserID,
		Limit: 100})
	if err != nil {
		return nil, fromOrchestrator(ctx, s.Log, "list approvals", err)
	}
	now := time.Now()
	out := &appv1.ListApprovalsResponse{}
	for _, t := range resp.GetTasks() {
		a := t.GetPendingApproval()
		if t.GetState() != orchv1.TaskState_TASK_STATE_AWAITING_APPROVAL || a == nil || !a.GetExpireTime().AsTime().After(now) {
			continue
		}
		out.Approvals = append(out.Approvals, approvalProto(t, a))
	}
	slices.SortFunc(out.Approvals, func(a, b *appv1.Approval) int {
		return a.GetExpireTime().AsTime().Compare(b.GetExpireTime().AsTime())
	})
	return connect.NewResponse(out), nil
}

// SubmitApproval implements AppServiceHandler.
func (s *Service) SubmitApproval(ctx context.Context, req *connect.Request[appv1.SubmitApprovalRequest]) (*connect.Response[appv1.SubmitApprovalResponse], error) {
	m := req.Msg
	switch {
	case m.GetApprovalId() == "" || len(m.GetApprovalId()) > 128:
		return nil, invalid("approval_id must be 1 to 128 characters")
	case !approverPattern.MatchString(m.GetApproverId()):
		return nil, invalid("approver_id must be 1 to 64 of A-Z a-z 0-9 . _ -")
	case len(m.GetSignature()) != 64:
		return nil, invalid("signature must be a raw 64-byte P-256 signature (r||s)")
	}
	c := callerOf(ctx)
	octx, cancel := s.orchestrator(ctx)
	defer cancel()
	resp, err := s.Orchestrator.SubmitDeviceApproval(octx, &orchv1.SubmitDeviceApprovalRequest{
		TenantId: c.TenantID.String(), UserId: c.UserID, ApprovalId: m.GetApprovalId(),
		ApproverId: m.GetApproverId(), Signature: m.GetSignature(),
	})
	switch status.Code(err) {
	case codes.OK:
	case codes.NotFound:
		return nil, reasoned(connect.CodeNotFound, appv1.ErrorReason_ERROR_REASON_APPROVAL_NOT_FOUND,
			"the approval is unknown or has expired")
	case codes.PermissionDenied:
		s.Log.Warn("approval rejected by the device", "request_id", requestID(ctx), "approval_id", m.GetApprovalId(),
			"approver_id", m.GetApproverId())
		return nil, reasoned(connect.CodePermissionDenied, appv1.ErrorReason_ERROR_REASON_APPROVAL_REJECTED,
			"the computer did not accept this approval; check that this phone is one of its approvers")
	default:
		return nil, fromOrchestrator(ctx, s.Log, "submit approval", err)
	}
	s.Log.Info("command approved from the app", "request_id", requestID(ctx), "approval_id", m.GetApprovalId(),
		"approver_id", m.GetApproverId())
	return connect.NewResponse(&appv1.SubmitApprovalResponse{Output: resp.GetOutput()}), nil
}

var taskStates = map[orchv1.TaskState]appv1.TaskState{
	orchv1.TaskState_TASK_STATE_QUEUED:                appv1.TaskState_TASK_STATE_QUEUED,
	orchv1.TaskState_TASK_STATE_RUNNING:               appv1.TaskState_TASK_STATE_RUNNING,
	orchv1.TaskState_TASK_STATE_AWAITING_CONFIRMATION: appv1.TaskState_TASK_STATE_AWAITING_CONFIRMATION,
	orchv1.TaskState_TASK_STATE_AWAITING_APPROVAL:     appv1.TaskState_TASK_STATE_AWAITING_APPROVAL,
	orchv1.TaskState_TASK_STATE_SUCCEEDED:             appv1.TaskState_TASK_STATE_SUCCEEDED,
	orchv1.TaskState_TASK_STATE_FAILED:                appv1.TaskState_TASK_STATE_FAILED,
	orchv1.TaskState_TASK_STATE_CANCELLED:             appv1.TaskState_TASK_STATE_CANCELLED,
}

func taskProto(t *orchv1.Task) *appv1.Task {
	out := &appv1.Task{
		TaskId: t.GetTaskId(), Goal: t.GetGoal(), State: taskStates[t.GetState()], Result: t.GetResult(),
		Steps: t.GetSteps(), CreateTime: t.GetCreateTime(), UpdateTime: t.GetUpdateTime(),
	}
	if a := t.GetPendingApproval(); a != nil && t.GetState() == orchv1.TaskState_TASK_STATE_AWAITING_APPROVAL {
		out.PendingApproval = approvalProto(t, a)
	}
	return out
}

func approvalProto(t *orchv1.Task, a *orchv1.PendingApproval) *appv1.Approval {
	return &appv1.Approval{
		ApprovalId: a.GetApprovalId(), TaskId: t.GetTaskId(), TaskGoal: t.GetGoal(), DeviceName: a.GetDeviceName(),
		Payload: a.GetPayload(), ExpireTime: a.GetExpireTime(),
	}
}

// --- push notifications ------------------------------------------------------------------

var pushEnvironments = map[appv1.PushEnvironment]string{
	appv1.PushEnvironment_PUSH_ENVIRONMENT_SANDBOX:    "sandbox",
	appv1.PushEnvironment_PUSH_ENVIRONMENT_PRODUCTION: "production",
}

// RegisterPushToken implements AppServiceHandler.
func (s *Service) RegisterPushToken(ctx context.Context, req *connect.Request[appv1.RegisterPushTokenRequest]) (*connect.Response[appv1.RegisterPushTokenResponse], error) {
	c := callerOf(ctx)
	token := strings.ToLower(req.Msg.GetDeviceToken())
	if token == "" {
		if err := s.Store.DeletePushToken(ctx, c.SessionID); err != nil {
			return nil, internal(ctx, s.Log, "delete push token", err)
		}
		s.Log.Info("push notifications turned off", "request_id", requestID(ctx), "session_id", c.SessionID)
		return connect.NewResponse(&appv1.RegisterPushTokenResponse{}), nil
	}
	environment, ok := pushEnvironments[req.Msg.GetEnvironment()]
	switch {
	case !deviceTokenPattern.MatchString(token):
		return nil, invalid("device_token must be the APNs device token in hex")
	case !ok:
		return nil, invalid("environment must be SANDBOX or PRODUCTION")
	}
	if err := s.Store.SetPushToken(ctx, c.SessionID, token, environment); err != nil {
		return nil, internal(ctx, s.Log, "set push token", err)
	}
	s.Log.Info("push notifications registered", "request_id", requestID(ctx), "session_id", c.SessionID,
		"environment", environment)
	return connect.NewResponse(&appv1.RegisterPushTokenResponse{}), nil
}
