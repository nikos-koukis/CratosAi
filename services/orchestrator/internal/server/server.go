// Package server implements jarvis.orchestrator.v1.OrchestratorService.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/orchestrator/internal/clients"
	"jarvis.internal/orchestrator/internal/engine"
	"jarvis.internal/orchestrator/internal/store"
)

// ErrorDomain is the google.rpc.ErrorInfo domain of orchestrator errors.
const ErrorDomain = "orchestrator.jarvis"

const (
	maxText      = 16000
	maxArguments = 64 << 10
	maxPEM       = 16 << 10
)

// Service implements OrchestratorServiceServer.
type Service struct {
	orchv1.UnimplementedOrchestratorServiceServer
	Engine  *engine.Engine
	Store   *store.Store
	Sealer  vaultclient.Sealer
	Guard   clients.DeviceGuard
	Devices engine.DeviceClients
	Log     *slog.Logger
}

func reasonError(code codes.Code, reason orchv1.ErrorReason, message string) error {
	st := status.New(code, message)
	if detailed, err := st.WithDetails(&errdetails.ErrorInfo{Domain: ErrorDomain, Reason: reason.String()}); err == nil {
		st = detailed
	}
	return st.Err()
}

func invalid(message string) error { return status.Error(codes.InvalidArgument, message) }

func (s *Service) internal(ctx context.Context, what string, err error) error {
	s.Log.Error(what+" failed", "error", err)
	return status.Error(codes.Internal, "internal error")
}

// conversationError maps engine errors of conversation calls.
func (s *Service) conversationError(ctx context.Context, what string, err error) error {
	switch {
	case errors.Is(err, engine.ErrConversationNotFound):
		return reasonError(codes.NotFound, orchv1.ErrorReason_ERROR_REASON_CONVERSATION_NOT_FOUND, "conversation not found")
	case errors.Is(err, engine.ErrConversationClosed):
		return reasonError(codes.FailedPrecondition, orchv1.ErrorReason_ERROR_REASON_CONVERSATION_CLOSED, "conversation is closed")
	default:
		return s.internal(ctx, what, err)
	}
}

// --- validation ---------------------------------------------------------------------

func printable(s string, low, high int) bool {
	if len(s) < low || len(s) > high {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

type owner struct {
	tenant string
	user   string
}

func parseOwner(tenant, user string) (owner, error) {
	id, err := uuid.Parse(tenant)
	if err != nil || id == uuid.Nil || id.String() != tenant {
		return owner{}, invalid("tenant_id must be a canonical lowercase UUID")
	}
	if !printable(user, 1, 128) {
		return owner{}, invalid("user_id must be 1 to 128 printable ASCII characters")
	}
	return owner{tenant: tenant, user: user}, nil
}

func parseID(value, field string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil || id.String() != value {
		return uuid.Nil, invalid(field + " must be a canonical lowercase UUID")
	}
	return id, nil
}

var locale = regexp.MustCompile(`^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$`)

func text(value, field string, high int) (string, error) {
	if len(value) > high || !utf8.ValidString(value) {
		return "", invalid(field + " is too long or not UTF-8")
	}
	return value, nil
}

// --- conversations -------------------------------------------------------------------

// OpenConversation implements OrchestratorServiceServer.
func (s *Service) OpenConversation(ctx context.Context, req *orchv1.OpenConversationRequest) (*orchv1.OpenConversationResponse, error) {
	o, err := parseOwner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	switch {
	case req.GetSessionId() != "" && !printable(req.GetSessionId(), 1, 128):
		return nil, invalid("session_id must be up to 128 printable ASCII characters")
	case req.GetProvider() != commonv1.Provider_PROVIDER_OPENAI && req.GetProvider() != commonv1.Provider_PROVIDER_XAI:
		return nil, invalid("provider must be OpenAI or xAI")
	case req.GetLocale() != "" && !locale.MatchString(req.GetLocale()):
		return nil, invalid("locale must be a language tag such as el-GR")
	}
	resp, err := s.Engine.Open(ctx, o.tenant, o.user, req.GetSessionId(), req.GetProvider(), req.GetLocale())
	if err != nil {
		return nil, s.internal(ctx, "open conversation", err)
	}
	return resp, nil
}

// RecordTurn implements OrchestratorServiceServer.
func (s *Service) RecordTurn(ctx context.Context, req *orchv1.RecordTurnRequest) (*orchv1.RecordTurnResponse, error) {
	id, err := parseID(req.GetConversationId(), "conversation_id")
	if err != nil {
		return nil, err
	}
	role := map[orchv1.Role]string{orchv1.Role_ROLE_USER: "user", orchv1.Role_ROLE_ASSISTANT: "assistant"}[req.GetRole()]
	switch {
	case role == "":
		return nil, invalid("role must be USER or ASSISTANT")
	case req.GetUserTurn() < 0:
		return nil, invalid("user_turn must not be negative")
	case !printable(req.GetItemId(), 1, 128):
		return nil, invalid("item_id must be 1 to 128 printable ASCII characters")
	}
	body, err := text(req.GetText(), "text", maxText)
	if err != nil {
		return nil, err
	}
	if err := s.Engine.RecordTurn(ctx, id, role, req.GetItemId(), req.GetUserTurn(), strings.TrimSpace(body)); err != nil {
		return nil, s.conversationError(ctx, "record turn", err)
	}
	return &orchv1.RecordTurnResponse{}, nil
}

// CallTool implements OrchestratorServiceServer.
func (s *Service) CallTool(ctx context.Context, req *orchv1.CallToolRequest) (*orchv1.CallToolResponse, error) {
	id, err := parseID(req.GetConversationId(), "conversation_id")
	if err != nil {
		return nil, err
	}
	switch {
	case !printable(req.GetCallId(), 1, 128):
		return nil, invalid("call_id must be 1 to 128 printable ASCII characters")
	case !printable(req.GetName(), 1, 64):
		return nil, invalid("name must be 1 to 64 printable ASCII characters")
	case len(req.GetArgumentsJson()) > maxArguments:
		return nil, invalid("arguments_json is larger than 64 KiB")
	case req.GetUserTurn() < 0:
		return nil, invalid("user_turn must not be negative")
	}
	args := req.GetArgumentsJson()
	if strings.TrimSpace(args) == "" {
		args = "{}"
	}
	r, err := s.Engine.CallTool(ctx, id, req.GetCallId(), req.GetName(), args, req.GetUserTurn())
	if err != nil {
		return nil, s.conversationError(ctx, "call tool", err)
	}
	return &orchv1.CallToolResponse{Output: r.Output, IsError: r.IsError, AckRequired: r.AckRequired}, nil
}

// AckToolOutput implements OrchestratorServiceServer.
func (s *Service) AckToolOutput(ctx context.Context, req *orchv1.AckToolOutputRequest) (*orchv1.AckToolOutputResponse, error) {
	id, err := parseID(req.GetConversationId(), "conversation_id")
	if err != nil {
		return nil, err
	}
	if !printable(req.GetCallId(), 1, 128) || req.GetUserTurn() < 0 {
		return nil, invalid("call_id must be 1 to 128 printable ASCII characters and user_turn not negative")
	}
	if err := s.Engine.AckToolOutput(ctx, id, req.GetCallId(), req.GetUserTurn()); err != nil {
		return nil, s.conversationError(ctx, "ack tool output", err)
	}
	return &orchv1.AckToolOutputResponse{}, nil
}

// WatchConversation implements OrchestratorServiceServer.
func (s *Service) WatchConversation(req *orchv1.WatchConversationRequest, stream orchv1.OrchestratorService_WatchConversationServer) error {
	id, err := parseID(req.GetConversationId(), "conversation_id")
	if err != nil {
		return err
	}
	if req.GetAfterEventId() < 0 {
		return invalid("after_event_id must not be negative")
	}
	ctx := stream.Context()
	if _, err := s.Store.Conversation(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return s.conversationError(ctx, "watch", engine.ErrConversationNotFound)
		}
		return s.internal(ctx, "watch", err)
	}
	err = s.Engine.Watch(ctx, id, req.GetAfterEventId(), func(e *orchv1.ConversationEvent) error {
		return stream.Send(&orchv1.WatchConversationResponse{Event: e})
	})
	if err != nil && ctx.Err() == nil {
		return s.internal(ctx, "watch", err)
	}
	return nil
}

// AckEvent implements OrchestratorServiceServer.
func (s *Service) AckEvent(ctx context.Context, req *orchv1.AckEventRequest) (*orchv1.AckEventResponse, error) {
	id, err := parseID(req.GetConversationId(), "conversation_id")
	if err != nil {
		return nil, err
	}
	if req.GetEventId() <= 0 || req.GetUserTurn() < 0 {
		return nil, invalid("event_id must be positive and user_turn not negative")
	}
	if err := s.Engine.Ack(ctx, id, req.GetEventId(), req.GetUserTurn()); err != nil {
		return nil, s.conversationError(ctx, "ack event", err)
	}
	return &orchv1.AckEventResponse{}, nil
}

// CloseConversation implements OrchestratorServiceServer.
func (s *Service) CloseConversation(ctx context.Context, req *orchv1.CloseConversationRequest) (*orchv1.CloseConversationResponse, error) {
	id, err := parseID(req.GetConversationId(), "conversation_id")
	if err != nil {
		return nil, err
	}
	if err := s.Engine.Close(ctx, id); err != nil {
		return nil, s.conversationError(ctx, "close conversation", err)
	}
	return &orchv1.CloseConversationResponse{}, nil
}

// --- tasks -------------------------------------------------------------------------

func (s *Service) taskError(ctx context.Context, what string, err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return reasonError(codes.NotFound, orchv1.ErrorReason_ERROR_REASON_TASK_NOT_FOUND, "task not found")
	}
	return s.internal(ctx, what, err)
}

// GetTask implements OrchestratorServiceServer.
func (s *Service) GetTask(ctx context.Context, req *orchv1.GetTaskRequest) (*orchv1.GetTaskResponse, error) {
	o, err := parseOwner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	id, err := parseID(req.GetTaskId(), "task_id")
	if err != nil {
		return nil, err
	}
	t, err := s.Store.Task(ctx, uuid.MustParse(o.tenant), o.user, id)
	if err != nil {
		return nil, s.taskError(ctx, "get task", err)
	}
	tasks, err := s.taskProtos(ctx, []store.Task{t})
	if err != nil {
		return nil, s.internal(ctx, "get task", err)
	}
	return &orchv1.GetTaskResponse{Task: tasks[0]}, nil
}

// taskProtos renders tasks, with the approvals the waiting ones need.
func (s *Service) taskProtos(ctx context.Context, tasks []store.Task) ([]*orchv1.Task, error) {
	var waiting []uuid.UUID
	for _, t := range tasks {
		if t.State == store.TaskAwaitingApproval {
			waiting = append(waiting, t.ID)
		}
	}
	approvals := map[uuid.UUID]store.PendingApproval{}
	if len(waiting) > 0 {
		var err error
		if approvals, err = s.Store.PendingApprovals(ctx, waiting); err != nil {
			return nil, err
		}
	}
	out := make([]*orchv1.Task, 0, len(tasks))
	for _, t := range tasks {
		task := engine.TaskProto(t)
		if a, ok := approvals[t.ID]; ok {
			task.PendingApproval = &orchv1.PendingApproval{ApprovalId: a.ApprovalID, DeviceName: a.DeviceName,
				Payload: a.Payload, ExpireTime: timestamppb.New(a.ExpiresAt)}
		}
		out = append(out, task)
	}
	return out, nil
}

// ListTasks implements OrchestratorServiceServer.
func (s *Service) ListTasks(ctx context.Context, req *orchv1.ListTasksRequest) (*orchv1.ListTasksResponse, error) {
	o, err := parseOwner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	limit := int(req.GetLimit())
	if limit == 0 {
		limit = 20
	}
	if limit < 1 || limit > 100 {
		return nil, invalid("limit must be between 1 and 100")
	}
	tasks, err := s.Store.Tasks(ctx, uuid.MustParse(o.tenant), o.user, limit)
	if err != nil {
		return nil, s.internal(ctx, "list tasks", err)
	}
	protos, err := s.taskProtos(ctx, tasks)
	if err != nil {
		return nil, s.internal(ctx, "list tasks", err)
	}
	return &orchv1.ListTasksResponse{Tasks: protos}, nil
}

// CancelTask implements OrchestratorServiceServer.
func (s *Service) CancelTask(ctx context.Context, req *orchv1.CancelTaskRequest) (*orchv1.CancelTaskResponse, error) {
	o, err := parseOwner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	id, err := parseID(req.GetTaskId(), "task_id")
	if err != nil {
		return nil, err
	}
	t, err := s.Engine.Cancel(ctx, o.tenant, o.user, id)
	if err != nil {
		return nil, s.taskError(ctx, "cancel task", err)
	}
	return &orchv1.CancelTaskResponse{Task: engine.TaskProto(t)}, nil
}

// --- devices -----------------------------------------------------------------------

func deviceProto(d store.Device) *orchv1.Device {
	return &orchv1.Device{DeviceId: d.ID.String(), Name: d.Name, Address: d.Address, ServerName: d.ServerName,
		CreateTime: timestamppb.New(d.CreatedAt)}
}

var deviceName = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._'-]{0,63}$`)

func validCA(data string) bool {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return false
	}
	_, err := x509.ParseCertificate(block.Bytes)
	return err == nil
}

// RegisterDevice implements OrchestratorServiceServer.
func (s *Service) RegisterDevice(ctx context.Context, req *orchv1.RegisterDeviceRequest) (*orchv1.RegisterDeviceResponse, error) {
	key := req.GetClientKeyPem()
	defer clear(key)
	o, err := parseOwner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.GetName())
	if !deviceName.MatchString(name) || utf8.RuneCountInString(name) > 64 {
		return nil, invalid("name must be 1 to 64 letters, digits, spaces or ._'-")
	}
	if err := s.Guard.CheckAddress(req.GetAddress()); err != nil {
		return nil, invalid(err.Error())
	}
	serverName := req.GetServerName()
	if serverName == "" {
		serverName, _, _ = net.SplitHostPort(req.GetAddress())
	}
	if !printable(serverName, 1, 253) {
		return nil, invalid("server_name is invalid")
	}
	if len(req.GetCaPem()) > maxPEM || len(req.GetClientCertPem()) > maxPEM || len(key) > maxPEM {
		return nil, invalid("PEM data is too large")
	}
	if !validCA(req.GetCaPem()) {
		return nil, invalid("ca_pem must be a PEM certificate")
	}
	if _, err := tls.X509KeyPair([]byte(req.GetClientCertPem()), key); err != nil {
		return nil, invalid("client_cert_pem and client_key_pem must be a matching PEM certificate and key")
	}

	// Keep the id of a device replaced by name: its sealed key is bound to it.
	id := uuid.New()
	devices, err := s.Store.Devices(ctx, uuid.MustParse(o.tenant), o.user)
	if err != nil {
		return nil, s.internal(ctx, "list devices", err)
	}
	for _, d := range devices {
		if d.Name == name {
			id = d.ID
		}
	}
	sealed, err := s.Sealer.Seal(ctx, "", vaultclient.Binding{TenantID: o.tenant, Purpose: clients.PurposeDeviceKey,
		Subject: id.String()}, key)
	if err != nil {
		if status.Code(err) == codes.Unavailable {
			return nil, status.Error(codes.Unavailable, "the key vault is unavailable")
		}
		return nil, s.internal(ctx, "seal device key", err)
	}
	d, err := s.Store.UpsertDevice(ctx, store.Device{ID: id, TenantID: uuid.MustParse(o.tenant), UserID: o.user,
		Name: name, Address: req.GetAddress(), ServerName: serverName, CAPEM: req.GetCaPem(),
		ClientCertPEM: req.GetClientCertPem(), ClientKeySealed: sealed})
	if err != nil {
		return nil, s.internal(ctx, "store device", err)
	}
	s.Devices.Forget(d.ID)
	s.Log.Info("device registered", "device_id", d.ID, "tenant_id", o.tenant)
	return &orchv1.RegisterDeviceResponse{Device: deviceProto(d)}, nil
}

// ListDevices implements OrchestratorServiceServer.
func (s *Service) ListDevices(ctx context.Context, req *orchv1.ListDevicesRequest) (*orchv1.ListDevicesResponse, error) {
	o, err := parseOwner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	devices, err := s.Store.Devices(ctx, uuid.MustParse(o.tenant), o.user)
	if err != nil {
		return nil, s.internal(ctx, "list devices", err)
	}
	resp := &orchv1.ListDevicesResponse{}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, deviceProto(d))
	}
	return resp, nil
}

// RemoveDevice implements OrchestratorServiceServer.
func (s *Service) RemoveDevice(ctx context.Context, req *orchv1.RemoveDeviceRequest) (*orchv1.RemoveDeviceResponse, error) {
	o, err := parseOwner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	id, err := parseID(req.GetDeviceId(), "device_id")
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.DeleteDevice(ctx, uuid.MustParse(o.tenant), o.user, id); err != nil {
		return nil, s.internal(ctx, "remove device", err)
	}
	s.Devices.Forget(id)
	return &orchv1.RemoveDeviceResponse{}, nil
}

// SubmitDeviceApproval implements OrchestratorServiceServer.
func (s *Service) SubmitDeviceApproval(ctx context.Context, req *orchv1.SubmitDeviceApprovalRequest) (*orchv1.SubmitDeviceApprovalResponse, error) {
	o, err := parseOwner(req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	switch {
	case !printable(req.GetApprovalId(), 1, 128):
		return nil, invalid("approval_id is required")
	case !printable(req.GetApproverId(), 1, 128):
		return nil, invalid("approver_id is required")
	case len(req.GetSignature()) != 64:
		return nil, invalid("signature must be 64 bytes (ECDSA P-256 r||s)")
	}
	out, err := s.Engine.SubmitApproval(ctx, o.tenant, o.user, req.GetApprovalId(), req.GetApproverId(), req.GetSignature())
	switch {
	case errors.Is(err, engine.ErrApprovalNotFound):
		return nil, reasonError(codes.NotFound, orchv1.ErrorReason_ERROR_REASON_APPROVAL_NOT_FOUND, "no pending approval with this id")
	case errors.Is(err, engine.ErrApprovalRejected):
		return nil, reasonError(codes.PermissionDenied, orchv1.ErrorReason_ERROR_REASON_APPROVAL_REJECTED, err.Error())
	case err != nil:
		return nil, status.Error(codes.Unavailable, "the device is not reachable")
	}
	return &orchv1.SubmitDeviceApprovalResponse{Output: out}, nil
}

// --- notifications ----------------------------------------------------------------

const maxNotificationWait = 30 * time.Second

var notificationKinds = map[string]orchv1.NotificationKind{
	store.NotifyApproval:     orchv1.NotificationKind_NOTIFICATION_KIND_APPROVAL_NEEDED,
	store.NotifyConfirmation: orchv1.NotificationKind_NOTIFICATION_KIND_CONFIRMATION_NEEDED,
	store.NotifyFinished:     orchv1.NotificationKind_NOTIFICATION_KIND_TASK_FINISHED,
}

// ClaimNotifications implements OrchestratorServiceServer.
func (s *Service) ClaimNotifications(ctx context.Context, req *orchv1.ClaimNotificationsRequest) (*orchv1.ClaimNotificationsResponse, error) {
	wait := req.GetWait().AsDuration()
	switch {
	case !printable(req.GetConsumer(), 1, 128):
		return nil, invalid("consumer must be 1 to 128 printable ASCII characters")
	case req.GetMax() < 1 || req.GetMax() > 100:
		return nil, invalid("max must be 1 to 100")
	case wait < 0 || wait > maxNotificationWait:
		return nil, invalid("wait must be 0 to 30s")
	}
	claimed, err := s.Engine.ClaimNotifications(ctx, req.GetConsumer(), int(req.GetMax()), wait)
	if err != nil {
		return nil, s.internal(ctx, "claim notifications", err)
	}
	resp := &orchv1.ClaimNotificationsResponse{}
	for _, n := range claimed {
		resp.Notifications = append(resp.Notifications, &orchv1.Notification{
			NotificationId: n.ID, TenantId: n.TenantID.String(), UserId: n.UserID, Kind: notificationKinds[n.Kind],
			TaskId: n.TaskID.String(), TaskState: engine.TaskStateProto(n.TaskState), CreateTime: timestamppb.New(n.CreatedAt),
		})
	}
	return resp, nil
}

// CompleteNotifications implements OrchestratorServiceServer.
func (s *Service) CompleteNotifications(ctx context.Context, req *orchv1.CompleteNotificationsRequest) (*orchv1.CompleteNotificationsResponse, error) {
	if len(req.GetNotificationIds()) > 100 {
		return nil, invalid("at most 100 notification_ids")
	}
	if len(req.GetNotificationIds()) > 0 {
		if err := s.Store.CompleteNotifications(ctx, req.GetNotificationIds()); err != nil {
			return nil, s.internal(ctx, "complete notifications", err)
		}
	}
	return &orchv1.CompleteNotificationsResponse{}, nil
}
