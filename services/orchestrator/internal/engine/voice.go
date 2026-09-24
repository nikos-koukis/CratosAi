package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "jarvis.internal/gen/go/jarvis/agent/v1"
	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	devicev1 "jarvis.internal/gen/go/jarvis/device/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	"jarvis.internal/orchestrator/internal/store"
)

// Errors of conversation calls.
var (
	ErrConversationNotFound = errors.New("conversation not found")
	ErrConversationClosed   = errors.New("conversation is closed")
)

const (
	maxGoal = 4000
	// carryOverWindow: unheard results older than this are left in the
	// dashboard rather than told in a new conversation.
	carryOverWindow = 24 * time.Hour
)

// Open starts a conversation and returns its tools and instructions.
func (e *Engine) Open(ctx context.Context, tenant, user, sessionID string, provider commonv1.Provider,
	locale string) (*orchv1.OpenConversationResponse, error) {
	c, err := e.buildCatalog(ctx, tenant, user, true)
	if err != nil {
		return nil, err
	}
	conv := store.Conversation{ID: uuid.New(), TenantID: mustUUID(tenant), UserID: user, SessionID: sessionID,
		Provider: int32(provider), Locale: locale, Tools: c.targets}
	if err := e.Store.CreateConversation(ctx, conv); err != nil {
		return nil, err
	}
	// Results and questions of background work the user has not heard yet
	// (they hung up first) are told in this conversation.
	carried, err := e.Store.CarryOverEvents(ctx, conv.ID, conv.TenantID, user, carryOverWindow)
	if err != nil {
		e.Log.Error("cannot carry over earlier events", "conversation_id", conv.ID, "error", err)
	}
	e.Log.Info("conversation opened", "request_id", requestID(ctx), "conversation_id", conv.ID, "tenant_id", tenant,
		"session_id", sessionID, "tools", len(c.tools), "carried_events", carried)
	return &orchv1.OpenConversationResponse{ConversationId: conv.ID.String(), Instructions: VoiceInstructions,
		Tools: c.tools}, nil
}

func (e *Engine) openConversation(ctx context.Context, id uuid.UUID) (store.Conversation, error) {
	conv, err := e.Store.Conversation(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return conv, ErrConversationNotFound
	}
	if err != nil {
		return conv, err
	}
	if conv.ClosedAt != nil {
		return conv, ErrConversationClosed
	}
	return conv, nil
}

// RecordTurn stores a speaker turn and advances the user turn.
func (e *Engine) RecordTurn(ctx context.Context, id uuid.UUID, role, itemID string, turn int64, text string) error {
	if _, err := e.openConversation(ctx, id); err != nil {
		return err
	}
	if err := e.Store.AdvanceTurn(ctx, id, turn); err != nil {
		return err
	}
	return e.Store.RecordTurn(ctx, id, role, itemID, turn, text)
}

// Close ends a conversation and schedules its memory extraction.
func (e *Engine) Close(ctx context.Context, id uuid.UUID) error {
	closed, err := e.Store.CloseConversation(ctx, id)
	if err != nil {
		return err
	}
	if _, err := e.Store.Conversation(ctx, id); errors.Is(err, store.ErrNotFound) {
		return ErrConversationNotFound
	}
	if closed {
		e.broker.notify(id) // ends WatchConversation streams
		if err := e.Store.QueueMemoryJob(ctx, id); err != nil {
			return err
		}
		e.Log.Info("conversation closed", "request_id", requestID(ctx), "conversation_id", id)
	}
	return nil
}

// Ack records that an event reached the conversation at a user turn; a
// question in it can be answered from the next turn.
func (e *Engine) Ack(ctx context.Context, id uuid.UUID, eventID, turn int64) error {
	confirmation, err := e.Store.AckEvent(ctx, id, eventID, turn)
	if errors.Is(err, store.ErrNotFound) {
		return ErrConversationNotFound
	}
	if err != nil {
		return err
	}
	if confirmation.Valid {
		return e.Store.MarkAsked(ctx, confirmation.UUID, turn)
	}
	return nil
}

// CallTool runs a realtime model's function call. The result is stored, so
// a retried call id returns the same output without running it again.
func (e *Engine) CallTool(ctx context.Context, id uuid.UUID, callID, name, args string, turn int64) (store.CallResult, error) {
	conv, err := e.openConversation(ctx, id)
	if err != nil {
		return store.CallResult{}, err
	}
	if r, err := e.Store.ToolCall(ctx, id, callID); err == nil {
		return r, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.CallResult{}, err
	}
	if err := e.Store.AdvanceTurn(ctx, id, turn); err != nil {
		return store.CallResult{}, err
	}
	c := caller{tenant: conv.TenantID.String(), user: conv.UserID, conversation: uuid.NullUUID{UUID: id, Valid: true},
		provider: conv.Provider, locale: conv.Locale, callID: callID, turn: turn}
	r := e.voiceCall(ctx, conv, c, name, json.RawMessage(args))
	if err := e.Store.SaveToolCall(context.WithoutCancel(ctx), id, callID, name, r); err != nil {
		return store.CallResult{}, err
	}
	e.Log.Info("tool called", "request_id", requestID(ctx), "conversation_id", id, "tool", name,
		"is_error", r.IsError, "ack_required", r.AckRequired)
	return r, nil
}

// AckToolOutput records the user turn at which a call's question reached
// the user; from the next turn it can be answered.
func (e *Engine) AckToolOutput(ctx context.Context, id uuid.UUID, callID string, turn int64) error {
	if _, err := e.openConversation(ctx, id); err != nil {
		return err
	}
	asked, err := e.Store.MarkCallAsked(ctx, id, callID, turn)
	if err != nil {
		return err
	}
	if asked {
		e.Log.Info("question reached the user", "request_id", requestID(ctx), "conversation_id", id,
			"call_id", callID, "turn", turn)
	}
	return nil
}

func (e *Engine) voiceCall(ctx context.Context, conv store.Conversation, c caller, name string, args json.RawMessage) store.CallResult {
	out, isError, p := e.voiceTool(ctx, conv, c, name, args)
	switch {
	case p == nil:
		return store.CallResult{Output: out, IsError: isError}
	case p.action != nil:
		out, isError := e.askConfirmation(ctx, c, p)
		return store.CallResult{Output: out, IsError: isError, AckRequired: !isError}
	default:
		out, isError := e.awaitApproval(ctx, c, p)
		return store.CallResult{Output: out, IsError: isError}
	}
}

func noPause(out string, isError bool) (string, bool, *pause) { return out, isError, nil }

func (e *Engine) voiceTool(ctx context.Context, conv store.Conversation, c caller, name string, args json.RawMessage) (string, bool, *pause) {
	target, ok := conv.Tools[name]
	if !ok {
		return noPause(failure("unknown tool " + truncate(name, 64)))
	}
	if !json.Valid(args) {
		return noPause(failure("arguments must be a JSON object"))
	}
	switch target.Kind {
	case ToolStart:
		var in struct{ Goal string }
		if json.Unmarshal(args, &in) != nil || strings.TrimSpace(in.Goal) == "" {
			return noPause(failure("goal is required"))
		}
		return noPause(e.startTask(ctx, c, truncate(strings.TrimSpace(in.Goal), maxGoal)))
	case ToolConfirm, ToolCancel:
		var in struct {
			ConfirmationID string `json:"confirmation_id"`
		}
		_ = json.Unmarshal(args, &in)
		confirmationID, err := uuid.Parse(in.ConfirmationID)
		if err != nil {
			return noPause(failure("confirmation_id is required"))
		}
		return noPause(e.settle(ctx, c, confirmationID, target.Kind == ToolConfirm))
	}
	return e.execute(ctx, c, target, args)
}

// askConfirmation stores an action for the user to confirm. It becomes
// answerable once the gateway reports the turn in which the model speaks the
// question (AckToolOutput), from the turn after that.
func (e *Engine) askConfirmation(ctx context.Context, c caller, p *pause) (string, bool) {
	confirmation := store.Confirmation{ID: uuid.New(), ConversationID: c.conversation.UUID, CallID: c.callID,
		Action: mustJSON(p.action), Summary: p.summary, ExpiresAt: time.Now().Add(e.opts.ConfirmationTTL)}
	if err := e.Store.CreateConfirmation(ctx, confirmation); err != nil {
		return failure("could not prepare the action")
	}
	e.Metrics.Confirmations.WithLabelValues("requested").Inc()
	return output(map[string]string{
		"status":          "needs_confirmation",
		"confirmation_id": confirmation.ID.String(),
		"action":          p.summary,
		"instruction": "Ask the user in one short sentence whether to do exactly this. Call confirm_action only " +
			"after they clearly agree in their next reply; call cancel_action if they decline.",
	}), false
}

// startTask queues a background agent task.
func (e *Engine) startTask(ctx context.Context, c caller, goal string) (string, bool) {
	cat, err := e.buildCatalog(ctx, c.tenant, c.user, false)
	if err != nil {
		return failure("could not start the task")
	}
	history := encodeItems([]*agentv1.Item{{Item: &agentv1.Item_UserText{UserText: e.taskIntro(ctx, c, goal)}}})
	t := store.Task{ID: uuid.New(), TenantID: mustUUID(c.tenant), UserID: c.user, ConversationID: c.conversation,
		Kind: store.KindAgent, Provider: c.provider, Goal: goal, State: store.TaskQueued, Tools: cat.targets,
		History: history, Deadline: time.Now().Add(e.opts.TaskTimeout)}
	if err := e.Store.CreateTask(ctx, t); err != nil {
		return failure("could not start the task")
	}
	e.signal()
	e.Log.Info("task started", "request_id", requestID(ctx), "task_id", t.ID, "conversation_id", c.conversation.UUID)
	return output(map[string]string{"status": "started", "task_id": t.ID.String(),
		"note": "Tell the user you are on it and will report back."}), false
}

// settle confirms or cancels a pending action.
func (e *Engine) settle(ctx context.Context, c caller, id uuid.UUID, confirm bool) (string, bool) {
	conf, err := e.Store.Settle(ctx, c.conversation.UUID, id, c.turn, confirm)
	if errors.Is(err, store.ErrNotFound) {
		return e.refuse(ctx, c, id, confirm)
	}
	if err != nil {
		return failure("could not settle the action")
	}
	outcome := "cancelled"
	if confirm {
		outcome = "confirmed"
	}
	e.Metrics.Confirmations.WithLabelValues(outcome).Inc()
	e.Log.Info("action "+outcome, "request_id", requestID(ctx), "confirmation_id", id,
		"conversation_id", c.conversation.UUID)

	var a action
	if err := json.Unmarshal(conf.Action, &a); err != nil {
		return failure("the action is unreadable")
	}
	result, isError := output(map[string]string{"status": "cancelled", "note": "The action was not done."}), false
	if confirm {
		result, isError = e.runAction(ctx, c, a)
	}
	if !conf.TaskID.Valid {
		return result, isError
	}
	// A task was waiting on this: give it the outcome and let it continue.
	taskResult := result
	if !confirm {
		taskResult = output(map[string]string{"error": "The user declined this action; it was not done."})
	}
	if _, err := e.Store.ResumeTask(ctx, conf.TaskID.UUID, func(t *store.Task) error {
		return completePending(t, conf.CallID, taskResult)
	}); err != nil {
		e.Log.Error("cannot resume task", "task_id", conf.TaskID.UUID, "error", err)
	}
	e.signal()
	if confirm {
		return output(map[string]any{"status": "done", "result": json.RawMessage(result),
			"note": "The task continues; its result will be reported when it finishes."}), isError
	}
	return output(map[string]string{"status": "cancelled", "note": "The task continues without this action."}), false
}

// refuse explains why a confirmation was not accepted.
func (e *Engine) refuse(ctx context.Context, c caller, id uuid.UUID, confirm bool) (string, bool) {
	conf, err := e.Store.Confirmation(ctx, c.conversation.UUID, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return failure("unknown confirmation_id")
	case err != nil:
		return failure("could not check the action")
	case conf.State != "pending":
		return failure("this action was already " + conf.State)
	case time.Now().After(conf.ExpiresAt):
		return failure("this action expired; ask the user again if they still want it")
	}
	if confirm {
		e.Metrics.Confirmations.WithLabelValues("refused").Inc()
		e.Log.Warn("confirmation refused: no user turn since the question", "request_id", requestID(ctx),
			"confirmation_id", id, "conversation_id", c.conversation.UUID, "turn", c.turn)
		return failure("The user has not answered yet. Ask them and wait for their reply before calling confirm_action.")
	}
	return failure("could not cancel the action")
}

// awaitApproval turns a device command that needs a signed approval into a
// task that waits for it.
func (e *Engine) awaitApproval(ctx context.Context, c caller, p *pause) (string, bool) {
	command, _ := protojson.Marshal(p.approval.command)
	t := store.Task{ID: uuid.New(), TenantID: mustUUID(c.tenant), UserID: c.user, ConversationID: c.conversation,
		Kind: store.KindCommand, Provider: c.provider, Goal: "Run on " + p.summary, State: store.TaskAwaitingApproval,
		Pending: command, Deadline: approvalExpiry(p.approval.required)}
	if err := e.Store.CreateTask(ctx, t); err != nil {
		return failure("could not queue the command")
	}
	if err := e.saveApproval(ctx, t.ID, "", p); err != nil {
		return failure("could not queue the command")
	}
	return output(map[string]string{"status": "waiting_for_approval", "task_id": t.ID.String(),
		"note": "The command needs the user's approval on their phone; its result will be reported when it runs."}), false
}

func (e *Engine) saveApproval(ctx context.Context, taskID uuid.UUID, callID string, p *pause) error {
	command, err := protojson.Marshal(p.approval.command)
	if err != nil {
		return err
	}
	req := p.approval.required
	if err := e.Store.SaveApproval(ctx, store.DeviceApproval{ApprovalID: req.GetApprovalId(), DeviceID: p.approval.device.ID,
		TaskID: taskID, CallID: callID, Command: command, Payload: req.GetPayload(), ExpiresAt: approvalExpiry(req)}); err != nil {
		return err
	}
	return nil
}

// approvalExpiry is when the device stops accepting the approval; a missing
// or past time (a misbehaving device) falls back to a short default.
func approvalExpiry(req *devicev1.ApprovalRequired) time.Time {
	if expiry := req.GetExpireTime(); expiry != nil && expiry.AsTime().After(time.Now()) {
		return expiry.AsTime()
	}
	return time.Now().Add(5 * time.Minute)
}

// ErrApprovalNotFound and ErrApprovalRejected are SubmitDeviceApproval failures.
var (
	ErrApprovalNotFound = errors.New("no pending approval with this id")
	ErrApprovalRejected = errors.New("the device rejected the approval")
)

// SubmitApproval runs a device command with an approver's signature and
// hands the result to the waiting task.
func (e *Engine) SubmitApproval(ctx context.Context, tenant, user, approvalID, approverID string, signature []byte) (string, error) {
	a, err := e.Store.Approval(ctx, mustUUID(tenant), user, approvalID)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrApprovalNotFound
	}
	if err != nil {
		return "", err
	}
	device, err := e.Store.DeviceByID(ctx, a.DeviceID)
	if err != nil {
		return "", err
	}
	command := &devicev1.ExecuteCommandRequest{}
	if err := protojson.Unmarshal(a.Command, command); err != nil {
		return "", err
	}
	c := caller{tenant: tenant, user: user}
	resp, err := e.execDevice(ctx, c, device, command,
		&devicev1.Approval{ApprovalId: approvalID, ApproverId: approverID, Signature: signature})
	if err != nil {
		if st := status.Convert(err); st.Code() == codes.PermissionDenied || st.Code() == codes.FailedPrecondition {
			return "", fmt.Errorf("%w: %s", ErrApprovalRejected, truncate(st.Message(), 300))
		}
		return "", err
	}
	if resp.GetResult() == nil {
		return "", fmt.Errorf("%w: the device asked for approval again", ErrApprovalRejected)
	}
	out, _ := commandOutput(resp.GetResult())
	_ = e.Store.DeleteApproval(ctx, approvalID)

	t, err := e.Store.ResumeTask(ctx, a.TaskID, func(t *store.Task) error {
		if t.Kind == store.KindCommand {
			t.State, t.Result = store.TaskSucceeded, out
			return nil
		}
		return completePending(t, a.CallID, out)
	})
	if err != nil {
		e.Log.Error("cannot resume task after approval", "task_id", a.TaskID, "error", err)
		return out, nil
	}
	if t.Kind == store.KindCommand {
		e.Metrics.Tasks.WithLabelValues(store.TaskSucceeded).Inc()
		e.finished(ctx, t)
	} else {
		e.signal()
	}
	return out, nil
}

func mustJSON(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

// TaskProto renders a task for the API.
func TaskProto(t store.Task) *orchv1.Task {
	states := map[string]orchv1.TaskState{
		store.TaskQueued: orchv1.TaskState_TASK_STATE_QUEUED, store.TaskRunning: orchv1.TaskState_TASK_STATE_RUNNING,
		store.TaskAwaitingConfirmation: orchv1.TaskState_TASK_STATE_AWAITING_CONFIRMATION,
		store.TaskAwaitingApproval:     orchv1.TaskState_TASK_STATE_AWAITING_APPROVAL,
		store.TaskSucceeded:            orchv1.TaskState_TASK_STATE_SUCCEEDED, store.TaskFailed: orchv1.TaskState_TASK_STATE_FAILED,
		store.TaskCancelled: orchv1.TaskState_TASK_STATE_CANCELLED,
	}
	conversation := ""
	if t.ConversationID.Valid {
		conversation = t.ConversationID.UUID.String()
	}
	return &orchv1.Task{TaskId: t.ID.String(), ConversationId: conversation, Goal: t.Goal, State: states[t.State],
		Result: t.Result, Steps: int32(t.Steps), CreateTime: timestamppb.New(t.CreatedAt), UpdateTime: timestamppb.New(t.UpdatedAt)}
}
