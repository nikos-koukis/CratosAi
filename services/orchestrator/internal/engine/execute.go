package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	devicev1 "jarvis.internal/gen/go/jarvis/device/v1"
	knowledgev1 "jarvis.internal/gen/go/jarvis/knowledge/v1"
	mcpv1 "jarvis.internal/gen/go/jarvis/mcp/v1"
	"jarvis.internal/libs/go/auditlog"
	"jarvis.internal/orchestrator/internal/store"
)

const (
	maxResultText      = 12 << 10
	maxStructured      = 8 << 10
	maxCommandOutput   = 8 << 10
	recallBudget       = 600
	taskCommandTimeout = 5 * time.Minute
)

// caller is who a tool runs for.
type caller struct {
	tenant       string
	user         string
	conversation uuid.NullUUID
	provider     int32
	locale       string
	// task is set for calls made by a background task.
	task   *store.Task
	callID string
	// turn is the user turn of a voice call.
	turn int64
}

// pause is a call that cannot complete now.
type pause struct {
	summary string
	// Exactly one of:
	action   *action          // needs the user's confirmation
	approval *pendingApproval // needs a signed approval on a device
}

// action is what a confirmation runs.
type action struct {
	Kind          string          `json:"kind"`
	IntegrationID string          `json:"integration_id,omitempty"`
	Integration   string          `json:"integration,omitempty"`
	Tool          string          `json:"tool,omitempty"`
	Title         string          `json:"title,omitempty"`
	Arguments     json.RawMessage `json:"arguments,omitempty"`
}

type pendingApproval struct {
	device   store.Device
	command  *devicev1.ExecuteCommandRequest
	required *devicev1.ApprovalRequired
}

// execute runs a tool, or says why it must wait.
func (e *Engine) execute(ctx context.Context, c caller, target store.Target, args json.RawMessage) (string, bool, *pause) {
	started := time.Now()
	callerKind := "voice"
	if c.task != nil {
		callerKind = "task"
	}
	out, isError, p := e.dispatch(ctx, c, target, args)
	outcome := "ok"
	switch {
	case p != nil:
		outcome = "paused"
	case isError:
		outcome = "error"
	}
	e.Metrics.ToolCalls.WithLabelValues(target.Kind, callerKind, outcome).Inc()
	e.Metrics.ToolSeconds.WithLabelValues(target.Kind).Observe(time.Since(started).Seconds())
	return out, isError, p
}

func (e *Engine) dispatch(ctx context.Context, c caller, target store.Target, args json.RawMessage) (string, bool, *pause) {
	switch target.Kind {
	case ToolRecall:
		var in struct{ Query string }
		if json.Unmarshal(args, &in) != nil || strings.TrimSpace(in.Query) == "" {
			out, isErr := failure("query is required")
			return out, isErr, nil
		}
		out, isErr := e.recall(ctx, c, in.Query)
		return out, isErr, nil
	case ToolRemember:
		var in struct{ Note string }
		if json.Unmarshal(args, &in) != nil || strings.TrimSpace(in.Note) == "" {
			out, isErr := failure("note is required")
			return out, isErr, nil
		}
		out, isErr := e.remember(ctx, c, in.Note)
		return out, isErr, nil
	case ToolDevice:
		return e.runDevice(ctx, c, args)
	case kindMCP:
		if !target.ReadOnly {
			a := &action{Kind: kindMCP, IntegrationID: target.IntegrationID, Integration: target.Integration,
				Tool: target.Tool, Title: target.Title, Arguments: args}
			return "", false, &pause{action: a, summary: a.summary()}
		}
		out, isErr := e.callMCP(ctx, c, target.IntegrationID, target.Integration, target.Tool, args)
		return out, isErr, nil
	default:
		out, isErr := failure("this tool is not available here")
		return out, isErr, nil
	}
}

// runAction runs a confirmed action.
func (e *Engine) runAction(ctx context.Context, c caller, a action) (string, bool) {
	if a.Kind != kindMCP {
		return failure("unknown action")
	}
	return e.callMCP(ctx, c, a.IntegrationID, a.Integration, a.Tool, a.Arguments)
}

func (a action) summary() string {
	args := string(a.Arguments)
	if len(args) > 300 {
		args = truncate(args, 300) + "…"
	}
	return fmt.Sprintf("%s: %s %s", a.Integration, a.Title, args)
}

func (e *Engine) recall(ctx context.Context, c caller, query string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, e.opts.ToolTimeout)
	defer cancel()
	resp, err := e.Knowledge.Retrieve(outgoing(ctx), &knowledgev1.RetrieveRequest{
		TenantId: c.tenant, UserId: c.user, Query: truncate(query, 2000), TokenBudget: recallBudget,
	})
	if err != nil {
		e.Log.Warn("recall failed", "request_id", requestID(ctx), "error", err)
		return failure("memory is unavailable right now")
	}
	if resp.GetContext() == "" {
		return output(map[string]string{"context": "", "note": "Nothing relevant is remembered."}), false
	}
	return output(map[string]string{"context": resp.GetContext()}), false
}

func (e *Engine) remember(ctx context.Context, c caller, note string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, e.opts.ToolTimeout)
	defer cancel()
	_, err := e.Knowledge.UpsertKnowledge(outgoing(ctx), &knowledgev1.UpsertKnowledgeRequest{
		TenantId: c.tenant, UserId: c.user, Scope: knowledgev1.Scope_SCOPE_USER,
		Source:   &knowledgev1.Source{Id: "note:" + uuid.NewString(), Kind: "note", Title: "Asked to remember"},
		Passages: []*knowledgev1.PassageInput{{Text: truncate(strings.TrimSpace(note), 8000)}},
	})
	if err != nil {
		e.Log.Warn("remember failed", "request_id", requestID(ctx), "error", err)
		return failure("memory is unavailable right now")
	}
	return output(map[string]string{"status": "remembered"}), false
}

func (e *Engine) callMCP(ctx context.Context, c caller, integrationID, integration, tool string, args json.RawMessage) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, e.opts.ToolTimeout+2*time.Second)
	defer cancel()
	arguments := string(args)
	if strings.TrimSpace(arguments) == "" {
		arguments = "{}"
	}
	resp, err := e.MCP.CallTool(outgoing(ctx), &mcpv1.CallToolRequest{
		TenantId: c.tenant, UserId: c.user, IntegrationId: integrationID, ToolName: tool, ArgumentsJson: arguments,
		Timeout: durationpb.New(e.opts.ToolTimeout),
	})
	if err != nil {
		return failure(mcpError(integration, err))
	}
	var texts []string
	for _, block := range resp.GetContent() {
		switch {
		case block.GetText() != nil:
			texts = append(texts, block.GetText().GetText())
		case block.GetResourceLink() != nil:
			texts = append(texts, block.GetResourceLink().GetUri())
		case block.GetResource() != nil:
			texts = append(texts, block.GetResource().GetText())
		}
	}
	result := map[string]any{"result": truncate(strings.Join(texts, "\n"), maxResultText)}
	if s := resp.GetStructuredContentJson(); s != "" && len(s) <= maxStructured && json.Valid([]byte(s)) {
		result["structured"] = json.RawMessage(s)
	}
	if resp.GetTruncated() || len(strings.Join(texts, "\n")) > maxResultText {
		result["truncated"] = true
	}
	if resp.GetIsError() {
		result["tool_error"] = true
	}
	return output(result), resp.GetIsError()
}

// mcpError explains a router error to the model (and so to the user).
func mcpError(integration string, err error) string {
	st := status.Convert(err)
	reason := ""
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			reason = info.GetReason()
		}
	}
	switch {
	case reason == mcpv1.ErrorReason_ERROR_REASON_NEEDS_REAUTHORIZATION.String():
		return fmt.Sprintf("The %s connection must be reauthorized in the Jarvis dashboard.", integration)
	case reason == mcpv1.ErrorReason_ERROR_REASON_NOT_CONNECTED.String():
		return fmt.Sprintf("%s is not connected yet; the user must finish connecting it in the dashboard.", integration)
	case reason == mcpv1.ErrorReason_ERROR_REASON_RATE_LIMITED.String():
		return "Too many calls right now; try again in a minute."
	case st.Code() == codes.DeadlineExceeded:
		return fmt.Sprintf("%s did not answer in time.", integration)
	case st.Code() == codes.Aborted:
		return fmt.Sprintf("%s refused the call: %s", integration, truncate(st.Message(), 300))
	default:
		return fmt.Sprintf("%s is unavailable right now.", integration)
	}
}

type deviceArgs struct {
	Device           string   `json:"device"`
	Program          string   `json:"program"`
	Args             []string `json:"args"`
	WorkingDirectory string   `json:"working_directory"`
}

func (e *Engine) runDevice(ctx context.Context, c caller, raw json.RawMessage) (string, bool, *pause) {
	var in deviceArgs
	if err := json.Unmarshal(raw, &in); err != nil || in.Program == "" {
		out, isErr := failure("program (an absolute path) is required")
		return out, isErr, nil
	}
	devices, err := e.Store.Devices(ctx, mustUUID(c.tenant), c.user)
	if err != nil {
		out, isErr := failure("the device list is unavailable")
		return out, isErr, nil
	}
	var device *store.Device
	for i := range devices {
		if devices[i].Name == in.Device || (in.Device == "" && len(devices) == 1) {
			device = &devices[i]
		}
	}
	if device == nil {
		out, isErr := failure("no such device")
		return out, isErr, nil
	}
	command := &devicev1.ExecuteCommandRequest{Program: in.Program, Args: in.Args, WorkingDirectory: in.WorkingDirectory}
	resp, err := e.execDevice(ctx, c, *device, command, nil)
	if err != nil {
		out, isErr := failure(deviceError(device.Name, err))
		return out, isErr, nil
	}
	if req := resp.GetApprovalRequired(); req != nil {
		summary := fmt.Sprintf("%s: %s %s", device.Name, in.Program, strings.Join(in.Args, " "))
		return "", false, &pause{summary: truncate(summary, 500),
			approval: &pendingApproval{device: *device, command: command, required: req}}
	}
	out, isErr := commandOutput(resp.GetResult())
	e.auditCommand(ctx, c.tenant, c.user, device.Name, in.Program, isErr, false)
	return out, isErr, nil
}

// auditCommand records a command that ran on a user's computer: where and
// which program, not its arguments or output.
func (e *Engine) auditCommand(ctx context.Context, tenant, user, device, program string, failed, approved bool) {
	outcome := auditlog.Success
	if failed {
		outcome = auditlog.Failure
	}
	e.audit(ctx, tenant, user, auditlog.Device(device), "command.ran", "device", device, outcome, "",
		map[string]string{"program": truncate(program, 256), "approved": strconv.FormatBool(approved)})
}

func (e *Engine) execDevice(ctx context.Context, c caller, dev store.Device, command *devicev1.ExecuteCommandRequest,
	approval *devicev1.Approval) (*devicev1.ExecuteCommandResponse, error) {
	client, err := e.Devices.Client(ctx, requestID(ctx), dev)
	if err != nil {
		return nil, err
	}
	timeout := e.opts.ToolTimeout
	if c.task != nil || approval != nil {
		timeout = taskCommandTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req := &devicev1.ExecuteCommandRequest{Program: command.GetProgram(), Args: command.GetArgs(),
		WorkingDirectory: command.GetWorkingDirectory(), Timeout: command.GetTimeout(), Sandbox: command.GetSandbox(),
		Approval: approval}
	return client.ExecuteCommand(outgoing(ctx), req)
}

func deviceError(name string, err error) string {
	st := status.Convert(err)
	switch {
	case errors.Is(err, context.DeadlineExceeded) || st.Code() == codes.DeadlineExceeded:
		return fmt.Sprintf("%s did not answer in time.", name)
	case st.Code() == codes.PermissionDenied:
		return fmt.Sprintf("%s refused the command: %s", name, truncate(st.Message(), 300))
	case st.Code() == codes.InvalidArgument || st.Code() == codes.FailedPrecondition || st.Code() == codes.ResourceExhausted:
		return fmt.Sprintf("%s could not run the command: %s", name, truncate(st.Message(), 300))
	default:
		return fmt.Sprintf("%s is not reachable (is it online and on the tailnet?).", name)
	}
}

func commandOutput(r *devicev1.CommandResult) (string, bool) {
	clip := func(b []byte, cut bool) string {
		s := strings.ToValidUTF8(string(b), "?")
		if len(s) > maxCommandOutput {
			s, cut = truncate(s, maxCommandOutput), true
		}
		if cut {
			s += "\n[output truncated]"
		}
		return s
	}
	out := map[string]any{
		"exit_code": r.GetExitCode(),
		"stdout":    clip(r.GetStdout(), r.GetStdoutTruncated()),
		"stderr":    clip(r.GetStderr(), r.GetStderrTruncated()),
	}
	if r.GetTimedOut() {
		out["timed_out"] = true
	}
	return output(out), r.GetExitCode() != 0 || r.GetTimedOut()
}
