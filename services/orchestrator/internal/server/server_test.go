package server_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "jarvis.internal/gen/go/jarvis/agent/v1"
	auditv1 "jarvis.internal/gen/go/jarvis/audit/v1"
	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	"jarvis.internal/orchestrator/internal/store"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("output %q: %v", s, err)
	}
	return m
}

func wantReason(t *testing.T, err error, code codes.Code, reason orchv1.ErrorReason) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("error = %v, want %v", err, code)
	}
	for _, d := range status.Convert(err).Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == reason.String() {
			return
		}
	}
	t.Fatalf("error %v lacks reason %v", err, reason)
}

func TestOpenConversationOffersTools(t *testing.T) {
	h := newHarness(t)
	resp := h.open(t)
	names := map[string]*orchv1.FunctionTool{}
	for _, tool := range resp.GetTools() {
		names[tool.GetName()] = tool
	}
	for _, want := range []string{"recall_memory", "remember", "start_task", "confirm_action", "cancel_action",
		"work_jira__create_issue", "work_jira__search"} {
		if names[want] == nil {
			t.Fatalf("tool %s missing from %v", want, resp.GetTools())
		}
	}
	if names["run_on_computer"] != nil {
		t.Fatal("device tool offered without devices")
	}
	if !strings.Contains(names["work_jira__search"].GetDescription(), "[Work Jira]") {
		t.Errorf("description = %q", names["work_jira__search"].GetDescription())
	}
	if !strings.Contains(resp.GetInstructions(), "confirm_action") {
		t.Error("instructions do not explain confirmations")
	}
	_, err := uuid.Parse(resp.GetConversationId())
	if err != nil {
		t.Fatal(err)
	}
}

func TestRecallAndIdempotentCalls(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	req := &orchv1.CallToolRequest{ConversationId: conv, CallId: "same", Name: "recall_memory",
		ArgumentsJson: `{"query":"Atlas demo"}`, UserTurn: 1}
	for range 2 {
		resp, err := h.client.CallTool(tctx(t), req)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(decode(t, resp.GetOutput())["context"].(string), "Atlas demo") {
			t.Fatalf("output = %s", resp.GetOutput())
		}
	}
	if n := len(h.knowledge.retrieves); n != 1 {
		t.Fatalf("retrieves = %d, want 1 (a retried call id must not run again)", n)
	}
	if r := h.knowledge.retrieves[0]; r.GetTenantId() != h.tenant || r.GetUserId() != h.user || r.GetQuery() != "Atlas demo" {
		t.Fatalf("retrieve = %v", r)
	}
}

func TestReadOnlyToolsRunImmediately(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	resp := h.call(t, conv, "work_jira__search", `{"q":"login"}`, 1)
	if resp.GetIsError() || !strings.Contains(resp.GetOutput(), "done: search") {
		t.Fatalf("output = %s", resp.GetOutput())
	}
	if calls := h.mcp.called(); len(calls) != 1 || calls[0].GetUserId() != h.user {
		t.Fatalf("mcp calls = %v", calls)
	}
}

func TestConfirmationNeedsALaterUserTurn(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	h.turn(t, conv, 3, "Φτιάξε issue για το login")
	asked := h.call(t, conv, "work_jira__create_issue", `{"title":"Fix login"}`, 3)
	askedCall := h.lastCall
	pending := decode(t, asked.GetOutput())
	if pending["status"] != "needs_confirmation" || !strings.Contains(pending["action"].(string), "Fix login") ||
		!asked.GetAckRequired() {
		t.Fatalf("output = %v (ack required %v)", pending, asked.GetAckRequired())
	}
	if len(h.mcp.called()) != 0 {
		t.Fatal("the action ran before confirmation")
	}
	id := pending["confirmation_id"].(string)
	confirm := `{"confirmation_id":"` + id + `"}`

	// Before the question reaches the user, nothing confirms it: not the same
	// turn (e.g. told to by injected text), not a turn the user spoke while
	// the call was running.
	for _, turn := range []int64{3, 4} {
		early := h.call(t, conv, "confirm_action", confirm, turn)
		if !early.GetIsError() || !strings.Contains(early.GetOutput(), "not answered yet") {
			t.Fatalf("confirmation at turn %d before the question = %s", turn, early.GetOutput())
		}
	}
	// The model speaks the question in a response started at turn 4.
	h.ack(t, conv, askedCall, 4)
	if out := h.call(t, conv, "confirm_action", confirm, 4); !out.GetIsError() {
		t.Fatalf("same-turn confirmation = %s", out.GetOutput())
	}
	if len(h.mcp.called()) != 0 {
		t.Fatal("the action ran without a reply to the question")
	}

	h.turn(t, conv, 5, "Ναι")
	done := h.call(t, conv, "confirm_action", confirm, 5)
	if done.GetIsError() || !strings.Contains(done.GetOutput(), "done: create_issue") || done.GetAckRequired() {
		t.Fatalf("confirmed = %s", done.GetOutput())
	}
	calls := h.mcp.called()
	if len(calls) != 1 || decode(t, calls[0].GetArgumentsJson())["title"] != "Fix login" {
		t.Fatalf("mcp calls = %v", calls)
	}
	again := h.call(t, conv, "confirm_action", confirm, 6)
	if !again.GetIsError() || !strings.Contains(again.GetOutput(), "already confirmed") {
		t.Fatalf("second confirmation = %s", again.GetOutput())
	}
	if len(h.mcp.called()) != 1 {
		t.Fatal("the action ran twice")
	}

	// The audit trail: asked, three attempts to confirm without the user
	// (blocked), then the user's own yes. What the action says stays out.
	if e := h.audit.waitFor(t, "action.confirmation_requested", 1)[0]; e.GetDetails()["tool"] != "create_issue" ||
		e.GetActor().GetKind() != auditv1.ActorKind_ACTOR_KIND_ASSISTANT || e.GetOnBehalfOf() != h.user {
		t.Fatalf("requested %+v", e)
	}
	for _, e := range h.audit.waitFor(t, "action.confirmation_blocked", 3) {
		if e.GetOutcome() != auditv1.Outcome_OUTCOME_DENIED || e.GetReason() != "no_user_answer" {
			t.Fatalf("blocked %+v", e)
		}
	}
	if e := h.audit.waitFor(t, "action.confirmed", 1)[0]; e.GetActor().GetId() != h.user || e.GetTargetId() != id {
		t.Fatalf("confirmed %+v", e)
	}
	if h.audit.mentions("Fix login") {
		t.Fatal("the action's content reached the audit trail")
	}
}

func TestQuestionTurnIsSetOnceAndPerConversation(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	other := h.open(t).GetConversationId()
	asked := h.call(t, conv, "work_jira__create_issue", `{"title":"A"}`, 1)
	askedCall := h.lastCall
	id := decode(t, asked.GetOutput())["confirmation_id"].(string)
	confirm := `{"confirmation_id":"` + id + `"}`

	// Acknowledging the call id in another conversation changes nothing.
	h.ack(t, other, askedCall, 1)
	if out := h.call(t, conv, "confirm_action", confirm, 2); !strings.Contains(out.GetOutput(), "not answered yet") {
		t.Fatalf("confirmed through another conversation's ack: %s", out.GetOutput())
	}

	// A retried call returns the stored result, still asking for the ack.
	retry, err := h.client.CallTool(tctx(t), &orchv1.CallToolRequest{ConversationId: conv,
		CallId: askedCall, Name: "work_jira__create_issue", ArgumentsJson: `{"title":"A"}`, UserTurn: 2})
	if err != nil || retry.GetOutput() != asked.GetOutput() || !retry.GetAckRequired() {
		t.Fatalf("retry = %v, %v", retry, err)
	}
	h.ack(t, conv, askedCall, 2)
	// Only the first ack counts: a later one cannot move the question turn.
	h.ack(t, conv, askedCall, 9)
	if out := h.call(t, conv, "confirm_action", confirm, 3); out.GetIsError() {
		t.Fatalf("confirmation after the question = %s", out.GetOutput())
	}
}

func TestCancelledExpiredAndForeignConfirmations(t *testing.T) {
	h := newHarness(t, func(o *options) { o.confirmationTTL = 150 * time.Millisecond })
	conv := h.open(t).GetConversationId()
	other := h.open(t).GetConversationId()

	id := decode(t, h.call(t, conv, "work_jira__create_issue", `{"title":"A"}`, 1).GetOutput())["confirmation_id"].(string)
	// Another conversation cannot confirm it.
	foreign := h.call(t, other, "confirm_action", `{"confirmation_id":"`+id+`"}`, 9)
	if !strings.Contains(foreign.GetOutput(), "unknown confirmation") {
		t.Fatalf("foreign = %s", foreign.GetOutput())
	}
	cancelled := decode(t, h.call(t, conv, "cancel_action", `{"confirmation_id":"`+id+`"}`, 1).GetOutput())
	if cancelled["status"] != "cancelled" {
		t.Fatalf("cancel = %v", cancelled)
	}
	late := h.call(t, conv, "confirm_action", `{"confirmation_id":"`+id+`"}`, 2)
	if !strings.Contains(late.GetOutput(), "already cancelled") {
		t.Fatalf("confirm after cancel = %s", late.GetOutput())
	}

	id2 := decode(t, h.call(t, conv, "work_jira__create_issue", `{"title":"B"}`, 2).GetOutput())["confirmation_id"].(string)
	time.Sleep(300 * time.Millisecond)
	expired := h.call(t, conv, "confirm_action", `{"confirmation_id":"`+id2+`"}`, 3)
	if !expired.GetIsError() || !strings.Contains(expired.GetOutput(), "expired") {
		t.Fatalf("expired = %s", expired.GetOutput())
	}
	if len(h.mcp.called()) != 0 {
		t.Fatal("a cancelled or expired action ran")
	}
}

func TestBackgroundTaskRunsAndReportsBack(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	h.agent.script(
		callTools(&agentv1.ToolCall{CallId: "c1", Name: "work_jira__search", ArgumentsJson: `{"q":"Atlas"}`}),
		answer("Βρήκα 1 issue για το Atlas."),
	)
	started := decode(t, h.call(t, conv, "start_task", `{"goal":"Βρες τα issues του Atlas"}`, 1).GetOutput())
	if started["status"] != "started" {
		t.Fatalf("start = %v", started)
	}
	task := h.waitTask(t, started["task_id"].(string), orchv1.TaskState_TASK_STATE_SUCCEEDED)
	if task.GetResult() != "Βρήκα 1 issue για το Atlas." || task.GetSteps() != 2 {
		t.Fatalf("task = %v", task)
	}
	events := h.events(t, conv, 1)
	finished := events[0].GetTaskFinished().GetTask()
	if finished.GetTaskId() != task.GetTaskId() || !strings.HasPrefix(events[0].GetMessage(), "[Jarvis]") ||
		!strings.Contains(events[0].GetMessage(), "Βρήκα 1 issue") {
		t.Fatalf("event = %v", events[0])
	}

	decisions := h.agent.decisions()
	first := decisions[0]
	if first.GetModel().GetModel() != "gpt-6-luna" || string(first.GetModel().GetApiKey()) != "sk-tenant-key" ||
		first.GetModel().GetProvider() != commonv1.Provider_PROVIDER_OPENAI {
		t.Fatalf("model = %v", first.GetModel())
	}
	intro := first.GetItems()[0].GetUserText()
	if !strings.Contains(intro, "Βρες τα issues του Atlas") || !strings.Contains(intro, "Atlas demo is on Friday") {
		t.Fatalf("intro = %q", intro)
	}
	var sawStart bool
	for _, spec := range first.GetTools() {
		sawStart = sawStart || spec.GetName() == "start_task" || spec.GetName() == "confirm_action"
	}
	if sawStart {
		t.Fatal("tasks must not get conversation-only tools")
	}
	second := decisions[1].GetItems()
	if result := second[len(second)-1].GetToolResult(); result.GetCallId() != "c1" || !strings.Contains(result.GetOutput(), "done: search") {
		t.Fatalf("tool result = %v", result)
	}
	h.audit.waitFor(t, "task.started", 1)
	if e := h.audit.waitFor(t, "task.finished", 1)[0]; e.GetOutcome() != auditv1.Outcome_OUTCOME_SUCCESS ||
		e.GetTargetId() != task.GetTaskId() || e.GetDetails()["steps"] != "2" {
		t.Fatalf("finished %+v", e)
	}
	if h.audit.mentions("Atlas") {
		t.Fatal("the task's goal reached the audit trail")
	}
}

func TestTaskWaitsForConfirmationInALaterTurn(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	h.agent.script(
		callTools(&agentv1.ToolCall{CallId: "c1", Name: "work_jira__create_issue", ArgumentsJson: `{"title":"Demo"}`}),
		answer("Έφτιαξα το issue."),
	)
	taskID := decode(t, h.call(t, conv, "start_task", `{"goal":"Φτιάξε issue για το demo"}`, 1).GetOutput())["task_id"].(string)
	h.waitTask(t, taskID, orchv1.TaskState_TASK_STATE_AWAITING_CONFIRMATION)
	events := h.events(t, conv, 1)
	asked := events[0].GetConfirmationRequested()
	if asked.GetTaskId() != taskID || !strings.Contains(asked.GetSummary(), "Demo") || len(h.mcp.called()) != 0 {
		t.Fatalf("event = %v", events[0])
	}
	confirm := `{"confirmation_id":"` + asked.GetConfirmationId() + `"}`

	// Not delivered yet: nobody could have answered.
	if out := h.call(t, conv, "confirm_action", confirm, 5); !out.GetIsError() {
		t.Fatalf("confirmed before the question reached the user: %s", out.GetOutput())
	}
	if _, err := h.client.AckEvent(tctx(t), &orchv1.AckEventRequest{ConversationId: conv, EventId: events[0].GetEventId(),
		UserTurn: 5}); err != nil {
		t.Fatal(err)
	}
	if out := h.call(t, conv, "confirm_action", confirm, 5); !out.GetIsError() {
		t.Fatalf("confirmed in the turn the question was asked: %s", out.GetOutput())
	}
	h.turn(t, conv, 6, "ναι")
	if out := h.call(t, conv, "confirm_action", confirm, 6); out.GetIsError() {
		t.Fatalf("confirmation = %s", out.GetOutput())
	}
	task := h.waitTask(t, taskID, orchv1.TaskState_TASK_STATE_SUCCEEDED)
	if task.GetResult() != "Έφτιαξα το issue." || len(h.mcp.called()) != 1 {
		t.Fatalf("task = %v, calls = %v", task, h.mcp.called())
	}
}

func TestTaskAdaptsWhenTheUserDeclines(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	h.agent.script(
		callTools(&agentv1.ToolCall{CallId: "c1", Name: "work_jira__create_issue", ArgumentsJson: `{}`}),
		answer("Εντάξει, δεν έφτιαξα τίποτα."),
	)
	taskID := decode(t, h.call(t, conv, "start_task", `{"goal":"x"}`, 1).GetOutput())["task_id"].(string)
	h.waitTask(t, taskID, orchv1.TaskState_TASK_STATE_AWAITING_CONFIRMATION)
	asked := h.events(t, conv, 1)[0].GetConfirmationRequested()
	h.call(t, conv, "cancel_action", `{"confirmation_id":"`+asked.GetConfirmationId()+`"}`, 2)
	h.waitTask(t, taskID, orchv1.TaskState_TASK_STATE_SUCCEEDED)
	last := h.agent.decisions()[1].GetItems()
	if !strings.Contains(last[len(last)-1].GetToolResult().GetOutput(), "declined") || len(h.mcp.called()) != 0 {
		t.Fatal("the task was not told the user declined")
	}
}

func TestTaskFailures(t *testing.T) {
	t.Run("no provider key", func(t *testing.T) {
		h := newHarness(t)
		h.keys.missing = true
		conv := h.open(t).GetConversationId()
		id := decode(t, h.call(t, conv, "start_task", `{"goal":"x"}`, 1).GetOutput())["task_id"].(string)
		task := h.waitTask(t, id, orchv1.TaskState_TASK_STATE_FAILED)
		if !strings.Contains(task.GetResult(), "no OpenAI key") {
			t.Fatalf("result = %q", task.GetResult())
		}
		if !strings.Contains(h.events(t, conv, 1)[0].GetMessage(), "failed") {
			t.Fatal("failure not reported")
		}
	})
	t.Run("step limit", func(t *testing.T) {
		h := newHarness(t, func(o *options) { o.maxSteps = 3 })
		for i := range 5 {
			h.agent.script(callTools(&agentv1.ToolCall{CallId: "c" + string(rune('a'+i)), Name: "recall_memory",
				ArgumentsJson: `{"query":"x"}`}))
		}
		conv := h.open(t).GetConversationId()
		id := decode(t, h.call(t, conv, "start_task", `{"goal":"loop"}`, 1).GetOutput())["task_id"].(string)
		task := h.waitTask(t, id, orchv1.TaskState_TASK_STATE_FAILED)
		if task.GetSteps() != 3 || !strings.Contains(task.GetResult(), "too many steps") {
			t.Fatalf("task = %v", task)
		}
	})
	t.Run("provider down", func(t *testing.T) {
		h := newHarness(t) // nothing scripted: every Decide is UNAVAILABLE
		conv := h.open(t).GetConversationId()
		id := decode(t, h.call(t, conv, "start_task", `{"goal":"x"}`, 1).GetOutput())["task_id"].(string)
		task := h.waitTask(t, id, orchv1.TaskState_TASK_STATE_FAILED)
		if !strings.Contains(task.GetResult(), "unavailable") || len(h.agent.decisions()) != 3 {
			t.Fatalf("task = %v after %d attempts", task, len(h.agent.decisions()))
		}
	})
}

func TestCancelTask(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	h.agent.script(callTools(&agentv1.ToolCall{CallId: "c1", Name: "work_jira__create_issue", ArgumentsJson: `{}`}))
	id := decode(t, h.call(t, conv, "start_task", `{"goal":"x"}`, 1).GetOutput())["task_id"].(string)
	h.waitTask(t, id, orchv1.TaskState_TASK_STATE_AWAITING_CONFIRMATION)
	asked := h.events(t, conv, 1)[0].GetConfirmationRequested()
	resp, err := h.client.CancelTask(tctx(t), &orchv1.CancelTaskRequest{TenantId: h.tenant, UserId: h.user, TaskId: id})
	if err != nil || resp.GetTask().GetState() != orchv1.TaskState_TASK_STATE_CANCELLED {
		t.Fatalf("cancel = %v, %v", resp, err)
	}
	events := h.events(t, conv, 2)
	if events[1].GetTaskFinished().GetTask().GetState() != orchv1.TaskState_TASK_STATE_CANCELLED {
		t.Fatalf("event = %v", events[1])
	}
	h.turn(t, conv, 2, "yes")
	if out := h.call(t, conv, "confirm_action", `{"confirmation_id":"`+asked.GetConfirmationId()+`"}`, 2); !out.GetIsError() {
		t.Fatal("confirmed an action of a cancelled task")
	}
	// Another user's cancel is NOT_FOUND.
	_, err = h.client.CancelTask(tctx(t), &orchv1.CancelTaskRequest{TenantId: h.tenant, UserId: "someone-else", TaskId: id})
	wantReason(t, err, codes.NotFound, orchv1.ErrorReason_ERROR_REASON_TASK_NOT_FOUND)
}

func TestConversationEndsInMemory(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	h.turn(t, conv, 1, "Θυμήσου ότι το demo του Atlas είναι την Παρασκευή")
	if _, err := h.client.RecordTurn(tctx(t), &orchv1.RecordTurnRequest{ConversationId: conv, Role: orchv1.Role_ROLE_ASSISTANT,
		UserTurn: 1, ItemId: "a1", Text: "Εντάξει."}); err != nil {
		t.Fatal(err)
	}
	for range 2 { // idempotent
		if _, err := h.client.CloseConversation(tctx(t), &orchv1.CloseConversationRequest{ConversationId: conv}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(h.knowledge.upserted()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("memory never extracted")
		}
		time.Sleep(20 * time.Millisecond)
	}
	up := h.knowledge.upserted()[0]
	if up.GetSource().GetId() != "conversation:"+conv || up.GetSource().GetKind() != "conversation" ||
		up.GetTenantId() != h.tenant || up.GetUserId() != h.user || len(up.GetEntities()) != 1 {
		t.Fatalf("upsert = %v", up)
	}
	extract := h.agent.extracts[0]
	if len(extract.GetTurns()) != 2 || extract.GetTurns()[0].GetSpeaker() != "user" || extract.GetLocale() != "el-GR" {
		t.Fatalf("extract = %v", extract)
	}
	// A closed conversation takes no more calls.
	_, err := h.client.CallTool(tctx(t), &orchv1.CallToolRequest{ConversationId: conv, CallId: "late", Name: "recall_memory",
		ArgumentsJson: `{"query":"x"}`})
	wantReason(t, err, codes.FailedPrecondition, orchv1.ErrorReason_ERROR_REASON_CONVERSATION_CLOSED)
}

func TestDevicesAndApprovals(t *testing.T) {
	h := newHarness(t)
	ca, cert, key := deviceIdentity(t)
	register := func(address string) (*orchv1.RegisterDeviceResponse, error) {
		return h.client.RegisterDevice(tctx(t), &orchv1.RegisterDeviceRequest{TenantId: h.tenant, UserId: h.user,
			Name: "MacBook", Address: address, ServerName: "macbook", CaPem: ca, ClientCertPem: cert,
			ClientKeyPem: []byte(key)})
	}
	for _, bad := range []string{"192.168.1.10:7443", "example.com:7443", "10.0.0.1:7443", "nonsense"} {
		if _, err := register(bad); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("address %s: %v", bad, err)
		}
	}
	dev, err := register("100.101.102.103:7443")
	if err != nil {
		t.Fatal(err)
	}
	again, err := register("127.0.0.1:7443") // same name: replaced, same id
	if err != nil || again.GetDevice().GetDeviceId() != dev.GetDevice().GetDeviceId() {
		t.Fatalf("replace = %v, %v", again, err)
	}
	var sealed []byte
	if err := db.QueryRow(tctx(t), `SELECT client_key_sealed FROM devices WHERE id = $1`, dev.GetDevice().GetDeviceId()).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "PRIVATE KEY") {
		t.Fatal("device key stored in plaintext")
	}

	conv := h.open(t)
	var offered bool
	for _, tool := range conv.GetTools() {
		offered = offered || tool.GetName() == "run_on_computer"
	}
	if !offered {
		t.Fatal("device tool not offered")
	}
	allowed := decode(t, h.call(t, conv.GetConversationId(), "run_on_computer",
		`{"device":"MacBook","program":"/usr/bin/git","args":["status"]}`, 1).GetOutput())
	if allowed["stdout"] != "ran /usr/bin/git" {
		t.Fatalf("allowlisted = %v", allowed)
	}
	waiting := decode(t, h.call(t, conv.GetConversationId(), "run_on_computer",
		`{"device":"MacBook","program":"/bin/rm","args":["-rf","build"]}`, 2).GetOutput())
	if waiting["status"] != "waiting_for_approval" {
		t.Fatalf("approval = %v", waiting)
	}
	// The dashboard shows the approver exactly what the device asked to sign.
	pending, err := h.client.GetTask(tctx(t), &orchv1.GetTaskRequest{TenantId: h.tenant, UserId: h.user,
		TaskId: waiting["task_id"].(string)})
	approval := pending.GetTask().GetPendingApproval()
	if err != nil || !strings.HasPrefix(approval.GetApprovalId(), "appr-") || string(approval.GetPayload()) != "payload" ||
		approval.GetDeviceName() != "MacBook" || !approval.GetExpireTime().AsTime().After(time.Now()) {
		t.Fatalf("pending approval = %v, %v", pending, err)
	}
	_, err = h.client.SubmitDeviceApproval(tctx(t), &orchv1.SubmitDeviceApprovalRequest{TenantId: h.tenant,
		UserId: "someone-else", ApprovalId: approval.GetApprovalId(), ApproverId: "my-iphone", Signature: make([]byte, 64)})
	wantReason(t, err, codes.NotFound, orchv1.ErrorReason_ERROR_REASON_APPROVAL_NOT_FOUND)

	// A signature the device refuses spends the approval (one attempt each):
	// the command did not run and the task says so.
	_, err = h.client.SubmitDeviceApproval(tctx(t), &orchv1.SubmitDeviceApprovalRequest{TenantId: h.tenant,
		UserId: h.user, ApprovalId: approval.GetApprovalId(), ApproverId: "stranger", Signature: make([]byte, 64)})
	wantReason(t, err, codes.PermissionDenied, orchv1.ErrorReason_ERROR_REASON_APPROVAL_REJECTED)
	rejected := h.waitTask(t, waiting["task_id"].(string), orchv1.TaskState_TASK_STATE_FAILED)
	if !strings.Contains(rejected.GetResult(), "rejected the approval") || rejected.GetPendingApproval() != nil {
		t.Fatalf("rejected task = %v", rejected)
	}
	_, err = h.client.SubmitDeviceApproval(tctx(t), &orchv1.SubmitDeviceApprovalRequest{TenantId: h.tenant,
		UserId: h.user, ApprovalId: approval.GetApprovalId(), ApproverId: "my-iphone", Signature: make([]byte, 64)})
	wantReason(t, err, codes.NotFound, orchv1.ErrorReason_ERROR_REASON_APPROVAL_NOT_FOUND)

	// Asked again, and approved by the right phone.
	waiting = decode(t, h.call(t, conv.GetConversationId(), "run_on_computer",
		`{"device":"MacBook","program":"/bin/rm","args":["-rf","build"]}`, 3).GetOutput())
	second, err := h.client.GetTask(tctx(t), &orchv1.GetTaskRequest{TenantId: h.tenant, UserId: h.user,
		TaskId: waiting["task_id"].(string)})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := h.client.SubmitDeviceApproval(tctx(t), &orchv1.SubmitDeviceApprovalRequest{TenantId: h.tenant,
		UserId: h.user, ApprovalId: second.GetTask().GetPendingApproval().GetApprovalId(), ApproverId: "my-iphone",
		Signature: make([]byte, 64)})
	if err != nil || !strings.Contains(approved.GetOutput(), "ran /bin/rm") {
		t.Fatalf("approved = %v, %v", approved, err)
	}
	task := h.waitTask(t, waiting["task_id"].(string), orchv1.TaskState_TASK_STATE_SUCCEEDED)
	if !strings.Contains(task.GetResult(), "ran /bin/rm") || task.GetPendingApproval() != nil {
		t.Fatalf("task = %v", task)
	}
	finished := h.events(t, conv.GetConversationId(), 2)
	if finished[0].GetTaskFinished().GetTask().GetState() != orchv1.TaskState_TASK_STATE_FAILED ||
		finished[1].GetTaskFinished().GetTask().GetTaskId() != task.GetTaskId() {
		t.Fatalf("events = %v", finished)
	}

	// The audit trail: commands that ran (allowlisted, then approved), the
	// approvals asked for, and the one that did not run. No arguments.
	ran := h.audit.waitFor(t, "command.ran", 2)
	if ran[0].GetDetails()["program"] != "/usr/bin/git" || ran[0].GetDetails()["approved"] != "false" ||
		ran[1].GetDetails()["program"] != "/bin/rm" || ran[1].GetDetails()["approved"] != "true" ||
		ran[0].GetActor().GetKind() != auditv1.ActorKind_ACTOR_KIND_DEVICE || ran[0].GetOnBehalfOf() != h.user {
		t.Fatalf("ran %+v", ran)
	}
	h.audit.waitFor(t, "command.approval_requested", 2)
	if e := h.audit.waitFor(t, "command.not_run", 1)[0]; e.GetReason() != "approval_rejected" ||
		e.GetOutcome() != auditv1.Outcome_OUTCOME_DENIED {
		t.Fatalf("not run %+v", e)
	}
	if h.audit.mentions("-rf") {
		t.Fatal("command arguments reached the audit trail")
	}

	list, _ := h.client.ListDevices(tctx(t), &orchv1.ListDevicesRequest{TenantId: h.tenant, UserId: h.user})
	if len(list.GetDevices()) != 1 {
		t.Fatalf("devices = %v", list)
	}
	if _, err := h.client.RemoveDevice(tctx(t), &orchv1.RemoveDeviceRequest{TenantId: h.tenant, UserId: h.user,
		DeviceId: dev.GetDevice().GetDeviceId()}); err != nil {
		t.Fatal(err)
	}
}

func TestValidation(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	ctx := tctx(t)
	checks := map[string]error{}
	_, checks["bad tenant"] = h.client.OpenConversation(ctx, &orchv1.OpenConversationRequest{TenantId: "x", UserId: "u",
		Provider: commonv1.Provider_PROVIDER_OPENAI})
	_, checks["anthropic"] = h.client.OpenConversation(ctx, &orchv1.OpenConversationRequest{TenantId: h.tenant, UserId: "u",
		Provider: commonv1.Provider_PROVIDER_ANTHROPIC})
	_, checks["bad locale"] = h.client.OpenConversation(ctx, &orchv1.OpenConversationRequest{TenantId: h.tenant, UserId: "u",
		Provider: commonv1.Provider_PROVIDER_XAI, Locale: "el GR"})
	_, checks["no role"] = h.client.RecordTurn(ctx, &orchv1.RecordTurnRequest{ConversationId: conv, ItemId: "i"})
	_, checks["negative turn"] = h.client.CallTool(ctx, &orchv1.CallToolRequest{ConversationId: conv, CallId: "c",
		Name: "recall_memory", UserTurn: -1})
	_, checks["huge args"] = h.client.CallTool(ctx, &orchv1.CallToolRequest{ConversationId: conv, CallId: "c",
		Name: "recall_memory", ArgumentsJson: strings.Repeat("x", 70000)})
	_, checks["bad signature"] = h.client.SubmitDeviceApproval(ctx, &orchv1.SubmitDeviceApprovalRequest{TenantId: h.tenant,
		UserId: h.user, ApprovalId: "a", ApproverId: "b", Signature: []byte{1}})
	for name, err := range checks {
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err := h.client.CallTool(ctx, &orchv1.CallToolRequest{ConversationId: uuid.NewString(), CallId: "c", Name: "x"})
	wantReason(t, err, codes.NotFound, orchv1.ErrorReason_ERROR_REASON_CONVERSATION_NOT_FOUND)
	unknown := h.call(t, conv, "no_such_tool", `{}`, 1)
	if !unknown.GetIsError() || !strings.Contains(unknown.GetOutput(), "unknown tool") {
		t.Fatalf("unknown tool = %s", unknown.GetOutput())
	}
}

func TestProviderKeysAreWipedAfterUse(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	h.agent.script(answer("ok"))
	id := decode(t, h.call(t, conv, "start_task", `{"goal":"x"}`, 1).GetOutput())["task_id"].(string)
	h.waitTask(t, id, orchv1.TaskState_TASK_STATE_SUCCEEDED)
	h.agent.mu.Lock()
	defer h.agent.mu.Unlock()
	for _, key := range h.agent.keys {
		for _, b := range key {
			if b != 0 {
				t.Fatal("the provider key stayed in memory after the call")
			}
		}
	}
}

func TestTasksSurviveAWorkerCrash(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	h.agent.script(answer("resumed and done"))
	// A task a dead worker was running: its lease expired.
	id := uuid.New()
	history := `[{"userText":"Goal: finish the report"}]`
	if _, err := db.Exec(tctx(t), `INSERT INTO tasks (id, tenant_id, user_id, conversation_id, kind, provider, goal, state,
		tools, history, pending, lease_owner, lease_until, deadline)
		VALUES ($1, $2, $3, $4, 'agent', 1, 'finish the report', 'running', '{}', $5, '[]', 'dead-worker',
		        now() - interval '1 minute', now() + interval '1 hour')`, id, h.tenant, h.user, conv, history); err != nil {
		t.Fatal(err)
	}
	task := h.waitTask(t, id.String(), orchv1.TaskState_TASK_STATE_SUCCEEDED)
	if task.GetResult() != "resumed and done" {
		t.Fatalf("task = %v", task)
	}
	if got := h.agent.decisions()[0].GetItems()[0].GetUserText(); got != "Goal: finish the report" {
		t.Fatalf("history not resumed: %q", got)
	}
}

func TestOldTranscriptsArePurged(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	h.turn(t, conv, 1, "private words")
	if _, err := h.client.CloseConversation(tctx(t), &orchv1.CloseConversationRequest{ConversationId: conv}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(tctx(t), `UPDATE conversations SET closed_at = now() - interval '2 hours' WHERE id = $1`, conv); err != nil {
		t.Fatal(err)
	}
	n, err := h.store.PurgeTranscripts(tctx(t), time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("purged %d, %v", n, err)
	}
	var left int
	_ = db.QueryRow(tctx(t), `SELECT count(*) FROM turns WHERE conversation_id = $1`, conv).Scan(&left)
	if left != 0 {
		t.Fatal("transcript survived its retention")
	}
}

func TestTasksAndDevicesStayWithTheirOwner(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	h.agent.script(answer("done"))
	id := decode(t, h.call(t, conv, "start_task", `{"goal":"x"}`, 1).GetOutput())["task_id"].(string)
	h.waitTask(t, id, orchv1.TaskState_TASK_STATE_SUCCEEDED)
	ca, cert, key := deviceIdentity(t)
	dev, err := h.client.RegisterDevice(tctx(t), &orchv1.RegisterDeviceRequest{TenantId: h.tenant, UserId: h.user,
		Name: "MacBook", Address: "100.101.102.103:7443", ServerName: "macbook", CaPem: ca, ClientCertPem: cert,
		ClientKeyPem: []byte(key)})
	if err != nil {
		t.Fatal(err)
	}

	otherTenant := uuid.NewString()
	for _, stranger := range []struct{ tenant, user string }{{h.tenant, "someone-else"}, {otherTenant, h.user}} {
		_, err := h.client.GetTask(tctx(t), &orchv1.GetTaskRequest{TenantId: stranger.tenant, UserId: stranger.user, TaskId: id})
		wantReason(t, err, codes.NotFound, orchv1.ErrorReason_ERROR_REASON_TASK_NOT_FOUND)
		tasks, err := h.client.ListTasks(tctx(t), &orchv1.ListTasksRequest{TenantId: stranger.tenant, UserId: stranger.user})
		if err != nil || len(tasks.GetTasks()) != 0 {
			t.Fatalf("%v listed %v, %v", stranger, tasks, err)
		}
		devices, err := h.client.ListDevices(tctx(t), &orchv1.ListDevicesRequest{TenantId: stranger.tenant, UserId: stranger.user})
		if err != nil || len(devices.GetDevices()) != 0 {
			t.Fatalf("%v listed %v, %v", stranger, devices, err)
		}
		// Removing is idempotent, so it succeeds, but must not touch the device.
		if _, err := h.client.RemoveDevice(tctx(t), &orchv1.RemoveDeviceRequest{TenantId: stranger.tenant,
			UserId: stranger.user, DeviceId: dev.GetDevice().GetDeviceId()}); err != nil {
			t.Fatal(err)
		}
	}
	tasks, _ := h.client.ListTasks(tctx(t), &orchv1.ListTasksRequest{TenantId: h.tenant, UserId: h.user})
	devices, _ := h.client.ListDevices(tctx(t), &orchv1.ListDevicesRequest{TenantId: h.tenant, UserId: h.user})
	if len(tasks.GetTasks()) != 1 || len(devices.GetDevices()) != 1 {
		t.Fatalf("the owner lost access: tasks %v devices %v", tasks, devices)
	}
}

func TestOnlyTheLeaseOwnerMayWriteATask(t *testing.T) {
	h := newHarness(t)
	id := uuid.New()
	// A task another live worker holds (its lease runs for an hour).
	if _, err := db.Exec(tctx(t), `INSERT INTO tasks (id, tenant_id, user_id, kind, provider, goal, state, tools,
		history, pending, lease_owner, lease_until, deadline)
		VALUES ($1, $2, $3, 'agent', 1, 'g', 'running', '{}', '[]', '[]', 'worker-b', now() + interval '1 hour',
		        now() + interval '2 hours')`, id, h.tenant, h.user); err != nil {
		t.Fatal(err)
	}
	task := store.Task{ID: id, History: json.RawMessage(`[]`), Pending: json.RawMessage(`[]`)}
	ctx := tctx(t)
	if ok, err := h.store.RenewLease(ctx, id, "worker-a", time.Minute); ok || err != nil {
		t.Fatalf("a stranger renewed the lease: %v %v", ok, err)
	}
	if ok, err := h.store.SaveProgress(ctx, task, "worker-a"); ok || err != nil {
		t.Fatalf("a stranger saved progress: %v %v", ok, err)
	}
	if ok, err := h.store.SetTaskState(ctx, task, "worker-a", store.TaskSucceeded, "hijacked"); ok || err != nil {
		t.Fatalf("a stranger finished the task: %v %v", ok, err)
	}
	if ok, err := h.store.RenewLease(ctx, id, "worker-b", time.Minute); !ok || err != nil {
		t.Fatalf("the owner could not renew: %v %v", ok, err)
	}
	if state, _ := h.store.TaskState(ctx, id); state != store.TaskRunning {
		t.Fatalf("state = %s", state)
	}
}

func TestWhatTheUserDidNotHearIsToldInTheirNextConversation(t *testing.T) {
	h := newHarness(t)
	first := h.open(t).GetConversationId()
	h.agent.script(
		callTools(&agentv1.ToolCall{CallId: "c1", Name: "work_jira__create_issue", ArgumentsJson: `{"title":"Demo"}`}),
		answer("Έφτιαξα το issue."),
	)
	taskID := decode(t, h.call(t, first, "start_task", `{"goal":"Φτιάξε issue"}`, 1).GetOutput())["task_id"].(string)
	h.waitTask(t, taskID, orchv1.TaskState_TASK_STATE_AWAITING_CONFIRMATION)
	// The user hangs up before hearing the question.
	if _, err := h.client.CloseConversation(tctx(t), &orchv1.CloseConversationRequest{ConversationId: first}); err != nil {
		t.Fatal(err)
	}
	// Conversations of someone else (in the same tenant) get nothing, whether
	// opened before or after the user's next one.
	openOther := func() string {
		other, err := h.client.OpenConversation(tctx(t), &orchv1.OpenConversationRequest{TenantId: h.tenant,
			UserId: "someone-else", SessionId: "s", Provider: commonv1.Provider_PROVIDER_OPENAI})
		if err != nil {
			t.Fatal(err)
		}
		return other.GetConversationId()
	}
	others := []string{openOther()}

	// Their next conversation asks it, and can confirm it.
	next := h.open(t).GetConversationId()
	others = append(others, openOther())
	asked := h.events(t, next, 1)[0]
	confirmationID := asked.GetConfirmationRequested().GetConfirmationId()
	if asked.GetConfirmationRequested().GetTaskId() != taskID {
		t.Fatalf("event = %v", asked)
	}
	confirm := `{"confirmation_id":"` + confirmationID + `"}`
	if out := h.call(t, next, "confirm_action", confirm, 1); !strings.Contains(out.GetOutput(), "not answered yet") {
		t.Fatalf("confirmed before the question was asked again: %s", out.GetOutput())
	}
	if _, err := h.client.AckEvent(tctx(t), &orchv1.AckEventRequest{ConversationId: next, EventId: asked.GetEventId(),
		UserTurn: 1}); err != nil {
		t.Fatal(err)
	}
	h.turn(t, next, 2, "ναι")
	if out := h.call(t, next, "confirm_action", confirm, 2); out.GetIsError() {
		t.Fatalf("confirmation = %s", out.GetOutput())
	}
	// The task belongs to the closed conversation; its result comes here
	// (a new stream starts after the acknowledged question).
	h.waitTask(t, taskID, orchv1.TaskState_TASK_STATE_SUCCEEDED)
	finished := h.events(t, next, 1)[0]
	if finished.GetTaskFinished().GetTask().GetResult() != "Έφτιαξα το issue." {
		t.Fatalf("event = %v", finished)
	}
	var strays int
	if err := db.QueryRow(tctx(t), `SELECT count(*) FROM events WHERE conversation_id = ANY($1::uuid[])`,
		others).Scan(&strays); err != nil || strays != 0 {
		t.Fatalf("another user's conversations got %d events (%v)", strays, err)
	}
}

func TestAbandonedConversationsAreClosedAndRemembered(t *testing.T) {
	h := newHarness(t)
	conv := h.open(t).GetConversationId()
	h.turn(t, conv, 1, "Το demo είναι την Παρασκευή.")
	// Its gateway crashed long ago and never closed it.
	if _, err := db.Exec(tctx(t), `UPDATE conversations SET created_at = now() - interval '3 hours' WHERE id = $1`,
		conv); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var state string
		err := db.QueryRow(tctx(t), `SELECT state FROM memory_jobs WHERE conversation_id = $1`, conv).Scan(&state)
		if err == nil && state == "done" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("abandoned conversation not remembered (state %q, %v)", state, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, err := h.client.CallTool(tctx(t), &orchv1.CallToolRequest{ConversationId: conv, CallId: "late",
		Name: "recall_memory", ArgumentsJson: `{"query":"demo"}`, UserTurn: 2})
	wantReason(t, err, codes.FailedPrecondition, orchv1.ErrorReason_ERROR_REASON_CONVERSATION_CLOSED)
}

func TestUnsignedApprovalsExpire(t *testing.T) {
	h := newHarness(t)
	ca, cert, key := deviceIdentity(t)
	if _, err := h.client.RegisterDevice(tctx(t), &orchv1.RegisterDeviceRequest{TenantId: h.tenant, UserId: h.user,
		Name: "MacBook", Address: "100.101.102.103:7443", ServerName: "macbook", CaPem: ca, ClientCertPem: cert,
		ClientKeyPem: []byte(key)}); err != nil {
		t.Fatal(err)
	}
	conv := h.open(t).GetConversationId()
	waiting := decode(t, h.call(t, conv, "run_on_computer", `{"device":"MacBook","program":"/bin/rm","args":["x"]}`, 1).GetOutput())
	if _, err := db.Exec(tctx(t), `UPDATE device_approvals SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	expired := h.waitTask(t, waiting["task_id"].(string), orchv1.TaskState_TASK_STATE_FAILED)
	if !strings.Contains(expired.GetResult(), "in time") {
		t.Fatalf("task = %v", expired)
	}
	var left int
	if err := db.QueryRow(tctx(t), `SELECT count(*) FROM device_approvals`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d approvals left (%v)", left, err)
	}
}
