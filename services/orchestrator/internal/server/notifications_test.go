package server_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "jarvis.internal/gen/go/jarvis/agent/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
)

// claim takes the pending notifications of this harness's user, waiting up
// to `wait` for some. Other tests' notifications (other tenants) share the
// outbox; they are completed and ignored.
func (h *harness) claim(t *testing.T, consumer string, wait time.Duration) []*orchv1.Notification {
	t.Helper()
	deadline := time.Now().Add(wait)
	for {
		remaining := max(0, time.Until(deadline))
		resp, err := h.client.ClaimNotifications(tctx(t), &orchv1.ClaimNotificationsRequest{Consumer: consumer, Max: 100,
			Wait: durationpb.New(remaining)})
		if err != nil {
			t.Fatal(err)
		}
		var mine, others []*orchv1.Notification
		for _, n := range resp.GetNotifications() {
			if n.GetTenantId() == h.tenant {
				mine = append(mine, n)
			} else {
				others = append(others, n)
			}
		}
		h.complete(t, others...)
		if len(mine) > 0 || remaining == 0 {
			return mine
		}
	}
}

func (h *harness) complete(t *testing.T, notifications ...*orchv1.Notification) {
	t.Helper()
	if len(notifications) == 0 {
		return
	}
	var ids []int64
	for _, n := range notifications {
		ids = append(ids, n.GetNotificationId())
	}
	if _, err := h.client.CompleteNotifications(tctx(t), &orchv1.CompleteNotificationsRequest{NotificationIds: ids}); err != nil {
		t.Fatal(err)
	}
}

func TestPhonesHearWhatNobodyHeard(t *testing.T) {
	h := newHarness(t, func(o *options) { o.confirmationTTL = 200 * time.Millisecond })
	ca, cert, key := deviceIdentity(t)
	if _, err := h.client.RegisterDevice(tctx(t), &orchv1.RegisterDeviceRequest{TenantId: h.tenant, UserId: h.user,
		Name: "MacBook", Address: "100.101.102.103:7443", ServerName: "macbook", CaPem: ca, ClientCertPem: cert,
		ClientKeyPem: []byte(key)}); err != nil {
		t.Fatal(err)
	}
	conv := h.open(t).GetConversationId()

	// Approvals happen on the phone: it is always told, even mid-conversation.
	waiting := decode(t, h.call(t, conv, "run_on_computer", `{"device":"MacBook","program":"/bin/rm","args":["x"]}`, 1).GetOutput())
	got := h.claim(t, "app-api-1", time.Second)
	if len(got) != 1 || got[0].GetKind() != orchv1.NotificationKind_NOTIFICATION_KIND_APPROVAL_NEEDED ||
		got[0].GetTaskId() != waiting["task_id"] || got[0].GetUserId() != h.user ||
		got[0].GetTaskState() != orchv1.TaskState_TASK_STATE_AWAITING_APPROVAL {
		t.Fatalf("notifications = %v", got)
	}
	h.complete(t, got...)

	// A task that finishes while the user talks to Jarvis is told by voice only.
	h.agent.script(answer("done while you listened"))
	spoken := decode(t, h.call(t, conv, "start_task", `{"goal":"quick"}`, 2).GetOutput())["task_id"].(string)
	h.waitTask(t, spoken, orchv1.TaskState_TASK_STATE_SUCCEEDED)
	if got := h.claim(t, "app-api-1", 0); len(got) != 0 {
		t.Fatalf("notified about a task the user heard: %v", got)
	}

	// The user hangs up while a task waits for a confirmation; it expires,
	// the task finishes, and nobody is there to hear it: the phone is told.
	h.agent.script(
		callTools(&agentv1.ToolCall{CallId: "c1", Name: "work_jira__create_issue", ArgumentsJson: `{"title":"x"}`}),
		answer("gave up on the issue"),
	)
	later := decode(t, h.call(t, conv, "start_task", `{"goal":"file an issue"}`, 3).GetOutput())["task_id"].(string)
	h.waitTask(t, later, orchv1.TaskState_TASK_STATE_AWAITING_CONFIRMATION)
	if _, err := h.client.CloseConversation(tctx(t), &orchv1.CloseConversationRequest{ConversationId: conv}); err != nil {
		t.Fatal(err)
	}
	h.waitTask(t, later, orchv1.TaskState_TASK_STATE_SUCCEEDED)
	got = h.claim(t, "app-api-1", 2*time.Second)
	if len(got) != 1 || got[0].GetKind() != orchv1.NotificationKind_NOTIFICATION_KIND_TASK_FINISHED ||
		got[0].GetTaskId() != later || got[0].GetTaskState() != orchv1.TaskState_TASK_STATE_SUCCEEDED {
		t.Fatalf("notifications = %v", got)
	}
	h.complete(t, got...)

	// A task asking for a confirmation with no conversation open.
	h.agent.script(callTools(&agentv1.ToolCall{CallId: "c2", Name: "work_jira__create_issue", ArgumentsJson: `{}`}))
	orphan := uuid.New()
	if _, err := db.Exec(tctx(t), `INSERT INTO tasks (id, tenant_id, user_id, conversation_id, kind, provider, goal, state,
		tools, history, pending, deadline)
		VALUES ($1, $2, $3, $4, 'agent', 1, 'file it later', 'queued', $5, '[{"userText":"Goal: file it"}]', '[]',
		        now() + interval '1 hour')`, orphan, h.tenant, h.user, conv,
		`{"work_jira__create_issue":{"kind":"mcp","integration_id":"i-1","integration":"Work Jira","tool":"create_issue"}}`); err != nil {
		t.Fatal(err)
	}
	h.waitTask(t, orphan.String(), orchv1.TaskState_TASK_STATE_AWAITING_CONFIRMATION)
	got = h.claim(t, "app-api-1", 2*time.Second)
	if len(got) != 1 || got[0].GetKind() != orchv1.NotificationKind_NOTIFICATION_KIND_CONFIRMATION_NEEDED ||
		got[0].GetTaskId() != orphan.String() {
		t.Fatalf("notifications = %v", got)
	}
	h.complete(t, got...)
}

func TestNotificationsAreClaimedOnceAndRetried(t *testing.T) {
	h := newHarness(t)
	ca, cert, key := deviceIdentity(t)
	if _, err := h.client.RegisterDevice(tctx(t), &orchv1.RegisterDeviceRequest{TenantId: h.tenant, UserId: h.user,
		Name: "MacBook", Address: "100.101.102.103:7443", ServerName: "macbook", CaPem: ca, ClientCertPem: cert,
		ClientKeyPem: []byte(key)}); err != nil {
		t.Fatal(err)
	}
	conv := h.open(t).GetConversationId()

	h.claim(t, "drain", 0) // other tests' leftovers

	// A waiting consumer is woken by a new notification at once.
	type result struct {
		got     []*orchv1.Notification
		elapsed time.Duration
	}
	done := make(chan result, 1)
	go func() {
		started := time.Now()
		got := h.claim(t, "app-api-1", 10*time.Second)
		done <- result{got, time.Since(started)}
	}()
	time.Sleep(200 * time.Millisecond)
	h.call(t, conv, "run_on_computer", `{"device":"MacBook","program":"/bin/rm","args":["y"]}`, 1)
	first := <-done
	if len(first.got) != 1 || first.elapsed > 3*time.Second {
		t.Fatalf("woken after %v with %v", first.elapsed, first.got)
	}

	// Claimed: nobody else gets it, until the claim lapses unfinished.
	if got := h.claim(t, "app-api-2", 0); len(got) != 0 {
		t.Fatalf("claimed twice: %v", got)
	}
	if _, err := db.Exec(tctx(t), `UPDATE notifications SET claimed_until = now() - interval '1 second'
		WHERE id = $1`, first.got[0].GetNotificationId()); err != nil {
		t.Fatal(err)
	}
	again := h.claim(t, "app-api-2", 0)
	if len(again) != 1 || again[0].GetNotificationId() != first.got[0].GetNotificationId() {
		t.Fatalf("retry = %v", again)
	}
	h.complete(t, again...)
	h.complete(t, again...) // idempotent
	if _, err := db.Exec(tctx(t), `UPDATE notifications SET claimed_until = NULL WHERE id = $1`,
		again[0].GetNotificationId()); err != nil {
		t.Fatal(err)
	}
	if got := h.claim(t, "app-api-2", 0); len(got) != 0 {
		t.Fatalf("a completed notification came back: %v", got)
	}

	// Give up after five tries, and on anything an hour old.
	h.call(t, conv, "run_on_computer", `{"device":"MacBook","program":"/bin/rm","args":["z"]}`, 2)
	if _, err := db.Exec(tctx(t), `UPDATE notifications SET attempts = 5 WHERE tenant_id = $1 AND done_at IS NULL`,
		h.tenant); err != nil {
		t.Fatal(err)
	}
	if got := h.claim(t, "app-api-2", 0); len(got) != 0 {
		t.Fatalf("tried a sixth time: %v", got)
	}
	h.call(t, conv, "run_on_computer", `{"device":"MacBook","program":"/bin/rm","args":["w"]}`, 3)
	if _, err := db.Exec(tctx(t), `UPDATE notifications SET created_at = now() - interval '2 hours'
		WHERE tenant_id = $1 AND attempts = 0`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if got := h.claim(t, "app-api-2", 0); len(got) != 0 {
		t.Fatalf("sent a stale notification: %v", got)
	}

	for _, bad := range []*orchv1.ClaimNotificationsRequest{
		{Consumer: "", Max: 1}, {Consumer: "c", Max: 0}, {Consumer: "c", Max: 101},
		{Consumer: "c", Max: 1, Wait: durationpb.New(time.Minute)},
	} {
		if _, err := h.client.ClaimNotifications(tctx(t), bad); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%v: %v", bad, err)
		}
	}
}
