package push

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	"jarvis.internal/app-api/internal/apns"
	"jarvis.internal/app-api/internal/metrics"
	"jarvis.internal/app-api/internal/store"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
)

type fakeOrchestrator struct {
	orchv1.OrchestratorServiceClient
	mu        sync.Mutex
	batches   [][]*orchv1.Notification
	completed []int64
}

func (f *fakeOrchestrator) ClaimNotifications(ctx context.Context, in *orchv1.ClaimNotificationsRequest, _ ...grpc.CallOption) (*orchv1.ClaimNotificationsResponse, error) {
	f.mu.Lock()
	if len(f.batches) > 0 {
		batch := f.batches[0]
		f.batches = f.batches[1:]
		f.mu.Unlock()
		return &orchv1.ClaimNotificationsResponse{Notifications: batch}, nil
	}
	f.mu.Unlock()
	<-ctx.Done() // nothing more: wait like the long poll
	return nil, ctx.Err()
}

func (f *fakeOrchestrator) CompleteNotifications(_ context.Context, in *orchv1.CompleteNotificationsRequest, _ ...grpc.CallOption) (*orchv1.CompleteNotificationsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completed = append(f.completed, in.GetNotificationIds()...)
	return &orchv1.CompleteNotificationsResponse{}, nil
}

type fakeTokens struct {
	mu        sync.Mutex
	tokens    map[string][]store.PushToken // by user
	forgotten []string
}

func (f *fakeTokens) PushTokens(_ context.Context, _ uuid.UUID, user string) ([]store.PushToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.PushToken(nil), f.tokens[user]...), nil
}

func (f *fakeTokens) ForgetDeviceToken(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forgotten = append(f.forgotten, token)
	for user, tokens := range f.tokens {
		kept := tokens[:0]
		for _, t := range tokens {
			if t.DeviceToken != token {
				kept = append(kept, t)
			}
		}
		f.tokens[user] = kept
	}
	return nil
}

type sent struct {
	environment, token string
	alert              apns.Alert
}

type fakeSender struct {
	mu   sync.Mutex
	sent []sent
	// errs answers by device token.
	errs map[string]error
}

func (f *fakeSender) Send(_ context.Context, environment, token string, a apns.Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sent{environment, token, a})
	return f.errs[token]
}

var tenant = uuid.NewString()

func notification(id int64, user string, kind orchv1.NotificationKind, state orchv1.TaskState) *orchv1.Notification {
	return &orchv1.Notification{NotificationId: id, TenantId: tenant, UserId: user, Kind: kind, TaskId: "task-" + user,
		TaskState: state}
}

func run(t *testing.T, orch *fakeOrchestrator, tokens *fakeTokens, sender *fakeSender) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	n := &Notifier{Orchestrator: orch, Tokens: tokens, APNs: sender, Consumer: "test", Metrics: metrics.New(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	go func() {
		n.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		orch.mu.Lock()
		empty := len(orch.batches) == 0
		orch.mu.Unlock()
		if empty {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // let the last batch finish
	cancel()
	<-done
}

func TestEveryPhoneOfTheUserIsTold(t *testing.T) {
	orch := &fakeOrchestrator{batches: [][]*orchv1.Notification{{
		notification(1, "ana", orchv1.NotificationKind_NOTIFICATION_KIND_APPROVAL_NEEDED, orchv1.TaskState_TASK_STATE_AWAITING_APPROVAL),
		notification(2, "bob", orchv1.NotificationKind_NOTIFICATION_KIND_TASK_FINISHED, orchv1.TaskState_TASK_STATE_FAILED),
		notification(3, "cid", orchv1.NotificationKind_NOTIFICATION_KIND_TASK_FINISHED, orchv1.TaskState_TASK_STATE_SUCCEEDED),
		notification(4, "dan", orchv1.NotificationKind_NOTIFICATION_KIND_TASK_FINISHED, orchv1.TaskState_TASK_STATE_SUCCEEDED),
	}}}
	tokens := &fakeTokens{tokens: map[string][]store.PushToken{
		"ana": {{DeviceToken: "phone", Environment: "sandbox"}, {DeviceToken: "ipad", Environment: "production"}},
		"bob": {{DeviceToken: "bob-phone", Environment: "production"}},
		"cid": {{DeviceToken: "cid-phone", Environment: "production"}},
	}}
	sender := &fakeSender{}
	run(t, orch, tokens, sender)

	if len(sender.sent) != 4 {
		t.Fatalf("sent %d pushes: %+v", len(sender.sent), sender.sent)
	}
	approval := sender.sent[0].alert
	if sender.sent[0].environment != "sandbox" || sender.sent[1].environment != "production" ||
		!approval.TimeSensitive || approval.CollapseID != "approval_needed-task-ana" ||
		approval.Data["kind"] != "approval_needed" || time.Until(approval.Expires) > 5*time.Minute {
		t.Fatalf("approval push %+v", sender.sent[:2])
	}
	if failed := sender.sent[2].alert; failed.Title != "Task not done" || failed.TimeSensitive {
		t.Fatalf("failed task push %+v", failed)
	}
	if done := sender.sent[3].alert; done.Title != "Task done" || done.Data["task_id"] != "task-cid" {
		t.Fatalf("finished task push %+v", done)
	}
	for _, s := range sender.sent {
		if strings.Contains(s.alert.Title+s.alert.Body, "task-") {
			t.Fatalf("task details on the lock screen: %q", s.alert.Body)
		}
	}
	// dan has no phone: nothing to send, done anyway.
	if len(orch.completed) != 4 {
		t.Fatalf("completed %v", orch.completed)
	}
}

func TestDeadTokensAreForgottenAndFailuresRetried(t *testing.T) {
	orch := &fakeOrchestrator{batches: [][]*orchv1.Notification{{
		notification(1, "ana", orchv1.NotificationKind_NOTIFICATION_KIND_CONFIRMATION_NEEDED, orchv1.TaskState_TASK_STATE_AWAITING_CONFIRMATION),
		notification(2, "bob", orchv1.NotificationKind_NOTIFICATION_KIND_TASK_FINISHED, orchv1.TaskState_TASK_STATE_SUCCEEDED),
	}}}
	tokens := &fakeTokens{tokens: map[string][]store.PushToken{
		"ana": {{DeviceToken: "old-phone", Environment: "sandbox"}},
		"bob": {{DeviceToken: "busy", Environment: "sandbox"}},
	}}
	sender := &fakeSender{errs: map[string]error{"old-phone": apns.ErrUnregistered,
		"busy": &apns.Error{Status: 503, Reason: "ServiceUnavailable"}}}
	run(t, orch, tokens, sender)

	if len(tokens.forgotten) != 1 || tokens.forgotten[0] != "old-phone" {
		t.Fatalf("forgotten %v", tokens.forgotten)
	}
	// ana's only phone is gone: done. bob's push may work later: not done.
	if len(orch.completed) != 1 || orch.completed[0] != 1 {
		t.Fatalf("completed %v", orch.completed)
	}
	if !errors.Is(sender.errs["old-phone"], apns.ErrUnregistered) {
		t.Fatal("setup")
	}
}
