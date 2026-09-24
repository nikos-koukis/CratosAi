// Package push turns the orchestrator's notifications into push
// notifications on the users' phones.
//
// The notifier claims notifications from the orchestrator (a long poll; each
// claim lasts a minute), sends each to every phone of the user through APNs,
// and completes it. A notification that could not reach any phone for a
// passing reason is left unfinished, so it is claimed again later; the
// orchestrator gives up after five tries or an hour. Notifications say only
// what happened, never a task's goal or result: those stay behind the app's
// sign-in.
package push

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/durationpb"

	"jarvis.internal/app-api/internal/apns"
	"jarvis.internal/app-api/internal/metrics"
	"jarvis.internal/app-api/internal/store"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
)

const (
	claimWait   = 25 * time.Second
	claimMax    = 50
	backoffMin  = time.Second
	backoffMax  = 30 * time.Second
	sendTimeout = 15 * time.Second
	// Approvals expire in minutes; a late notification is only noise.
	approvalExpiry = 5 * time.Minute
	otherExpiry    = time.Hour
)

// Sender sends one alert (apns.Client).
type Sender interface {
	Send(ctx context.Context, environment, deviceToken string, a apns.Alert) error
}

// Tokens are the users' device tokens (store.Store).
type Tokens interface {
	PushTokens(ctx context.Context, tenant uuid.UUID, user string) ([]store.PushToken, error)
	ForgetDeviceToken(ctx context.Context, token string) error
}

// Notifier delivers notifications until its context ends.
type Notifier struct {
	Orchestrator orchv1.OrchestratorServiceClient
	Tokens       Tokens
	APNs         Sender
	Consumer     string
	Metrics      *metrics.Metrics
	Log          *slog.Logger
}

// Run claims and delivers notifications until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	backoff := backoffMin
	for ctx.Err() == nil {
		claimCtx, cancel := context.WithTimeout(ctx, claimWait+10*time.Second)
		claimCtx = metadata.AppendToOutgoingContext(claimCtx, "x-request-id", "push-"+uuid.NewString())
		resp, err := n.Orchestrator.ClaimNotifications(claimCtx, &orchv1.ClaimNotificationsRequest{
			Consumer: n.Consumer, Max: claimMax, Wait: durationpb.New(claimWait)})
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			n.Log.Warn("cannot claim notifications; retrying", "error", err, "backoff_ms", backoff.Milliseconds())
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, backoffMax)
			continue
		}
		backoff = backoffMin
		var done []int64
		for _, notification := range resp.GetNotifications() {
			if n.deliver(ctx, notification) {
				done = append(done, notification.GetNotificationId())
			}
		}
		if len(done) > 0 {
			completeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			if _, err := n.Orchestrator.CompleteNotifications(completeCtx,
				&orchv1.CompleteNotificationsRequest{NotificationIds: done}); err != nil {
				// They will be claimed and sent again after the lease; the
				// collapse id keeps phones from showing duplicates.
				n.Log.Warn("cannot complete notifications", "error", err, "count", len(done))
			}
			cancel()
		}
	}
}

// deliver sends a notification to every phone of its user; it reports
// whether the notification is finished with (sent, or nowhere to send it).
func (n *Notifier) deliver(ctx context.Context, notification *orchv1.Notification) bool {
	kind := kindLabel(notification.GetKind())
	tenant, err := uuid.Parse(notification.GetTenantId())
	if err != nil {
		n.Log.Error("dropping a notification with a bad tenant", "notification_id", notification.GetNotificationId())
		return true
	}
	tokens, err := n.Tokens.PushTokens(ctx, tenant, notification.GetUserId())
	if err != nil {
		n.Log.Error("cannot load push tokens", "error", err)
		return false
	}
	if len(tokens) == 0 {
		n.Metrics.Pushes.WithLabelValues(kind, "no_device").Inc()
		return true
	}
	alert := alertFor(notification)
	finished := false
	for _, token := range tokens {
		sendCtx, cancel := context.WithTimeout(ctx, sendTimeout)
		err := n.APNs.Send(sendCtx, token.Environment, token.DeviceToken, alert)
		cancel()
		switch {
		case err == nil:
			n.Metrics.Pushes.WithLabelValues(kind, "sent").Inc()
			finished = true
		case errors.Is(err, apns.ErrUnregistered):
			n.Metrics.Pushes.WithLabelValues(kind, "unregistered").Inc()
			n.Log.Info("forgetting a device token APNs no longer accepts", "session_id", token.SessionID)
			if err := n.Tokens.ForgetDeviceToken(ctx, token.DeviceToken); err != nil {
				n.Log.Error("cannot forget device token", "error", err)
			}
		default:
			n.Metrics.Pushes.WithLabelValues(kind, "failed").Inc()
			n.Log.Warn("push failed", "session_id", token.SessionID, "notification_id",
				notification.GetNotificationId(), "error", err)
		}
	}
	// Finished if some phone got it, or every phone's token was dead.
	if !finished {
		live, err := n.Tokens.PushTokens(ctx, tenant, notification.GetUserId())
		finished = err == nil && len(live) == 0
	}
	n.Log.Info("notification delivered", "notification_id", notification.GetNotificationId(), "kind", kind,
		"tenant_id", tenant, "phones", len(tokens), "finished", finished)
	return finished
}

func kindLabel(kind orchv1.NotificationKind) string {
	switch kind {
	case orchv1.NotificationKind_NOTIFICATION_KIND_APPROVAL_NEEDED:
		return "approval_needed"
	case orchv1.NotificationKind_NOTIFICATION_KIND_CONFIRMATION_NEEDED:
		return "confirmation_needed"
	case orchv1.NotificationKind_NOTIFICATION_KIND_TASK_FINISHED:
		return "task_finished"
	}
	return "unknown"
}

// alertFor words a notification. The text is generic on purpose: lock
// screens are public, and the app shows the details after sign-in.
func alertFor(notification *orchv1.Notification) apns.Alert {
	task := notification.GetTaskId()
	kind := kindLabel(notification.GetKind())
	a := apns.Alert{
		Thread:     "tasks",
		CollapseID: kind + "-" + task,
		Expires:    time.Now().Add(otherExpiry),
		Data:       map[string]string{"kind": kind, "task_id": task},
	}
	switch notification.GetKind() {
	case orchv1.NotificationKind_NOTIFICATION_KIND_APPROVAL_NEEDED:
		a.Title, a.Body = "Approval needed", "A command on one of your computers is waiting for your approval."
		a.Thread, a.TimeSensitive, a.Expires = "approvals", true, time.Now().Add(approvalExpiry)
	case orchv1.NotificationKind_NOTIFICATION_KIND_CONFIRMATION_NEEDED:
		a.Title, a.Body = "Jarvis needs your OK", "A background task is waiting for you to confirm an action. Open Jarvis to answer."
	default:
		if notification.GetTaskState() == orchv1.TaskState_TASK_STATE_SUCCEEDED {
			a.Title, a.Body = "Task done", "Jarvis finished a background task."
		} else {
			a.Title, a.Body = "Task not done", "A background task could not finish."
		}
	}
	return a
}
