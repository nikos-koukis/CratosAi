// Package engine is the orchestrator's execution engine: the tools of voice
// conversations, confirmations, background tasks (durable agent loops) and
// the memory extracted from finished conversations.
package engine

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "jarvis.internal/gen/go/jarvis/agent/v1"
	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	devicev1 "jarvis.internal/gen/go/jarvis/device/v1"
	knowledgev1 "jarvis.internal/gen/go/jarvis/knowledge/v1"
	mcpv1 "jarvis.internal/gen/go/jarvis/mcp/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/orchestrator/internal/metrics"
	"jarvis.internal/orchestrator/internal/store"
)

// DeviceClients connects to users' devices.
type DeviceClients interface {
	Client(ctx context.Context, requestID string, dev store.Device) (devicev1.DeviceServiceClient, error)
	Forget(id uuid.UUID)
}

// Deps are the engine's collaborators.
type Deps struct {
	Store     *store.Store
	Keys      vaultclient.KeySource
	Sealer    vaultclient.Sealer
	MCP       mcpv1.McpRouterServiceClient
	Knowledge knowledgev1.KnowledgeServiceClient
	Agent     agentv1.AgentWorkerServiceClient
	Devices   DeviceClients
	Metrics   *metrics.Metrics
	Log       *slog.Logger
}

// Options are the engine's limits and models.
type Options struct {
	OpenAIModel         string
	XAIModel            string
	Workers             int
	TaskMaxSteps        int
	TaskTimeout         time.Duration
	ToolTimeout         time.Duration
	ConfirmationTTL     time.Duration
	TranscriptRetention time.Duration
	MaxVoiceTools       int
	// PollInterval is how often idle workers look for work another instance queued.
	PollInterval time.Duration
}

// Engine runs everything.
type Engine struct {
	Deps
	opts   Options
	owner  string
	broker broker
	wake   chan struct{}
}

// New creates an engine.
func New(deps Deps, opts Options) *Engine {
	if opts.PollInterval == 0 {
		opts.PollInterval = time.Second
	}
	return &Engine{Deps: deps, opts: opts, owner: uuid.NewString(), wake: make(chan struct{}, 1)}
}

// --- request ids ------------------------------------------------------------------

type requestIDKey struct{}

// WithRequestID attaches a request id (sent on to other services for audit).
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

func requestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// outgoing passes the request id to the service called.
func outgoing(ctx context.Context) context.Context {
	if id := requestID(ctx); id != "" {
		return metadata.AppendToOutgoingContext(ctx, "x-request-id", id)
	}
	return ctx
}

func mustUUID(s string) uuid.UUID {
	id, _ := uuid.Parse(s)
	return id
}

func (e *Engine) model(provider int32) string {
	if commonv1.Provider(provider) == commonv1.Provider_PROVIDER_XAI {
		return e.opts.XAIModel
	}
	return e.opts.OpenAIModel
}

// output renders a tool result for a model.
func output(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return `{"error":"internal error"}`
	}
	return string(data)
}

func failure(message string) (string, bool) { return output(map[string]string{"error": message}), true }

// --- events -------------------------------------------------------------------------

// broker wakes WatchConversation streams when their conversation gets an event.
type broker struct {
	mu   sync.Mutex
	subs map[uuid.UUID]map[chan struct{}]struct{}
}

func (b *broker) subscribe(id uuid.UUID) (chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	if b.subs == nil {
		b.subs = map[uuid.UUID]map[chan struct{}]struct{}{}
	}
	if b.subs[id] == nil {
		b.subs[id] = map[chan struct{}]struct{}{}
	}
	b.subs[id][ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs[id], ch)
		if len(b.subs[id]) == 0 {
			delete(b.subs, id)
		}
		b.mu.Unlock()
	}
}

func (b *broker) notify(id uuid.UUID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[id] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// emit queues an event for a conversation's user and reports whether a live
// conversation got it (so the user hears it now).
func (e *Engine) emit(ctx context.Context, conversation uuid.NullUUID, event *orchv1.ConversationEvent, confirmation uuid.NullUUID) bool {
	if !conversation.Valid {
		return false
	}
	event.CreateTime = timestamppb.Now()
	payload, err := proto.Marshal(event)
	target, live := conversation.UUID, false
	if err == nil {
		target, live, err = e.Store.AddEvent(context.WithoutCancel(ctx), conversation.UUID, payload, confirmation)
	}
	if err != nil {
		e.Log.Error("cannot queue event", "conversation_id", conversation.UUID, "error", err)
		return false
	}
	if target != conversation.UUID {
		e.Log.Info("event sent to the user's current conversation", "from", conversation.UUID, "conversation_id", target)
	}
	e.Metrics.Events.Inc()
	e.broker.notify(target)
	return live
}

// notificationsTopic is the broker key that wakes ClaimNotifications.
var notificationsTopic = uuid.Nil

// notify queues a push notification about a task for its user.
func (e *Engine) notify(ctx context.Context, t store.Task, kind string) {
	err := e.Store.AddNotification(context.WithoutCancel(ctx), store.Notification{TenantID: t.TenantID, UserID: t.UserID,
		Kind: kind, TaskID: t.ID, TaskState: t.State})
	if err != nil {
		e.Log.Error("cannot queue notification", "task_id", t.ID, "kind", kind, "error", err)
		return
	}
	e.Metrics.Notifications.WithLabelValues(kind).Inc()
	e.broker.notify(notificationsTopic)
}

// Notification limits: a claim lasts a minute; a notification is tried at
// most five times and never sent once it is an hour old.
const (
	notificationLease    = time.Minute
	notificationAttempts = 5
	notificationMaxAge   = time.Hour
)

// ClaimNotifications hands out pending notifications, waiting up to `wait`
// for new ones.
func (e *Engine) ClaimNotifications(ctx context.Context, consumer string, max int, wait time.Duration) ([]store.Notification, error) {
	wake, unsubscribe := e.broker.subscribe(notificationsTopic)
	defer unsubscribe()
	deadline := time.Now().Add(wait)
	for {
		claimed, err := e.Store.ClaimNotifications(ctx, consumer, max, notificationLease, notificationAttempts,
			notificationMaxAge)
		if err != nil || len(claimed) > 0 {
			return claimed, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil
		case <-wake:
		case <-time.After(min(remaining, 2*e.opts.PollInterval)): // other instances' notifications
		}
	}
}

// Watch sends a conversation's events after a cursor until the conversation
// closes (and its events are sent) or ctx ends.
func (e *Engine) Watch(ctx context.Context, conversation uuid.UUID, after int64, send func(*orchv1.ConversationEvent) error) error {
	cursor := after
	if cursor == 0 {
		var err error
		if cursor, err = e.Store.LastAcked(ctx, conversation); err != nil {
			return err
		}
	}
	wake, unsubscribe := e.broker.subscribe(conversation)
	defer unsubscribe()
	for {
		events, err := e.Store.Events(ctx, conversation, cursor, 100)
		if err != nil {
			return err
		}
		for _, ev := range events {
			event := &orchv1.ConversationEvent{}
			if err := proto.Unmarshal(ev.Payload, event); err != nil {
				return err
			}
			event.EventId = ev.ID
			if err := send(event); err != nil {
				return err
			}
			cursor = ev.ID
		}
		if len(events) == 100 {
			continue
		}
		conv, err := e.Store.Conversation(ctx, conversation)
		if err != nil {
			return err
		}
		if conv.ClosedAt != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
		case <-time.After(e.opts.PollInterval * 2):
		}
	}
}

// signal wakes idle task workers.
func (e *Engine) signal() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}
