// Package auditlog records audit events at the audit service (AuditService
// over gRPC with mutual TLS) without slowing the caller down.
//
// Record never blocks: events wait in a bounded in-memory queue, a
// background loop sends them in batches, and a failed batch is retried with
// backoff (the service ignores events it already has, by event id). When the
// queue is full, or the process stops before its events are sent, the event
// is written to the log instead (message "audit event not delivered"), so it
// is not lost silently. A nil *Recorder records nothing, for services run
// without an audit service.
package auditlog

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "jarvis.internal/gen/go/jarvis/audit/v1"
	"jarvis.internal/libs/go/mtls"
)

// Actor is who performed an action.
type Actor struct {
	Kind auditv1.ActorKind
	ID   string
}

// User is a person, by their user id.
func User(id string) Actor { return Actor{Kind: auditv1.ActorKind_ACTOR_KIND_USER, ID: id} }

// Assistant is Jarvis acting for a user (set Event.OnBehalfOf).
func Assistant() Actor { return Actor{Kind: auditv1.ActorKind_ACTOR_KIND_ASSISTANT, ID: "jarvis"} }

// Device is a paired phone or a computer's daemon.
func Device(id string) Actor { return Actor{Kind: auditv1.ActorKind_ACTOR_KIND_DEVICE, ID: id} }

// Service is a service acting on its own.
func Service(name string) Actor { return Actor{Kind: auditv1.ActorKind_ACTOR_KIND_SERVICE, ID: name} }

// Outcomes.
const (
	Success = auditv1.Outcome_OUTCOME_SUCCESS
	Failure = auditv1.Outcome_OUTCOME_FAILURE
	Denied  = auditv1.Outcome_OUTCOME_DENIED
)

// Event is one audited action. Never put secrets (keys, tokens, codes,
// message contents) in it.
type Event struct {
	TenantID   string
	Actor      Actor
	OnBehalfOf string
	Action     string // e.g. "tool.called"
	TargetType string
	TargetID   string
	Outcome    auditv1.Outcome
	Reason     string
	RequestID  string
	Details    map[string]string
	// When it happened; now if zero.
	OccurTime time.Time
}

// Options tune a Recorder; zero values take the defaults.
type Options struct {
	QueueSize  int           // events waiting to be sent (default 10000)
	BatchSize  int           // events per Record call (default 200, at most 500)
	FlushEvery time.Duration // how long an event may wait for a batch (default 500ms)
	MaxBackoff time.Duration // between retries (default 30s)
	Timeout    time.Duration // per Record call (default 10s)
}

// Recorder delivers events in the background. Close it to flush.
type Recorder struct {
	client  auditv1.AuditServiceClient
	log     *slog.Logger
	opts    Options
	queue   chan *auditv1.Event
	stop    chan struct{}
	done    chan struct{}
	closing sync.Once
	closed  atomic.Bool
	dropped atomic.Int64
}

// New starts a Recorder that sends through client.
func New(client auditv1.AuditServiceClient, log *slog.Logger, opts Options) *Recorder {
	if opts.QueueSize <= 0 {
		opts.QueueSize = 10000
	}
	if opts.BatchSize <= 0 || opts.BatchSize > 500 {
		opts.BatchSize = 200
	}
	if opts.FlushEvery <= 0 {
		opts.FlushEvery = 500 * time.Millisecond
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = 30 * time.Second
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	r := &Recorder{client: client, log: log, opts: opts, queue: make(chan *auditv1.Event, opts.QueueSize),
		stop: make(chan struct{}), done: make(chan struct{})}
	go r.loop()
	return r
}

// Dial connects to the audit service at addr with this service's client
// certificate, and starts a Recorder. close flushes and disconnects.
func Dial(addr, certFile, keyFile, caFile, serverName string, log *slog.Logger) (*Recorder, func(context.Context), error) {
	tlsConfig, err := mtls.ClientConfig(certFile, keyFile, caFile, serverName)
	if err != nil {
		return nil, nil, err
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, nil, err
	}
	r := New(auditv1.NewAuditServiceClient(conn), log, Options{})
	return r, func(ctx context.Context) {
		r.Close(ctx)
		_ = conn.Close()
	}, nil
}

// Record queues an event; it never blocks.
func (r *Recorder) Record(e Event) {
	if r == nil {
		return
	}
	occur := e.OccurTime
	if occur.IsZero() {
		occur = time.Now()
	}
	event := &auditv1.Event{
		EventId:    uuid.Must(uuid.NewV7()).String(),
		TenantId:   e.TenantID,
		OccurTime:  timestamppb.New(occur),
		Actor:      &auditv1.Actor{Kind: e.Actor.Kind, Id: e.Actor.ID},
		OnBehalfOf: e.OnBehalfOf,
		Action:     e.Action,
		TargetType: e.TargetType,
		TargetId:   e.TargetID,
		Outcome:    e.Outcome,
		Reason:     e.Reason,
		RequestId:  e.RequestID,
		Details:    e.Details,
	}
	if r.closed.Load() {
		r.dropped.Add(1)
		r.undelivered(event, "recorded after the recorder was closed")
		return
	}
	select {
	case r.queue <- event:
	default:
		r.dropped.Add(1)
		r.undelivered(event, "the audit queue is full")
	}
}

// Dropped is how many events were not delivered (queue full, refused, or
// still waiting at Close).
func (r *Recorder) Dropped() int64 {
	if r == nil {
		return 0
	}
	return r.dropped.Load()
}

// Close stops accepting events and sends what is queued, until ctx ends;
// whatever is left is logged.
func (r *Recorder) Close(ctx context.Context) {
	if r == nil {
		return
	}
	r.closing.Do(func() {
		r.closed.Store(true)
		close(r.stop)
	})
	select {
	case <-r.done:
	case <-ctx.Done():
	}
}

// undelivered writes an event to the log, the last resort for its record.
func (r *Recorder) undelivered(e *auditv1.Event, why string) {
	r.log.Warn("audit event not delivered", "why", why, "event_id", e.GetEventId(), "tenant_id", e.GetTenantId(),
		"action", e.GetAction(), "actor_kind", e.GetActor().GetKind().String(), "actor_id", e.GetActor().GetId(),
		"on_behalf_of", e.GetOnBehalfOf(), "target_type", e.GetTargetType(), "target_id", e.GetTargetId(),
		"outcome", e.GetOutcome().String(), "reason", e.GetReason(), "occur_time", e.GetOccurTime().AsTime(),
		"details", e.GetDetails())
}

func (r *Recorder) loop() {
	defer close(r.done)
	ticker := time.NewTicker(r.opts.FlushEvery)
	defer ticker.Stop()
	var batch []*auditv1.Event
	backoff := time.Second
	stopping := false
	for {
		full := len(batch) >= r.opts.BatchSize
		if !full && !stopping {
			select {
			case e := <-r.queue:
				batch = append(batch, e)
				continue
			case <-ticker.C:
			case <-r.stop:
				stopping = true
			}
		}
		if stopping {
			// Take everything still queued.
			for drained := false; !drained && len(batch) < r.opts.BatchSize; {
				select {
				case e := <-r.queue:
					batch = append(batch, e)
				default:
					drained = true
				}
			}
		}
		if len(batch) == 0 {
			if stopping {
				return
			}
			continue
		}
		n := min(len(batch), r.opts.BatchSize)
		if err := r.send(batch[:n]); err != nil {
			if stopping {
				for _, e := range batch {
					r.dropped.Add(1)
					r.undelivered(e, "the audit service was unreachable at shutdown")
				}
				for {
					select {
					case e := <-r.queue:
						r.dropped.Add(1)
						r.undelivered(e, "the audit service was unreachable at shutdown")
					default:
						return
					}
				}
			}
			r.log.Warn("cannot record audit events; retrying", "error", err, "events", n,
				"backoff_ms", backoff.Milliseconds())
			select {
			case <-time.After(backoff):
			case <-r.stop:
				stopping = true
			}
			backoff = min(2*backoff, r.opts.MaxBackoff)
			continue
		}
		backoff = time.Second
		batch = batch[n:]
	}
}

// send records a batch. A batch the service refuses as malformed is sent
// again one event at a time, so one bad event does not lose the others.
func (r *Recorder) send(batch []*auditv1.Event) error {
	err := r.call(batch)
	if status.Code(err) != codes.InvalidArgument {
		return err
	}
	for _, e := range batch {
		switch err := r.call([]*auditv1.Event{e}); status.Code(err) {
		case codes.OK:
		case codes.InvalidArgument:
			r.dropped.Add(1)
			r.log.Error("the audit service refused an event (a bug in this service)", "error", err)
			r.undelivered(e, "refused as malformed")
		default:
			return err // retried later, as a batch (the good ones are not recorded twice)
		}
	}
	return nil
}

func (r *Recorder) call(events []*auditv1.Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.opts.Timeout)
	defer cancel()
	_, err := r.client.Record(ctx, &auditv1.RecordRequest{Events: events})
	return err
}
