package auditlog

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	auditv1 "jarvis.internal/gen/go/jarvis/audit/v1"
)

// fakeAudit stores events by id, like the real service (idempotent).
type fakeAudit struct {
	auditv1.UnimplementedAuditServiceServer
	mu       sync.Mutex
	events   map[string]*auditv1.Event
	calls    int
	failNext int           // this many calls fail with UNAVAILABLE
	hold     chan struct{} // when set, calls wait for it to close
}

func (f *fakeAudit) Record(_ context.Context, req *auditv1.RecordRequest) (*auditv1.RecordResponse, error) {
	f.mu.Lock()
	hold := f.hold
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failNext > 0 {
		f.failNext--
		return nil, status.Error(codes.Unavailable, "down")
	}
	for _, e := range req.GetEvents() {
		if e.GetAction() == "bad" {
			return nil, status.Error(codes.InvalidArgument, "event: action is malformed")
		}
	}
	for _, e := range req.GetEvents() {
		f.events[e.GetEventId()] = e
	}
	return &auditv1.RecordResponse{Recorded: int32(len(req.GetEvents()))}, nil
}

func (f *fakeAudit) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

func start(t *testing.T, fake *fakeAudit, opts Options) (*Recorder, *bytes.Buffer) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	auditv1.RegisterAuditServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///audit", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	logs := &bytes.Buffer{}
	var mu sync.Mutex
	log := slog.New(slog.NewTextHandler(lockedWriter{&mu, logs}, nil))
	if opts.FlushEvery == 0 {
		opts.FlushEvery = 20 * time.Millisecond
	}
	return New(auditv1.NewAuditServiceClient(conn), log, opts), logs
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func sample(action string) Event {
	return Event{TenantID: "0199e2e0-0000-7000-8000-000000000001", Actor: User("ana"), Action: action,
		Outcome: Success, Details: map[string]string{"provider": "openai"}}
}

func TestEventsAreSentInBatchesWithIdsAndTimes(t *testing.T) {
	fake := &fakeAudit{events: map[string]*auditv1.Event{}}
	r, _ := start(t, fake, Options{BatchSize: 10})
	before := time.Now()
	for range 25 {
		r.Record(sample("key.read"))
	}
	eventually(t, "25 events", func() bool { return fake.count() == 25 })
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.calls > 5 {
		t.Fatalf("%d calls for 25 events in batches of 10", fake.calls)
	}
	for id, e := range fake.events {
		if len(id) != 36 || e.GetOccurTime().AsTime().Before(before.Add(-time.Second)) ||
			e.GetActor().GetKind() != auditv1.ActorKind_ACTOR_KIND_USER || e.GetDetails()["provider"] != "openai" {
			t.Fatalf("event %+v", e)
		}
	}
}

func TestFailedBatchesAreRetriedUntilTheServiceIsBack(t *testing.T) {
	fake := &fakeAudit{events: map[string]*auditv1.Event{}, failNext: 2}
	r, logs := start(t, fake, Options{MaxBackoff: 50 * time.Millisecond})
	for range 3 {
		r.Record(sample("tool.called"))
	}
	eventually(t, "delivery after the outage", func() bool { return fake.count() == 3 })
	if r.Dropped() != 0 || !strings.Contains(logs.String(), "retrying") {
		t.Fatalf("dropped %d, logs %s", r.Dropped(), logs)
	}
}

func TestOneMalformedEventDoesNotLoseTheOthers(t *testing.T) {
	fake := &fakeAudit{events: map[string]*auditv1.Event{}}
	r, logs := start(t, fake, Options{BatchSize: 50})
	r.Record(sample("key.read"))
	r.Record(sample("bad"))
	r.Record(sample("key.revoked"))
	eventually(t, "the good events", func() bool { return fake.count() == 2 })
	eventually(t, "the bad one logged", func() bool { return r.Dropped() == 1 })
	if !strings.Contains(logs.String(), "audit event not delivered") || !strings.Contains(logs.String(), "action=bad") {
		t.Fatalf("logs: %s", logs)
	}
}

func TestAFullQueueLogsInsteadOfBlocking(t *testing.T) {
	hold := make(chan struct{})
	fake := &fakeAudit{events: map[string]*auditv1.Event{}, hold: hold}
	r, logs := start(t, fake, Options{QueueSize: 2, BatchSize: 1})
	done := make(chan struct{})
	go func() {
		for range 20 {
			r.Record(sample("tool.called"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked")
	}
	close(hold)
	if r.Dropped() == 0 || !strings.Contains(logs.String(), "the audit queue is full") {
		t.Fatalf("dropped %d, logs %s", r.Dropped(), logs)
	}
	eventually(t, "the queued events", func() bool { return int64(fake.count())+r.Dropped() == 20 })
}

func TestCloseFlushesAndLogsWhatCannotBeSent(t *testing.T) {
	fake := &fakeAudit{events: map[string]*auditv1.Event{}}
	r, _ := start(t, fake, Options{FlushEvery: time.Hour})
	for range 5 {
		r.Record(sample("key.read"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.Close(ctx)
	if fake.count() != 5 {
		t.Fatalf("flushed %d of 5", fake.count())
	}
	r.Record(sample("after.close")) // too late: logged, not sent
	if fake.count() != 5 || r.Dropped() != 1 {
		t.Fatalf("after Close: recorded %d, dropped %d", fake.count(), r.Dropped())
	}

	down := &fakeAudit{events: map[string]*auditv1.Event{}, failNext: 1000}
	r2, logs := start(t, down, Options{FlushEvery: time.Hour, MaxBackoff: 10 * time.Millisecond})
	r2.Record(sample("key.revoked"))
	r2.Close(ctx)
	if r2.Dropped() != 1 || !strings.Contains(logs.String(), "unreachable at shutdown") {
		t.Fatalf("dropped %d, logs %s", r2.Dropped(), logs)
	}
}

func TestANilRecorderRecordsNothing(t *testing.T) {
	var r *Recorder
	r.Record(sample("key.read"))
	r.Close(context.Background())
	if r.Dropped() != 0 {
		t.Fatal("nil recorder")
	}
}
