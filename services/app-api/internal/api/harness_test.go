package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"jarvis.internal/app-api/internal/admin"
	"jarvis.internal/app-api/internal/api"
	"jarvis.internal/app-api/internal/metrics"
	"jarvis.internal/app-api/internal/ratelimit"
	"jarvis.internal/app-api/internal/store"
	appv1 "jarvis.internal/gen/go/jarvis/app/v1"
	"jarvis.internal/gen/go/jarvis/app/v1/appv1connect"
	auditv1 "jarvis.internal/gen/go/jarvis/audit/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	"jarvis.internal/libs/go/auditlog"
)

const (
	tokenIssuer = "https://id.jarvis.test"
	voiceURL    = "wss://voice.jarvis.test/v1/voice"
	publicURL   = "https://api.jarvis.test"
)

var db *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	container, err := postgres.Run(ctx, "postgres:18.6-alpine",
		postgres.WithDatabase("app"), postgres.WithUsername("app_api"), postgres.WithPassword("test"),
		postgres.BasicWaitStrategies())
	if err != nil {
		fmt.Fprintln(os.Stderr, "app API tests need Docker for PostgreSQL:", err)
		os.Exit(1)
	}
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err == nil {
		db, err = pgxpool.New(ctx, dsn)
	}
	if err == nil {
		if err = store.New(db).Migrate(ctx); err == nil {
			err = store.New(db).Migrate(ctx) // idempotent
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "database setup:", err)
		_ = container.Terminate(ctx)
		os.Exit(1)
	}
	code := m.Run()
	db.Close()
	_ = container.Terminate(ctx)
	os.Exit(code)
}

// fakeOrchestrator records who each call was made for.
type fakeOrchestrator struct {
	orchv1.UnimplementedOrchestratorServiceServer

	mu        sync.Mutex
	tasks     []*orchv1.Task
	owners    []string // "tenant/user" of each call
	approvals []*orchv1.SubmitDeviceApprovalRequest
	requestID []string
	// submitErr answers SubmitDeviceApproval when set.
	submitErr error
}

func (f *fakeOrchestrator) note(ctx context.Context, tenant, user string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owners = append(f.owners, tenant+"/"+user)
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		f.requestID = append(f.requestID, md.Get("x-request-id")...)
	}
}

func (f *fakeOrchestrator) ListTasks(ctx context.Context, req *orchv1.ListTasksRequest) (*orchv1.ListTasksResponse, error) {
	f.note(ctx, req.GetTenantId(), req.GetUserId())
	f.mu.Lock()
	defer f.mu.Unlock()
	return &orchv1.ListTasksResponse{Tasks: f.tasks}, nil
}

func (f *fakeOrchestrator) CancelTask(ctx context.Context, req *orchv1.CancelTaskRequest) (*orchv1.CancelTaskResponse, error) {
	f.note(ctx, req.GetTenantId(), req.GetUserId())
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tasks {
		if t.GetTaskId() == req.GetTaskId() {
			t.State = orchv1.TaskState_TASK_STATE_CANCELLED
			return &orchv1.CancelTaskResponse{Task: t}, nil
		}
	}
	return nil, errNotFound
}

func (f *fakeOrchestrator) SubmitDeviceApproval(ctx context.Context, req *orchv1.SubmitDeviceApprovalRequest) (*orchv1.SubmitDeviceApprovalResponse, error) {
	f.note(ctx, req.GetTenantId(), req.GetUserId())
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approvals = append(f.approvals, req)
	if f.submitErr != nil {
		return nil, f.submitErr
	}
	return &orchv1.SubmitDeviceApprovalResponse{Output: `{"exit_code":0}`}, nil
}

func (f *fakeOrchestrator) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.owners...)
}

type harness struct {
	client appv1connect.AppServiceClient
	server *httptest.Server
	admin  *admin.Service
	store  *store.Store
	orch   *fakeOrchestrator
	audit  *fakeAudit
	key    ed25519.PrivateKey
	tenant string
	user   string
}

type options struct {
	burst int
}

func newHarness(t *testing.T, opts ...func(*options)) *harness {
	t.Helper()
	o := options{burst: 50}
	for _, apply := range opts {
		apply(&o)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	minter, err := api.NewMinter(key, "test-key", tokenIssuer, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	orch := &fakeOrchestrator{}
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	orchv1.RegisterOrchestratorServiceServer(grpcServer, orch)
	go func() { _ = grpcServer.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///orchestrator",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New()
	st := store.New(db)
	audit := &fakeAudit{}
	recorder := auditlog.New(audit, log, auditlog.Options{FlushEvery: 10 * time.Millisecond})
	t.Cleanup(func() { recorder.Close(context.Background()) })
	service := &api.Service{Store: st, Minter: minter, Orchestrator: orchv1.NewOrchestratorServiceClient(conn),
		Metrics: m, Log: log, VoiceURL: voiceURL, RefreshTTL: 30 * 24 * time.Hour, Audit: recorder}
	path, handler := appv1connect.NewAppServiceHandler(service,
		connect.WithInterceptors(api.Logging(log, m), api.RateLimit(ratelimit.New(o.burst, 60), m, log),
			api.Auth(minter, st, log)),
		connect.WithRecover(api.Recover(log)))
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	jwks := minter.JWKS()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) })
	server := httptest.NewServer(mux)
	t.Cleanup(func() {
		server.Close()
		_ = conn.Close()
		grpcServer.Stop()
	})
	return &harness{audit: audit,
		client: appv1connect.NewAppServiceClient(server.Client(), server.URL),
		server: server,
		admin: &admin.Service{Store: st, Metrics: m, Log: log, PublicURL: publicURL,
			PairingTTL: 10 * time.Minute},
		store:  st,
		orch:   orch,
		key:    key,
		tenant: uuid.NewString(),
		user:   "user-" + uuid.NewString()[:8],
	}
}

func tctx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// code issues a pairing code through the admin service.
func (h *harness) code(t *testing.T) *appv1.CreatePairingCodeResponse {
	t.Helper()
	resp, err := h.admin.CreatePairingCode(tctx(t), &appv1.CreatePairingCodeRequest{TenantId: h.tenant, UserId: h.user})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// pair redeems a new code and returns the session.
func (h *harness) pair(t *testing.T) *appv1.Session {
	t.Helper()
	resp, err := h.client.RedeemPairingCode(tctx(t), connect.NewRequest(&appv1.RedeemPairingCodeRequest{
		Code: h.code(t).GetCode(), DeviceName: "Κώστα's iPhone", DeviceModel: "iPhone17,1"}))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg.GetSession()
}

func authed[T any](token string, msg *T) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer "+token)
	return req
}

// wantReason checks a Connect error's code and ErrorInfo reason.
func wantReason(t *testing.T, err error, code connect.Code, reason appv1.ErrorReason) {
	t.Helper()
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != code {
		t.Fatalf("error = %v, want %v", err, code)
	}
	if reason == appv1.ErrorReason_ERROR_REASON_UNSPECIFIED {
		return
	}
	for _, detail := range cerr.Details() {
		value, derr := detail.Value()
		if info, ok := value.(*errdetails.ErrorInfo); derr == nil && ok && info.GetReason() == reason.String() &&
			info.GetDomain() == api.ErrorDomain {
			return
		}
	}
	t.Fatalf("error %v lacks reason %v", err, reason)
}

// fakeAudit collects what the service records.
type fakeAudit struct {
	mu     sync.Mutex
	events []*auditv1.Event
}

func (f *fakeAudit) Record(_ context.Context, req *auditv1.RecordRequest, _ ...grpc.CallOption) (*auditv1.RecordResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, req.GetEvents()...)
	return &auditv1.RecordResponse{Recorded: int32(len(req.GetEvents()))}, nil
}

func (f *fakeAudit) ListEvents(context.Context, *auditv1.ListEventsRequest, ...grpc.CallOption) (*auditv1.ListEventsResponse, error) {
	return nil, errors.New("not used")
}

func (f *fakeAudit) VerifyChain(context.Context, *auditv1.VerifyChainRequest, ...grpc.CallOption) (*auditv1.VerifyChainResponse, error) {
	return nil, errors.New("not used")
}

// waitFor returns the recorded events with this action, waiting for at least n.
func (f *fakeAudit) waitFor(t *testing.T, action string, n int) []*auditv1.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		var found []*auditv1.Event
		for _, e := range f.events {
			if e.GetAction() == action {
				found = append(found, e)
			}
		}
		f.mu.Unlock()
		if len(found) >= n {
			return found
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %d %q audit events (got %d)", n, action, len(found))
		}
		time.Sleep(5 * time.Millisecond)
	}
}
