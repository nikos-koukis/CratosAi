package server_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	agentv1 "jarvis.internal/gen/go/jarvis/agent/v1"
	auditv1 "jarvis.internal/gen/go/jarvis/audit/v1"
	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	devicev1 "jarvis.internal/gen/go/jarvis/device/v1"
	knowledgev1 "jarvis.internal/gen/go/jarvis/knowledge/v1"
	mcpv1 "jarvis.internal/gen/go/jarvis/mcp/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	"jarvis.internal/libs/go/auditlog"
	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/orchestrator/internal/clients"
	"jarvis.internal/orchestrator/internal/engine"
	"jarvis.internal/orchestrator/internal/metrics"
	"jarvis.internal/orchestrator/internal/server"
	"jarvis.internal/orchestrator/internal/store"
)

var db *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	container, err := postgres.Run(ctx, "postgres:18.6-alpine",
		postgres.WithDatabase("orchestrator"), postgres.WithUsername("orchestrator"), postgres.WithPassword("test"),
		postgres.BasicWaitStrategies())
	if err != nil {
		fmt.Fprintln(os.Stderr, "orchestrator tests need Docker for PostgreSQL:", err)
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

// --- fakes ---------------------------------------------------------------------------

type fakeKeys struct {
	mu      sync.Mutex
	missing bool
	calls   int
}

func (k *fakeKeys) ProviderKey(_ context.Context, _, _ string, _ commonv1.Provider) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls++
	if k.missing {
		return nil, vaultclient.ErrNoKey
	}
	return []byte("sk-tenant-key"), nil
}

type fakeSealer struct{ aead cipher.AEAD }

func newSealer() *fakeSealer {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return &fakeSealer{aead: aead}
}

func aad(b vaultclient.Binding) []byte { return []byte(b.TenantID + "|" + b.Purpose + "|" + b.Subject) }

func (f *fakeSealer) Seal(_ context.Context, _ string, b vaultclient.Binding, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, f.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return f.aead.Seal(nonce, nonce, plaintext, aad(b)), nil
}

func (f *fakeSealer) Open(_ context.Context, _ string, b vaultclient.Binding, sealed []byte) ([]byte, error) {
	n := f.aead.NonceSize()
	return f.aead.Open(nil, sealed[:n], sealed[n:], aad(b))
}

// fakeMCP is the MCP router: scripted tools, recorded calls.
type fakeMCP struct {
	mcpv1.McpRouterServiceClient
	mu    sync.Mutex
	tools []*mcpv1.Tool
	calls []*mcpv1.CallToolRequest
}

func (f *fakeMCP) ListTools(context.Context, *mcpv1.ListToolsRequest, ...grpc.CallOption) (*mcpv1.ListToolsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &mcpv1.ListToolsResponse{Tools: f.tools}, nil
}

func (f *fakeMCP) CallTool(_ context.Context, in *mcpv1.CallToolRequest, _ ...grpc.CallOption) (*mcpv1.CallToolResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, in)
	return &mcpv1.CallToolResponse{Content: []*mcpv1.Content{{Content: &mcpv1.Content_Text{Text: &mcpv1.TextContent{
		Text: "done: " + in.GetToolName() + " " + in.GetArgumentsJson()}}}}}, nil
}

func (f *fakeMCP) called() []*mcpv1.CallToolRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*mcpv1.CallToolRequest(nil), f.calls...)
}

type fakeKnowledge struct {
	knowledgev1.KnowledgeServiceClient
	mu        sync.Mutex
	retrieves []*knowledgev1.RetrieveRequest
	upserts   []*knowledgev1.UpsertKnowledgeRequest
}

func (f *fakeKnowledge) Retrieve(_ context.Context, in *knowledgev1.RetrieveRequest, _ ...grpc.CallOption) (*knowledgev1.RetrieveResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retrieves = append(f.retrieves, in)
	return &knowledgev1.RetrieveResponse{Context: "Facts:\n- The Atlas demo is on Friday"}, nil
}

func (f *fakeKnowledge) UpsertKnowledge(_ context.Context, in *knowledgev1.UpsertKnowledgeRequest, _ ...grpc.CallOption) (*knowledgev1.UpsertKnowledgeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upserts = append(f.upserts, in)
	return &knowledgev1.UpsertKnowledgeResponse{Passages: int32(len(in.GetPassages()))}, nil
}

func (f *fakeKnowledge) upserted() []*knowledgev1.UpsertKnowledgeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*knowledgev1.UpsertKnowledgeRequest(nil), f.upserts...)
}

// fakeAgent answers Decide from a script: each call pops the next step.
type fakeAgent struct {
	agentv1.AgentWorkerServiceClient
	mu       sync.Mutex
	steps    []*agentv1.DecideResponse
	requests []*agentv1.DecideRequest
	extracts []*agentv1.ExtractKnowledgeRequest
	// The key buffers as passed in, to check they are wiped after use.
	keys [][]byte
}

func (f *fakeAgent) script(steps ...*agentv1.DecideResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.steps = append(f.steps, steps...)
}

func (f *fakeAgent) Decide(_ context.Context, in *agentv1.DecideRequest, _ ...grpc.CallOption) (*agentv1.DecideResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// The orchestrator clears the key after the call: keep a copy.
	recorded := proto.Clone(in).(*agentv1.DecideRequest)
	recorded.Model.ApiKey = append([]byte(nil), in.GetModel().GetApiKey()...)
	f.requests = append(f.requests, recorded)
	f.keys = append(f.keys, in.GetModel().GetApiKey())
	if len(f.steps) == 0 {
		return nil, status.Error(codes.Unavailable, "no scripted step")
	}
	step := f.steps[0]
	f.steps = f.steps[1:]
	return step, nil
}

func (f *fakeAgent) ExtractKnowledge(_ context.Context, in *agentv1.ExtractKnowledgeRequest, _ ...grpc.CallOption) (*agentv1.ExtractKnowledgeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.extracts = append(f.extracts, in)
	return &agentv1.ExtractKnowledgeResponse{
		Entities: []*knowledgev1.EntityInput{{Type: "Person", Name: "Μαρία"}},
		Passages: []*knowledgev1.PassageInput{{Text: "Το demo είναι την Παρασκευή."}},
	}, nil
}

func (f *fakeAgent) decisions() []*agentv1.DecideRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*agentv1.DecideRequest(nil), f.requests...)
}

func answer(text string) *agentv1.DecideResponse {
	return &agentv1.DecideResponse{Text: text, Step: &agentv1.ModelStep{ProviderItems: []byte(`[]`)}}
}

func callTools(calls ...*agentv1.ToolCall) *agentv1.DecideResponse {
	return &agentv1.DecideResponse{ToolCalls: calls, Step: &agentv1.ModelStep{ProviderItems: []byte(`[]`)}}
}

// fakeDevice runs allowlisted programs and asks approval for the rest.
type fakeDevice struct {
	devicev1.DeviceServiceClient
	mu       sync.Mutex
	commands []*devicev1.ExecuteCommandRequest
}

func (f *fakeDevice) ExecuteCommand(_ context.Context, in *devicev1.ExecuteCommandRequest, _ ...grpc.CallOption) (*devicev1.ExecuteCommandResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, in)
	if in.GetProgram() == "/usr/bin/git" || strings.HasPrefix(in.GetApproval().GetApprovalId(), "appr-") {
		if in.GetApproval() != nil && in.GetApproval().GetApproverId() != "my-iphone" {
			return nil, status.Error(codes.PermissionDenied, "the approval signature is invalid")
		}
		return &devicev1.ExecuteCommandResponse{Outcome: &devicev1.ExecuteCommandResponse_Result{Result: &devicev1.CommandResult{
			ExitCode: 0, Stdout: []byte("ran " + in.GetProgram())}}}, nil
	}
	return &devicev1.ExecuteCommandResponse{Outcome: &devicev1.ExecuteCommandResponse_ApprovalRequired{
		// Approval ids are global (a primary key): unique per request, as on a real device.
		ApprovalRequired: &devicev1.ApprovalRequired{ApprovalId: "appr-" + uuid.NewString(), Payload: []byte("payload")}}}, nil
}

type fakeDevices struct{ device *fakeDevice }

func (f *fakeDevices) Client(context.Context, string, store.Device) (devicev1.DeviceServiceClient, error) {
	return f.device, nil
}
func (f *fakeDevices) Forget(uuid.UUID) {}

// --- harness ---------------------------------------------------------------------------

type harness struct {
	client    orchv1.OrchestratorServiceClient
	lastCall  string // call id of the last h.call
	store     *store.Store
	keys      *fakeKeys
	mcp       *fakeMCP
	knowledge *fakeKnowledge
	agent     *fakeAgent
	device    *fakeDevice
	metrics   *metrics.Metrics
	audit     *fakeAudit
	tenant    string
	user      string
}

// fakeAudit collects what the engine records.
type fakeAudit struct {
	mu     sync.Mutex
	events []*auditv1.Event
}

func (f *fakeAudit) Record(_ context.Context, req *auditv1.RecordRequest, _ ...grpc.CallOption) (*auditv1.RecordResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, req.GetEvents()...)
	return &auditv1.RecordResponse{}, nil
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

// mentions reports whether any recorded event's details contain text.
func (f *fakeAudit) mentions(text string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.events {
		for _, v := range e.GetDetails() {
			if strings.Contains(v, text) {
				return true
			}
		}
	}
	return false
}

type options struct {
	confirmationTTL time.Duration
	maxSteps        int
}

func newHarness(t *testing.T, opts ...func(*options)) *harness {
	t.Helper()
	o := options{confirmationTTL: time.Minute, maxSteps: 5}
	for _, f := range opts {
		f(&o)
	}
	h := &harness{
		store: store.New(db), keys: &fakeKeys{}, knowledge: &fakeKnowledge{}, agent: &fakeAgent{},
		device: &fakeDevice{}, metrics: metrics.New(), tenant: uuid.NewString(), user: "user-" + uuid.NewString()[:8],
		mcp: &fakeMCP{tools: []*mcpv1.Tool{
			{IntegrationId: uuid.NewString(), IntegrationName: "Work Jira", Name: "create_issue", Title: "Create issue",
				Description: "Creates an issue", InputSchemaJson: `{"type":"object","properties":{"title":{"type":"string"}}}`,
				Annotations: &mcpv1.ToolAnnotations{Destructive: true}},
			{IntegrationId: uuid.NewString(), IntegrationName: "Work Jira", Name: "search", Title: "Search",
				Description: "Searches issues", InputSchemaJson: `{"type":"object"}`,
				Annotations: &mcpv1.ToolAnnotations{ReadOnly: true}},
		}},
	}
	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))
	devices := &fakeDevices{device: h.device}
	h.audit = &fakeAudit{}
	recorder := auditlog.New(h.audit, logger, auditlog.Options{FlushEvery: 10 * time.Millisecond})
	t.Cleanup(func() { recorder.Close(context.Background()) })
	eng := engine.New(engine.Deps{Store: h.store, Keys: h.keys, Sealer: newSealer(), MCP: h.mcp, Knowledge: h.knowledge,
		Agent: h.agent, Devices: devices, Metrics: h.metrics, Log: logger, Audit: recorder}, engine.Options{
		OpenAIModel: "gpt-6-luna", XAIModel: "grok-4.6", Workers: 2, TaskMaxSteps: o.maxSteps, TaskTimeout: time.Minute,
		ToolTimeout: 5 * time.Second, ConfirmationTTL: o.confirmationTTL, TranscriptRetention: time.Hour,
		MaxVoiceTools: 40, PollInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { eng.Run(ctx) })

	svc := &server.Service{Engine: eng, Store: h.store, Sealer: newSealer(), Guard: clients.DeviceGuard{AllowLoopback: true},
		Devices: devices, Log: logger}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(server.UnaryInterceptor(logger, h.metrics)),
		grpc.StreamInterceptor(server.StreamInterceptor(logger, h.metrics)))
	orchv1.RegisterOrchestratorServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		cancel()
		wg.Wait()
	})
	h.client = orchv1.NewOrchestratorServiceClient(conn)
	return h
}

func tctx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func (h *harness) open(t *testing.T) *orchv1.OpenConversationResponse {
	t.Helper()
	resp, err := h.client.OpenConversation(tctx(t), &orchv1.OpenConversationRequest{TenantId: h.tenant, UserId: h.user,
		SessionId: "session-1", Provider: commonv1.Provider_PROVIDER_OPENAI, Locale: "el-GR"})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

var calls int

func (h *harness) call(t *testing.T, conversation, name, args string, turn int64) *orchv1.CallToolResponse {
	t.Helper()
	calls++
	h.lastCall = fmt.Sprintf("call-%d", calls)
	resp, err := h.client.CallTool(tctx(t), &orchv1.CallToolRequest{ConversationId: conversation,
		CallId: h.lastCall, Name: name, ArgumentsJson: args, UserTurn: turn})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// ack reports that the output of a call reached the user at turn.
func (h *harness) ack(t *testing.T, conversation, callID string, turn int64) {
	t.Helper()
	if _, err := h.client.AckToolOutput(tctx(t), &orchv1.AckToolOutputRequest{ConversationId: conversation,
		CallId: callID, UserTurn: turn}); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) turn(t *testing.T, conversation string, turn int64, text string) {
	t.Helper()
	if _, err := h.client.RecordTurn(tctx(t), &orchv1.RecordTurnRequest{ConversationId: conversation,
		Role: orchv1.Role_ROLE_USER, UserTurn: turn, ItemId: fmt.Sprintf("item-%d", turn), Text: text}); err != nil {
		t.Fatal(err)
	}
}

// events collects a conversation's events until n arrived.
func (h *harness) events(t *testing.T, conversation string, n int) []*orchv1.ConversationEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := h.client.WatchConversation(ctx, &orchv1.WatchConversationRequest{ConversationId: conversation})
	if err != nil {
		t.Fatal(err)
	}
	var out []*orchv1.ConversationEvent
	for len(out) < n {
		resp, err := stream.Recv()
		if err == io.EOF || err != nil {
			t.Fatalf("after %d events: %v", len(out), err)
		}
		out = append(out, resp.GetEvent())
	}
	return out
}

// waitTask polls until a task reaches one of the states.
func (h *harness) waitTask(t *testing.T, id string, states ...orchv1.TaskState) *orchv1.Task {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := h.client.GetTask(tctx(t), &orchv1.GetTaskRequest{TenantId: h.tenant, UserId: h.user, TaskId: id})
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range states {
			if resp.GetTask().GetState() == s {
				return resp.GetTask()
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("task %s stuck in %v (want %v): %s", id, resp.GetTask().GetState(), states, resp.GetTask().GetResult())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// deviceIdentity makes a CA and a client certificate like a device issues.
func deviceIdentity(t *testing.T) (caPEM, certPEM, keyPEM string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "device CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "orchestrator"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}
