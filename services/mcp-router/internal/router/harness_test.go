package router_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	mcpv1 "jarvis.internal/gen/go/jarvis/mcp/v1"
	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/mcp-router/internal/catalog"
	"jarvis.internal/mcp-router/internal/limits"
	"jarvis.internal/mcp-router/internal/mcptest"
	"jarvis.internal/mcp-router/internal/metrics"
	"jarvis.internal/mcp-router/internal/netguard"
	"jarvis.internal/mcp-router/internal/oauthflow"
	"jarvis.internal/mcp-router/internal/router"
	"jarvis.internal/mcp-router/internal/store"
	"jarvis.internal/mcp-router/internal/upstream"

	"google.golang.org/grpc"
	auditv1 "jarvis.internal/gen/go/jarvis/audit/v1"
	"jarvis.internal/libs/go/auditlog"
)

const redirectURI = "http://127.0.0.1:9/callback"

var db *pgxpool.Pool

// TestMain starts one PostgreSQL for the package; tests isolate themselves
// with fresh tenants and servers.
func TestMain(m *testing.M) {
	ctx := context.Background()
	container, err := postgres.Run(ctx, "postgres:18.6-alpine",
		postgres.WithDatabase("mcp"), postgres.WithUsername("mcp_router"), postgres.WithPassword("test"),
		postgres.BasicWaitStrategies())
	if err != nil {
		fmt.Fprintln(os.Stderr, "router tests need Docker for PostgreSQL:", err)
		os.Exit(1)
	}
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err == nil {
		db, err = pgxpool.New(ctx, dsn)
	}
	if err == nil {
		// Twice: migrations must be idempotent.
		if err = store.New(db).Migrate(ctx); err == nil {
			err = store.New(db).Migrate(ctx)
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

type harnessOptions struct {
	guard          netguard.Guard
	allowCustom    bool
	perIntegration int
	clients        map[string]catalog.ClientCredentials
}

type harness struct {
	svc    *router.Service
	env    *mcptest.Env
	store  *store.Store
	redis  *miniredis.Miniredis
	sealer *fakeSealer
	pool   *upstream.Pool
	tenant string
	user   string
	audit  *fakeAudit
}

// fakeAudit collects what the router records.
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

func (f *fakeAudit) all() []*auditv1.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*auditv1.Event(nil), f.events...)
}

func newHarness(t *testing.T, configure ...func(*harnessOptions)) *harness {
	t.Helper()
	opts := harnessOptions{guard: netguard.Guard{AllowLoopback: true}, allowCustom: true, perIntegration: 1000}
	for _, c := range configure {
		c(&opts)
	}

	handler := &swappable{}
	srv := httptest.NewUnstartedServer(handler)
	env, h := mcptest.NewEnv("http://" + srv.Listener.Addr().String())
	handler.h = h
	srv.Start()
	t.Cleanup(srv.Close)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), Protocol: 2, MaxRetries: -1, DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })
	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))
	st := store.New(db)
	sealer := newFakeSealer()
	cat := catalog.New(opts.clients)
	lim := limits.New(rdb, 1000, opts.perIntegration, time.Minute, logger)
	pool := upstream.NewPool(opts.guard.StreamingClient(), "test", time.Minute)
	t.Cleanup(pool.Close)
	audit := &fakeAudit{}
	recorder := auditlog.New(audit, logger, auditlog.Options{FlushEvery: 10 * time.Millisecond})
	t.Cleanup(func() { recorder.Close(context.Background()) })
	svc := router.New(router.Deps{
		Store: st,
		Flow: &oauthflow.Flow{
			Store: st, Sealer: sealer, Catalog: cat, HTTP: opts.guard.Client(10 * time.Second), Guard: opts.guard,
			RedirectURI: redirectURI, ClientName: "Jarvis test", Log: logger,
		},
		Catalog: cat, Pool: pool, Limits: lim, Guard: opts.guard, Metrics: metrics.New(), Log: logger, Audit: recorder,
	}, router.Options{
		AllowCustomServers: opts.allowCustom,
		DefaultCallTimeout: 5 * time.Second,
		MaxCallTimeout:     10 * time.Second,
	})
	return &harness{
		svc: svc, env: env, store: st, redis: mr, sealer: sealer, pool: pool, audit: audit,
		tenant: uuid.NewString(), user: "user-" + uuid.NewString()[:8],
	}
}

type swappable struct{ h http.Handler }

func (s *swappable) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.h.ServeHTTP(w, r) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(router.WithRequestID(context.Background(), "test-"+t.Name()), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

// connect creates an OAuth integration to the fake server and completes the
// user's (automatic) consent.
func (h *harness) connect(t *testing.T) *mcpv1.Integration {
	t.Helper()
	created, err := h.svc.CreateIntegration(ctx(t), &mcpv1.CreateIntegrationRequest{
		TenantId: h.tenant, UserId: h.user, DisplayName: "Tracker",
		Server: &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: h.env.MCPURL},
	})
	if err != nil {
		t.Fatalf("CreateIntegration: %v", err)
	}
	if got := created.GetIntegration().GetStatus(); got != mcpv1.IntegrationStatus_INTEGRATION_STATUS_PENDING_AUTHORIZATION {
		t.Fatalf("status after create = %v", got)
	}
	done, err := h.complete(t, created.GetAuthorizationUrl())
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	return done.GetIntegration()
}

// consent visits the authorization URL like a browser and returns the query
// of the redirect back to Jarvis.
func consent(t *testing.T, authURL string) url.Values {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", resp.StatusCode)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Scheme + "://" + location.Host + location.Path; got != redirectURI {
		t.Fatalf("redirected to %s", got)
	}
	return location.Query()
}

func (h *harness) complete(t *testing.T, authURL string) (*mcpv1.CompleteAuthorizationResponse, error) {
	t.Helper()
	q := consent(t, authURL)
	return h.svc.CompleteAuthorization(ctx(t), &mcpv1.CompleteAuthorizationRequest{
		State: q.Get("state"), Code: q.Get("code"), Iss: q.Get("iss"), Error: q.Get("error"),
	})
}

func (h *harness) call(t *testing.T, integrationID, tool, args string) (*mcpv1.CallToolResponse, error) {
	t.Helper()
	return h.svc.CallTool(ctx(t), &mcpv1.CallToolRequest{
		TenantId: h.tenant, UserId: h.user, IntegrationId: integrationID, ToolName: tool, ArgumentsJson: args,
	})
}

func (h *harness) integration(t *testing.T, id string) *mcpv1.Integration {
	t.Helper()
	resp, err := h.svc.ListIntegrations(ctx(t), &mcpv1.ListIntegrationsRequest{TenantId: h.tenant, UserId: h.user})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range resp.GetIntegrations() {
		if i.GetIntegrationId() == id {
			return i
		}
	}
	t.Fatalf("integration %s not listed", id)
	return nil
}

func wantStatus(t *testing.T, err error, code codes.Code, reason mcpv1.ErrorReason) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("error = %v, want code %v", err, code)
	}
	if reason == mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED {
		return
	}
	for _, detail := range status.Convert(err).Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok {
			if info.GetDomain() != router.ErrorDomain || info.GetReason() != reason.String() {
				t.Fatalf("ErrorInfo = %s/%s, want %s/%s", info.GetDomain(), info.GetReason(), router.ErrorDomain, reason)
			}
			return
		}
	}
	t.Fatalf("error %v has no ErrorInfo (want %v)", err, reason)
}

// fakeSealer is the Vault's SealData/OpenData: AES-GCM bound to the binding.
type fakeSealer struct {
	aead cipher.AEAD

	mu   sync.Mutex
	down bool
}

func newFakeSealer() *fakeSealer {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return &fakeSealer{aead: aead}
}

func (f *fakeSealer) setDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

func (f *fakeSealer) unavailable() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return status.Error(codes.Unavailable, "connection refused")
	}
	return nil
}

func aad(b vaultclient.Binding) []byte {
	return []byte(b.TenantID + "\x00" + b.Purpose + "\x00" + b.Subject)
}

func (f *fakeSealer) Seal(_ context.Context, _ string, b vaultclient.Binding, plaintext []byte) ([]byte, error) {
	if err := f.unavailable(); err != nil {
		return nil, fmt.Errorf("vault SealData: %w", err)
	}
	nonce := make([]byte, f.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return f.aead.Seal(nonce, nonce, plaintext, aad(b)), nil
}

func (f *fakeSealer) Open(_ context.Context, _ string, b vaultclient.Binding, sealed []byte) ([]byte, error) {
	if err := f.unavailable(); err != nil {
		return nil, fmt.Errorf("vault OpenData: %w", err)
	}
	n := f.aead.NonceSize()
	if len(sealed) < n {
		return nil, vaultclient.ErrSealedDataInvalid
	}
	plaintext, err := f.aead.Open(nil, sealed[:n], sealed[n:], aad(b))
	if err != nil {
		return nil, vaultclient.ErrSealedDataInvalid
	}
	return plaintext, nil
}
