package router_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	mcpv1 "jarvis.internal/gen/go/jarvis/mcp/v1"
	"jarvis.internal/mcp-router/internal/catalog"
	"jarvis.internal/mcp-router/internal/mcptest"
	"jarvis.internal/mcp-router/internal/netguard"
)

func TestConnectListAndCallTools(t *testing.T) {
	h := newHarness(t)
	created, err := h.svc.CreateIntegration(ctx(t), &mcpv1.CreateIntegrationRequest{
		TenantId: h.tenant, UserId: h.user,
		Server: &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: h.env.MCPURL},
	})
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := url.Parse(created.GetAuthorizationUrl())
	if err != nil {
		t.Fatal(err)
	}
	q := authURL.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("resource") != h.env.MCPURL ||
		q.Get("redirect_uri") != redirectURI || len(q.Get("state")) < 40 || q.Get("scope") != strings.Join(mcptest.Scopes, " ") {
		t.Fatalf("authorization URL lacks PKCE, resource, state or scopes: %s", authURL)
	}
	if got := created.GetIntegration().GetDisplayName(); got != "127.0.0.1" {
		t.Errorf("default display name = %q", got)
	}

	done, err := h.complete(t, created.GetAuthorizationUrl())
	if err != nil {
		t.Fatal(err)
	}
	integration := done.GetIntegration()
	if integration.GetStatus() != mcpv1.IntegrationStatus_INTEGRATION_STATUS_CONNECTED || integration.GetAuth() != mcpv1.AuthKind_AUTH_KIND_OAUTH {
		t.Fatalf("after consent: %v", integration)
	}

	// Tokens are stored only sealed.
	var sealed []byte
	if err := db.QueryRow(ctx(t), `SELECT credentials_sealed FROM integrations WHERE id = $1`, integration.GetIntegrationId()).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if len(sealed) == 0 || bytes.Contains(sealed, []byte("access_token")) || bytes.Contains(sealed, []byte("refresh_token")) {
		t.Fatal("credentials are not sealed")
	}

	tools, err := h.svc.ListTools(ctx(t), &mcpv1.ListToolsRequest{TenantId: h.tenant, UserId: h.user})
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.GetUnavailable()) != 0 {
		t.Fatalf("unavailable: %v", tools.GetUnavailable())
	}
	byName := map[string]*mcpv1.Tool{}
	for _, tool := range tools.GetTools() {
		byName[tool.GetName()] = tool
	}
	for _, name := range []string{"echo", "create_issue", "fail", "slow", "big"} {
		if byName[name] == nil {
			t.Fatalf("tool %s missing from %v", name, tools.GetTools())
		}
	}
	echo := byName["echo"]
	if echo.GetTitle() != "Echo" || echo.GetIntegrationName() != "127.0.0.1" || echo.GetIntegrationId() != integration.GetIntegrationId() ||
		!strings.Contains(echo.GetInputSchemaJson(), `"text"`) {
		t.Errorf("echo = %v", echo)
	}
	if a := echo.GetAnnotations(); !a.GetReadOnly() || a.GetOpenWorld() {
		t.Errorf("echo annotations = %v", a)
	}
	if a := byName["create_issue"].GetAnnotations(); a.GetDestructive() || !a.GetOpenWorld() || a.GetReadOnly() {
		t.Errorf("create_issue annotations = %v", a)
	}
	if a := byName["fail"].GetAnnotations(); !a.GetDestructive() || !a.GetOpenWorld() {
		t.Errorf("absent annotations must default to destructive and open world: %v", a)
	}
	if byName["create_issue"].GetOutputSchemaJson() == "" {
		t.Error("create_issue has no output schema")
	}

	id := integration.GetIntegrationId()
	resp, err := h.call(t, id, "echo", `{"text":"καλημέρα"}`)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetIsError() || len(resp.GetContent()) != 1 || resp.GetContent()[0].GetText().GetText() != "καλημέρα" || resp.GetDuration() == nil {
		t.Fatalf("echo = %v", resp)
	}
	resp, err = h.call(t, id, "create_issue", `{"title":"Fix login"}`)
	if err != nil {
		t.Fatal(err)
	}
	var issue struct{ ID, Title string }
	if err := json.Unmarshal([]byte(resp.GetStructuredContentJson()), &issue); err != nil || issue.ID != "JAR-1" || issue.Title != "Fix login" {
		t.Fatalf("create_issue structured = %q (%v)", resp.GetStructuredContentJson(), err)
	}
	resp, err = h.call(t, id, "fail", "")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetIsError() || !strings.Contains(resp.GetContent()[0].GetText().GetText(), "read-only today") {
		t.Fatalf("fail = %v", resp)
	}
	_, err = h.call(t, id, "no_such_tool", "{}")
	wantStatus(t, err, codes.Aborted, mcpv1.ErrorReason_ERROR_REASON_UPSTREAM_ERROR)
}

func TestToolListIsCached(t *testing.T) {
	h := newHarness(t)
	id := h.connect(t).GetIntegrationId()
	list := func(refresh bool) int {
		resp, err := h.svc.ListTools(ctx(t), &mcpv1.ListToolsRequest{TenantId: h.tenant, UserId: h.user, Refresh: refresh})
		if err != nil {
			t.Fatal(err)
		}
		return len(resp.GetTools())
	}
	if n := list(false); n != 5 {
		t.Fatalf("tools = %d", n)
	}
	key := "jarvis:mcp:tools:" + id
	if !h.redis.Exists(key) {
		t.Fatal("tool list not cached")
	}
	if ttl := h.redis.TTL(key); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("cache TTL = %v", ttl)
	}
	// Served from the cache even when the server would refuse.
	h.pool.Invalidate(uuid.MustParse(id))
	h.env.Auth.RevokeAll()
	if n := list(false); n != 5 {
		t.Fatalf("cached tools = %d", n)
	}
	_, err := h.svc.DeleteIntegration(ctx(t), &mcpv1.DeleteIntegrationRequest{TenantId: h.tenant, UserId: h.user, IntegrationId: id})
	if err != nil {
		t.Fatal(err)
	}
	if h.redis.Exists(key) {
		t.Fatal("cache survived deletion")
	}
}

func TestDynamicRegistrationIsReused(t *testing.T) {
	h := newHarness(t)
	h.connect(t)
	h.connect(t)
	if h.env.Auth.Registrations != 1 {
		t.Fatalf("registrations = %d, want 1", h.env.Auth.Registrations)
	}
	var sealedSecret []byte
	if err := db.QueryRow(ctx(t), `SELECT client_secret_sealed FROM oauth_clients WHERE issuer = $1`, h.env.Auth.Issuer).Scan(&sealedSecret); err != nil {
		t.Fatal(err)
	}
	if len(sealedSecret) == 0 {
		t.Fatal("client secret not stored sealed")
	}
}

func TestExpiringRegistrationIsRenewed(t *testing.T) {
	h := newHarness(t)
	h.env.Auth.SecretTTL = 5 * time.Minute // inside the router's safety margin
	h.connect(t)
	h.connect(t)
	if h.env.Auth.Registrations != 2 {
		t.Fatalf("registrations = %d, want 2 (expiring client not renewed)", h.env.Auth.Registrations)
	}
}

func TestRejectedRegistrationIsForgotten(t *testing.T) {
	h := newHarness(t)
	h.connect(t)
	// The server drops our registration between consent and code exchange.
	created, err := h.svc.CreateIntegration(ctx(t), &mcpv1.CreateIntegrationRequest{
		TenantId: h.tenant, UserId: h.user, Server: &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: h.env.MCPURL},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := consent(t, created.GetAuthorizationUrl())
	h.env.Auth.ForgetClients()
	_, err = h.svc.CompleteAuthorization(ctx(t), &mcpv1.CompleteAuthorizationRequest{State: q.Get("state"), Code: q.Get("code"), Iss: q.Get("iss")})
	wantStatus(t, err, codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_AUTHORIZATION_FAILED)
	// The next authorization registers again and works.
	h.connect(t)
	if h.env.Auth.Registrations != 2 {
		t.Fatalf("registrations = %d, want 2", h.env.Auth.Registrations)
	}
}

func TestExpiredTokenIsRefreshed(t *testing.T) {
	h := newHarness(t)
	id := h.connect(t).GetIntegrationId()
	if _, err := h.call(t, id, "echo", `{"text":"1"}`); err != nil {
		t.Fatal(err)
	}
	var before []byte
	_ = db.QueryRow(ctx(t), `SELECT credentials_sealed FROM integrations WHERE id = $1`, id).Scan(&before)

	// The server stops accepting the access token before its advertised
	// expiry: the router refreshes once and retries.
	h.env.Auth.ExpireAccessTokens()
	resp, err := h.call(t, id, "echo", `{"text":"2"}`)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetContent()[0].GetText().GetText() != "2" || h.env.Auth.Refreshes != 1 {
		t.Fatalf("resp = %v, refreshes = %d", resp, h.env.Auth.Refreshes)
	}
	var after []byte
	_ = db.QueryRow(ctx(t), `SELECT credentials_sealed FROM integrations WHERE id = $1`, id).Scan(&after)
	if bytes.Equal(before, after) {
		t.Fatal("rotated tokens were not persisted")
	}
	// A new session (another router instance, a restart) uses the rotated
	// refresh token.
	h.pool.Invalidate(uuid.MustParse(id))
	h.env.Auth.ExpireAccessTokens()
	if _, err := h.call(t, id, "echo", `{"text":"3"}`); err != nil {
		t.Fatal(err)
	}
	if h.env.Auth.Refreshes != 2 {
		t.Fatalf("refreshes = %d", h.env.Auth.Refreshes)
	}
	if got := h.integration(t, id).GetStatus(); got != mcpv1.IntegrationStatus_INTEGRATION_STATUS_CONNECTED {
		t.Fatalf("status = %v", got)
	}
}

func TestRevokedAuthorizationNeedsReauthorization(t *testing.T) {
	h := newHarness(t)
	id := h.connect(t).GetIntegrationId()
	if _, err := h.call(t, id, "echo", `{"text":"1"}`); err != nil {
		t.Fatal(err)
	}
	h.env.Auth.RevokeAll()

	_, err := h.call(t, id, "echo", `{"text":"2"}`)
	wantStatus(t, err, codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_NEEDS_REAUTHORIZATION)
	if got := h.integration(t, id); got.GetStatus() != mcpv1.IntegrationStatus_INTEGRATION_STATUS_NEEDS_REAUTHORIZATION || got.GetStatusDetail() == "" {
		t.Fatalf("integration = %v", got)
	}
	// Refused up front from now on, and reported by ListTools.
	_, err = h.call(t, id, "echo", `{"text":"3"}`)
	wantStatus(t, err, codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_NEEDS_REAUTHORIZATION)
	tools, err := h.svc.ListTools(ctx(t), &mcpv1.ListToolsRequest{TenantId: h.tenant, UserId: h.user})
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.GetTools()) != 0 || len(tools.GetUnavailable()) != 1 ||
		tools.GetUnavailable()[0].GetReason() != mcpv1.ErrorReason_ERROR_REASON_NEEDS_REAUTHORIZATION {
		t.Fatalf("ListTools = %v", tools)
	}

	re, err := h.svc.ReauthorizeIntegration(ctx(t), &mcpv1.ReauthorizeIntegrationRequest{TenantId: h.tenant, UserId: h.user, IntegrationId: id})
	if err != nil {
		t.Fatal(err)
	}
	done, err := h.complete(t, re.GetAuthorizationUrl())
	if err != nil {
		t.Fatal(err)
	}
	if done.GetIntegration().GetIntegrationId() != id || done.GetIntegration().GetStatus() != mcpv1.IntegrationStatus_INTEGRATION_STATUS_CONNECTED {
		t.Fatalf("after reauthorization: %v", done.GetIntegration())
	}
	if _, err := h.call(t, id, "echo", `{"text":"4"}`); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshedTokenAlsoRejectedNeedsReauthorization(t *testing.T) {
	// E.g. the user removed a scope: refreshing succeeds but the server
	// still refuses. One refresh, then NEEDS_REAUTHORIZATION, no loop.
	h := newHarness(t)
	id := h.connect(t).GetIntegrationId()
	h.env.Auth.RejectTokens = true
	_, err := h.call(t, id, "echo", `{"text":"x"}`)
	wantStatus(t, err, codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_NEEDS_REAUTHORIZATION)
	if h.env.Auth.Refreshes != 1 {
		t.Fatalf("refreshes = %d, want 1", h.env.Auth.Refreshes)
	}
	if got := h.integration(t, id).GetStatus(); got != mcpv1.IntegrationStatus_INTEGRATION_STATUS_NEEDS_REAUTHORIZATION {
		t.Fatalf("status = %v", got)
	}
}

func TestAuthorizationFailures(t *testing.T) {
	h := newHarness(t)
	begin := func() (string, string) {
		created, err := h.svc.CreateIntegration(ctx(t), &mcpv1.CreateIntegrationRequest{
			TenantId: h.tenant, UserId: h.user,
			Server: &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: h.env.MCPURL},
		})
		if err != nil {
			t.Fatal(err)
		}
		return created.GetIntegration().GetIntegrationId(), created.GetAuthorizationUrl()
	}
	completeWith := func(q url.Values) error {
		_, err := h.svc.CompleteAuthorization(ctx(t), &mcpv1.CompleteAuthorizationRequest{
			State: q.Get("state"), Code: q.Get("code"), Iss: q.Get("iss"), Error: q.Get("error"),
		})
		return err
	}

	t.Run("user denies", func(t *testing.T) {
		h.env.Auth.DenyAll = true
		defer func() { h.env.Auth.DenyAll = false }()
		id, authURL := begin()
		wantStatus(t, completeWith(consent(t, authURL)), codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_AUTHORIZATION_FAILED)
		got := h.integration(t, id)
		if got.GetStatus() != mcpv1.IntegrationStatus_INTEGRATION_STATUS_PENDING_AUTHORIZATION || !strings.Contains(got.GetStatusDetail(), "access_denied") {
			t.Fatalf("integration = %v", got)
		}
	})
	t.Run("mix-up attack: another issuer", func(t *testing.T) {
		h.env.Auth.WrongIss = true
		defer func() { h.env.Auth.WrongIss = false }()
		_, authURL := begin()
		err := completeWith(consent(t, authURL))
		wantStatus(t, err, codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_AUTHORIZATION_FAILED)
		if !strings.Contains(err.Error(), "unexpected issuer") {
			t.Fatal(err)
		}
	})
	t.Run("missing iss", func(t *testing.T) {
		_, authURL := begin()
		q := consent(t, authURL)
		q.Del("iss")
		wantStatus(t, completeWith(q), codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_AUTHORIZATION_FAILED)
	})
	t.Run("state is single use", func(t *testing.T) {
		_, authURL := begin()
		q := consent(t, authURL)
		if err := completeWith(q); err != nil {
			t.Fatal(err)
		}
		exchanges := h.env.Auth.Exchanges
		err := completeWith(q)
		wantStatus(t, err, codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_AUTHORIZATION_FAILED)
		// Refused by the router itself, before reaching the token endpoint.
		if h.env.Auth.Exchanges != exchanges || !strings.Contains(err.Error(), "already used") {
			t.Fatalf("replayed state reached the authorization server: %v", err)
		}
	})
	t.Run("unknown state", func(t *testing.T) {
		wantStatus(t, completeWith(url.Values{"state": {"forged"}, "code": {"x"}}), codes.FailedPrecondition,
			mcpv1.ErrorReason_ERROR_REASON_AUTHORIZATION_FAILED)
	})
	t.Run("expired state", func(t *testing.T) {
		id, authURL := begin()
		if _, err := db.Exec(ctx(t), `UPDATE pending_authorizations SET expires_at = now() - interval '1 second' WHERE integration_id = $1`, id); err != nil {
			t.Fatal(err)
		}
		wantStatus(t, completeWith(consent(t, authURL)), codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_AUTHORIZATION_FAILED)
	})
	t.Run("a newer authorization replaces the older", func(t *testing.T) {
		id, first := begin()
		re, err := h.svc.ReauthorizeIntegration(ctx(t), &mcpv1.ReauthorizeIntegrationRequest{TenantId: h.tenant, UserId: h.user, IntegrationId: id})
		if err != nil {
			t.Fatal(err)
		}
		wantStatus(t, completeWith(consent(t, first)), codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_AUTHORIZATION_FAILED)
		if err := completeWith(consent(t, re.GetAuthorizationUrl())); err != nil {
			t.Fatal(err)
		}
	})
}

func TestNoRegistrationEndpointLeavesNothingBehind(t *testing.T) {
	h := newHarness(t)
	h.env.Auth.NoRegistration = true
	_, err := h.svc.CreateIntegration(ctx(t), &mcpv1.CreateIntegrationRequest{
		TenantId: h.tenant, UserId: h.user,
		Server: &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: h.env.MCPURL},
	})
	wantStatus(t, err, codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_AUTHORIZATION_FAILED)
	list, _ := h.svc.ListIntegrations(ctx(t), &mcpv1.ListIntegrationsRequest{TenantId: h.tenant, UserId: h.user})
	if len(list.GetIntegrations()) != 0 {
		t.Fatalf("half-created integration left: %v", list)
	}
}

func TestServerGuard(t *testing.T) {
	strict := newHarness(t, func(o *harnessOptions) { o.guard = netguard.Guard{} })
	for _, target := range []string{
		strict.env.MCPURL, // loopback
		"https://127.0.0.1/mcp",
		"https://localhost/mcp",
		"https://10.0.0.5/mcp",
		"https://169.254.169.254/latest/meta-data",
		"https://[::1]/mcp",
		"https://[::ffff:192.168.1.1]/mcp",
		"http://mcp.example.com/mcp",
		"https://user:pass@mcp.example.com/mcp",
		"file:///etc/passwd",
	} {
		_, err := strict.svc.CreateIntegration(ctx(t), &mcpv1.CreateIntegrationRequest{
			TenantId: strict.tenant, UserId: strict.user,
			Server: &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: target},
		})
		wantStatus(t, err, codes.PermissionDenied, mcpv1.ErrorReason_ERROR_REASON_SERVER_NOT_ALLOWED)
	}

	closed := newHarness(t, func(o *harnessOptions) { o.allowCustom = false })
	_, err := closed.svc.CreateIntegration(ctx(t), &mcpv1.CreateIntegrationRequest{
		TenantId: closed.tenant, UserId: closed.user,
		Server: &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: "https://mcp.example.com/mcp"},
	})
	wantStatus(t, err, codes.PermissionDenied, mcpv1.ErrorReason_ERROR_REASON_SERVER_NOT_ALLOWED)
}

func TestDiscoveredURLsAreGuardedToo(t *testing.T) {
	// A public-looking server whose metadata points the router at a private
	// address must be refused (here loopback is allowed for the MCP server
	// itself, but the discovered issuer is a private IP).
	h := newHarness(t)
	handler := &swappable{}
	srv := httptest.NewUnstartedServer(handler)
	base := "http://" + srv.Listener.Addr().String()
	handler.h = mcptest.MCPHandler(base, "https://10.1.2.3/as", mcptest.StaticToken("unused"))
	srv.Start()
	t.Cleanup(srv.Close)
	_, err := h.svc.CreateIntegration(ctx(t), &mcpv1.CreateIntegrationRequest{
		TenantId: h.tenant, UserId: h.user,
		Server: &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: base + "/mcp"},
	})
	wantStatus(t, err, codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_AUTHORIZATION_FAILED)
	if !strings.Contains(err.Error(), "10.1.2.3") {
		t.Fatalf("error = %v", err)
	}
	list, _ := h.svc.ListIntegrations(ctx(t), &mcpv1.ListIntegrationsRequest{TenantId: h.tenant, UserId: h.user})
	if len(list.GetIntegrations()) != 0 {
		t.Fatalf("half-created integration left: %v", list)
	}
}

func TestIntegrationsAreIsolated(t *testing.T) {
	h := newHarness(t)
	id := h.connect(t).GetIntegrationId()
	others := []struct{ tenant, user string }{
		{h.tenant, "someone-else"},
		{uuid.NewString(), h.user},
	}
	for _, o := range others {
		_, err := h.svc.CallTool(ctx(t), &mcpv1.CallToolRequest{TenantId: o.tenant, UserId: o.user, IntegrationId: id, ToolName: "echo"})
		wantStatus(t, err, codes.NotFound, mcpv1.ErrorReason_ERROR_REASON_INTEGRATION_NOT_FOUND)
		_, err = h.svc.ReauthorizeIntegration(ctx(t), &mcpv1.ReauthorizeIntegrationRequest{TenantId: o.tenant, UserId: o.user, IntegrationId: id})
		wantStatus(t, err, codes.NotFound, mcpv1.ErrorReason_ERROR_REASON_INTEGRATION_NOT_FOUND)
		if _, err := h.svc.DeleteIntegration(ctx(t), &mcpv1.DeleteIntegrationRequest{TenantId: o.tenant, UserId: o.user, IntegrationId: id}); err != nil {
			t.Fatal(err)
		}
		list, _ := h.svc.ListIntegrations(ctx(t), &mcpv1.ListIntegrationsRequest{TenantId: o.tenant, UserId: o.user})
		tools, _ := h.svc.ListTools(ctx(t), &mcpv1.ListToolsRequest{TenantId: o.tenant, UserId: o.user})
		if len(list.GetIntegrations()) != 0 || len(tools.GetTools()) != 0 {
			t.Fatalf("another owner sees the integration")
		}
	}
	// Still there for its owner.
	if _, err := h.call(t, id, "echo", `{"text":"mine"}`); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimit(t *testing.T) {
	h := newHarness(t, func(o *harnessOptions) { o.perIntegration = 2 })
	id := h.connect(t).GetIntegrationId()
	for range 2 {
		if _, err := h.call(t, id, "echo", `{"text":"x"}`); err != nil {
			t.Fatal(err)
		}
	}
	_, err := h.call(t, id, "echo", `{"text":"x"}`)
	wantStatus(t, err, codes.ResourceExhausted, mcpv1.ErrorReason_ERROR_REASON_RATE_LIMITED)
	var retry *errdetails.RetryInfo
	for _, d := range status.Convert(err).Details() {
		if r, ok := d.(*errdetails.RetryInfo); ok {
			retry = r
		}
	}
	if retry == nil || retry.GetRetryDelay().AsDuration() <= 0 || retry.GetRetryDelay().AsDuration() > time.Minute {
		t.Fatalf("RetryInfo = %v", retry)
	}

	// Without Redis the router keeps working (fails open).
	h.redis.Close()
	if _, err := h.call(t, id, "echo", `{"text":"x"}`); err != nil {
		t.Fatalf("with Redis down: %v", err)
	}
}

func TestCallTimeout(t *testing.T) {
	h := newHarness(t)
	id := h.connect(t).GetIntegrationId()
	start := time.Now()
	_, err := h.svc.CallTool(ctx(t), &mcpv1.CallToolRequest{
		TenantId: h.tenant, UserId: h.user, IntegrationId: id, ToolName: "slow",
		ArgumentsJson: `{"millis":1500}`, Timeout: durationpb.New(200 * time.Millisecond),
	})
	wantStatus(t, err, codes.DeadlineExceeded, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
	// The integration stays usable.
	if _, err := h.call(t, id, "echo", `{"text":"after"}`); err != nil {
		t.Fatal(err)
	}
}

func TestLargeResultsAreTruncated(t *testing.T) {
	h := newHarness(t)
	id := h.connect(t).GetIntegrationId()
	resp, err := h.call(t, id, "big", `{"bytes":2097152}`)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetTruncated() || len(resp.GetContent()) != 1 {
		t.Fatalf("truncated = %v, blocks = %d", resp.GetTruncated(), len(resp.GetContent()))
	}
	text := resp.GetContent()[0].GetText().GetText()
	if len(text) > 1<<20 || len(text) < 1<<19 || !utf8.ValidString(text) {
		t.Fatalf("text: %d bytes, valid UTF-8 = %v", len(text), utf8.ValidString(text))
	}
	resp, err = h.call(t, id, "big", `{"bytes":1000}`)
	if err != nil || resp.GetTruncated() || len(resp.GetContent()) != 2 || resp.GetContent()[1].GetImage().GetMimeType() != "image/png" {
		t.Fatalf("small result = %v, %v", resp, err)
	}
}

func TestBearerTokenIntegration(t *testing.T) {
	h := newHarness(t)
	handler := &swappable{}
	srv := httptest.NewUnstartedServer(handler)
	base := "http://" + srv.Listener.Addr().String()
	handler.h = mcptest.MCPHandler(base, "https://unused.example", mcptest.StaticToken("ghp_correct"))
	srv.Start()
	t.Cleanup(srv.Close)

	create := func(token string) string {
		resp, err := h.svc.CreateIntegration(ctx(t), &mcpv1.CreateIntegrationRequest{
			TenantId: h.tenant, UserId: h.user, DisplayName: "GitHub (work)", BearerToken: []byte(token),
			Server: &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: base + "/mcp"},
		})
		if err != nil {
			t.Fatal(err)
		}
		i := resp.GetIntegration()
		if resp.GetAuthorizationUrl() != "" || i.GetAuth() != mcpv1.AuthKind_AUTH_KIND_BEARER_TOKEN ||
			i.GetStatus() != mcpv1.IntegrationStatus_INTEGRATION_STATUS_CONNECTED {
			t.Fatalf("bearer integration = %v", resp)
		}
		return i.GetIntegrationId()
	}

	good := create("ghp_correct")
	if resp, err := h.call(t, good, "echo", `{"text":"pat"}`); err != nil || resp.GetContent()[0].GetText().GetText() != "pat" {
		t.Fatalf("call = %v, %v", resp, err)
	}
	var sealed []byte
	_ = db.QueryRow(ctx(t), `SELECT credentials_sealed FROM integrations WHERE id = $1`, good).Scan(&sealed)
	if bytes.Contains(sealed, []byte("ghp_correct")) {
		t.Fatal("bearer token stored in plaintext")
	}

	bad := create("ghp_wrong")
	_, err := h.call(t, bad, "echo", `{"text":"x"}`)
	wantStatus(t, err, codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_NEEDS_REAUTHORIZATION)
	_, err = h.svc.ReauthorizeIntegration(ctx(t), &mcpv1.ReauthorizeIntegrationRequest{TenantId: h.tenant, UserId: h.user, IntegrationId: bad})
	wantStatus(t, err, codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED)
}

func TestVaultUnavailable(t *testing.T) {
	h := newHarness(t)
	id := h.connect(t).GetIntegrationId()
	h.pool.Invalidate(uuid.MustParse(id)) // force the credentials to be opened again
	h.sealer.setDown(true)
	_, err := h.call(t, id, "echo", `{"text":"x"}`)
	wantStatus(t, err, codes.Unavailable, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED)
	if !strings.Contains(err.Error(), "key vault") {
		t.Fatalf("error = %v", err)
	}
	_, err = h.svc.CreateIntegration(ctx(t), &mcpv1.CreateIntegrationRequest{
		TenantId: h.tenant, UserId: h.user, BearerToken: []byte("token"),
		Server: &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: h.env.MCPURL},
	})
	wantStatus(t, err, codes.Unavailable, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED)
	// The integration is not blamed for the Vault's outage.
	if got := h.integration(t, id).GetStatus(); got != mcpv1.IntegrationStatus_INTEGRATION_STATUS_CONNECTED {
		t.Fatalf("status = %v", got)
	}
	h.sealer.setDown(false)
	if _, err := h.call(t, id, "echo", `{"text":"x"}`); err != nil {
		t.Fatal(err)
	}
}

func TestUnreachableServer(t *testing.T) {
	h := newHarness(t)
	id := h.connect(t).GetIntegrationId()
	if _, err := db.Exec(ctx(t), `UPDATE integrations SET server_url = 'http://127.0.0.1:1/mcp' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	h.pool.Invalidate(uuid.MustParse(id))
	_, err := h.call(t, id, "echo", `{"text":"x"}`)
	wantStatus(t, err, codes.Unavailable, mcpv1.ErrorReason_ERROR_REASON_UPSTREAM_UNAVAILABLE)
	tools, err := h.svc.ListTools(ctx(t), &mcpv1.ListToolsRequest{TenantId: h.tenant, UserId: h.user, Refresh: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.GetUnavailable()) != 1 || tools.GetUnavailable()[0].GetReason() != mcpv1.ErrorReason_ERROR_REASON_UPSTREAM_UNAVAILABLE {
		t.Fatalf("ListTools = %v", tools)
	}
}

func TestCatalog(t *testing.T) {
	h := newHarness(t)
	resp, err := h.svc.ListCatalog(ctx(t), &mcpv1.ListCatalogRequest{})
	if err != nil {
		t.Fatal(err)
	}
	available := map[string]bool{}
	for _, s := range resp.GetServers() {
		available[s.GetSlug()] = s.GetAvailable()
		if !strings.HasPrefix(s.GetUrl(), "https://") {
			t.Errorf("%s URL %s", s.GetSlug(), s.GetUrl())
		}
	}
	for slug, want := range map[string]bool{"atlassian": true, "clickup": true, "linear": true, "notion": true, "github": true, "slack": false, "gmail": false} {
		if got, ok := available[slug]; !ok || got != want {
			t.Errorf("%s available = %v (listed %v), want %v", slug, got, ok, want)
		}
	}
	_, err = h.svc.CreateIntegration(ctx(t), &mcpv1.CreateIntegrationRequest{
		TenantId: h.tenant, UserId: h.user, Server: &mcpv1.CreateIntegrationRequest_CatalogSlug{CatalogSlug: "slack"},
	})
	wantStatus(t, err, codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_CATALOG_NOT_CONFIGURED)
	_, err = h.svc.CreateIntegration(ctx(t), &mcpv1.CreateIntegrationRequest{
		TenantId: h.tenant, UserId: h.user, Server: &mcpv1.CreateIntegrationRequest_CatalogSlug{CatalogSlug: "github"},
	})
	wantStatus(t, err, codes.InvalidArgument, mcpv1.ErrorReason_ERROR_REASON_UNSPECIFIED) // needs a token

	configured := newHarness(t, func(o *harnessOptions) {
		o.clients = map[string]catalog.ClientCredentials{"slack": {ClientID: "id", ClientSecret: "secret"}}
	})
	resp, _ = configured.svc.ListCatalog(ctx(t), &mcpv1.ListCatalogRequest{})
	for _, s := range resp.GetServers() {
		if s.GetSlug() == "slack" && !s.GetAvailable() {
			t.Error("slack not available with a configured client")
		}
	}
}

func TestValidation(t *testing.T) {
	h := newHarness(t)
	id := h.connect(t).GetIntegrationId()
	server := &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: h.env.MCPURL}
	creates := map[string]*mcpv1.CreateIntegrationRequest{
		"tenant not a UUID":      {TenantId: "acme", UserId: h.user, Server: server},
		"tenant not canonical":   {TenantId: strings.ToUpper(h.tenant), UserId: h.user, Server: server},
		"nil tenant":             {TenantId: uuid.Nil.String(), UserId: h.user, Server: server},
		"empty user":             {TenantId: h.tenant, Server: server},
		"user with newline":      {TenantId: h.tenant, UserId: "a\nb", Server: server},
		"user too long":          {TenantId: h.tenant, UserId: strings.Repeat("u", 129), Server: server},
		"no server":              {TenantId: h.tenant, UserId: h.user},
		"unknown slug":           {TenantId: h.tenant, UserId: h.user, Server: &mcpv1.CreateIntegrationRequest_CatalogSlug{CatalogSlug: "nope"}},
		"display name too long":  {TenantId: h.tenant, UserId: h.user, Server: server, DisplayName: strings.Repeat("α", 65)},
		"display name control":   {TenantId: h.tenant, UserId: h.user, Server: server, DisplayName: "a\u202eb"},
		"display name padded":    {TenantId: h.tenant, UserId: h.user, Server: server, DisplayName: " Jira"},
		"token with space":       {TenantId: h.tenant, UserId: h.user, Server: server, BearerToken: []byte("a b")},
		"token for OAuth server": {TenantId: h.tenant, UserId: h.user, BearerToken: []byte("x"), Server: &mcpv1.CreateIntegrationRequest_CatalogSlug{CatalogSlug: "linear"}},
		"fragment":               {TenantId: h.tenant, UserId: h.user, Server: &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: h.env.MCPURL + "#x"}},
	}
	for name, req := range creates {
		if _, err := h.svc.CreateIntegration(ctx(t), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	calls := map[string]*mcpv1.CallToolRequest{
		"bad integration id": {TenantId: h.tenant, UserId: h.user, IntegrationId: "x", ToolName: "echo"},
		"empty tool":         {TenantId: h.tenant, UserId: h.user, IntegrationId: id},
		"tool with space":    {TenantId: h.tenant, UserId: h.user, IntegrationId: id, ToolName: "a b"},
		"arguments array":    {TenantId: h.tenant, UserId: h.user, IntegrationId: id, ToolName: "echo", ArgumentsJson: `[1]`},
		"arguments null":     {TenantId: h.tenant, UserId: h.user, IntegrationId: id, ToolName: "echo", ArgumentsJson: `null`},
		"arguments invalid":  {TenantId: h.tenant, UserId: h.user, IntegrationId: id, ToolName: "echo", ArgumentsJson: `{`},
		"arguments too big":  {TenantId: h.tenant, UserId: h.user, IntegrationId: id, ToolName: "echo", ArgumentsJson: `{"a":"` + strings.Repeat("x", 256<<10) + `"}`},
		"negative timeout":   {TenantId: h.tenant, UserId: h.user, IntegrationId: id, ToolName: "echo", Timeout: durationpb.New(-time.Second)},
	}
	for name, req := range calls {
		if _, err := h.svc.CallTool(ctx(t), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := h.svc.CompleteAuthorization(ctx(t), &mcpv1.CompleteAuthorizationRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty state: %v", err)
	}
}

func TestDeleteIntegration(t *testing.T) {
	h := newHarness(t)
	id := h.connect(t).GetIntegrationId()
	// A pending reauthorization is removed with it.
	if _, err := h.svc.ReauthorizeIntegration(ctx(t), &mcpv1.ReauthorizeIntegrationRequest{TenantId: h.tenant, UserId: h.user, IntegrationId: id}); err != nil {
		t.Fatal(err)
	}
	for range 2 { // idempotent
		if _, err := h.svc.DeleteIntegration(ctx(t), &mcpv1.DeleteIntegrationRequest{TenantId: h.tenant, UserId: h.user, IntegrationId: id}); err != nil {
			t.Fatal(err)
		}
	}
	var pending int
	_ = db.QueryRow(ctx(t), `SELECT count(*) FROM pending_authorizations WHERE integration_id = $1`, id).Scan(&pending)
	if pending != 0 {
		t.Fatal("pending authorization survived deletion")
	}
	_, err := h.call(t, id, "echo", `{}`)
	wantStatus(t, err, codes.NotFound, mcpv1.ErrorReason_ERROR_REASON_INTEGRATION_NOT_FOUND)
}

func TestPendingIntegrationIsNotCallable(t *testing.T) {
	h := newHarness(t)
	created, err := h.svc.CreateIntegration(ctx(t), &mcpv1.CreateIntegrationRequest{
		TenantId: h.tenant, UserId: h.user, Server: &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: h.env.MCPURL},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.call(t, created.GetIntegration().GetIntegrationId(), "echo", `{}`)
	wantStatus(t, err, codes.FailedPrecondition, mcpv1.ErrorReason_ERROR_REASON_NOT_CONNECTED)
	tools, _ := h.svc.ListTools(ctx(t), &mcpv1.ListToolsRequest{TenantId: h.tenant, UserId: h.user})
	if len(tools.GetUnavailable()) != 1 || tools.GetUnavailable()[0].GetReason() != mcpv1.ErrorReason_ERROR_REASON_NOT_CONNECTED {
		t.Fatalf("ListTools = %v", tools)
	}
}

func TestConcurrentCalls(t *testing.T) {
	h := newHarness(t)
	id := h.connect(t).GetIntegrationId()
	errs := make(chan error, 20)
	for i := range 20 {
		go func() {
			resp, err := h.call(t, id, "echo", `{"text":"`+string(rune('a'+i))+`"}`)
			if err == nil && resp.GetContent()[0].GetText().GetText() != string(rune('a'+i)) {
				err = status.Error(codes.Internal, "mixed up results")
			}
			errs <- err
		}()
	}
	for range 20 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
