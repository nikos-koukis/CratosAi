package server_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	voicev1 "jarvis.internal/gen/go/jarvis/voice/v1"
	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/voice-gateway/internal/auth"
	"jarvis.internal/voice-gateway/internal/metrics"
	"jarvis.internal/voice-gateway/internal/realtime"
	"jarvis.internal/voice-gateway/internal/realtime/realtimetest"
	"jarvis.internal/voice-gateway/internal/server"
	"jarvis.internal/voice-gateway/internal/session"
)

const (
	tenantA     = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	tenantNoKey = "0199a1b2-c3d4-7e5f-8a9b-000000000000"
	providerKey = "sk-tenant-a-provider-key"
	issuer      = "https://id.jarvis.test"
	audience    = "jarvis-voice-gateway"
)

// fakeKeys plays the Vault.
type fakeKeys struct {
	mu       sync.Mutex
	keys     map[string]string
	requests []string
}

func (f *fakeKeys) ProviderKey(_ context.Context, requestID, tenant string, _ commonv1.Provider) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, requestID)
	key, ok := f.keys[tenant]
	if !ok {
		return nil, vaultclient.ErrNoKey
	}
	return []byte(key), nil
}

type harness struct {
	t        *testing.T
	gateway  *server.Server
	http     *httptest.Server
	provider *realtimetest.Server
	issuer   auth.Issuer
	keys     *fakeKeys
	metrics  *metrics.Metrics
}

type options struct {
	perTenant    int
	idleTimeout  time.Duration
	orchestrator orchv1.OrchestratorServiceClient
}

func newHarness(t *testing.T, opts options) *harness {
	t.Helper()
	if opts.perTenant == 0 {
		opts.perTenant = 2
	}
	if opts.idleTimeout == 0 {
		opts.idleTimeout = time.Minute
	}
	privatePEM, jwksJSON, err := auth.GenerateKey("test")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := auth.ParseJWKS(jwksJSON)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := auth.NewVerifier(jwks, issuer, audience, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signingKey := writeAndLoadKey(t, privatePEM)

	provider := realtimetest.NewServer(t, providerKey)
	keys := &fakeKeys{keys: map[string]string{tenantA: providerKey}}
	m := metrics.New()
	gateway := server.New(verifier, session.Config{
		Providers: map[commonv1.Provider]realtime.Provider{
			commonv1.Provider_PROVIDER_OPENAI: {
				Name: "openai", URL: provider.URL(), Dialect: realtime.DialectOpenAI,
				DefaultVoice: "marin", VADSilenceMs: 500,
			},
		},
		DefaultProvider: commonv1.Provider_PROVIDER_OPENAI,
		Instructions:    "test",
		StartTimeout:    2 * time.Second,
		MaxDuration:     time.Minute,
		IdleTimeout:     opts.idleTimeout,
		ToolTimeout:     2 * time.Second,
	}, session.Deps{
		Keys:         keys,
		Orchestrator: opts.orchestrator,
		Limiter:      session.NewLimiter(10, opts.perTenant),
		Metrics:      m,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	httpServer := httptest.NewServer(gateway.Handler())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = gateway.Shutdown(ctx)
		httpServer.Close()
	})
	return &harness{
		t: t, gateway: gateway, http: httpServer, provider: provider, keys: keys, metrics: m,
		issuer: auth.Issuer{Key: signingKey, KeyID: "test", Issuer: issuer, Audience: audience},
	}
}

func writeAndLoadKey(t *testing.T, privatePEM []byte) []byte {
	t.Helper()
	path := t.TempDir() + "/key.pem"
	if err := writeFile(path, privatePEM); err != nil {
		t.Fatal(err)
	}
	key, err := auth.LoadSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func (h *harness) url() string {
	return "ws" + strings.TrimPrefix(h.http.URL, "http") + "/v1/voice"
}

func (h *harness) token(tenant string) string {
	token, err := h.issuer.Issue("user-1", tenant, 10*time.Minute)
	if err != nil {
		h.t.Fatal(err)
	}
	return token
}

type client struct {
	t  *testing.T
	ws *websocket.Conn
	// messages receives what the gateway sends, when a test drains the
	// socket in the background (see drain).
	messages chan *voicev1.ServerMessage
}

func (h *harness) dial(tenant string) *client {
	h.t.Helper()
	ws, resp, err := websocket.Dial(context.Background(), h.url(), &websocket.DialOptions{
		HTTPHeader:   http.Header{"Authorization": {"Bearer " + h.token(tenant)}},
		Subprotocols: []string{server.Subprotocol},
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		h.t.Fatalf("dial: %v", err)
	}
	ws.SetReadLimit(1 << 20)
	h.t.Cleanup(func() { _ = ws.CloseNow() })
	return &client{t: h.t, ws: ws}
}

func (c *client) send(msg *voicev1.ClientMessage) {
	c.t.Helper()
	data, _ := proto.Marshal(msg)
	if err := c.ws.Write(context.Background(), websocket.MessageBinary, data); err != nil {
		c.t.Fatalf("send: %v", err)
	}
}

func (c *client) start(provider commonv1.Provider, voice string) {
	c.send(&voicev1.ClientMessage{Message: &voicev1.ClientMessage_StartSession{StartSession: &voicev1.StartSession{Provider: provider, Voice: voice}}})
}

func (c *client) startWithLocale(locale string) {
	c.send(&voicev1.ClientMessage{Message: &voicev1.ClientMessage_StartSession{StartSession: &voicev1.StartSession{Locale: locale}}})
}

func (c *client) audio(pcm []byte) {
	c.send(&voicev1.ClientMessage{Message: &voicev1.ClientMessage_InputAudio{InputAudio: &voicev1.InputAudio{Pcm16: pcm}}})
}

func (c *client) recv() *voicev1.ServerMessage {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	kind, data, err := c.ws.Read(ctx)
	if err != nil {
		c.t.Fatalf("recv: %v", err)
	}
	if kind != websocket.MessageBinary {
		c.t.Fatal("gateway sent a text frame")
	}
	msg := &voicev1.ServerMessage{}
	if err := proto.Unmarshal(data, msg); err != nil {
		c.t.Fatal(err)
	}
	return msg
}

// expectError reads until a fatal error arrives, then checks the socket closes.
func (c *client) expectError(code voicev1.ErrorCode) {
	c.t.Helper()
	for {
		msg := c.recv()
		if e := msg.GetError(); e != nil {
			if e.GetCode() != code || !e.GetFatal() {
				c.t.Fatalf("got error %v (fatal=%v) %q, want fatal %v", e.GetCode(), e.GetFatal(), e.GetMessage(), code)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, _, err := c.ws.Read(ctx); err == nil {
				c.t.Fatal("socket stayed open after a fatal error")
			}
			return
		}
	}
}

func (h *harness) startSession(tenant string) (*client, *realtimetest.Session) {
	h.t.Helper()
	c := h.dial(tenant)
	c.start(commonv1.Provider_PROVIDER_UNSPECIFIED, "")
	ready := c.recv().GetSessionReady()
	if ready == nil {
		h.t.Fatal("expected SessionReady")
	}
	return c, h.provider.NextSession(h.t)
}

func frame(n int, value byte) []byte {
	pcm := make([]byte, n)
	for i := range pcm {
		pcm[i] = value
	}
	return pcm
}

func TestConversationRoundTrip(t *testing.T) {
	h := newHarness(t, options{})
	c := h.dial(tenantA)
	c.start(commonv1.Provider_PROVIDER_OPENAI, "cedar")
	ready := c.recv().GetSessionReady()
	if ready == nil || ready.GetVoice() != "cedar" || ready.GetSampleRateHz() != 24000 || ready.GetSessionId() == "" {
		t.Fatalf("SessionReady: %v", ready)
	}
	p := h.provider.NextSession(t)
	if p.Header.Get("Authorization") != "Bearer "+providerKey {
		t.Fatal("the tenant's key was not used for the provider")
	}
	if len(p.Header.Get("OpenAI-Safety-Identifier")) != 32 {
		t.Fatal("expected a pseudonymous safety identifier")
	}
	if h.keys.requests[0] != ready.GetSessionId() {
		t.Fatal("the vault request should carry the session id for audit correlation")
	}

	for i := range 3 {
		c.audio(frame(960, byte(i+1)))
	}
	got := p.WaitForAudio(t, 3*960)
	if got[0] != 1 || got[960] != 2 || got[1920] != 3 {
		t.Fatal("audio arrived out of order")
	}

	p.Send(t, map[string]any{"type": "input_audio_buffer.speech_started", "item_id": "item_u"})
	p.Send(t, map[string]any{"type": "input_audio_buffer.speech_stopped", "item_id": "item_u"})
	p.Send(t, map[string]any{"type": "response.created", "response": map[string]any{"id": "r1"}})
	p.SendAudio(t, "r1", "item_a", frame(480, 7))
	p.Send(t, map[string]any{"type": "response.output_audio_transcript.delta", "item_id": "item_a", "delta": "Hi"})
	p.Send(t, map[string]any{"type": "response.done", "response": map[string]any{"id": "r1", "status": "completed"}})

	if c.recv().GetSpeechStarted() == nil || c.recv().GetSpeechStopped() == nil {
		t.Fatal("expected speech started/stopped")
	}
	if out := c.recv().GetOutputAudio(); out == nil || len(out.GetPcm16()) != 480 || out.GetResponseId() != "r1" {
		t.Fatalf("output audio: %v", out)
	}
	if tr := c.recv().GetTranscript(); tr.GetRole() != voicev1.Role_ROLE_ASSISTANT || tr.GetText() != "Hi" {
		t.Fatalf("transcript: %v", tr)
	}
	if done := c.recv().GetResponseDone(); done.GetStatus() != voicev1.ResponseStatus_RESPONSE_STATUS_COMPLETED {
		t.Fatalf("response done: %v", done)
	}

	c.send(&voicev1.ClientMessage{Message: &voicev1.ClientMessage_EndSession{EndSession: &voicev1.EndSession{}}})
	p.Closed(t)
}

func TestBargeInDropsQueuedAudioAndTruncates(t *testing.T) {
	h := newHarness(t, options{})
	c, p := h.startSession(tenantA)

	// Flood the client, which is not reading, until its socket buffers fill
	// and assistant audio backs up in the gateway.
	const chunk, chunks = 4800, 400
	p.Send(t, map[string]any{"type": "response.created", "response": map[string]any{"id": "r1"}})
	for range chunks {
		p.SendAudio(t, "r1", "item_a", frame(chunk, 1))
	}
	time.Sleep(300 * time.Millisecond)

	p.Send(t, map[string]any{"type": "input_audio_buffer.speech_started", "item_id": "item_u"})
	truncate := p.Next(t, "conversation.item.truncate")
	heardMs := int(truncate["audio_end_ms"].(float64))
	if truncate["item_id"] != "item_a" || heardMs >= chunks*chunk/realtime.BytesPerMillisecond {
		t.Fatalf("truncate should cut item_a short: %v", truncate)
	}

	// Audio for the interrupted response that is still in flight is dropped.
	p.SendAudio(t, "r1", "item_a", frame(chunk, 2))
	p.Send(t, map[string]any{"type": "response.done", "response": map[string]any{"id": "r1", "status": "cancelled"}})

	received := 0
	sawSpeechStarted := false
	for {
		msg := c.recv()
		if out := msg.GetOutputAudio(); out != nil {
			if sawSpeechStarted {
				t.Fatal("assistant audio arrived after the barge-in")
			}
			received += len(out.GetPcm16())
			continue
		}
		if msg.GetSpeechStarted() != nil {
			sawSpeechStarted = true
			continue
		}
		if done := msg.GetResponseDone(); done != nil {
			if done.GetStatus() != voicev1.ResponseStatus_RESPONSE_STATUS_CANCELLED {
				t.Fatalf("status %v, want CANCELLED", done.GetStatus())
			}
			break
		}
	}
	if !sawSpeechStarted || received >= chunks*chunk {
		t.Fatalf("received %d of %d bytes; barge-in must drop the rest", received, chunks*chunk)
	}
	if heardMs*realtime.BytesPerMillisecond > received {
		t.Fatalf("truncated at %d ms but the client only got %d bytes", heardMs, received)
	}
}

func TestClientCancelStopsTheResponse(t *testing.T) {
	h := newHarness(t, options{})
	c, p := h.startSession(tenantA)
	p.Send(t, map[string]any{"type": "response.created", "response": map[string]any{"id": "r1"}})
	p.SendAudio(t, "r1", "item_a", frame(480, 1))
	c.recv() // the audio
	c.send(&voicev1.ClientMessage{Message: &voicev1.ClientMessage_CancelResponse{CancelResponse: &voicev1.CancelResponse{}}})
	p.Next(t, "response.cancel")
}

func TestConnectionsWithoutValidCredentialsAreRejectedBeforeUpgrade(t *testing.T) {
	h := newHarness(t, options{})
	cases := map[string]*websocket.DialOptions{
		"no token":       {Subprotocols: []string{server.Subprotocol}},
		"bad token":      {HTTPHeader: http.Header{"Authorization": {"Bearer nope"}}, Subprotocols: []string{server.Subprotocol}},
		"no subprotocol": {HTTPHeader: http.Header{"Authorization": {"Bearer " + h.token(tenantA)}}},
	}
	want := map[string]int{"no token": 401, "bad token": 401, "no subprotocol": 400}
	for name, opts := range cases {
		_, resp, err := websocket.Dial(context.Background(), h.url(), opts)
		if err == nil {
			t.Fatalf("%s: connection accepted", name)
		}
		if resp == nil || resp.StatusCode != want[name] {
			t.Fatalf("%s: got %v, want HTTP %d", name, resp, want[name])
		}
		_ = resp.Body.Close()
	}
	if len(h.keys.requests) != 0 {
		t.Fatal("no key may be fetched for unauthenticated callers")
	}
}

func TestMissingOrRejectedKeysEndTheSessionClearly(t *testing.T) {
	h := newHarness(t, options{})
	c := h.dial(tenantNoKey)
	c.start(commonv1.Provider_PROVIDER_OPENAI, "")
	c.expectError(voicev1.ErrorCode_ERROR_CODE_PROVIDER_KEY_MISSING)

	h.keys.mu.Lock()
	h.keys.keys[tenantNoKey] = "sk-revoked-at-provider"
	h.keys.mu.Unlock()
	c = h.dial(tenantNoKey)
	c.start(commonv1.Provider_PROVIDER_OPENAI, "")
	c.expectError(voicev1.ErrorCode_ERROR_CODE_PROVIDER_AUTH_FAILED)
}

func TestProtocolViolationsAreRejected(t *testing.T) {
	h := newHarness(t, options{})
	cases := map[string]func(c *client){
		"audio before start": func(c *client) { c.audio(frame(960, 1)) },
		"text frame": func(c *client) {
			_ = c.ws.Write(context.Background(), websocket.MessageText, []byte(`{"start":true}`))
		},
		"garbage":              func(c *client) { _ = c.ws.Write(context.Background(), websocket.MessageBinary, []byte{0xff, 0xff}) },
		"provider not enabled": func(c *client) { c.start(commonv1.Provider_PROVIDER_XAI, "") },
		"bad voice":            func(c *client) { c.start(commonv1.Provider_PROVIDER_OPENAI, "Robot Voice!") },
	}
	for name, act := range cases {
		t.Run(name, func(t *testing.T) {
			c := h.dial(tenantA)
			act(c)
			c.expectError(voicev1.ErrorCode_ERROR_CODE_INVALID_MESSAGE)
		})
	}

	c, _ := h.startSession(tenantA)
	c.audio(frame(961, 1)) // odd length is not PCM16
	c.expectError(voicev1.ErrorCode_ERROR_CODE_INVALID_MESSAGE)
}

func TestAudioFasterThanRealTimeIsRejected(t *testing.T) {
	h := newHarness(t, options{})
	c, _ := h.startSession(tenantA)
	for range 100 { // 10 s of audio at once; the burst allowance is 2 s
		c.audio(frame(session.MaxFrameBytes, 0))
	}
	c.expectError(voicev1.ErrorCode_ERROR_CODE_RATE_LIMITED)
}

func TestSessionLimitsPerTenant(t *testing.T) {
	h := newHarness(t, options{perTenant: 1})
	h.startSession(tenantA)
	second := h.dial(tenantA)
	second.start(commonv1.Provider_PROVIDER_OPENAI, "")
	second.expectError(voicev1.ErrorCode_ERROR_CODE_SESSION_LIMIT)
}

func TestIdleSessionsExpire(t *testing.T) {
	h := newHarness(t, options{idleTimeout: 300 * time.Millisecond})
	c, p := h.startSession(tenantA)
	c.expectError(voicev1.ErrorCode_ERROR_CODE_SESSION_EXPIRED)
	p.Closed(t)
}

func TestProviderFailureEndsTheSession(t *testing.T) {
	h := newHarness(t, options{})
	c, p := h.startSession(tenantA)
	p.Drop()
	c.expectError(voicev1.ErrorCode_ERROR_CODE_PROVIDER_UNAVAILABLE)
}

func TestShutdownTellsClientsToReconnect(t *testing.T) {
	h := newHarness(t, options{})
	c, p := h.startSession(tenantA)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.gateway.Shutdown(ctx)
	}()
	c.expectError(voicev1.ErrorCode_ERROR_CODE_SHUTTING_DOWN)
	p.Closed(t)

	_, resp, err := websocket.Dial(context.Background(), h.url(), &websocket.DialOptions{
		HTTPHeader:   http.Header{"Authorization": {"Bearer " + h.token(tenantA)}},
		Subprotocols: []string{server.Subprotocol},
	})
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("new sessions must be refused while draining: %v", err)
	}
	_ = resp.Body.Close()
}

func TestAdminEndpoints(t *testing.T) {
	h := newHarness(t, options{})
	c, p := h.startSession(tenantA)
	c.audio(frame(960, 1))
	p.WaitForAudio(t, 960)
	c.send(&voicev1.ClientMessage{Message: &voicev1.ClientMessage_EndSession{EndSession: &voicev1.EndSession{}}})
	p.Closed(t)

	admin := httptest.NewServer(h.gateway.AdminHandler())
	defer admin.Close()
	for path, want := range map[string]string{
		"/healthz": "ok",
		"/readyz":  "ready",
		"/metrics": `voice_audio_bytes_total{direction="in"} 960`,
	} {
		resp, err := http.Get(admin.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), want) {
			t.Fatalf("%s: %d %q", path, resp.StatusCode, body)
		}
	}
}
