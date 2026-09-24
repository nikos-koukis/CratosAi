// Package session runs one voice session: it bridges a client WebSocket
// (jarvis.voice.v1) and a provider realtime connection opened with the
// tenant's own API key. With an orchestrator configured, the model also gets
// Jarvis's tools (see jarvis.go).
//
// Pipeline, one goroutine each:
//
//	client ws ──reader──▶ audioIn ──upstream──▶ provider
//	provider ──events──▶ outbox ──writer──▶ client ws
//
// The reader validates and rate-limits microphone audio. Upstream forwards it
// at once, coalescing only frames that are already waiting, so it adds no
// latency. When the user starts talking over the assistant (barge-in), the
// queued assistant audio is dropped immediately and the provider is told how
// much of the answer the user actually heard.
package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	voicev1 "jarvis.internal/gen/go/jarvis/voice/v1"
	"jarvis.internal/libs/go/usertoken"
	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/voice-gateway/internal/metrics"
	"jarvis.internal/voice-gateway/internal/realtime"
)

const (
	// MaxFrameBytes is 100 ms of PCM16 mono 24 kHz audio.
	MaxFrameBytes    = 100 * realtime.BytesPerMillisecond
	audioBacklog     = 100 // frames (about 2 s at 20 ms)
	outboxCapacity   = 1024
	maxBatchBytes    = 2 * MaxFrameBytes
	keyTimeout       = 3 * time.Second
	writeTimeout     = 5 * time.Second
	providerTimeout  = 5 * time.Second
	finalWriteBudget = 2 * time.Second
	// Clients may send up to 1.5x real time, with 2 s of burst for catch-up
	// after network hiccups.
	audioRateBytesPerSecond = realtime.SampleRate * 2 * 3 / 2
	audioBurstBytes         = 2000 * realtime.BytesPerMillisecond
)

var (
	voicePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	localePattern = regexp.MustCompile(`^[A-Za-z]{2,3}(-[A-Za-z0-9]{1,8}){0,4}$`)
)

// harmlessProviderErrors are expected races (e.g. cancelling a response that
// already finished) and are not shown to clients.
var harmlessProviderErrors = map[string]bool{
	"response_cancel_not_active":               true,
	"conversation_already_has_active_response": true,
}

// Config is the per-gateway session configuration.
type Config struct {
	Providers       map[commonv1.Provider]realtime.Provider
	DefaultProvider commonv1.Provider
	Instructions    string
	StartTimeout    time.Duration
	MaxDuration     time.Duration
	IdleTimeout     time.Duration
	// ToolTimeout bounds one function call on the orchestrator.
	ToolTimeout time.Duration
}

// Deps are the collaborators a session needs.
type Deps struct {
	Keys vaultclient.KeySource
	// Orchestrator provides Jarvis's tools; nil runs sessions without tools.
	Orchestrator orchv1.OrchestratorServiceClient
	Limiter      *Limiter
	Metrics      *metrics.Metrics
	Logger       *slog.Logger
}

// ending says why a session ended and what the client is told.
type ending struct {
	reason string // metrics label
	status websocket.StatusCode
	err    *voicev1.Error // final message, if any
}

func fatal(reason string, status websocket.StatusCode, code voicev1.ErrorCode, message string) ending {
	return ending{reason: reason, status: status, err: &voicev1.Error{Code: code, Message: message, Fatal: true}}
}

var (
	endClientClosed = ending{reason: "client_closed", status: websocket.StatusNormalClosure}
	endClientEnded  = ending{reason: "client_ended", status: websocket.StatusNormalClosure}
)

type session struct {
	id       string
	identity usertoken.Identity
	ws       *websocket.Conn
	cfg      Config
	deps     Deps
	log      *slog.Logger

	providerName string
	locale       string
	conn         *realtime.Conn
	jarvis       *jarvis // nil without tools
	out          *outbox
	audioIn      chan []byte
	bucket       tokenBucket

	mu              sync.Mutex
	currentResponse string
	currentItem     string
	interrupted     map[string]bool

	lastAudio       atomic.Int64 // unix nanos
	speechStoppedAt atomic.Int64 // unix nanos, 0 when not waiting
	bytesIn         atomic.Int64
	bytesOut        atomic.Int64

	endOnce sync.Once
	end     ending
	cancel  context.CancelFunc
}

// Run serves one accepted WebSocket until the session ends. `parent` is
// cancelled when the gateway shuts down.
func Run(parent context.Context, ws *websocket.Conn, identity usertoken.Identity, cfg Config, deps Deps) {
	if cfg.ToolTimeout <= 0 {
		cfg.ToolTimeout = 30 * time.Second
	}
	s := &session{
		id:           uuid.NewString(),
		identity:     identity,
		ws:           ws,
		cfg:          cfg,
		deps:         deps,
		providerName: "none",
		out:          newOutbox(outboxCapacity),
		audioIn:      make(chan []byte, audioBacklog),
		bucket:       newTokenBucket(audioBurstBytes, audioRateBytesPerSecond),
		interrupted:  map[string]bool{},
	}
	s.log = deps.Logger.With("session_id", s.id, "tenant_id", identity.TenantID, "user_id", identity.UserID)
	started := time.Now()

	end := s.run(parent)

	if end.err != nil {
		deps.Metrics.Errors.WithLabelValues(end.err.GetCode().String()).Inc()
		s.writeFinal(end.err)
	}
	_ = ws.Close(end.status, closeReason(end))
	// After the client is gone: it need not wait for the transcript upload.
	s.closeJarvis()
	deps.Metrics.SessionsEnded.WithLabelValues(s.providerName, end.reason).Inc()
	s.log.Info("voice session ended",
		"provider", s.providerName,
		"reason", end.reason,
		"duration_ms", time.Since(started).Milliseconds(),
		"bytes_in", s.bytesIn.Load(),
		"bytes_out", s.bytesOut.Load(),
	)
}

func closeReason(end ending) string {
	if end.err != nil {
		return end.err.GetCode().String()
	}
	return end.reason
}

func (s *session) run(parent context.Context) ending {
	start, bad := s.readStart()
	if bad != nil {
		return *bad
	}
	kind, provider, voice, bad := s.resolve(start)
	if bad != nil {
		return *bad
	}
	s.providerName = provider.Name
	s.locale = start.GetLocale()

	release, ok := s.deps.Limiter.Acquire(s.identity.TenantID)
	if !ok {
		return fatal("session_limit", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_SESSION_LIMIT,
			"too many concurrent voice sessions")
	}
	defer release()

	conn, bad := s.connect(parent, kind, provider, voice)
	if bad != nil {
		return *bad
	}
	s.conn = conn
	defer func() { _ = conn.Close() }()

	active := s.deps.Metrics.SessionsActive.WithLabelValues(provider.Name)
	active.Inc()
	defer active.Dec()

	ready := &voicev1.ServerMessage{Message: &voicev1.ServerMessage_SessionReady{SessionReady: &voicev1.SessionReady{
		SessionId:    s.id,
		Provider:     kind,
		Voice:        voice,
		SampleRateHz: realtime.SampleRate,
	}}}
	if err := s.write(ready); err != nil {
		return endClientClosed
	}
	s.log.Info("voice session started", "provider", provider.Name, "voice", voice)

	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	defer cancel()
	s.lastAudio.Store(time.Now().UnixNano())

	loops := []func(context.Context){s.providerLoop, s.writerLoop, s.upstreamLoop, s.watchdog}
	if s.jarvis != nil {
		loops = append(loops, s.watchLoop)
	}
	var wg sync.WaitGroup
	for _, loop := range loops {
		wg.Go(func() { loop(ctx) })
	}
	// The reader blocks in ws.Read until the socket closes, so it is not
	// waited for; it only ever ends the session.
	go s.readerLoop(ctx)

	<-ctx.Done()
	wg.Wait()
	s.finish(fatal("shutting_down", websocket.StatusGoingAway, voicev1.ErrorCode_ERROR_CODE_SHUTTING_DOWN,
		"the gateway is restarting; reconnect"))
	return s.end
}

// finish records the first reason the session ends and stops the pipeline.
func (s *session) finish(end ending) {
	s.endOnce.Do(func() {
		s.end = end
		if s.cancel != nil {
			s.cancel()
		}
	})
}

// --- start -----------------------------------------------------------------------

func (s *session) readStart() (*voicev1.StartSession, *ending) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.StartTimeout)
	defer cancel()
	msg, err := s.read(ctx)
	if err != nil {
		bad := fatal("no_start", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_INVALID_MESSAGE, err.Error())
		return nil, &bad
	}
	start := msg.GetStartSession()
	if start == nil {
		bad := fatal("protocol_error", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_INVALID_MESSAGE,
			"the first message must be StartSession")
		return nil, &bad
	}
	return start, nil
}

func (s *session) resolve(start *voicev1.StartSession) (commonv1.Provider, realtime.Provider, string, *ending) {
	kind := start.GetProvider()
	if kind == commonv1.Provider_PROVIDER_UNSPECIFIED {
		kind = s.cfg.DefaultProvider
	}
	provider, ok := s.cfg.Providers[kind]
	if !ok {
		bad := fatal("protocol_error", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_INVALID_MESSAGE,
			fmt.Sprintf("provider %s is not enabled on this gateway", kind))
		return 0, realtime.Provider{}, "", &bad
	}
	voice := start.GetVoice()
	if voice == "" {
		voice = provider.DefaultVoice
	}
	if !voicePattern.MatchString(voice) {
		bad := fatal("protocol_error", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_INVALID_MESSAGE,
			"voice must be 1-32 characters of a-z 0-9 _ -")
		return 0, realtime.Provider{}, "", &bad
	}
	if locale := start.GetLocale(); locale != "" && (len(locale) > 35 || !localePattern.MatchString(locale)) {
		bad := fatal("protocol_error", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_INVALID_MESSAGE,
			"locale must be a BCP 47 tag such as el-GR")
		return 0, realtime.Provider{}, "", &bad
	}
	return kind, provider, voice, nil
}

func (s *session) connect(parent context.Context, kind commonv1.Provider, provider realtime.Provider, voice string) (*realtime.Conn, *ending) {
	keyCtx, cancel := context.WithTimeout(parent, keyTimeout)
	key, err := s.deps.Keys.ProviderKey(keyCtx, s.id, s.identity.TenantID, kind)
	cancel()
	if err != nil {
		if errors.Is(err, vaultclient.ErrNoKey) {
			bad := fatal("key_missing", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_PROVIDER_KEY_MISSING,
				fmt.Sprintf("no active %s API key is configured for your workspace", provider.Name))
			return nil, &bad
		}
		s.log.Error("cannot fetch provider key", "provider", provider.Name, "error", err)
		bad := fatal("vault_error", websocket.StatusInternalError, voicev1.ErrorCode_ERROR_CODE_INTERNAL,
			"could not load your API key; try again")
		return nil, &bad
	}
	defer clear(key)

	opts := realtime.Options{
		Voice:            voice,
		Instructions:     s.cfg.Instructions,
		SafetyIdentifier: safetyIdentifier(s.identity),
	}
	if s.jarvis = s.openJarvis(parent, kind); s.jarvis != nil {
		if s.jarvis.instructions != "" {
			opts.Instructions += "\n\n" + s.jarvis.instructions
		}
		opts.Tools = s.jarvis.tools
	}

	started := time.Now()
	conn, err := realtime.Dial(parent, provider, key, opts)
	s.deps.Metrics.ProviderConnect.WithLabelValues(provider.Name).Observe(time.Since(started).Seconds())
	switch {
	case err == nil:
		return conn, nil
	case errors.Is(err, realtime.ErrAuth):
		s.log.Warn("provider rejected the tenant key", "provider", provider.Name, "error", err)
		bad := fatal("provider_auth", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_PROVIDER_AUTH_FAILED,
			fmt.Sprintf("%s rejected your API key; update it in the dashboard", provider.Name))
		return nil, &bad
	case errors.Is(err, realtime.ErrRateLimited):
		bad := fatal("provider_rate_limited", websocket.StatusTryAgainLater, voicev1.ErrorCode_ERROR_CODE_PROVIDER_UNAVAILABLE,
			fmt.Sprintf("%s rate limit reached; try again shortly", provider.Name))
		return nil, &bad
	default:
		s.log.Warn("cannot connect to provider", "provider", provider.Name, "error", err)
		bad := fatal("provider_unavailable", websocket.StatusInternalError, voicev1.ErrorCode_ERROR_CODE_PROVIDER_UNAVAILABLE,
			fmt.Sprintf("could not reach %s; try again", provider.Name))
		return nil, &bad
	}
}

// safetyIdentifier is a stable pseudonymous user id for provider abuse
// detection; it does not reveal the tenant or user.
func safetyIdentifier(identity usertoken.Identity) string {
	sum := sha256.Sum256([]byte("jarvis-voice/v1\x00" + identity.TenantID + "\x00" + identity.UserID))
	return hex.EncodeToString(sum[:16])
}

// --- client → provider --------------------------------------------------------------

func (s *session) readerLoop(ctx context.Context) {
	for {
		msg, err := s.read(context.Background())
		if err != nil {
			if isProtocolError(err) {
				s.finish(fatal("protocol_error", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_INVALID_MESSAGE, err.Error()))
			} else {
				s.finish(endClientClosed)
			}
			return
		}
		switch m := msg.GetMessage().(type) {
		case *voicev1.ClientMessage_InputAudio:
			if end := s.acceptAudio(m.InputAudio.GetPcm16()); end != nil {
				s.finish(*end)
				return
			}
		case *voicev1.ClientMessage_CancelResponse:
			s.interrupt(ctx, true)
		case *voicev1.ClientMessage_EndSession:
			s.finish(endClientEnded)
			return
		default:
			s.finish(fatal("protocol_error", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_INVALID_MESSAGE,
				"unexpected message after StartSession"))
			return
		}
	}
}

func (s *session) acceptAudio(pcm []byte) *ending {
	if len(pcm) == 0 || len(pcm)%2 != 0 || len(pcm) > MaxFrameBytes {
		bad := fatal("protocol_error", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_INVALID_MESSAGE,
			fmt.Sprintf("audio frames must be PCM16 of 1 to %d bytes", MaxFrameBytes))
		return &bad
	}
	if !s.bucket.take(len(pcm), time.Now()) {
		bad := fatal("rate_limited", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_RATE_LIMITED,
			"audio is arriving faster than real time")
		return &bad
	}
	select {
	case s.audioIn <- pcm:
	default:
		bad := fatal("rate_limited", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_RATE_LIMITED,
			"audio backlog exceeded; the provider is not keeping up")
		return &bad
	}
	s.lastAudio.Store(time.Now().UnixNano())
	s.bytesIn.Add(int64(len(pcm)))
	s.deps.Metrics.AudioBytes.WithLabelValues("in").Add(float64(len(pcm)))
	return nil
}

// upstreamLoop forwards audio immediately; frames that are already waiting
// are merged into one append, so batching never delays audio.
func (s *session) upstreamLoop(ctx context.Context) {
	for {
		var batch []byte
		select {
		case <-ctx.Done():
			return
		case batch = <-s.audioIn:
		}
	drain:
		for len(batch) < maxBatchBytes {
			select {
			case more := <-s.audioIn:
				batch = append(batch, more...)
			default:
				break drain
			}
		}
		writeCtx, cancel := context.WithTimeout(ctx, providerTimeout)
		err := s.conn.AppendAudio(writeCtx, batch)
		cancel()
		if err != nil {
			s.providerFailed(ctx, err)
			return
		}
	}
}

// --- provider → client --------------------------------------------------------------

func (s *session) providerLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-s.conn.Events():
			if !ok {
				s.providerFailed(ctx, s.conn.Err())
				return
			}
			if err := s.handleEvent(ctx, event); err != nil {
				s.finish(fatal("client_too_slow", websocket.StatusPolicyViolation, voicev1.ErrorCode_ERROR_CODE_INTERNAL, err.Error()))
				return
			}
		// Nil channels (no Jarvis tools) are never ready.
		case result := <-s.jarvisResults():
			s.jarvisResult(ctx, result)
		case notice := <-s.jarvisNotices():
			s.jarvisNotice(ctx, notice)
		}
	}
}

func (s *session) jarvisResults() <-chan toolResult {
	if s.jarvis == nil {
		return nil
	}
	return s.jarvis.results
}

func (s *session) jarvisNotices() <-chan *orchv1.ConversationEvent {
	if s.jarvis == nil {
		return nil
	}
	return s.jarvis.notices
}

func (s *session) handleEvent(ctx context.Context, event realtime.Event) error {
	switch e := event.(type) {
	case realtime.AudioDelta:
		s.mu.Lock()
		dropped := s.interrupted[e.ResponseID]
		if !dropped {
			s.currentItem = e.ItemID
			if s.currentResponse == "" {
				s.currentResponse = e.ResponseID
			}
		}
		s.mu.Unlock()
		if dropped || len(e.PCM) == 0 {
			return nil
		}
		return s.out.push(outItem{
			msg: &voicev1.ServerMessage{Message: &voicev1.ServerMessage_OutputAudio{OutputAudio: &voicev1.OutputAudio{
				Pcm16: e.PCM, ResponseId: e.ResponseID,
			}}},
			itemID:     e.ItemID,
			audioBytes: len(e.PCM),
			enqueued:   time.Now(),
		})

	case realtime.TranscriptDelta:
		s.jarvisTranscript(e)
		role := voicev1.Role_ROLE_USER
		if e.Role == realtime.RoleAssistant {
			role = voicev1.Role_ROLE_ASSISTANT
		}
		return s.push(&voicev1.ServerMessage{Message: &voicev1.ServerMessage_Transcript{Transcript: &voicev1.Transcript{
			Role: role, Text: e.Text, Final: e.Final, ItemId: e.ItemID,
		}}})

	case realtime.SpeechStarted:
		// The provider cancels its own response (server VAD with
		// interrupt_response); the gateway drops what is queued.
		s.interrupt(ctx, false)
		s.jarvisSpeechStarted()
		return s.push(&voicev1.ServerMessage{Message: &voicev1.ServerMessage_SpeechStarted{SpeechStarted: &voicev1.SpeechStarted{}}})

	case realtime.SpeechStopped:
		s.speechStoppedAt.Store(time.Now().UnixNano())
		s.jarvisSpeechStopped(e.ItemID)
		return s.push(&voicev1.ServerMessage{Message: &voicev1.ServerMessage_SpeechStopped{SpeechStopped: &voicev1.SpeechStopped{}}})

	case realtime.ResponseCreated:
		s.mu.Lock()
		s.currentResponse = e.ResponseID
		s.mu.Unlock()
		s.jarvisResponseCreated(e.ResponseID)

	case realtime.ResponseDone:
		s.mu.Lock()
		cancelled := s.interrupted[e.ResponseID]
		delete(s.interrupted, e.ResponseID)
		if s.currentResponse == e.ResponseID {
			s.currentResponse = ""
		}
		s.mu.Unlock()
		status := responseStatus(e.Status)
		if cancelled {
			status = voicev1.ResponseStatus_RESPONSE_STATUS_CANCELLED
		}
		s.jarvisResponseDone(ctx, e)
		return s.push(&voicev1.ServerMessage{Message: &voicev1.ServerMessage_ResponseDone{ResponseDone: &voicev1.ResponseDone{
			ResponseId: e.ResponseID, Status: status,
		}}})

	case realtime.FunctionCall:
		s.jarvisFunctionCall(ctx, e)

	case realtime.ProviderError:
		s.jarvisProviderError(ctx)
		if harmlessProviderErrors[e.Code] {
			s.log.Debug("ignored provider error", "code", e.Code)
			return nil
		}
		s.log.Warn("provider error", "type", e.Type, "code", e.Code, "message", e.Message)
		s.deps.Metrics.Errors.WithLabelValues(voicev1.ErrorCode_ERROR_CODE_PROVIDER_ERROR.String()).Inc()
		return s.push(&voicev1.ServerMessage{Message: &voicev1.ServerMessage_Error{Error: &voicev1.Error{
			Code: voicev1.ErrorCode_ERROR_CODE_PROVIDER_ERROR, Message: e.Message,
		}}})
	}
	return nil
}

// interrupt drops queued assistant audio and tells the provider how much of
// the current item the user heard. With cancelResponse it also stops the
// provider's response (a user tap; VAD barge-in cancels on its own).
func (s *session) interrupt(ctx context.Context, cancelResponse bool) {
	s.mu.Lock()
	response, item := s.currentResponse, s.currentItem
	if response != "" {
		s.interrupted[response] = true
	}
	s.mu.Unlock()

	dropped, delivered := s.out.dropAudio(item)
	providerCtx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	if cancelResponse && response != "" {
		if err := s.conn.CancelResponse(providerCtx); err != nil {
			s.log.Warn("cannot cancel provider response", "error", err)
		}
	}
	if item != "" && dropped > 0 {
		if err := s.conn.Truncate(providerCtx, item, delivered/realtime.BytesPerMillisecond); err != nil {
			s.log.Warn("cannot truncate provider item", "error", err)
		}
	}
}

func (s *session) writerLoop(ctx context.Context) {
	for {
		item, err := s.out.pop(ctx)
		if err != nil {
			return
		}
		if err := s.write(item.msg); err != nil {
			s.finish(endClientClosed)
			return
		}
		if item.audioBytes > 0 {
			s.out.markDelivered(item)
			s.bytesOut.Add(int64(item.audioBytes))
			s.deps.Metrics.AudioBytes.WithLabelValues("out").Add(float64(item.audioBytes))
			s.deps.Metrics.ForwardLatency.Observe(time.Since(item.enqueued).Seconds())
			if stopped := s.speechStoppedAt.Swap(0); stopped != 0 {
				s.deps.Metrics.ResponseLatency.WithLabelValues(s.providerName).
					Observe(time.Since(time.Unix(0, stopped)).Seconds())
			}
		}
	}
}

func (s *session) watchdog(ctx context.Context) {
	deadline := time.NewTimer(s.cfg.MaxDuration)
	defer deadline.Stop()
	tick := min(time.Second, s.cfg.IdleTimeout/4)
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			s.finish(fatal("max_duration", websocket.StatusGoingAway, voicev1.ErrorCode_ERROR_CODE_SESSION_EXPIRED,
				"the session reached its maximum duration; reconnect to continue"))
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, s.lastAudio.Load())) > s.cfg.IdleTimeout {
				s.finish(fatal("idle", websocket.StatusGoingAway, voicev1.ErrorCode_ERROR_CODE_SESSION_EXPIRED,
					"no audio received; the session idled out"))
				return
			}
		}
	}
}

func (s *session) providerFailed(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return // already ending
	}
	s.log.Warn("provider connection lost", "error", err)
	s.finish(fatal("provider_lost", websocket.StatusInternalError, voicev1.ErrorCode_ERROR_CODE_PROVIDER_UNAVAILABLE,
		"the connection to the provider was lost; reconnect"))
}

// --- framing ---------------------------------------------------------------------------

type protocolError struct{ msg string }

func (e protocolError) Error() string { return e.msg }

func isProtocolError(err error) bool {
	var p protocolError
	return errors.As(err, &p)
}

func (s *session) read(ctx context.Context) (*voicev1.ClientMessage, error) {
	kind, data, err := s.ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	if kind != websocket.MessageBinary {
		return nil, protocolError{"frames must be binary protobuf ClientMessage"}
	}
	msg := &voicev1.ClientMessage{}
	if err := proto.Unmarshal(data, msg); err != nil {
		return nil, protocolError{"malformed ClientMessage"}
	}
	return msg, nil
}

func (s *session) push(msg *voicev1.ServerMessage) error {
	return s.out.push(outItem{msg: msg, enqueued: time.Now()})
}

func (s *session) write(msg *voicev1.ServerMessage) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	return s.ws.Write(ctx, websocket.MessageBinary, data)
}

func (s *session) writeFinal(e *voicev1.Error) {
	data, err := proto.Marshal(&voicev1.ServerMessage{Message: &voicev1.ServerMessage_Error{Error: e}})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), finalWriteBudget)
	defer cancel()
	_ = s.ws.Write(ctx, websocket.MessageBinary, data)
}

func responseStatus(status realtime.Status) voicev1.ResponseStatus {
	switch status {
	case realtime.StatusCompleted:
		return voicev1.ResponseStatus_RESPONSE_STATUS_COMPLETED
	case realtime.StatusCancelled:
		return voicev1.ResponseStatus_RESPONSE_STATUS_CANCELLED
	default:
		return voicev1.ResponseStatus_RESPONSE_STATUS_FAILED
	}
}

// --- rate limiting ---------------------------------------------------------------------

// tokenBucket limits audio bytes per second; used from the reader goroutine only.
type tokenBucket struct {
	capacity, tokens, perSecond float64
	last                        time.Time
}

func newTokenBucket(capacity, perSecond int) tokenBucket {
	return tokenBucket{capacity: float64(capacity), tokens: float64(capacity), perSecond: float64(perSecond)}
}

func (b *tokenBucket) take(n int, now time.Time) bool {
	if !b.last.IsZero() {
		b.tokens = min(b.capacity, b.tokens+now.Sub(b.last).Seconds()*b.perSecond)
	}
	b.last = now
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}
