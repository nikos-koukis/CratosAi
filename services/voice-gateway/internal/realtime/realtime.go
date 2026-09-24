// Package realtime speaks the OpenAI Realtime WebSocket protocol, which both
// OpenAI (gpt-realtime) and xAI (Grok Voice Agent API) implement, and turns
// the provider's server events into a small typed event stream.
//
// The two providers differ only in the shape of session.update and in a few
// event names; Dialect captures those differences.
package realtime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// SampleRate is the only PCM16 rate used end to end (both providers support it).
const SampleRate = 24000

// BytesPerMillisecond of PCM16 mono audio at SampleRate.
const BytesPerMillisecond = SampleRate * 2 / 1000

const (
	handshakeTimeout = 10 * time.Second
	eventBuffer      = 256
	readLimit        = 8 << 20
)

// Dialect selects the provider-specific parts of the protocol.
type Dialect int

const (
	// DialectOpenAI is OpenAI's GA Realtime API.
	DialectOpenAI Dialect = iota
	// DialectXAI is xAI's Grok Voice Agent API.
	DialectXAI
)

// Provider is the static configuration of one provider.
type Provider struct {
	// Name for logs and metrics ("openai", "xai").
	Name string
	// WebSocket URL including the model query parameter.
	URL     string
	Dialect Dialect
	// Voice used when the client does not choose one.
	DefaultVoice string
	// Input transcription model (OpenAI only; xAI transcribes by default).
	TranscriptionModel string
	// Silence that ends the user's turn, in milliseconds.
	VADSilenceMs int
}

// Options are per-session settings.
type Options struct {
	Voice        string
	Instructions string
	// SafetyIdentifier is a stable, non-reversible end-user id that OpenAI
	// uses for abuse detection (sent as OpenAI-Safety-Identifier).
	SafetyIdentifier string
	// Tools the model may call; calls arrive as FunctionCall events.
	Tools []Tool
}

// Tool is a function the model may call.
type Tool struct {
	Name        string
	Description string
	// Parameters is the JSON Schema (an object schema) of the arguments.
	Parameters json.RawMessage
}

// Errors returned by Dial; wrap them to keep details.
var (
	ErrAuth        = errors.New("provider rejected the API key")
	ErrRateLimited = errors.New("provider rate limit reached")
	ErrUnavailable = errors.New("provider unavailable")
)

// Role of a transcript.
type Role int

const (
	RoleUser Role = iota + 1
	RoleAssistant
)

// Status of a finished response.
type Status int

const (
	StatusCompleted Status = iota + 1
	StatusCancelled
	StatusFailed
)

// Event is one of the concrete event types below.
type Event interface{ isEvent() }

// AudioDelta is a chunk of assistant speech.
type AudioDelta struct {
	ResponseID string
	ItemID     string
	PCM        []byte
}

// TranscriptDelta is text for the user or the assistant.
type TranscriptDelta struct {
	Role   Role
	ItemID string
	Text   string
	// Final means Text is the complete transcript of the item.
	Final bool
}

// SpeechStarted: the provider's VAD heard the user start speaking.
type SpeechStarted struct{ ItemID string }

// SpeechStopped: the provider's VAD heard the user stop speaking.
type SpeechStopped struct{ ItemID string }

// ResponseCreated: the assistant started a response.
type ResponseCreated struct{ ResponseID string }

// ResponseDone: the assistant finished, or abandoned, a response.
type ResponseDone struct {
	ResponseID string
	Status     Status
	// Calls are the response's complete function calls, which were also
	// announced as FunctionCall events (unless the provider skipped those).
	Calls []FunctionCall
}

// FunctionCall: the model called a tool; its arguments are complete. The
// result goes back with SendFunctionOutput, then CreateResponse.
type FunctionCall struct {
	ResponseID string
	ItemID     string
	CallID     string
	Name       string
	// Arguments is a JSON object as the model wrote it (not validated).
	Arguments string
}

// ProviderError is an error event; the session usually stays open.
type ProviderError struct{ Type, Code, Message string }

func (AudioDelta) isEvent()      {}
func (TranscriptDelta) isEvent() {}
func (SpeechStarted) isEvent()   {}
func (SpeechStopped) isEvent()   {}
func (ResponseCreated) isEvent() {}
func (ResponseDone) isEvent()    {}
func (FunctionCall) isEvent()    {}
func (ProviderError) isEvent()   {}

func (e ProviderError) Error() string {
	return fmt.Sprintf("provider error %s/%s: %s", e.Type, e.Code, e.Message)
}

// Conn is an open realtime session with a provider.
type Conn struct {
	ws        *websocket.Conn
	provider  Provider
	events    chan Event
	done      chan struct{}
	closeOnce sync.Once
	writeMu   sync.Mutex

	errMu   sync.Mutex
	readErr error
}

// Dial connects, configures the session and starts reading events. apiKey is
// only used for the handshake; the caller should clear it afterwards.
func Dial(ctx context.Context, p Provider, apiKey []byte, opts Options) (*Conn, error) {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+string(apiKey))
	if p.Dialect == DialectOpenAI && opts.SafetyIdentifier != "" {
		header.Set("OpenAI-Safety-Identifier", opts.SafetyIdentifier)
	}

	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	ws, resp, err := websocket.Dial(ctx, p.URL, &websocket.DialOptions{
		HTTPHeader:      header,
		CompressionMode: websocket.CompressionDisabled,
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, classifyDialError(resp, err)
	}
	ws.SetReadLimit(readLimit)

	c := &Conn{ws: ws, provider: p, events: make(chan Event, eventBuffer), done: make(chan struct{})}
	if err := c.handshake(ctx, opts); err != nil {
		_ = ws.CloseNow()
		return nil, err
	}
	go c.readLoop()
	return c, nil
}

func classifyDialError(resp *http.Response, err error) error {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("%w (HTTP %d)", ErrAuth, resp.StatusCode)
		case http.StatusTooManyRequests:
			return fmt.Errorf("%w (HTTP %d)", ErrRateLimited, resp.StatusCode)
		}
		return fmt.Errorf("%w (HTTP %d): %v", ErrUnavailable, resp.StatusCode, err)
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

// handshake waits for session.created, sends session.update and waits for
// session.updated. An error event during the handshake fails the dial.
func (c *Conn) handshake(ctx context.Context, opts Options) error {
	if err := c.await(ctx, "session.created"); err != nil {
		return err
	}
	update, err := json.Marshal(sessionUpdate(c.provider, opts))
	if err != nil {
		return fmt.Errorf("encode session.update: %w", err)
	}
	if err := c.ws.Write(ctx, websocket.MessageText, update); err != nil {
		return fmt.Errorf("%w: send session.update: %v", ErrUnavailable, err)
	}
	return c.await(ctx, "session.updated")
}

func (c *Conn) await(ctx context.Context, want string) error {
	for {
		_, data, err := c.ws.Read(ctx)
		if err != nil {
			return fmt.Errorf("%w: waiting for %s: %v", ErrUnavailable, want, err)
		}
		var event wireEvent
		if err := json.Unmarshal(data, &event); err != nil {
			return fmt.Errorf("%w: malformed event: %v", ErrUnavailable, err)
		}
		switch event.Type {
		case want:
			return nil
		case "error":
			perr := event.providerError()
			if isAuthError(perr) {
				return fmt.Errorf("%w: %s", ErrAuth, perr.Message)
			}
			return fmt.Errorf("%w: %v", ErrUnavailable, perr)
		}
	}
}

func isAuthError(e ProviderError) bool {
	return strings.Contains(e.Code, "api_key") ||
		strings.Contains(e.Type, "authentication") ||
		strings.Contains(e.Code, "unauthorized")
}

// Events delivers provider events until the connection closes, then closes.
func (c *Conn) Events() <-chan Event { return c.events }

// Err reports why the event stream ended (nil after a normal close).
func (c *Conn) Err() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.readErr
}

func (c *Conn) readLoop() {
	defer close(c.events)
	for {
		_, data, err := c.ws.Read(context.Background())
		if err != nil {
			if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
				c.errMu.Lock()
				c.readErr = fmt.Errorf("%w: %v", ErrUnavailable, err)
				c.errMu.Unlock()
			}
			return
		}
		var wire wireEvent
		var event Event
		if err := json.Unmarshal(data, &wire); err != nil {
			event = ProviderError{Type: "gateway", Code: "malformed_event", Message: err.Error()}
		} else if mapped, ok := wire.toEvent(); ok {
			event = mapped
		} else {
			continue
		}
		// Never block forever on a consumer that has gone away.
		select {
		case c.events <- event:
		case <-c.done:
			return
		}
	}
}

// AppendAudio sends PCM16 audio to the provider's input buffer.
func (c *Conn) AppendAudio(ctx context.Context, pcm []byte) error {
	const prefix, suffix = `{"type":"input_audio_buffer.append","audio":"`, `"}`
	// Base64 has no characters that need JSON escaping.
	message := make([]byte, 0, len(prefix)+base64.StdEncoding.EncodedLen(len(pcm))+len(suffix))
	message = append(message, prefix...)
	message = base64.StdEncoding.AppendEncode(message, pcm)
	message = append(message, suffix...)
	return c.write(ctx, message)
}

// CancelResponse stops the response in progress, if any.
func (c *Conn) CancelResponse(ctx context.Context) error {
	return c.write(ctx, []byte(`{"type":"response.cancel"}`))
}

// Truncate tells the provider how much of an assistant item the user heard,
// so the conversation history matches what was actually played.
func (c *Conn) Truncate(ctx context.Context, itemID string, audioEndMs int) error {
	message, err := json.Marshal(map[string]any{
		"type":          "conversation.item.truncate",
		"item_id":       itemID,
		"content_index": 0,
		"audio_end_ms":  audioEndMs,
	})
	if err != nil {
		return err
	}
	return c.write(ctx, message)
}

// SendFunctionOutput adds the result of a function call to the conversation.
// The model reacts to it after CreateResponse.
func (c *Conn) SendFunctionOutput(ctx context.Context, callID, output string) error {
	return c.writeJSON(ctx, map[string]any{
		"type": "conversation.item.create",
		"item": map[string]any{"type": "function_call_output", "call_id": callID, "output": output},
	})
}

// CreateResponse asks the model to respond now (after function outputs or an
// injected message). Only one response may be in progress at a time.
func (c *Conn) CreateResponse(ctx context.Context) error {
	return c.write(ctx, []byte(`{"type":"response.create"}`))
}

// InjectMessage adds a message from Jarvis itself (not the user) to the
// conversation, e.g. "a background task finished". OpenAI takes it as a
// system message; xAI accepts only user messages, so there the text must
// say where it comes from (the orchestrator prefixes "[Jarvis]").
func (c *Conn) InjectMessage(ctx context.Context, text string) error {
	role := "system"
	if c.provider.Dialect == DialectXAI {
		role = "user"
	}
	return c.writeJSON(ctx, map[string]any{
		"type": "conversation.item.create",
		"item": map[string]any{
			"type":    "message",
			"role":    role,
			"content": []map[string]string{{"type": "input_text", "text": text}},
		},
	})
}

func (c *Conn) writeJSON(ctx context.Context, event any) error {
	message, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return c.write(ctx, message)
}

func (c *Conn) write(ctx context.Context, message []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.ws.Write(ctx, websocket.MessageText, message); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

// Close ends the session. Safe to call more than once.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		err = c.ws.Close(websocket.StatusNormalClosure, "")
	})
	return err
}

// --- wire format -------------------------------------------------------------

type wireEvent struct {
	Type       string `json:"type"`
	Delta      string `json:"delta"`
	Transcript string `json:"transcript"`
	ResponseID string `json:"response_id"`
	ItemID     string `json:"item_id"`
	CallID     string `json:"call_id"`
	Name       string `json:"name"`
	Arguments  string `json:"arguments"`
	Response   *struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Output []struct {
			Type      string `json:"type"`
			ID        string `json:"id"`
			CallID    string `json:"call_id"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"output"`
	} `json:"response"`
	Error *struct {
		Type    string `json:"type"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (w *wireEvent) providerError() ProviderError {
	if w.Error == nil {
		return ProviderError{Type: "unknown", Message: "error event without details"}
	}
	return ProviderError{Type: w.Error.Type, Code: w.Error.Code, Message: w.Error.Message}
}

// toEvent maps provider events we use; everything else is ignored.
func (w *wireEvent) toEvent() (Event, bool) {
	switch w.Type {
	// GA name first; "response.audio.delta" is the older name xAI also emits.
	case "response.output_audio.delta", "response.audio.delta":
		pcm, err := base64.StdEncoding.DecodeString(w.Delta)
		if err != nil {
			return ProviderError{Type: "gateway", Code: "malformed_audio", Message: err.Error()}, true
		}
		return AudioDelta{ResponseID: w.ResponseID, ItemID: w.ItemID, PCM: pcm}, true
	case "response.output_audio_transcript.delta", "response.audio_transcript.delta":
		return TranscriptDelta{Role: RoleAssistant, ItemID: w.ItemID, Text: w.Delta}, true
	case "response.output_audio_transcript.done", "response.audio_transcript.done":
		return TranscriptDelta{Role: RoleAssistant, ItemID: w.ItemID, Text: w.Transcript, Final: true}, true
	case "conversation.item.input_audio_transcription.delta":
		return TranscriptDelta{Role: RoleUser, ItemID: w.ItemID, Text: w.Delta}, true
	case "conversation.item.input_audio_transcription.completed":
		return TranscriptDelta{Role: RoleUser, ItemID: w.ItemID, Text: w.Transcript, Final: true}, true
	case "input_audio_buffer.speech_started":
		return SpeechStarted{ItemID: w.ItemID}, true
	case "input_audio_buffer.speech_stopped":
		return SpeechStopped{ItemID: w.ItemID}, true
	case "response.created":
		if w.Response != nil {
			return ResponseCreated{ResponseID: w.Response.ID}, true
		}
	case "response.done":
		if w.Response != nil {
			done := ResponseDone{ResponseID: w.Response.ID, Status: parseStatus(w.Response.Status)}
			for _, item := range w.Response.Output {
				if item.Type == "function_call" && item.CallID != "" && item.Name != "" {
					done.Calls = append(done.Calls, FunctionCall{ResponseID: w.Response.ID, ItemID: item.ID,
						CallID: item.CallID, Name: item.Name, Arguments: item.Arguments})
				}
			}
			return done, true
		}
	case "response.function_call_arguments.done":
		if w.CallID != "" && w.Name != "" {
			return FunctionCall{ResponseID: w.ResponseID, ItemID: w.ItemID, CallID: w.CallID, Name: w.Name,
				Arguments: w.Arguments}, true
		}
	case "error":
		return w.providerError(), true
	}
	return nil, false
}

func parseStatus(status string) Status {
	switch status {
	case "completed":
		return StatusCompleted
	case "cancelled":
		return StatusCancelled
	default:
		return StatusFailed
	}
}

// --- session.update ------------------------------------------------------------

type audioFormat struct {
	Type string `json:"type"`
	Rate int    `json:"rate"`
}

var pcm24k = audioFormat{Type: "audio/pcm", Rate: SampleRate}

type turnDetection struct {
	Type              string   `json:"type"`
	Threshold         *float64 `json:"threshold,omitempty"`
	PrefixPaddingMs   int      `json:"prefix_padding_ms,omitempty"`
	SilenceDurationMs int      `json:"silence_duration_ms,omitempty"`
	CreateResponse    *bool    `json:"create_response,omitempty"`
	InterruptResponse *bool    `json:"interrupt_response,omitempty"`
}

type sessionUpdateEvent struct {
	Type    string `json:"type"`
	Session any    `json:"session"`
}

// sessionUpdate configures server-side VAD (the provider decides when the
// user has finished and interrupts itself on barge-in) and 24 kHz PCM16 in
// both directions.
func sessionUpdate(p Provider, opts Options) sessionUpdateEvent {
	voice := opts.Voice
	if voice == "" {
		voice = p.DefaultVoice
	}
	yes := true
	vad := turnDetection{
		Type:              "server_vad",
		PrefixPaddingMs:   300,
		SilenceDurationMs: p.VADSilenceMs,
	}

	var session map[string]any
	switch p.Dialect {
	case DialectXAI:
		// xAI keeps voice and turn_detection at the top of the session and
		// has no session.type.
		session = map[string]any{
			"voice":          voice,
			"instructions":   opts.Instructions,
			"turn_detection": vad,
			"audio": map[string]any{
				"input":  map[string]any{"format": pcm24k},
				"output": map[string]any{"format": pcm24k},
			},
		}
	default:
		threshold := 0.5
		vad.Threshold = &threshold
		vad.CreateResponse = &yes
		vad.InterruptResponse = &yes
		input := map[string]any{"format": pcm24k, "turn_detection": vad}
		if p.TranscriptionModel != "" {
			input["transcription"] = map[string]any{"model": p.TranscriptionModel}
		}
		session = map[string]any{
			"type":              "realtime",
			"instructions":      opts.Instructions,
			"output_modalities": []string{"audio"},
			"audio": map[string]any{
				"input":  input,
				"output": map[string]any{"format": pcm24k, "voice": voice},
			},
		}
	}
	// Both providers declare function tools the same way.
	if len(opts.Tools) > 0 {
		tools := make([]map[string]any, 0, len(opts.Tools))
		for _, t := range opts.Tools {
			tools = append(tools, map[string]any{
				"type":        "function",
				"name":        t.Name,
				"description": t.Description,
				"parameters":  t.Parameters,
			})
		}
		session["tools"] = tools
		session["tool_choice"] = "auto"
	}
	return sessionUpdateEvent{Type: "session.update", Session: session}
}
