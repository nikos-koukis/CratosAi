package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
)

const (
	silenceAmplitude = 500 // |sample| below this counts as silence
	endOfSpeech      = 600 * time.Millisecond
)

// echoProvider is a local stand-in for OpenAI/xAI that speaks the same
// realtime protocol: it detects speech by loudness and plays it back, so the
// whole pipeline (app → gateway → vault → provider) can be exercised without
// paying for an LLM. Point GATEWAY_OPENAI_URL at it.
//
// With -tool it also exercises Jarvis's tools: after each utterance it calls
// that tool (as the model would), waits for the gateway to return the result
// and ask for a response, then speaks the result as its transcript. Messages
// Jarvis puts into the conversation (e.g. a background task finished) are
// spoken the same way. When a result asks for a confirmation, your next
// utterance confirms it (confirm_action). With -confirm-early it also tries
// to confirm at once, before you answer, as a prompt injection would; Jarvis
// must refuse that.
func echoProvider(args []string) error {
	flags := flag.NewFlagSet("echo-provider", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:9900", "address (loopback only)")
	key := flags.String("key", "", "API key it accepts (required; must match the key stored in the vault)")
	tool := flags.String("tool", "", "tool to call after each utterance, e.g. recall_memory (needs the orchestrator)")
	toolArgs := flags.String("tool-args", "{}", "arguments of -tool, a JSON object")
	confirmEarly := flags.Bool("confirm-early", false, "also try to confirm before the user answers (must be refused)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *key == "" {
		return fmt.Errorf("-key is required")
	}
	if !json.Valid([]byte(*toolArgs)) {
		return fmt.Errorf("-tool-args must be a JSON object")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("-listen must be a loopback address")
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+*key {
			log.Warn("rejected key")
			http.Error(w, `{"error":{"type":"invalid_request_error","code":"invalid_api_key"}}`, http.StatusUnauthorized)
			return
		}
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		ws.SetReadLimit(8 << 20)
		log.Info("session opened")
		e := &echo{ws: ws, log: log, tool: *tool, toolArgs: *toolArgs, confirmEarly: *confirmEarly}
		e.run(r.Context())
		log.Info("session closed")
	})
	log.Info("echo provider listening", "url", "ws://"+*listen+"/v1/realtime", "tool", *tool)
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	return server.ListenAndServe()
}

// echo is one fake provider session.
type echo struct {
	ws           *websocket.Conn
	log          *slog.Logger
	tool         string
	toolArgs     string
	confirmEarly bool

	toolDeclared bool
	confirmation string // a confirmation the last results asked for
	triedEarly   bool
	recording    []byte   // the last utterance
	said         []string // tool outputs and Jarvis messages to speak next
}

type clientEvent struct {
	Type    string `json:"type"`
	Audio   string `json:"audio"`
	Session struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	} `json:"session"`
	Item struct {
		Type    string `json:"type"`
		CallID  string `json:"call_id"`
		Output  string `json:"output"`
		Role    string `json:"role"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	} `json:"item"`
}

func (e *echo) send(ctx context.Context, event map[string]any) error {
	data, _ := json.Marshal(event)
	return e.ws.Write(ctx, websocket.MessageText, data)
}

func (e *echo) run(ctx context.Context) {
	defer func() { _ = e.ws.CloseNow() }()
	if e.send(ctx, map[string]any{"type": "session.created"}) != nil {
		return
	}
	var silentFor time.Duration
	speaking := false
	for {
		_, data, err := e.ws.Read(ctx)
		if err != nil {
			return
		}
		var event clientEvent
		if json.Unmarshal(data, &event) != nil {
			continue
		}
		switch event.Type {
		case "session.update":
			for _, t := range event.Session.Tools {
				e.toolDeclared = e.toolDeclared || t.Name == e.tool
			}
			if e.tool != "" && !e.toolDeclared {
				e.log.Warn("the session does not offer -tool; only echoing", "tool", e.tool,
					"offered", len(event.Session.Tools))
			}
			if e.send(ctx, map[string]any{"type": "session.updated"}) != nil {
				return
			}
		case "conversation.item.create":
			switch event.Item.Type {
			case "function_call_output":
				e.log.Info("tool result", "call_id", event.Item.CallID, "output", truncate(event.Item.Output, 300))
				e.said = append(e.said, "Tool result: "+event.Item.Output)
				var result struct {
					Status         string `json:"status"`
					ConfirmationID string `json:"confirmation_id"`
				}
				if json.Unmarshal([]byte(event.Item.Output), &result) == nil && result.Status == "needs_confirmation" {
					e.confirmation, e.triedEarly = result.ConfirmationID, false
				}
			case "message":
				for _, c := range event.Item.Content {
					e.log.Info("message from Jarvis", "role", event.Item.Role, "text", truncate(c.Text, 300))
					e.said = append(e.said, c.Text)
				}
			}
		case "response.create":
			if e.confirmEarly && e.confirmation != "" && !e.triedEarly {
				// The response that should ask the question confirms instead.
				e.triedEarly = true
				e.log.Info("trying to confirm before the user answered", "confirmation_id", e.confirmation)
				if err := e.callTool(ctx, "confirm_action", fmt.Sprintf(`{"confirmation_id":%q}`, e.confirmation)); err != nil {
					return
				}
				continue
			}
			if err := e.speak(ctx, strings.Join(e.said, " ")); err != nil {
				return
			}
			e.said = nil
		case "input_audio_buffer.append":
			pcm, err := base64.StdEncoding.DecodeString(event.Audio)
			if err != nil {
				continue
			}
			loud := isLoud(pcm)
			switch {
			case loud && !speaking:
				speaking, silentFor, e.recording = true, 0, nil
				_ = e.send(ctx, map[string]any{"type": "input_audio_buffer.speech_started", "item_id": "item_" + uuid.NewString()[:8]})
			case !loud && speaking:
				silentFor += time.Duration(len(pcm)/48) * time.Millisecond
			case loud:
				silentFor = 0
			}
			if speaking {
				e.recording = append(e.recording, pcm...)
			}
			if speaking && silentFor >= endOfSpeech {
				speaking = false
				if err := e.endOfTurn(ctx); err != nil {
					return
				}
			}
		}
	}
}

// endOfTurn answers an utterance: a tool call when -tool is offered,
// otherwise the echo.
func (e *echo) endOfTurn(ctx context.Context) error {
	item := "item_" + uuid.NewString()[:8]
	for _, step := range []map[string]any{
		{"type": "input_audio_buffer.speech_stopped", "item_id": item},
		{"type": "conversation.item.input_audio_transcription.completed", "item_id": item,
			"transcript": fmt.Sprintf("(%.1f seconds of speech)", float64(len(e.recording))/48000)},
	} {
		if err := e.send(ctx, step); err != nil {
			return err
		}
	}
	switch {
	case e.confirmation != "":
		// The user answered the question: confirm.
		id := e.confirmation
		e.confirmation = ""
		return e.callTool(ctx, "confirm_action", fmt.Sprintf(`{"confirmation_id":%q}`, id))
	case e.tool == "" || !e.toolDeclared:
		e.log.Info("echoed", "seconds", float64(len(e.recording))/48000)
		return e.speak(ctx, "Echo: this is what you said.")
	default:
		return e.callTool(ctx, e.tool, e.toolArgs)
	}
}

// callTool emits a response that only calls a tool; the gateway sends the
// output, then response.create.
func (e *echo) callTool(ctx context.Context, name, arguments string) error {
	response, callItem, call := "resp_"+uuid.NewString()[:8], "item_"+uuid.NewString()[:8], "call_"+uuid.NewString()[:8]
	e.log.Info("calling tool", "tool", name, "call_id", call)
	for _, step := range []map[string]any{
		{"type": "response.created", "response": map[string]any{"id": response}},
		{"type": "response.function_call_arguments.done", "response_id": response, "item_id": callItem,
			"call_id": call, "name": name, "arguments": arguments},
		{"type": "response.done", "response": map[string]any{"id": response, "status": "completed",
			"output": []map[string]any{{"type": "function_call", "id": callItem, "call_id": call, "name": name,
				"arguments": arguments, "status": "completed"}}}},
	} {
		if err := e.send(ctx, step); err != nil {
			return err
		}
	}
	return nil
}

// speak plays the last utterance back (or a short tone) as a response whose
// transcript is text, in 100 ms chunks.
func (e *echo) speak(ctx context.Context, text string) error {
	audio := e.recording
	if len(audio) == 0 {
		audio = tone(300 * time.Millisecond)
	}
	response, item := "resp_"+uuid.NewString()[:8], "item_"+uuid.NewString()[:8]
	if err := e.send(ctx, map[string]any{"type": "response.created", "response": map[string]any{"id": response}}); err != nil {
		return err
	}
	for offset := 0; offset < len(audio); offset += 4800 {
		chunk := audio[offset:min(offset+4800, len(audio))]
		if err := e.send(ctx, map[string]any{
			"type": "response.output_audio.delta", "response_id": response, "item_id": item,
			"delta": base64.StdEncoding.EncodeToString(chunk),
		}); err != nil {
			return err
		}
	}
	for _, step := range []map[string]any{
		{"type": "response.output_audio_transcript.done", "item_id": item, "transcript": strings.TrimSpace(text)},
		{"type": "response.done", "response": map[string]any{"id": response, "status": "completed"}},
	} {
		if err := e.send(ctx, step); err != nil {
			return err
		}
	}
	return nil
}

// tone is a quiet 440 Hz beep in PCM16 at 24 kHz.
func tone(d time.Duration) []byte {
	samples := int(d.Seconds() * 24000)
	pcm := make([]byte, 2*samples)
	for i := range samples {
		value := int16(3000 * math.Sin(2*math.Pi*440*float64(i)/24000))
		binary.LittleEndian.PutUint16(pcm[2*i:], uint16(value))
	}
	return pcm
}

func truncate(text string, n int) string {
	if len(text) <= n {
		return text
	}
	return text[:n] + "…"
}

func isLoud(pcm []byte) bool {
	for i := 0; i+1 < len(pcm); i += 2 {
		sample := int16(binary.LittleEndian.Uint16(pcm[i:]))
		if sample > silenceAmplitude || sample < -silenceAmplitude {
			return true
		}
	}
	return false
}
