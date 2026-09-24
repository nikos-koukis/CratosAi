// Package realtimetest provides a scripted fake realtime provider for tests.
package realtimetest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const waitTimeout = 5 * time.Second

// Server accepts realtime sessions authenticated with Key.
type Server struct {
	httpServer *httptest.Server
	key        string
	sessions   chan *Session
}

// Session is one accepted connection, after the handshake.
type Session struct {
	ws *websocket.Conn
	// Header of the upgrade request.
	Header http.Header
	// Update is the session.update the client sent.
	Update map[string]any

	events chan map[string]any

	mu    sync.Mutex
	audio []byte
}

// NewServer starts a fake provider; it is closed when the test ends.
func NewServer(t *testing.T, key string) *Server {
	t.Helper()
	s := &Server{key: key, sessions: make(chan *Session, 16)}
	s.httpServer = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.httpServer.Close)
	return s
}

// URL is the WebSocket URL to configure as the provider URL.
func (s *Server) URL() string {
	return "ws" + strings.TrimPrefix(s.httpServer.URL, "http") + "/v1/realtime?model=fake"
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.key {
		http.Error(w, "invalid api key", http.StatusUnauthorized)
		return
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(8 << 20)
	ctx := context.Background()
	session := &Session{ws: ws, Header: r.Header.Clone(), events: make(chan map[string]any, 4096)}

	if err := writeJSON(ctx, ws, map[string]any{"type": "session.created"}); err != nil {
		return
	}
	update, err := readJSON(ctx, ws)
	if err != nil || update["type"] != "session.update" {
		_ = ws.Close(websocket.StatusProtocolError, "expected session.update")
		return
	}
	session.Update, _ = update["session"].(map[string]any)
	if err := writeJSON(ctx, ws, map[string]any{"type": "session.updated"}); err != nil {
		return
	}
	s.sessions <- session

	for {
		event, err := readJSON(ctx, ws)
		if err != nil {
			close(session.events)
			return
		}
		if event["type"] == "input_audio_buffer.append" {
			encoded, _ := event["audio"].(string)
			pcm, _ := base64.StdEncoding.DecodeString(encoded)
			session.mu.Lock()
			session.audio = append(session.audio, pcm...)
			session.mu.Unlock()
			continue
		}
		session.events <- event
	}
}

// NextSession waits for the next connected session.
func (s *Server) NextSession(t *testing.T) *Session {
	t.Helper()
	select {
	case session := <-s.sessions:
		return session
	case <-time.After(waitTimeout):
		t.Fatal("no realtime session was opened")
		return nil
	}
}

// Send emits a server event.
func (s *Session) Send(t *testing.T, event map[string]any) {
	t.Helper()
	if err := writeJSON(context.Background(), s.ws, event); err != nil {
		t.Fatalf("fake provider send: %v", err)
	}
}

// SendAudio emits one response.output_audio.delta.
func (s *Session) SendAudio(t *testing.T, responseID, itemID string, pcm []byte) {
	t.Helper()
	s.Send(t, map[string]any{
		"type":        "response.output_audio.delta",
		"response_id": responseID,
		"item_id":     itemID,
		"delta":       base64.StdEncoding.EncodeToString(pcm),
	})
}

// Call is a function call in a fake response.
type Call struct{ ItemID, CallID, Name, Arguments string }

// SendFunctionCall emits response.function_call_arguments.done.
func (s *Session) SendFunctionCall(t *testing.T, responseID, itemID, callID, name, arguments string) {
	t.Helper()
	s.Send(t, map[string]any{
		"type":        "response.function_call_arguments.done",
		"response_id": responseID,
		"item_id":     itemID,
		"call_id":     callID,
		"name":        name,
		"arguments":   arguments,
	})
}

// SendResponseCreated emits response.created.
func (s *Session) SendResponseCreated(t *testing.T, responseID string) {
	t.Helper()
	s.Send(t, map[string]any{"type": "response.created", "response": map[string]any{"id": responseID}})
}

// SendResponseDone emits response.done with the given function calls as output.
func (s *Session) SendResponseDone(t *testing.T, responseID, status string, calls ...Call) {
	t.Helper()
	output := make([]map[string]any, 0, len(calls))
	for _, c := range calls {
		output = append(output, map[string]any{"type": "function_call", "id": c.ItemID, "call_id": c.CallID,
			"name": c.Name, "arguments": c.Arguments, "status": "completed"})
	}
	s.Send(t, map[string]any{"type": "response.done",
		"response": map[string]any{"id": responseID, "status": status, "output": output}})
}

// Next waits for the next non-audio client event and checks its type.
func (s *Session) Next(t *testing.T, eventType string) map[string]any {
	t.Helper()
	select {
	case event, ok := <-s.events:
		if !ok {
			t.Fatalf("connection closed while waiting for %s", eventType)
		}
		if event["type"] != eventType {
			t.Fatalf("got client event %v, want %s", event["type"], eventType)
		}
		return event
	case <-time.After(waitTimeout):
		t.Fatalf("no %s event from the client", eventType)
		return nil
	}
}

// Quiet checks that the client sends no (non-audio) event for d.
func (s *Session) Quiet(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case event, ok := <-s.events:
		if ok {
			t.Fatalf("unexpected client event %v", event)
		}
	case <-time.After(d):
	}
}

// AudioReceived returns all PCM appended so far.
func (s *Session) AudioReceived() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.audio...)
}

// WaitForAudio waits until at least n bytes of audio have been appended.
func (s *Session) WaitForAudio(t *testing.T, n int) []byte {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if audio := s.AudioReceived(); len(audio) >= n {
			return audio
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("received %d bytes of audio, want %d", len(s.AudioReceived()), n)
	return nil
}

// Closed waits until the client closes the connection.
func (s *Session) Closed(t *testing.T) {
	t.Helper()
	deadline := time.After(waitTimeout)
	for {
		select {
		case _, ok := <-s.events:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("client did not close the provider connection")
		}
	}
}

func writeJSON(ctx context.Context, ws *websocket.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return ws.Write(ctx, websocket.MessageText, data)
}

func readJSON(ctx context.Context, ws *websocket.Conn) (map[string]any, error) {
	_, data, err := ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	var event map[string]any
	err = json.Unmarshal(data, &event)
	return event, err
}

// Drop closes the connection abruptly, as a failing provider would.
func (s *Session) Drop() {
	_ = s.ws.CloseNow()
}
