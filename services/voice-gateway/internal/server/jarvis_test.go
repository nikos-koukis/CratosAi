package server_test

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	voicev1 "jarvis.internal/gen/go/jarvis/voice/v1"
	"jarvis.internal/voice-gateway/internal/realtime/realtimetest"
)

// fakeOrchestrator records what the gateway asks, in order.
type fakeOrchestrator struct {
	orchv1.UnimplementedOrchestratorServiceServer

	failOpen bool
	ackDelay time.Duration
	// callTool answers CallTool; nil answers {"ok":true}.
	callTool func(*orchv1.CallToolRequest) (*orchv1.CallToolResponse, error)
	events   chan *orchv1.ConversationEvent

	mu         sync.Mutex
	opened     *orchv1.OpenConversationRequest
	requestIDs []string
	log        []string
	closed     chan struct{}
}

func newFakeOrchestrator(t *testing.T, configure func(*fakeOrchestrator)) (*fakeOrchestrator, orchv1.OrchestratorServiceClient) {
	t.Helper()
	f := &fakeOrchestrator{events: make(chan *orchv1.ConversationEvent, 8), closed: make(chan struct{})}
	if configure != nil {
		configure(f)
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	orchv1.RegisterOrchestratorServiceServer(server, f)
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///orchestrator",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		server.Stop()
	})
	return f, orchv1.NewOrchestratorServiceClient(conn)
}

func (f *fakeOrchestrator) note(ctx context.Context, format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, fmt.Sprintf(format, args...))
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		f.requestIDs = append(f.requestIDs, md.Get("x-request-id")...)
	}
}

func (f *fakeOrchestrator) entries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.log)
}

// waitFor waits until an entry with the prefix is logged and returns its index.
func (f *fakeOrchestrator) waitFor(t *testing.T, prefix string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for i, entry := range f.entries() {
			if strings.HasPrefix(entry, prefix) {
				return i
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %q in %q", prefix, f.entries())
	return -1
}

func (f *fakeOrchestrator) OpenConversation(ctx context.Context, req *orchv1.OpenConversationRequest) (*orchv1.OpenConversationResponse, error) {
	f.note(ctx, "open")
	if f.failOpen {
		return nil, status.Error(codes.Unavailable, "down")
	}
	f.mu.Lock()
	f.opened = req
	f.mu.Unlock()
	return &orchv1.OpenConversationResponse{
		ConversationId: "conv-1",
		Instructions:   "Use Jarvis tools.",
		Tools: []*orchv1.FunctionTool{
			{Name: "recall_memory", Description: "Search memory.", ParametersJson: `{"type":"object"}`},
			{Name: "work_jira__create_issue", Description: "Create an issue.", ParametersJson: `{"type":"object"}`},
			{Name: "bad name", Description: "Skipped.", ParametersJson: `{"type":"object"}`},
			{Name: "broken", Description: "Skipped.", ParametersJson: `{"type":`},
		},
	}, nil
}

func (f *fakeOrchestrator) RecordTurn(ctx context.Context, req *orchv1.RecordTurnRequest) (*orchv1.RecordTurnResponse, error) {
	f.note(ctx, "record %s %d %s %q", req.GetRole(), req.GetUserTurn(), req.GetItemId(), req.GetText())
	return &orchv1.RecordTurnResponse{}, nil
}

func (f *fakeOrchestrator) CallTool(ctx context.Context, req *orchv1.CallToolRequest) (*orchv1.CallToolResponse, error) {
	f.note(ctx, "call %s %s turn=%d args=%s", req.GetCallId(), req.GetName(), req.GetUserTurn(), req.GetArgumentsJson())
	if f.callTool != nil {
		return f.callTool(req)
	}
	return &orchv1.CallToolResponse{Output: `{"ok":true}`}, nil
}

func (f *fakeOrchestrator) AckToolOutput(ctx context.Context, req *orchv1.AckToolOutputRequest) (*orchv1.AckToolOutputResponse, error) {
	time.Sleep(f.ackDelay)
	f.note(ctx, "ack-call %s turn=%d", req.GetCallId(), req.GetUserTurn())
	return &orchv1.AckToolOutputResponse{}, nil
}

func (f *fakeOrchestrator) AckEvent(ctx context.Context, req *orchv1.AckEventRequest) (*orchv1.AckEventResponse, error) {
	f.note(ctx, "ack-event %d turn=%d", req.GetEventId(), req.GetUserTurn())
	return &orchv1.AckEventResponse{}, nil
}

func (f *fakeOrchestrator) WatchConversation(req *orchv1.WatchConversationRequest, stream grpc.ServerStreamingServer[orchv1.WatchConversationResponse]) error {
	f.note(stream.Context(), "watch %s", req.GetConversationId())
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case event := <-f.events:
			if err := stream.Send(&orchv1.WatchConversationResponse{Event: event}); err != nil {
				return err
			}
		}
	}
}

func (f *fakeOrchestrator) CloseConversation(ctx context.Context, req *orchv1.CloseConversationRequest) (*orchv1.CloseConversationResponse, error) {
	f.note(ctx, "close %s", req.GetConversationId())
	close(f.closed)
	return &orchv1.CloseConversationResponse{}, nil
}

// startJarvis opens a session with tools and returns the client, the
// provider side and the fake orchestrator.
func startJarvis(t *testing.T, configure func(*fakeOrchestrator)) (*client, *realtimetest.Session, *fakeOrchestrator, string) {
	t.Helper()
	orch, orchClient := newFakeOrchestrator(t, configure)
	h := newHarness(t, options{orchestrator: orchClient})
	c := h.dial(tenantA)
	c.startWithLocale("el-GR")
	ready := c.recv().GetSessionReady()
	if ready == nil {
		t.Fatal("expected SessionReady")
	}
	c.messages = make(chan *voicev1.ServerMessage, 1024)
	go drain(c) // the tests below mostly watch the provider and orchestrator sides
	return c, h.provider.NextSession(t), orch, ready.GetSessionId()
}

func drain(c *client) {
	defer close(c.messages)
	for {
		_, data, err := c.ws.Read(context.Background())
		if err != nil {
			return
		}
		msg := &voicev1.ServerMessage{}
		if proto.Unmarshal(data, msg) == nil {
			select {
			case c.messages <- msg:
			default:
			}
		}
	}
}

// await waits until the gateway sends the client a matching message, which
// shows it has handled the provider events before it.
func (c *client) await(t *testing.T, what string, match func(*voicev1.ServerMessage) bool) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case msg := <-c.messages:
			if match(msg) {
				return
			}
		case <-timeout:
			t.Fatalf("the client never got %s", what)
		}
	}
}

func speak(p *realtimetest.Session, t *testing.T, item string) {
	t.Helper()
	p.Send(t, map[string]any{"type": "input_audio_buffer.speech_started", "item_id": item})
	p.Send(t, map[string]any{"type": "input_audio_buffer.speech_stopped", "item_id": item})
}

func end(c *client) {
	c.send(&voicev1.ClientMessage{Message: &voicev1.ClientMessage_EndSession{EndSession: &voicev1.EndSession{}}})
}

func TestJarvisToolsAreOfferedAndCallsRunOnTheOrchestrator(t *testing.T) {
	c, p, orch, sessionID := startJarvis(t, nil)

	orch.mu.Lock()
	opened := orch.opened
	orch.mu.Unlock()
	if opened.GetTenantId() != tenantA || opened.GetUserId() != "user-1" || opened.GetSessionId() != sessionID ||
		opened.GetProvider() != commonv1.Provider_PROVIDER_OPENAI || opened.GetLocale() != "el-GR" {
		t.Fatalf("OpenConversation = %v", opened)
	}
	if p.Update["instructions"] != "test\n\nUse Jarvis tools." {
		t.Fatalf("instructions = %q", p.Update["instructions"])
	}
	tools, _ := p.Update["tools"].([]any)
	if len(tools) != 2 || tools[0].(map[string]any)["name"] != "recall_memory" {
		t.Fatalf("tools = %v (malformed ones must be skipped)", tools)
	}

	speak(p, t, "item_u1")
	p.Send(t, map[string]any{"type": "conversation.item.input_audio_transcription.completed", "item_id": "item_u1",
		"transcript": "Τι είπαμε χθες;"})
	p.SendResponseCreated(t, "r1")
	p.SendFunctionCall(t, "r1", "item_f", "call_1", "recall_memory", `{"query":"χθες"}`)
	// The call also appears in response.done; it must run once.
	p.SendResponseDone(t, "r1", "completed", realtimetest.Call{ItemID: "item_f", CallID: "call_1",
		Name: "recall_memory", Arguments: `{"query":"χθες"}`})

	item := p.Next(t, "conversation.item.create")["item"].(map[string]any)
	if item["type"] != "function_call_output" || item["call_id"] != "call_1" || item["output"] != `{"ok":true}` {
		t.Fatalf("output = %v", item)
	}
	p.Next(t, "response.create")
	p.SendResponseCreated(t, "r2")
	p.Send(t, map[string]any{"type": "response.output_audio_transcript.done", "item_id": "item_a", "transcript": "Μιλήσαμε για το ταξίδι."})
	p.SendResponseDone(t, "r2", "completed")
	c.await(t, "the end of r2", func(m *voicev1.ServerMessage) bool { return m.GetResponseDone().GetResponseId() == "r2" })

	end(c)
	select {
	case <-orch.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the conversation was not closed")
	}
	// Transcripts are recorded in order; calls run beside them; closing
	// comes last, after the transcript is complete.
	got := orch.entries()
	records := slices.DeleteFunc(slices.Clone(got), func(e string) bool { return !strings.HasPrefix(e, "record") })
	wantRecords := []string{
		`record ROLE_USER 1 item_u1 ""`,
		`record ROLE_USER 1 item_u1 "Τι είπαμε χθες;"`,
		`record ROLE_ASSISTANT 1 item_a "Μιλήσαμε για το ταξίδι."`,
	}
	calls := slices.DeleteFunc(slices.Clone(got), func(e string) bool { return !strings.HasPrefix(e, "call") })
	if got[0] != "open" || got[len(got)-1] != "close conv-1" || !slices.Contains(got, "watch conv-1") ||
		!slices.Equal(records, wantRecords) || !slices.Equal(calls, []string{`call call_1 recall_memory turn=1 args={"query":"χθες"}`}) {
		t.Fatalf("orchestrator saw\n%s", strings.Join(got, "\n"))
	}
	for _, id := range orch.requestIDs {
		if id != sessionID {
			t.Fatalf("request id %q, want the session id", id)
		}
	}
}

func TestOutputsWaitForTheWholeResponseAndNeverInterruptTheUser(t *testing.T) {
	release := make(chan struct{})
	c, p, orch, _ := startJarvis(t, func(f *fakeOrchestrator) {
		f.callTool = func(req *orchv1.CallToolRequest) (*orchv1.CallToolResponse, error) {
			if req.GetCallId() == "slow" {
				<-release
			}
			return &orchv1.CallToolResponse{Output: `{"id":"` + req.GetCallId() + `"}`}, nil
		}
	})

	p.SendResponseCreated(t, "r1")
	p.SendFunctionCall(t, "r1", "i1", "slow", "recall_memory", `{}`)
	p.SendFunctionCall(t, "r1", "i2", "fast", "recall_memory", `{}`)
	p.SendResponseDone(t, "r1", "completed")
	orch.waitFor(t, "call fast")
	p.Quiet(t, 200*time.Millisecond) // "fast" is held until "slow" returns

	// The user starts talking; the outputs arrive meanwhile.
	p.Send(t, map[string]any{"type": "input_audio_buffer.speech_started", "item_id": "u1"})
	c.await(t, "speech started", func(m *voicev1.ServerMessage) bool { return m.GetSpeechStarted() != nil })
	close(release)
	outputs := map[any]bool{}
	for range 2 {
		outputs[p.Next(t, "conversation.item.create")["item"].(map[string]any)["call_id"]] = true
	}
	if !outputs["slow"] || !outputs["fast"] {
		t.Fatalf("outputs = %v", outputs)
	}
	p.Quiet(t, 200*time.Millisecond) // no response.create while the user talks

	// The user's turn starts a response that sees the outputs: no second one.
	p.Send(t, map[string]any{"type": "input_audio_buffer.speech_stopped", "item_id": "u1"})
	p.SendResponseCreated(t, "r2")
	p.SendResponseDone(t, "r2", "completed")
	p.Quiet(t, 200*time.Millisecond)
}

func TestConfirmationQuestionsAreStampedWithTheTurnThatSpeaksThem(t *testing.T) {
	_, p, orch, _ := startJarvis(t, func(f *fakeOrchestrator) {
		f.ackDelay = 100 * time.Millisecond // a slow ack must still come first
		f.callTool = func(req *orchv1.CallToolRequest) (*orchv1.CallToolResponse, error) {
			if req.GetName() == "work_jira__create_issue" {
				return &orchv1.CallToolResponse{Output: `{"status":"needs_confirmation"}`, AckRequired: true}, nil
			}
			return &orchv1.CallToolResponse{Output: `{"status":"done"}`}, nil
		}
	})

	speak(p, t, "u1") // turn 1: "create an issue"
	p.SendResponseCreated(t, "r1")
	p.SendFunctionCall(t, "r1", "i1", "ask", "work_jira__create_issue", `{"title":"x"}`)
	p.SendResponseDone(t, "r1", "completed")
	p.Next(t, "conversation.item.create")
	p.Next(t, "response.create")

	// The response that speaks the question starts at turn 1; its own call
	// runs only after the question's turn is stored.
	p.SendResponseCreated(t, "r2")
	p.SendFunctionCall(t, "r2", "i2", "early", "confirm_action", `{}`)
	p.SendResponseDone(t, "r2", "completed")
	ack, early := orch.waitFor(t, "ack-call ask turn=1"), orch.waitFor(t, "call early confirm_action turn=1")
	if ack > early {
		t.Fatalf("the confirm call ran before the question was acknowledged: %q", orch.entries())
	}
	p.Next(t, "conversation.item.create")
	p.Next(t, "response.create")
	p.SendResponseCreated(t, "r3")
	p.SendResponseDone(t, "r3", "completed")

	// The user answers (turn 2): a call of the response to that answer
	// carries turn 2.
	speak(p, t, "u2")
	p.SendResponseCreated(t, "r4")
	// The user speaks again (turn 3) while r4 is still running: r4's call
	// keeps r4's turn, since r4 was not a response to that speech.
	speak(p, t, "u3")
	p.SendFunctionCall(t, "r4", "i4", "yes", "confirm_action", `{}`)
	orch.waitFor(t, "call yes confirm_action turn=2")
}

func TestBackgroundEventsAreSpokenAndAcknowledged(t *testing.T) {
	_, p, orch, _ := startJarvis(t, nil)
	orch.waitFor(t, "watch conv-1")

	// A response is running (the gateway has seen it once its call arrives):
	// the event is added, but the model is only asked to speak once that
	// response is over.
	p.SendResponseCreated(t, "r1")
	p.SendFunctionCall(t, "r1", "i0", "c0", "recall_memory", `{}`)
	orch.waitFor(t, "call c0")
	orch.events <- &orchv1.ConversationEvent{EventId: 7, Message: "[Jarvis] Background task finished: booked."}
	item := p.Next(t, "conversation.item.create")["item"].(map[string]any)
	content := item["content"].([]any)[0].(map[string]any)
	if item["type"] != "message" || item["role"] != "system" || content["text"] != "[Jarvis] Background task finished: booked." {
		t.Fatalf("injected = %v", item)
	}
	p.Quiet(t, 200*time.Millisecond)
	p.SendResponseDone(t, "r1", "completed")
	p.Next(t, "conversation.item.create") // c0's output
	p.Next(t, "response.create")

	speak(p, t, "u1") // turn 1, after the event was added but before it was spoken
	p.SendResponseCreated(t, "r2")
	orch.waitFor(t, "ack-event 7 turn=1")

	// Events already seen are not repeated.
	orch.events <- &orchv1.ConversationEvent{EventId: 7, Message: "again"}
	orch.events <- &orchv1.ConversationEvent{EventId: 8, Message: "[Jarvis] Next."}
	next := p.Next(t, "conversation.item.create")["item"].(map[string]any)
	if next["content"].([]any)[0].(map[string]any)["text"] != "[Jarvis] Next." {
		t.Fatalf("expected event 8, got %v", next)
	}
}

func TestToolFailuresAreReportedToTheModel(t *testing.T) {
	_, p, _, _ := startJarvis(t, func(f *fakeOrchestrator) {
		f.callTool = func(*orchv1.CallToolRequest) (*orchv1.CallToolResponse, error) {
			return nil, status.Error(codes.Unavailable, "orchestrator down")
		}
	})
	p.SendResponseCreated(t, "r1")
	p.SendFunctionCall(t, "r1", "i1", "c1", "recall_memory", `{}`)
	p.SendResponseDone(t, "r1", "completed")
	output := p.Next(t, "conversation.item.create")["item"].(map[string]any)["output"].(string)
	if !strings.Contains(output, "could not run this tool") || strings.Contains(output, "orchestrator down") {
		t.Fatalf("output = %s", output)
	}
	p.Next(t, "response.create")
}

func TestTooManyCallsAtOnceAreRefused(t *testing.T) {
	release := make(chan struct{})
	_, p, orch, _ := startJarvis(t, func(f *fakeOrchestrator) {
		f.callTool = func(*orchv1.CallToolRequest) (*orchv1.CallToolResponse, error) {
			<-release
			return &orchv1.CallToolResponse{Output: `{}`}, nil
		}
	})
	p.SendResponseCreated(t, "r1")
	for i := range 9 {
		p.SendFunctionCall(t, "r1", fmt.Sprint("i", i), fmt.Sprint("c", i), "recall_memory", `{}`)
	}
	p.SendResponseDone(t, "r1", "completed")
	orch.waitFor(t, "call c7")
	close(release)
	busy := 0
	for range 9 {
		output := p.Next(t, "conversation.item.create")["item"].(map[string]any)["output"].(string)
		if strings.Contains(output, "Too many tools") {
			busy++
		}
	}
	if busy != 1 {
		t.Fatalf("%d calls refused, want 1", busy)
	}
	if n := len(slices.DeleteFunc(orch.entries(), func(e string) bool { return !strings.HasPrefix(e, "call ") })); n != 8 {
		t.Fatalf("%d calls reached the orchestrator, want 8", n)
	}
}

func TestSessionsWorkWithoutTheOrchestrator(t *testing.T) {
	c, p, orch, _ := startJarvis(t, func(f *fakeOrchestrator) { f.failOpen = true })
	if _, ok := p.Update["tools"]; ok || p.Update["instructions"] != "test" {
		t.Fatalf("session.update = %v", p.Update)
	}
	speak(p, t, "u1")
	end(c)
	p.Closed(t)
	if got := orch.entries(); !slices.Equal(got, []string{"open"}) {
		t.Fatalf("orchestrator saw %q after a failed open", got)
	}
}

func TestInvalidLocalesAreRejected(t *testing.T) {
	_, orchClient := newFakeOrchestrator(t, nil)
	h := newHarness(t, options{orchestrator: orchClient})
	c := h.dial(tenantA)
	c.startWithLocale("el_GR; DROP")
	c.expectError(voicev1.ErrorCode_ERROR_CODE_INVALID_MESSAGE)
}

func TestAnEventAddedWhileAResponseIsRequestedGetsItsOwnResponse(t *testing.T) {
	_, p, orch, _ := startJarvis(t, nil)
	orch.waitFor(t, "watch conv-1")
	p.SendResponseCreated(t, "r1")
	p.SendFunctionCall(t, "r1", "i1", "c1", "recall_memory", `{}`)
	p.SendResponseDone(t, "r1", "completed")
	p.Next(t, "conversation.item.create")
	p.Next(t, "response.create") // asked for; the provider has not created it yet

	orch.events <- &orchv1.ConversationEvent{EventId: 9, Message: "[Jarvis] Task finished."}
	p.Next(t, "conversation.item.create")
	// The requested response was created from the conversation before the
	// event: it does not speak the event, so the event is not acknowledged.
	p.SendResponseCreated(t, "r2")
	p.SendResponseDone(t, "r2", "completed")
	p.Next(t, "response.create") // a response of its own for the event
	if slices.ContainsFunc(orch.entries(), func(e string) bool { return strings.HasPrefix(e, "ack-event") }) {
		t.Fatalf("event acknowledged by a response that did not include it: %q", orch.entries())
	}
	speak(p, t, "u1") // the user talks before the event is spoken
	p.SendResponseCreated(t, "r3")
	orch.waitFor(t, "ack-event 9 turn=1")
}
