package realtime_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"jarvis.internal/voice-gateway/internal/realtime"
	"jarvis.internal/voice-gateway/internal/realtime/realtimetest"
)

const key = "sk-test-key"

func provider(url string, dialect realtime.Dialect) realtime.Provider {
	return realtime.Provider{
		Name:               "fake",
		URL:                url,
		Dialect:            dialect,
		DefaultVoice:       "marin",
		TranscriptionModel: "gpt-transcribe",
		VADSilenceMs:       500,
	}
}

func dial(t *testing.T, fake *realtimetest.Server, dialect realtime.Dialect, opts realtime.Options) (*realtime.Conn, *realtimetest.Session) {
	t.Helper()
	conn, err := realtime.Dial(context.Background(), provider(fake.URL(), dialect), []byte(key), opts)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, fake.NextSession(t)
}

func next(t *testing.T, conn *realtime.Conn) realtime.Event {
	t.Helper()
	select {
	case event, ok := <-conn.Events():
		if !ok {
			t.Fatalf("event stream ended: %v", conn.Err())
		}
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
		return nil
	}
}

func TestOpenAISessionUpdateUsesTheGAShape(t *testing.T) {
	fake := realtimetest.NewServer(t, key)
	_, session := dial(t, fake, realtime.DialectOpenAI, realtime.Options{
		Instructions:     "be brief",
		SafetyIdentifier: "user-hash",
	})

	update := session.Update
	if update["type"] != "realtime" || update["instructions"] != "be brief" {
		t.Fatalf("session: %v", update)
	}
	audio := update["audio"].(map[string]any)
	input := audio["input"].(map[string]any)
	output := audio["output"].(map[string]any)
	format := input["format"].(map[string]any)
	if format["type"] != "audio/pcm" || format["rate"] != float64(24000) {
		t.Fatalf("input format: %v", format)
	}
	vad := input["turn_detection"].(map[string]any)
	if vad["type"] != "server_vad" || vad["interrupt_response"] != true || vad["silence_duration_ms"] != float64(500) {
		t.Fatalf("turn_detection: %v", vad)
	}
	if input["transcription"].(map[string]any)["model"] != "gpt-transcribe" {
		t.Fatalf("transcription: %v", input["transcription"])
	}
	if output["voice"] != "marin" {
		t.Fatalf("default voice not applied: %v", output)
	}
	if session.Header.Get("OpenAI-Safety-Identifier") != "user-hash" {
		t.Fatal("safety identifier header missing")
	}
	if session.Header.Get("OpenAI-Beta") != "" {
		t.Fatal("the removed beta header must not be sent")
	}
}

func TestXAISessionUpdateKeepsVoiceAndVADAtTheTop(t *testing.T) {
	fake := realtimetest.NewServer(t, key)
	_, session := dial(t, fake, realtime.DialectXAI, realtime.Options{Voice: "eve"})

	update := session.Update
	if _, ok := update["type"]; ok {
		t.Fatal("xAI has no session.type")
	}
	if update["voice"] != "eve" {
		t.Fatalf("voice: %v", update["voice"])
	}
	if update["turn_detection"].(map[string]any)["type"] != "server_vad" {
		t.Fatalf("turn_detection: %v", update["turn_detection"])
	}
	if session.Header.Get("OpenAI-Safety-Identifier") != "" {
		t.Fatal("OpenAI-only header sent to xAI")
	}
}

func TestAudioAndEventsRoundTrip(t *testing.T) {
	fake := realtimetest.NewServer(t, key)
	conn, session := dial(t, fake, realtime.DialectOpenAI, realtime.Options{})

	pcm := []byte{1, 2, 3, 4, 5, 6}
	if err := conn.AppendAudio(context.Background(), pcm); err != nil {
		t.Fatal(err)
	}
	if got := session.WaitForAudio(t, len(pcm)); string(got) != string(pcm) {
		t.Fatalf("provider received %v", got)
	}

	session.Send(t, map[string]any{"type": "input_audio_buffer.speech_started", "item_id": "item_u"})
	session.Send(t, map[string]any{"type": "response.created", "response": map[string]any{"id": "resp_1"}})
	session.SendAudio(t, "resp_1", "item_a", []byte{9, 8})
	session.Send(t, map[string]any{"type": "response.audio.delta", "response_id": "resp_1", "item_id": "item_a", "delta": "BwY="})
	session.Send(t, map[string]any{"type": "response.output_audio_transcript.delta", "item_id": "item_a", "delta": "Hel"})
	session.Send(t, map[string]any{"type": "conversation.item.input_audio_transcription.completed", "item_id": "item_u", "transcript": "hi"})
	session.Send(t, map[string]any{"type": "some.unknown.event"})
	session.Send(t, map[string]any{"type": "response.done", "response": map[string]any{"id": "resp_1", "status": "cancelled"}})
	session.Send(t, map[string]any{"type": "error", "error": map[string]any{"type": "invalid_request_error", "code": "x", "message": "bad"}})

	want := []realtime.Event{
		realtime.SpeechStarted{ItemID: "item_u"},
		realtime.ResponseCreated{ResponseID: "resp_1"},
		realtime.AudioDelta{ResponseID: "resp_1", ItemID: "item_a", PCM: []byte{9, 8}},
		realtime.AudioDelta{ResponseID: "resp_1", ItemID: "item_a", PCM: []byte{7, 6}},
		realtime.TranscriptDelta{Role: realtime.RoleAssistant, ItemID: "item_a", Text: "Hel"},
		realtime.TranscriptDelta{Role: realtime.RoleUser, ItemID: "item_u", Text: "hi", Final: true},
		realtime.ResponseDone{ResponseID: "resp_1", Status: realtime.StatusCancelled},
		realtime.ProviderError{Type: "invalid_request_error", Code: "x", Message: "bad"},
	}
	for i, expected := range want {
		got := next(t, conn)
		if gotAudio, ok := got.(realtime.AudioDelta); ok {
			wantAudio := expected.(realtime.AudioDelta)
			if gotAudio.ResponseID != wantAudio.ResponseID || string(gotAudio.PCM) != string(wantAudio.PCM) {
				t.Fatalf("event %d: got %+v, want %+v", i, got, expected)
			}
			continue
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("event %d: got %#v, want %#v", i, got, expected)
		}
	}
}

func TestControlEvents(t *testing.T) {
	fake := realtimetest.NewServer(t, key)
	conn, session := dial(t, fake, realtime.DialectOpenAI, realtime.Options{})
	ctx := context.Background()

	if err := conn.CancelResponse(ctx); err != nil {
		t.Fatal(err)
	}
	session.Next(t, "response.cancel")

	if err := conn.Truncate(ctx, "item_a", 1250); err != nil {
		t.Fatal(err)
	}
	truncate := session.Next(t, "conversation.item.truncate")
	if truncate["item_id"] != "item_a" || truncate["audio_end_ms"] != float64(1250) || truncate["content_index"] != float64(0) {
		t.Fatalf("truncate: %v", truncate)
	}

	_ = conn.Close()
	session.Closed(t)
}

var weatherTool = realtime.Tool{
	Name:        "weather",
	Description: "Current weather in a city.",
	Parameters:  json.RawMessage(`{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}`),
}

func TestToolsAreDeclaredForBothProviders(t *testing.T) {
	for _, dialect := range []realtime.Dialect{realtime.DialectOpenAI, realtime.DialectXAI} {
		fake := realtimetest.NewServer(t, key)
		_, session := dial(t, fake, dialect, realtime.Options{Tools: []realtime.Tool{weatherTool}})
		tools, _ := session.Update["tools"].([]any)
		if len(tools) != 1 || session.Update["tool_choice"] != "auto" {
			t.Fatalf("dialect %d: tools = %v, tool_choice = %v", dialect, session.Update["tools"], session.Update["tool_choice"])
		}
		tool := tools[0].(map[string]any)
		params, _ := tool["parameters"].(map[string]any)
		if tool["type"] != "function" || tool["name"] != "weather" || tool["description"] != weatherTool.Description ||
			params["type"] != "object" {
			t.Fatalf("dialect %d: tool = %v", dialect, tool)
		}
	}
	// Without tools, nothing about tools is sent.
	fake := realtimetest.NewServer(t, key)
	_, session := dial(t, fake, realtime.DialectOpenAI, realtime.Options{})
	if _, ok := session.Update["tools"]; ok {
		t.Fatal("tools sent without tools")
	}
}

func TestFunctionCallsAndOutputs(t *testing.T) {
	fake := realtimetest.NewServer(t, key)
	conn, session := dial(t, fake, realtime.DialectOpenAI, realtime.Options{Tools: []realtime.Tool{weatherTool}})
	ctx := context.Background()

	session.SendFunctionCall(t, "resp_1", "item_f", "call_1", "weather", `{"city":"Athens"}`)
	// Incomplete announcements are ignored.
	session.Send(t, map[string]any{"type": "response.function_call_arguments.done", "call_id": "call_x"})
	session.SendResponseDone(t, "resp_1", "completed",
		realtimetest.Call{ItemID: "item_f", CallID: "call_1", Name: "weather", Arguments: `{"city":"Athens"}`},
		realtimetest.Call{ItemID: "item_g", CallID: "call_2", Name: "weather", Arguments: `{}`})

	call := realtime.FunctionCall{ResponseID: "resp_1", ItemID: "item_f", CallID: "call_1", Name: "weather",
		Arguments: `{"city":"Athens"}`}
	if got := next(t, conn); !reflect.DeepEqual(got, call) {
		t.Fatalf("got %#v", got)
	}
	done := next(t, conn).(realtime.ResponseDone)
	if done.Status != realtime.StatusCompleted || len(done.Calls) != 2 || !reflect.DeepEqual(done.Calls[0], call) ||
		done.Calls[1].CallID != "call_2" {
		t.Fatalf("done = %#v", done)
	}

	if err := conn.SendFunctionOutput(ctx, "call_1", `{"temp":21}`); err != nil {
		t.Fatal(err)
	}
	item := session.Next(t, "conversation.item.create")["item"].(map[string]any)
	if item["type"] != "function_call_output" || item["call_id"] != "call_1" || item["output"] != `{"temp":21}` {
		t.Fatalf("output item = %v", item)
	}
	if err := conn.CreateResponse(ctx); err != nil {
		t.Fatal(err)
	}
	session.Next(t, "response.create")
}

func TestInjectedMessagesAreNotFromTheUserWhereSupported(t *testing.T) {
	for dialect, role := range map[realtime.Dialect]string{realtime.DialectOpenAI: "system", realtime.DialectXAI: "user"} {
		fake := realtimetest.NewServer(t, key)
		conn, session := dial(t, fake, dialect, realtime.Options{})
		if err := conn.InjectMessage(context.Background(), "[Jarvis] task finished"); err != nil {
			t.Fatal(err)
		}
		item := session.Next(t, "conversation.item.create")["item"].(map[string]any)
		content := item["content"].([]any)[0].(map[string]any)
		if item["type"] != "message" || item["role"] != role || content["type"] != "input_text" ||
			content["text"] != "[Jarvis] task finished" {
			t.Fatalf("dialect %d: item = %v", dialect, item)
		}
	}
}

func TestWrongKeyIsReportedAsAuthFailure(t *testing.T) {
	fake := realtimetest.NewServer(t, key)
	_, err := realtime.Dial(context.Background(), provider(fake.URL(), realtime.DialectOpenAI), []byte("sk-wrong"), realtime.Options{})
	if !errors.Is(err, realtime.ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestUnreachableProviderIsUnavailable(t *testing.T) {
	_, err := realtime.Dial(context.Background(), provider("ws://127.0.0.1:1/v1/realtime", realtime.DialectOpenAI), []byte(key), realtime.Options{})
	if !errors.Is(err, realtime.ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}
}
