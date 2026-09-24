package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	voicev1 "jarvis.internal/gen/go/jarvis/voice/v1"
)

const frameBytes = 960 // 20 ms of PCM16 mono 24 kHz

// talk streams a WAV file in real time, like a microphone would, then keeps
// sending silence so the provider's VAD notices the end of speech, and saves
// the first spoken reply.
func talk(args []string) error {
	flags := flag.NewFlagSet("talk", flag.ContinueOnError)
	url := flags.String("url", "ws://127.0.0.1:8080/v1/voice", "gateway endpoint")
	tokenFlag := flags.String("token", os.Getenv("VOICE_TOKEN"), "access token (or VOICE_TOKEN)")
	provider := flags.String("provider", "", "openai or xai (default: the gateway's)")
	voice := flags.String("voice", "", "provider voice (default: the gateway's)")
	in := flags.String("in", "", "input WAV: PCM16 mono 24 kHz (required)")
	out := flags.String("out", "reply.wav", "where to save the replies")
	turns := flags.Int("turns", 1, "say the input this many times, each after the previous spoken reply")
	locale := flags.String("locale", "", "user locale, e.g. el-GR")
	linger := flags.Duration("linger", 0, "after the last reply, keep listening this long (e.g. for background task results)")
	timeout := flags.Duration("timeout", 60*time.Second, "give up after")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *in == "" || *tokenFlag == "" {
		return errors.New("-in and -token are required")
	}
	if *turns < 1 {
		return errors.New("-turns must be at least 1")
	}
	speech, err := readWAV(*in)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ws, resp, err := websocket.Dial(ctx, *url, &websocket.DialOptions{
		HTTPHeader:   http.Header{"Authorization": {"Bearer " + *tokenFlag}},
		Subprotocols: []string{"jarvis.voice.v1"},
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		if resp != nil {
			return fmt.Errorf("gateway refused the connection: HTTP %d", resp.StatusCode)
		}
		return err
	}
	defer func() { _ = ws.CloseNow() }()
	ws.SetReadLimit(1 << 20)

	send := func(msg *voicev1.ClientMessage) error {
		data, err := proto.Marshal(msg)
		if err != nil {
			return err
		}
		return ws.Write(ctx, websocket.MessageBinary, data)
	}
	if err := send(&voicev1.ClientMessage{Message: &voicev1.ClientMessage_StartSession{StartSession: &voicev1.StartSession{
		Provider: parseProvider(*provider), Voice: *voice, Locale: *locale,
	}}}); err != nil {
		return err
	}

	events := make(chan *voicev1.ServerMessage, 1024)
	readErr := make(chan error, 1)
	go func() {
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				readErr <- err
				return
			}
			msg := &voicev1.ServerMessage{}
			if err := proto.Unmarshal(data, msg); err == nil {
				events <- msg
			}
		}
	}()

	first := <-events
	if e := first.GetError(); e != nil {
		return fmt.Errorf("%s: %s", e.GetCode(), e.GetMessage())
	}
	ready := first.GetSessionReady()
	if ready == nil {
		return errors.New("expected SessionReady")
	}
	fmt.Printf("session %s: %s, voice %q\n", ready.GetSessionId(), ready.GetProvider(), ready.GetVoice())

	// The microphone: speech in real time when asked to speak, silence otherwise.
	speechEnded := make(chan time.Time, 1)
	speakNow := make(chan struct{}, 1)
	speakNow <- struct{}{}
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		silence := make([]byte, frameBytes)
		var pending []byte
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			select {
			case <-speakNow:
				pending = speech[:len(speech)&^1]
			default:
			}
			frame := silence
			if len(pending) > 0 {
				frame, pending = pending[:min(frameBytes, len(pending))], pending[min(frameBytes, len(pending)):]
				if len(pending) == 0 {
					speechEnded <- time.Now()
				}
			}
			if err := send(&voicev1.ClientMessage{Message: &voicev1.ClientMessage_InputAudio{InputAudio: &voicev1.InputAudio{Pcm16: frame}}}); err != nil {
				return
			}
		}
	}()

	var reply, replies []byte
	var ended, firstAudio time.Time
	var assistant strings.Builder
	spoken := 0
	var lingering <-chan time.Time
	finish := func() error {
		if err := writeWAV(*out, replies); err != nil {
			return err
		}
		fmt.Printf("saved %.1f s of replies to %s\n", float64(len(replies))/48000, *out)
		_ = send(&voicev1.ClientMessage{Message: &voicev1.ClientMessage_EndSession{EndSession: &voicev1.EndSession{}}})
		_ = ws.Close(websocket.StatusNormalClosure, "")
		return nil
	}
	for {
		select {
		case <-lingering:
			return finish()
		case <-ctx.Done():
			return errors.New("timed out waiting for a reply")
		case err := <-readErr:
			return fmt.Errorf("connection closed: %w", err)
		case t := <-speechEnded:
			ended = t
			fmt.Println("… speech sent, waiting for the reply")
		case msg := <-events:
			switch m := msg.GetMessage().(type) {
			case *voicev1.ServerMessage_OutputAudio:
				if firstAudio.IsZero() {
					firstAudio = time.Now()
				}
				reply = append(reply, m.OutputAudio.GetPcm16()...)
			case *voicev1.ServerMessage_Transcript:
				t := m.Transcript
				switch {
				case t.GetRole() == voicev1.Role_ROLE_USER && t.GetFinal():
					fmt.Printf("you:       %s\n", t.GetText())
				case t.GetRole() == voicev1.Role_ROLE_ASSISTANT && t.GetFinal():
					assistant.Reset()
					assistant.WriteString(t.GetText())
				case t.GetRole() == voicev1.Role_ROLE_ASSISTANT:
					assistant.WriteString(t.GetText())
				}
			case *voicev1.ServerMessage_Error:
				fmt.Printf("error: %s: %s\n", m.Error.GetCode(), m.Error.GetMessage())
				if m.Error.GetFatal() {
					return errors.New("session ended by the gateway")
				}
			case *voicev1.ServerMessage_ResponseDone:
				if len(reply) == 0 && assistant.Len() == 0 {
					// A response that only called tools: the spoken one follows.
					fmt.Println("… the assistant is using a tool")
					continue
				}
				fmt.Printf("assistant: %s\n", assistant.String())
				fmt.Printf("reply: %.1f s of audio (%s)\n", float64(len(reply))/48000, m.ResponseDone.GetStatus())
				if !ended.IsZero() && !firstAudio.IsZero() {
					fmt.Printf("latency: %d ms from the end of your speech to the first reply audio "+
						"(includes the provider's end-of-speech silence window)\n", firstAudio.Sub(ended).Milliseconds())
				}
				replies = append(replies, reply...)
				reply, firstAudio, ended = nil, time.Time{}, time.Time{}
				assistant.Reset()
				switch spoken++; {
				case spoken < *turns:
					speakNow <- struct{}{}
					continue
				case lingering != nil:
					continue // a reply while lingering
				case *linger > 0:
					fmt.Printf("… listening for %s\n", *linger)
					lingering = time.After(*linger)
					continue
				}
				return finish()
			}
		}
	}
}

func parseProvider(name string) commonv1.Provider {
	switch strings.ToLower(name) {
	case "openai":
		return commonv1.Provider_PROVIDER_OPENAI
	case "xai":
		return commonv1.Provider_PROVIDER_XAI
	default:
		return commonv1.Provider_PROVIDER_UNSPECIFIED
	}
}
