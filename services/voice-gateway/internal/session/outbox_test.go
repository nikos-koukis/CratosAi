package session

import (
	"context"
	"testing"
	"time"

	voicev1 "jarvis.internal/gen/go/jarvis/voice/v1"
)

func audio(item string, n int) outItem {
	return outItem{
		msg:        &voicev1.ServerMessage{Message: &voicev1.ServerMessage_OutputAudio{OutputAudio: &voicev1.OutputAudio{Pcm16: make([]byte, n)}}},
		itemID:     item,
		audioBytes: n,
	}
}

func control() outItem {
	return outItem{msg: &voicev1.ServerMessage{Message: &voicev1.ServerMessage_SpeechStopped{}}}
}

func TestDropAudioKeepsControlMessagesAndCountsDelivery(t *testing.T) {
	o := newOutbox(16)
	for _, item := range []outItem{audio("a", 100), control(), audio("a", 200), audio("b", 50)} {
		if err := o.push(item); err != nil {
			t.Fatal(err)
		}
	}
	first, err := o.pop(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	o.markDelivered(first)

	dropped, delivered := o.dropAudio("a")
	if dropped != 200 || delivered != 100 {
		t.Fatalf("dropped=%d delivered=%d, want 200 and 100", dropped, delivered)
	}
	if o.len() != 1 {
		t.Fatalf("only the control message should remain, have %d items", o.len())
	}
	remaining, _ := o.pop(context.Background())
	if remaining.audioBytes != 0 {
		t.Fatal("audio survived the drop")
	}
}

func TestOutboxIsBounded(t *testing.T) {
	o := newOutbox(2)
	_ = o.push(control())
	_ = o.push(control())
	if err := o.push(control()); err != errOutboxFull {
		t.Fatalf("got %v, want errOutboxFull", err)
	}
}

func TestPopWaitsAndHonoursCancellation(t *testing.T) {
	o := newOutbox(4)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := o.pop(ctx); err == nil {
		t.Fatal("pop on an empty outbox must wait for the context")
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = o.push(control())
	}()
	if _, err := o.pop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTokenBucketAllowsBurstThenRealTime(t *testing.T) {
	b := newTokenBucket(1000, 500)
	now := time.Unix(0, 0)
	if !b.take(1000, now) {
		t.Fatal("burst should be allowed")
	}
	if b.take(1, now) {
		t.Fatal("bucket should be empty")
	}
	if !b.take(500, now.Add(time.Second)) {
		t.Fatal("one second refills 500 tokens")
	}
}

func TestLimiterCapsTenantsAndTotal(t *testing.T) {
	l := NewLimiter(3, 2)
	r1, ok1 := l.Acquire("t1")
	_, ok2 := l.Acquire("t1")
	_, ok3 := l.Acquire("t1")
	_, ok4 := l.Acquire("t2")
	_, ok5 := l.Acquire("t3")
	if !ok1 || !ok2 || ok3 || !ok4 || ok5 {
		t.Fatalf("got %v %v %v %v %v", ok1, ok2, ok3, ok4, ok5)
	}
	r1()
	r1() // idempotent
	if l.Active() != 2 {
		t.Fatalf("active=%d, want 2", l.Active())
	}
	if _, ok := l.Acquire("t3"); !ok {
		t.Fatal("a slot was freed")
	}
}
