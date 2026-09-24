package chain

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

func sample() Event {
	return Event{
		TenantID:   "0199e2e0-0000-7000-8000-000000000001",
		Sequence:   1,
		EventID:    "0199e2e0-0000-7000-8000-0000000000e1",
		OccurTime:  time.Date(2026, 9, 24, 12, 0, 0, 123456000, time.UTC),
		RecordTime: time.Date(2026, 9, 24, 12, 0, 1, 0, time.UTC),
		ActorKind:  "ACTOR_KIND_USER",
		ActorID:    "ana",
		Action:     "key.revoked",
		TargetType: "provider_key",
		TargetID:   "k1",
		Outcome:    "OUTCOME_SUCCESS",
		Source:     "spiffe://jarvis.local/dashboard-api",
		Details:    map[string]string{"provider": "openai", "reason": "compromised"},
	}
}

func TestHashIsStableAndCoversEveryField(t *testing.T) {
	base := Hash(nil, sample())
	// A pinned value: the encoding must never change silently, or every
	// stored chain would stop verifying.
	if got := hex.EncodeToString(base); got != pinned {
		t.Fatalf("hash of the sample changed: %s", got)
	}

	changes := map[string]func(*Event){
		"tenant":       func(e *Event) { e.TenantID = "0199e2e0-0000-7000-8000-000000000002" },
		"sequence":     func(e *Event) { e.Sequence = 2 },
		"event id":     func(e *Event) { e.EventID = "0199e2e0-0000-7000-8000-0000000000e2" },
		"occur time":   func(e *Event) { e.OccurTime = e.OccurTime.Add(time.Microsecond) },
		"record time":  func(e *Event) { e.RecordTime = e.RecordTime.Add(time.Second) },
		"actor kind":   func(e *Event) { e.ActorKind = "ACTOR_KIND_ASSISTANT" },
		"actor":        func(e *Event) { e.ActorID = "bob" },
		"on behalf of": func(e *Event) { e.OnBehalfOf = "bob" },
		"action":       func(e *Event) { e.Action = "key.created" },
		"target type":  func(e *Event) { e.TargetType = "integration" },
		"target":       func(e *Event) { e.TargetID = "k2" },
		"outcome":      func(e *Event) { e.Outcome = "OUTCOME_DENIED" },
		"reason":       func(e *Event) { e.Reason = "x" },
		"request id":   func(e *Event) { e.RequestID = "r" },
		"source":       func(e *Event) { e.Source = "spiffe://jarvis.local/vault" },
		"detail value": func(e *Event) { e.Details = map[string]string{"provider": "xai", "reason": "compromised"} },
		"detail added": func(e *Event) {
			e.Details = map[string]string{"provider": "openai", "reason": "compromised", "x": ""}
		},
	}
	for name, change := range changes {
		e := sample()
		change(&e)
		if bytes.Equal(Hash(nil, e), base) {
			t.Errorf("changing the %s does not change the hash", name)
		}
	}
	if bytes.Equal(Hash([]byte("previous"), sample()), base) {
		t.Error("the previous hash is not chained")
	}
}

func TestFieldsCannotShiftIntoEachOther(t *testing.T) {
	a, b := sample(), sample()
	a.TargetType, a.TargetID = "provider_key", "k1"
	b.TargetType, b.TargetID = "provider_keyk", "1"
	if bytes.Equal(Hash(nil, a), Hash(nil, b)) {
		t.Fatal("moving characters between fields keeps the hash")
	}
	c, d := sample(), sample()
	c.Details = map[string]string{"ab": "c"}
	d.Details = map[string]string{"a": "bc"}
	if bytes.Equal(Hash(nil, c), Hash(nil, d)) {
		t.Fatal("moving characters between a detail's key and value keeps the hash")
	}
}

func TestDetailOrderDoesNotMatter(t *testing.T) {
	a, b := sample(), sample()
	a.Details = map[string]string{"a": "1", "b": "2", "c": "3"}
	b.Details = map[string]string{"c": "3", "a": "1", "b": "2"}
	for range 20 { // maps iterate in random order
		if !bytes.Equal(Hash(nil, a), Hash(nil, b)) {
			t.Fatal("the hash depends on map order")
		}
	}
}

// Recomputed independently (Python, from the package documentation).
const pinned = "e918ba974c98ef1e05faace10bbeebeee587d0d402e9c07eb29d12dcf65f785c"
