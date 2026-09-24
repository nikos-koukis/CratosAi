package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

func TestBurstThenRefill(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(3, 60) // one per second
	l.now = func() time.Time { return now }
	for i := range 3 {
		if !l.Allow("a") {
			t.Fatalf("request %d refused within the burst", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("burst exceeded")
	}
	if !l.Allow("b") {
		t.Fatal("addresses must not share a bucket")
	}
	now = now.Add(1100 * time.Millisecond)
	if !l.Allow("a") || l.Allow("a") {
		t.Fatal("expected exactly one refilled token")
	}
}

func TestMemoryIsBounded(t *testing.T) {
	l := New(1, 60)
	for i := range maxAddresses + 10 {
		l.Allow(fmt.Sprint(i))
	}
	if len(l.buckets) > maxAddresses {
		t.Fatalf("%d buckets", len(l.buckets))
	}
}
