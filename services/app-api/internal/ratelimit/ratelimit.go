// Package ratelimit limits requests per client address with token buckets
// kept in memory. It guards the endpoints that take secrets from anonymous
// callers (pairing codes, refresh tokens); the secrets are long enough that
// guessing is hopeless anyway, so per-instance limits are enough.
package ratelimit

import (
	"sync"
	"time"
)

const maxAddresses = 100_000

// Limiter allows `burst` requests at once per address, refilled at `perMinute`.
type Limiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	burst     float64
	perSecond float64
	now       func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter.
func New(burst int, perMinute float64) *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, burst: float64(burst), perSecond: perMinute / 60, now: time.Now}
}

// Allow takes a token for the address, if one is left.
func (l *Limiter) Allow(address string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[address]
	if !ok {
		if len(l.buckets) >= maxAddresses {
			l.sweep(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[address] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.perSecond)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops full buckets (addresses idle long enough to have refilled);
// if every bucket is in use it starts over rather than grow without bound.
func (l *Limiter) sweep(now time.Time) {
	for address, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.perSecond >= l.burst {
			delete(l.buckets, address)
		}
	}
	if len(l.buckets) >= maxAddresses {
		clear(l.buckets)
	}
}
