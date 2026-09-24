package session

import "sync"

// Limiter caps concurrent sessions per gateway and per tenant.
type Limiter struct {
	mu           sync.Mutex
	maxTotal     int
	maxPerTenant int
	total        int
	perTenant    map[string]int
}

// NewLimiter allows maxTotal sessions overall and maxPerTenant per tenant.
func NewLimiter(maxTotal, maxPerTenant int) *Limiter {
	return &Limiter{maxTotal: maxTotal, maxPerTenant: maxPerTenant, perTenant: map[string]int{}}
}

// Acquire reserves a slot; call release exactly once when the session ends.
func (l *Limiter) Acquire(tenant string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.maxTotal || l.perTenant[tenant] >= l.maxPerTenant {
		return nil, false
	}
	l.total++
	l.perTenant[tenant]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			if l.perTenant[tenant]--; l.perTenant[tenant] == 0 {
				delete(l.perTenant, tenant)
			}
		})
	}, true
}

// Active is the number of open sessions.
func (l *Limiter) Active() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}
