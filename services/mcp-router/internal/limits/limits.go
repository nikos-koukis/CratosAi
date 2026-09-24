// Package limits holds the router's shared state in DragonflyDB (Redis
// protocol): per-tenant and per-integration rate limits (GCRA, shared by all
// router instances) and the tool-list cache.
//
// Redis being unavailable must not take tools down: limits then fail open
// and the cache is bypassed, both loudly logged.
package limits

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix     = "jarvis:mcp:"
	maxCachedSize = 2 << 20
)

// gcra is the generic cell rate algorithm: each call pushes the key's
// "theoretical arrival time" one interval further; a call is refused when
// that time is more than `burst` intervals ahead of now. All arithmetic is
// in integer milliseconds and integers are returned formatted, because Lua
// number replies differ between Redis (truncated to integers) and
// DragonflyDB (doubles or strings).
var gcra = redis.NewScript(`
local interval = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local t = redis.call("TIME")
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local tat = tonumber(redis.call("GET", KEYS[1]) or now)
if tat < now then
  tat = now
end
local new_tat = tat + interval
local allow_at = new_tat - burst * interval
if now < allow_at then
  return {"0", string.format("%d", allow_at - now)}
end
redis.call("SET", KEYS[1], string.format("%d", new_tat), "PX", string.format("%d", new_tat - now))
return {"1", "0"}
`)

// rule allows `burst` calls at once, refilling one every `interval`.
type rule struct {
	intervalMs int64
	burst      int64
}

func perMinute(n int) rule {
	return rule{intervalMs: max(int64(time.Minute/time.Millisecond)/int64(n), 1), burst: int64(n)}
}

// Limits wraps a Redis client.
type Limits struct {
	rdb         redis.UniversalClient
	tenant      rule
	integration rule
	toolsTTL    time.Duration
	log         *slog.Logger
}

// NewClient connects to Redis or DragonflyDB with short timeouts: failing
// open is better than making tool calls wait.
func NewClient(addr, password string) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  500 * time.Millisecond,
		WriteTimeout: 500 * time.Millisecond,
	})
}

// New creates limits allowing the given calls per minute.
func New(rdb redis.UniversalClient, perTenant, perIntegration int, toolsTTL time.Duration, log *slog.Logger) *Limits {
	return &Limits{
		rdb:         rdb,
		tenant:      perMinute(perTenant),
		integration: perMinute(perIntegration),
		toolsTTL:    toolsTTL,
		log:         log,
	}
}

// Allow consumes one call for the tenant and the integration. It returns
// false (and how long to wait) when either limit is exhausted.
func (l *Limits) Allow(ctx context.Context, tenantID, integrationID string) (bool, time.Duration) {
	for _, check := range []struct {
		key  string
		rule rule
	}{
		{keyPrefix + "rate:tenant:" + tenantID, l.tenant},
		{keyPrefix + "rate:integration:" + integrationID, l.integration},
	} {
		allowed, retryAfter, err := l.allow(ctx, check.key, check.rule)
		if err != nil {
			l.log.Warn("rate limiter unavailable; allowing the call", "error", err)
			continue
		}
		if !allowed {
			return false, retryAfter
		}
	}
	return true, 0
}

func (l *Limits) allow(ctx context.Context, key string, r rule) (bool, time.Duration, error) {
	reply, err := gcra.Run(ctx, l.rdb, []string{key}, r.intervalMs, r.burst).Slice()
	if err != nil {
		return false, 0, err
	}
	if len(reply) != 2 {
		return false, 0, fmt.Errorf("unexpected rate limiter reply %v", reply)
	}
	allowed, err := integer(reply[0])
	if err != nil {
		return false, 0, err
	}
	retryMs, err := integer(reply[1])
	if err != nil {
		return false, 0, err
	}
	return allowed == 1, time.Duration(retryMs) * time.Millisecond, nil
}

func integer(v any) (int64, error) {
	switch x := v.(type) {
	case int64:
		return x, nil
	case string:
		return strconv.ParseInt(x, 10, 64)
	default:
		return 0, fmt.Errorf("unexpected rate limiter value %T", v)
	}
}

// Tools returns a cached tool list.
func (l *Limits) Tools(ctx context.Context, integrationID string) ([]byte, bool) {
	data, err := l.rdb.Get(ctx, keyPrefix+"tools:"+integrationID).Bytes()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			l.log.Warn("tool cache unavailable", "error", err)
		}
		return nil, false
	}
	return data, true
}

// SetTools caches a tool list.
func (l *Limits) SetTools(ctx context.Context, integrationID string, data []byte) {
	if len(data) > maxCachedSize {
		return
	}
	if err := l.rdb.Set(ctx, keyPrefix+"tools:"+integrationID, data, l.toolsTTL).Err(); err != nil {
		l.log.Warn("cannot cache tools", "error", err)
	}
}

// ForgetTools drops a cached tool list.
func (l *Limits) ForgetTools(ctx context.Context, integrationID string) {
	if err := l.rdb.Del(ctx, keyPrefix+"tools:"+integrationID).Err(); err != nil {
		l.log.Warn("cannot drop cached tools", "error", err)
	}
}
