package limits

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func newLimits(t *testing.T, perTenant, perIntegration int) (*Limits, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })
	return New(rdb, perTenant, perIntegration, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil))), mr
}

func TestBurstThenRefill(t *testing.T) {
	l, mr := newLimits(t, 1000, 7)
	ctx := context.Background()
	allowed := 0
	for range 10 {
		if ok, _ := l.Allow(ctx, "tenant", "int"); ok {
			allowed++
		}
	}
	if allowed != 7 {
		t.Fatalf("allowed %d of 10, want 7", allowed)
	}
	if ttl := mr.TTL("jarvis:mcp:rate:integration:int"); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("key TTL = %v", ttl)
	}
}

func TestLimitsAreSeparatePerTenantAndIntegration(t *testing.T) {
	l, _ := newLimits(t, 3, 2)
	ctx := context.Background()
	for i := range 2 {
		if ok, _ := l.Allow(ctx, "tenant-a", "int-1"); !ok {
			t.Fatalf("call %d refused", i)
		}
	}
	ok, retry := l.Allow(ctx, "tenant-a", "int-1")
	if ok || retry <= 0 {
		t.Fatalf("integration limit not enforced (ok=%v retry=%v)", ok, retry)
	}
	// Another integration of the same tenant still has room, until the
	// tenant's own limit (3, one already spent on the refused call) is hit.
	if ok, _ := l.Allow(ctx, "tenant-a", "int-2"); ok {
		t.Fatal("tenant limit not enforced")
	}
	// Other tenants are unaffected.
	if ok, _ := l.Allow(ctx, "tenant-b", "int-3"); !ok {
		t.Fatal("another tenant was limited")
	}
}

func TestToolCache(t *testing.T) {
	l, mr := newLimits(t, 10, 10)
	ctx := context.Background()
	if _, ok := l.Tools(ctx, "int-1"); ok {
		t.Fatal("empty cache hit")
	}
	l.SetTools(ctx, "int-1", []byte("tools"))
	if data, ok := l.Tools(ctx, "int-1"); !ok || string(data) != "tools" {
		t.Fatalf("cache = %q, %v", data, ok)
	}
	if ttl := mr.TTL("jarvis:mcp:tools:int-1"); ttl != time.Minute {
		t.Fatalf("ttl = %v", ttl)
	}
	l.SetTools(ctx, "int-2", make([]byte, maxCachedSize+1))
	if _, ok := l.Tools(ctx, "int-2"); ok {
		t.Fatal("oversized entry cached")
	}
	l.ForgetTools(ctx, "int-1")
	if _, ok := l.Tools(ctx, "int-1"); ok {
		t.Fatal("entry survived ForgetTools")
	}
}

func TestRedisOutageFailsOpen(t *testing.T) {
	l, mr := newLimits(t, 1, 1)
	mr.Close()
	ctx := context.Background()
	for range 3 {
		if ok, _ := l.Allow(ctx, "tenant", "int"); !ok {
			t.Fatal("refused while Redis is down")
		}
	}
	l.SetTools(ctx, "int", []byte("x"))
	if _, ok := l.Tools(ctx, "int"); ok {
		t.Fatal("cache hit while Redis is down")
	}
}

// TestDragonfly runs the limits against the DragonflyDB used in deployment
// (miniredis does not reproduce its Lua reply types).
func TestDragonfly(t *testing.T) {
	ctx := context.Background()
	container, err := testcontainers.Run(ctx, "docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2",
		testcontainers.WithExposedPorts("6379/tcp"),
		testcontainers.WithCmd("dragonfly", "--logtostderr", "--proactor_threads=1", "--maxmemory=256mb"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("6379/tcp")),
	)
	testcontainers.CleanupContainer(t, container)
	if err != nil {
		t.Fatalf("DragonflyDB container (needs Docker): %v", err)
	}
	endpoint, err := container.PortEndpoint(ctx, "6379/tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	rdb := NewClient(endpoint, "")
	t.Cleanup(func() { _ = rdb.Close() })
	// 7 per minute: intervals that are not whole seconds, where Lua number
	// replies used to differ from Redis.
	l := New(rdb, 100, 7, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	allowed := 0
	var retry time.Duration
	for range 10 {
		ok, after := l.Allow(ctx, "tenant", "int")
		if ok {
			allowed++
		} else {
			retry = after
		}
	}
	if allowed != 7 || retry <= 0 || retry > 9*time.Second {
		t.Fatalf("allowed %d of 10 (want 7), retry after %v", allowed, retry)
	}
	l.SetTools(ctx, "int", []byte("tools"))
	if data, ok := l.Tools(ctx, "int"); !ok || string(data) != "tools" {
		t.Fatalf("cache on Dragonfly = %q, %v", data, ok)
	}
}
