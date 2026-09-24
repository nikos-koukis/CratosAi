package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type received struct {
	path    string
	header  http.Header
	payload map[string]any
	proto   string
}

// fakeAPNs answers with scripted statuses and records requests.
type fakeAPNs struct {
	mu       sync.Mutex
	requests []received
	replies  []struct {
		status int
		reason string
	}
}

func (f *fakeAPNs) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var payload map[string]any
	_ = json.Unmarshal(body, &payload)
	f.mu.Lock()
	f.requests = append(f.requests, received{path: r.URL.Path, header: r.Header.Clone(), payload: payload, proto: r.Proto})
	status, reason := http.StatusOK, ""
	if len(f.replies) > 0 {
		status, reason = f.replies[0].status, f.replies[0].reason
		f.replies = f.replies[1:]
	}
	f.mu.Unlock()
	w.WriteHeader(status)
	if reason != "" {
		_, _ = w.Write([]byte(`{"reason":"` + reason + `"}`))
	}
}

func (f *fakeAPNs) reply(status int, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies = append(f.replies, struct {
		status int
		reason string
	}{status, reason})
}

func setup(t *testing.T) (*Client, *fakeAPNs, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	path := filepath.Join(t.TempDir(), "AuthKey_ABCDE12345.p8")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := New(Config{KeyFile: path, KeyID: "ABCDE12345", TeamID: "TEAM123456", Topic: "com.example.jarvis"})
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeAPNs{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(fake.handle))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	client.WithHosts(map[string]string{"sandbox": server.URL, "production": server.URL + "/prod"}, server.Client())
	return client, fake, key
}

var alert = Alert{Title: "Approval needed", Body: "A command waits.", Thread: "approvals", CollapseID: "approval-t1",
	TimeSensitive: true, Expires: time.Unix(1_800_000_000, 0), Data: map[string]string{"kind": "approval_needed"}}

func TestSendsAnAuthenticatedAlertOverHTTP2(t *testing.T) {
	client, fake, key := setup(t)
	if err := client.Send(context.Background(), "sandbox", "abcd", alert); err != nil {
		t.Fatal(err)
	}
	got := fake.requests[0]
	if got.proto != "HTTP/2.0" || got.path != "/3/device/abcd" {
		t.Fatalf("request %s %s", got.proto, got.path)
	}
	for name, want := range map[string]string{"apns-topic": "com.example.jarvis", "apns-push-type": "alert",
		"apns-priority": "10", "apns-collapse-id": "approval-t1", "apns-expiration": "1800000000"} {
		if got.header.Get(name) != want {
			t.Errorf("%s = %q, want %q", name, got.header.Get(name), want)
		}
	}
	bearer := strings.TrimPrefix(got.header.Get("Authorization"), "bearer ")
	token, err := jwt.Parse(bearer, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatalf("provider token: %v", err)
	}
	claims := token.Claims.(jwt.MapClaims)
	if token.Header["kid"] != "ABCDE12345" || claims["iss"] != "TEAM123456" || claims["iat"] == nil {
		t.Fatalf("provider token %v %v", token.Header, claims)
	}
	aps := got.payload["aps"].(map[string]any)
	a := aps["alert"].(map[string]any)
	if a["title"] != "Approval needed" || aps["interruption-level"] != "time-sensitive" || aps["thread-id"] != "approvals" ||
		got.payload["jarvis"].(map[string]any)["kind"] != "approval_needed" {
		t.Fatalf("payload %v", got.payload)
	}
	// Production goes to its own host.
	if err := client.Send(context.Background(), "production", "abcd", alert); err != nil ||
		fake.requests[1].path != "/prod/3/device/abcd" {
		t.Fatalf("production: %v %s", err, fake.requests[1].path)
	}
	if err := client.Send(context.Background(), "staging", "abcd", alert); err == nil {
		t.Fatal("unknown environment accepted")
	}
}

func TestDeadTokensAndPassingFailures(t *testing.T) {
	client, fake, _ := setup(t)
	for _, c := range []struct {
		status int
		reason string
	}{{410, "Unregistered"}, {400, "BadDeviceToken"}, {400, "DeviceTokenNotForTopic"}} {
		fake.reply(c.status, c.reason)
		if err := client.Send(context.Background(), "sandbox", "abcd", alert); !errors.Is(err, ErrUnregistered) {
			t.Errorf("%d %s: %v", c.status, c.reason, err)
		}
	}
	fake.reply(429, "TooManyRequests")
	var apnsErr *Error
	if err := client.Send(context.Background(), "sandbox", "abcd", alert); !errors.As(err, &apnsErr) ||
		apnsErr.Status != 429 || apnsErr.Reason != "TooManyRequests" {
		t.Fatalf("429: %v", err)
	}
}

func TestProviderTokensAreReusedAndRenewed(t *testing.T) {
	client, fake, _ := setup(t)
	now := time.Now()
	client.now = func() time.Time { return now }
	send := func() string {
		t.Helper()
		if err := client.Send(context.Background(), "sandbox", "abcd", alert); err != nil {
			t.Fatal(err)
		}
		return fake.requests[len(fake.requests)-1].header.Get("Authorization")
	}
	first := send()
	if send() != first {
		t.Fatal("a fresh provider token was made too soon (Apple throttles that)")
	}
	now = now.Add(41 * time.Minute)
	second := send()
	if second == first {
		t.Fatal("an old provider token was reused")
	}
	// Rejected as expired: one retry with a new token.
	fake.reply(403, "ExpiredProviderToken")
	now = now.Add(time.Second)
	if err := client.Send(context.Background(), "sandbox", "abcd", alert); err != nil {
		t.Fatal(err)
	}
	n := len(fake.requests)
	if fake.requests[n-1].header.Get("Authorization") == fake.requests[n-2].header.Get("Authorization") {
		t.Fatal("retried with the rejected token")
	}
}

func TestBadConfigurationIsRefused(t *testing.T) {
	dir := t.TempDir()
	rsaLike := filepath.Join(dir, "not-a-key.p8")
	_ = os.WriteFile(rsaLike, []byte("hello"), 0o600)
	for name, c := range map[string]Config{
		"short key id":  {KeyFile: rsaLike, KeyID: "ABC", TeamID: "TEAM123456", Topic: "t"},
		"no topic":      {KeyFile: rsaLike, KeyID: "ABCDE12345", TeamID: "TEAM123456"},
		"missing file":  {KeyFile: filepath.Join(dir, "nope"), KeyID: "ABCDE12345", TeamID: "TEAM123456", Topic: "t"},
		"not a PEM key": {KeyFile: rsaLike, KeyID: "ABCDE12345", TeamID: "TEAM123456", Topic: "t"},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
