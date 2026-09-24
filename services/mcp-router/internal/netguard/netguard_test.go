package netguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestInternalAddressesAreBlocked(t *testing.T) {
	g := Guard{}
	for _, blocked := range []string{
		"127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "169.254.169.254", "100.100.100.100",
		"0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fc00::1", "fd12::1",
		"::ffff:10.0.0.1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "198.18.0.1",
	} {
		if g.AllowedAddr(netip.MustParseAddr(blocked)) {
			t.Errorf("%s must be blocked", blocked)
		}
	}
	for _, allowed := range []string{"8.8.8.8", "104.18.0.1", "2606:4700::1"} {
		if !g.AllowedAddr(netip.MustParseAddr(allowed)) {
			t.Errorf("%s must be allowed", allowed)
		}
	}
	if !(Guard{AllowLoopback: true}).AllowedAddr(netip.MustParseAddr("127.0.0.1")) {
		t.Error("loopback must be allowed when enabled")
	}
	if (Guard{AllowLoopback: true}).AllowedAddr(netip.MustParseAddr("10.0.0.1")) {
		t.Error("enabling loopback must not open private ranges")
	}
}

func TestURLChecks(t *testing.T) {
	g := Guard{}
	for _, bad := range []string{
		"http://mcp.example.com/mcp", "ftp://example.com", "https://user:pw@example.com/mcp",
		"https://10.1.2.3/mcp", "https://[::1]/mcp", "https://localhost/mcp", "mcp.example.com",
		"https://169.254.169.254/latest/meta-data",
	} {
		if _, err := g.CheckURL(bad); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: got %v, want ErrNotAllowed", bad, err)
		}
	}
	if _, err := g.CheckURL("https://mcp.atlassian.com/v2/mcp"); err != nil {
		t.Errorf("public https rejected: %v", err)
	}
	if _, err := (Guard{AllowLoopback: true}).CheckURL("http://127.0.0.1:9000/mcp"); err != nil {
		t.Errorf("dev loopback rejected: %v", err)
	}
}

func TestConnectionsToBlockedAddressesFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("internal secret"))
	}))
	defer server.Close()

	// A public-looking name that resolves to loopback (DNS rebinding) is
	// caught at connection time, not just by the URL check.
	strict := Guard{}.Client(5 * time.Second)
	if _, err := strict.Get(server.URL); err == nil {
		t.Fatal("connection to loopback must be refused")
	}
	if resp, err := (Guard{AllowLoopback: true}).Client(5 * time.Second).Get(server.URL); err != nil {
		t.Fatalf("dev client: %v", err)
	} else {
		_ = resp.Body.Close()
	}
}

func TestRedirectsIntoPrivateNetworksAreRefused(t *testing.T) {
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer redirector.Close()
	client := Guard{AllowLoopback: true}.Client(5 * time.Second)
	if _, err := client.Get(redirector.URL); err == nil {
		t.Fatal("redirect to the metadata service must be refused")
	}
}
