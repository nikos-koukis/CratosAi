// Package netguard keeps the router's outbound HTTP (MCP calls, OAuth
// discovery, registration and token requests) on the public internet.
//
// MCP server URLs and every URL discovered from them come from users and
// remote servers, so they are a server-side request forgery (SSRF) vector.
// The guard checks URLs up front and, more importantly, checks the actual IP
// address of every connection as it is made, which also defeats DNS
// rebinding and redirects into private networks.
package netguard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// ErrNotAllowed means a destination is not a public HTTPS endpoint.
var ErrNotAllowed = errors.New("destination is not an allowed public HTTPS endpoint")

const maxRedirects = 5

// Blocked in addition to what netip classifies as private, loopback,
// link-local, multicast or unspecified.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this" network
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT (and Tailscale)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, broadcast
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64: would reach IPv4 space
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}

// Guard decides which destinations are reachable.
type Guard struct {
	// AllowLoopback permits http:// and https:// to 127.0.0.0/8 and ::1, for
	// development and tests only.
	AllowLoopback bool
}

// AllowedAddr reports whether a connection to addr may be made.
func (g Guard) AllowedAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return g.AllowLoopback
	}
	if !addr.IsValid() || addr.IsPrivate() || addr.IsUnspecified() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() {
		return false
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// CheckURL validates a URL before use: https (http only to loopback when
// allowed), no credentials, and no literal IP outside the allowed ranges.
func (g Guard) CheckURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, fmt.Errorf("%w: %q is not an absolute URL", ErrNotAllowed, raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: URLs must not contain credentials", ErrNotAllowed)
	}
	host := u.Hostname()
	loopbackHost := host == "localhost"
	if addr, err := netip.ParseAddr(host); err == nil {
		if !g.AllowedAddr(addr) {
			return nil, fmt.Errorf("%w: %s", ErrNotAllowed, host)
		}
		loopbackHost = addr.Unmap().IsLoopback()
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && g.AllowLoopback && loopbackHost:
	default:
		return nil, fmt.Errorf("%w: %s must use https", ErrNotAllowed, u.Redacted())
	}
	if loopbackHost && !g.AllowLoopback {
		return nil, fmt.Errorf("%w: %s", ErrNotAllowed, host)
	}
	return u, nil
}

// Client returns an HTTP client for short requests (OAuth discovery,
// registration, tokens) that only connects to allowed addresses and re-checks
// every redirect.
func (g Guard) Client(timeout time.Duration) *http.Client {
	client := g.client(30 * time.Second)
	client.Timeout = timeout
	return client
}

// StreamingClient is Client for MCP traffic: no overall timeout and no
// response header timeout (a tool may take minutes before it answers), so
// every request must carry a context deadline.
func (g Guard) StreamingClient() *http.Client {
	return g.client(0)
}

func (g Guard) client(responseHeaderTimeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		// Runs for each resolved address right before connecting.
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrNotAllowed, address)
			}
			addr, err := netip.ParseAddr(host)
			if err != nil || !g.AllowedAddr(addr) {
				return fmt.Errorf("%w: %s", ErrNotAllowed, host)
			}
			return nil
		},
	}
	transport := &http.Transport{
		// Never route through environment proxies: the checks above must see
		// the real destination.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			if _, err := g.CheckURL(req.URL.String()); err != nil {
				return err
			}
			return nil
		},
	}
}
