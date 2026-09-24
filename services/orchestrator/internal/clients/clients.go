// Package clients connects the orchestrator to the other Jarvis services:
// the MCP router, the knowledge service and the Vault with its mTLS identity,
// the LLM sidecar over a Unix socket, and users' devices over their tailnet.
package clients

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	agentv1 "jarvis.internal/gen/go/jarvis/agent/v1"
	devicev1 "jarvis.internal/gen/go/jarvis/device/v1"
	"jarvis.internal/libs/go/mtls"
	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/orchestrator/internal/store"
)

// PurposeDeviceKey is the Vault purpose of sealed device client keys.
const PurposeDeviceKey = "orchestrator.device-key"

// Identity is the orchestrator's client certificate for internal services.
type Identity struct{ Cert, Key, CA string }

// Dial connects to an internal service with mutual TLS.
func Dial(addr, serverName string, id Identity) (*grpc.ClientConn, error) {
	cfg, err := mtls.ClientConfig(id.Cert, id.Key, id.CA, serverName)
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
}

// DialAgent connects to the sidecar's Unix socket (same pod, mode 0600).
func DialAgent(socket string) (agentv1.AgentWorkerServiceClient, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient("unix:"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16<<20), grpc.MaxCallSendMsgSize(16<<20)))
	if err != nil {
		return nil, nil, err
	}
	return agentv1.NewAgentWorkerServiceClient(conn), conn, nil
}

// ErrAddressNotAllowed means a device address is outside the tailnet.
var ErrAddressNotAllowed = errors.New("device address must be on the tailnet (100.64.0.0/10, fd7a:115c:a1e0::/48 or *.ts.net)")

var tailnet = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

// DeviceGuard keeps device connections on the tailnet: users register
// device addresses, so they must not become a way into other networks.
type DeviceGuard struct{ AllowLoopback bool }

func (g DeviceGuard) allowed(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return g.AllowLoopback
	}
	for _, p := range tailnet {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// CheckAddress validates a device's host:port.
func (g DeviceGuard) CheckAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("%w: %q is not host:port", ErrAddressNotAllowed, address)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !g.allowed(ip) {
			return ErrAddressNotAllowed
		}
		return nil
	}
	if strings.HasSuffix(host, ".ts.net") || (g.AllowLoopback && host == "localhost") {
		return nil
	}
	return ErrAddressNotAllowed
}

// Devices keeps one connection per registered device.
type Devices struct {
	Sealer vaultclient.Sealer
	Guard  DeviceGuard

	mu    sync.Mutex
	conns map[uuid.UUID]*grpc.ClientConn
}

// Client returns a DeviceService client for a device, opening its sealed
// client key through the Vault when first connecting.
func (d *Devices) Client(ctx context.Context, requestID string, dev store.Device) (devicev1.DeviceServiceClient, error) {
	d.mu.Lock()
	conn := d.conns[dev.ID]
	d.mu.Unlock()
	if conn != nil {
		return devicev1.NewDeviceServiceClient(conn), nil
	}
	if err := d.Guard.CheckAddress(dev.Address); err != nil {
		return nil, err
	}
	keyPEM, err := d.Sealer.Open(ctx, requestID, vaultclient.Binding{
		TenantID: dev.TenantID.String(), Purpose: PurposeDeviceKey, Subject: dev.ID.String(),
	}, dev.ClientKeySealed)
	if err != nil {
		return nil, fmt.Errorf("open device key: %w", err)
	}
	certificate, err := tls.X509KeyPair([]byte(dev.ClientCertPEM), keyPEM)
	clear(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("device client certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(dev.CAPEM)) {
		return nil, errors.New("device CA contains no certificate")
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{certificate}, RootCAs: roots, ServerName: dev.ServerName,
		MinVersion: tls.VersionTLS13}
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return ErrAddressNotAllowed
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !d.Guard.allowed(ip) {
			return ErrAddressNotAllowed // e.g. a *.ts.net name resolving elsewhere
		}
		return nil
	}}
	conn, err = grpc.NewClient(dev.Address, grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		}))
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conns == nil {
		d.conns = map[uuid.UUID]*grpc.ClientConn{}
	}
	if existing := d.conns[dev.ID]; existing != nil {
		_ = conn.Close()
		conn = existing
	} else {
		d.conns[dev.ID] = conn
	}
	return devicev1.NewDeviceServiceClient(conn), nil
}

// Forget closes a device's connection (after it is replaced or removed).
func (d *Devices) Forget(id uuid.UUID) {
	d.mu.Lock()
	conn := d.conns[id]
	delete(d.conns, id)
	d.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// Close closes every device connection.
func (d *Devices) Close() {
	d.mu.Lock()
	conns := d.conns
	d.conns = nil
	d.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}
