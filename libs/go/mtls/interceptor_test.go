package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

type testPKI struct {
	dir string
	ca  *x509.Certificate
	key *ecdsa.PrivateKey
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &testPKI{dir: t.TempDir(), ca: ca, key: key}
	writePEM(t, filepath.Join(p.dir, "ca.pem"), "CERTIFICATE", der)
	return p
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// issue writes <name>.pem and <name>-key.pem; uri is the URI SAN ("" for none).
func (p *testPKI) issue(t *testing.T, name, uri string, server bool) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
	}
	if uri != "" {
		u, _ := url.Parse(uri)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, keyPath := filepath.Join(p.dir, name+".pem"), filepath.Join(p.dir, name+"-key.pem")
	writePEM(t, cert, "CERTIFICATE", der)
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)
	return cert, keyPath
}

func TestInterceptorsEnforceThePolicy(t *testing.T) {
	pki := newPKI(t)
	serverCert, serverKey := pki.issue(t, "server", "", true)
	ca := filepath.Join(pki.dir, "ca.pem")
	policy, err := ParsePolicy(`
[[principal]]
id = "spiffe://jarvis.local/checker"
allow = ["Check"]

[[principal]]
id = "spiffe://jarvis.local/watcher"
allow = ["Watch"]
`, []string{"Check", "Watch", "List"})
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := ServerConfig(serverCert, serverKey, ca)
	if err != nil {
		t.Fatal(err)
	}
	const service = "grpc.health.v1.Health"
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)),
		grpc.UnaryInterceptor(policy.UnaryInterceptor(service)),
		grpc.StreamInterceptor(policy.StreamInterceptor(service)))
	h := health.NewServer()
	healthpb.RegisterHealthServer(srv, h)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	client := func(name, uri string) healthpb.HealthClient {
		cert, key := pki.issue(t, name, uri, false)
		cfg, err := ClientConfig(cert, key, ca, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return healthpb.NewHealthClient(conn)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	checker := client("checker", "spiffe://jarvis.local/checker")
	if _, err := checker.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("allowed unary call: %v", err)
	}
	watch := func(c healthpb.HealthClient) error {
		stream, err := c.Watch(ctx, &healthpb.HealthCheckRequest{})
		if err != nil {
			return err
		}
		_, err = stream.Recv()
		return err
	}
	if code := status.Code(watch(checker)); code != codes.PermissionDenied {
		t.Fatalf("streaming call outside the grant: %v", code)
	}
	watcher := client("watcher", "spiffe://jarvis.local/watcher")
	if err := watch(watcher); err != nil {
		t.Fatalf("allowed streaming call: %v", err)
	}
	if _, err := watcher.Check(ctx, &healthpb.HealthCheckRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unary call outside the grant: %v", err)
	}
	anonymous := client("anonymous", "")
	if _, err := anonymous.Check(ctx, &healthpb.HealthCheckRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("certificate without URI SAN, unary: %v", err)
	}
	if code := status.Code(watch(anonymous)); code != codes.Unauthenticated {
		t.Fatalf("certificate without URI SAN, stream: %v", code)
	}
}
