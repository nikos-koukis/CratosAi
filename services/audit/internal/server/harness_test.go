package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"jarvis.internal/audit/internal/metrics"
	"jarvis.internal/audit/internal/server"
	"jarvis.internal/audit/internal/store"
	auditv1 "jarvis.internal/gen/go/jarvis/audit/v1"
	"jarvis.internal/libs/go/mtls"
)

// A real PostgreSQL for the whole package, and the service over real mTLS
// with a throwaway PKI. Each test uses its own tenants.

var (
	pool    *pgxpool.Pool // the service's
	admin   *pgxpool.Pool // superuser, to tamper with the trail
	address string
	pki     *testPKI
)

const policy = `
[[principal]]
id = "spiffe://jarvis.test/vault"
allow = ["Record"]

[[principal]]
id = "spiffe://jarvis.test/dashboard-api"
allow = ["Record", "ListEvents", "VerifyChain"]
`

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx := context.Background()
	container, err := postgres.Run(ctx, "postgres:18.6-alpine",
		postgres.WithDatabase("audit"), postgres.BasicWaitStrategies())
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot start PostgreSQL (is Docker running?):", err)
		return 1
	}
	defer func() { _ = container.Terminate(ctx) }()
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if pool, err = pgxpool.New(ctx, dsn); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer pool.Close()
	admin = pool
	st := store.New(pool)
	if err := st.Migrate(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		return 1
	}

	dir, err := os.MkdirTemp("", "audit-pki-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	pki = newPKI(dir)
	serverCert, serverKey := pki.issue("server", "", true)
	tlsConfig, err := mtls.ServerConfig(serverCert, serverKey, filepath.Join(dir, "ca.pem"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	methods := []string{}
	for _, method := range auditv1.AuditService_ServiceDesc.Methods {
		methods = append(methods, method.MethodName)
	}
	authz, err := mtls.ParsePolicy(policy, methods)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	met := metrics.New()
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.ChainUnaryInterceptor(server.UnaryInterceptor(log, met),
			authz.UnaryInterceptor(auditv1.AuditService_ServiceDesc.ServiceName)))
	auditv1.RegisterAuditServiceServer(srv, &server.Service{Store: st, Metrics: met, Log: log, Now: time.Now})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	address = lis.Addr().String()
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	return m.Run()
}

// client connects as spiffe://jarvis.test/<name>.
func client(t *testing.T, name string) auditv1.AuditServiceClient {
	t.Helper()
	cert, key := pki.issue(name, "spiffe://jarvis.test/"+name, false)
	tlsConfig, err := mtls.ClientConfig(cert, key, filepath.Join(pki.dir, "ca.pem"), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return auditv1.NewAuditServiceClient(conn)
}

type testPKI struct {
	dir string
	ca  *x509.Certificate
	key *ecdsa.PrivateKey
}

func newPKI(dir string) *testPKI {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ca, _ := x509.ParseCertificate(der)
	writePEM(filepath.Join(dir, "ca.pem"), "CERTIFICATE", der)
	return &testPKI{dir: dir, ca: ca, key: key}
}

func writePEM(path, kind string, der []byte) {
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600)
}

// issue writes <name>.pem and <name>-key.pem; uri is the URI SAN ("" for none).
func (p *testPKI) issue(name, uri string, isServer bool) (string, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if isServer {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
	}
	if uri != "" {
		u, _ := url.Parse(uri)
		tmpl.URIs = []*url.URL{u}
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, keyPath := filepath.Join(p.dir, name+".pem"), filepath.Join(p.dir, name+"-key.pem")
	writePEM(cert, "CERTIFICATE", der)
	writePEM(keyPath, "PRIVATE KEY", keyDER)
	return cert, keyPath
}
