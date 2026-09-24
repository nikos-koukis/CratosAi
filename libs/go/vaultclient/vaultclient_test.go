package vaultclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	vaultv1 "jarvis.internal/gen/go/jarvis/vault/v1"
)

const gatewayID = "spiffe://jarvis.test/voice-gateway"

// fakeVault answers like the real Vault and records the caller's identity.
type fakeVault struct {
	vaultv1.UnimplementedVaultServiceServer
	caller    string
	requestID string
}

func (f *fakeVault) SealData(_ context.Context, req *vaultv1.SealDataRequest) (*vaultv1.SealDataResponse, error) {
	return &vaultv1.SealDataResponse{Sealed: []byte(req.GetTenantId() + "|" + req.GetPurpose() + "|" + req.GetSubjectId() + "|" + string(req.GetPlaintext()))}, nil
}

func (f *fakeVault) OpenData(_ context.Context, req *vaultv1.OpenDataRequest) (*vaultv1.OpenDataResponse, error) {
	prefix := req.GetTenantId() + "|" + req.GetPurpose() + "|" + req.GetSubjectId() + "|"
	sealed := string(req.GetSealed())
	if len(sealed) < len(prefix) || sealed[:len(prefix)] != prefix {
		return nil, status.Error(codes.FailedPrecondition, "sealed data does not open")
	}
	return &vaultv1.OpenDataResponse{Plaintext: []byte(sealed[len(prefix):])}, nil
}

func (f *fakeVault) GetDecryptedKey(ctx context.Context, req *vaultv1.GetDecryptedKeyRequest) (*vaultv1.GetDecryptedKeyResponse, error) {
	if p, ok := peer.FromContext(ctx); ok {
		if info, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(info.State.PeerCertificates) > 0 {
			if uris := info.State.PeerCertificates[0].URIs; len(uris) == 1 {
				f.caller = uris[0].String()
			}
		}
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok && len(md.Get("x-request-id")) == 1 {
		f.requestID = md.Get("x-request-id")[0]
	}
	switch req.GetTenantId() {
	case "with-key":
		if req.GetProvider() != commonv1.Provider_PROVIDER_XAI {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return &vaultv1.GetDecryptedKeyResponse{KeyId: "k1", Provider: req.GetProvider(), Secret: []byte("xai-secret")}, nil
	case "revoked":
		return nil, status.Error(codes.FailedPrecondition, "key has been revoked")
	case "broken":
		return nil, status.Error(codes.Internal, "internal error")
	default:
		return nil, status.Error(codes.NotFound, "key not found")
	}
}

type pki struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &pki{caCert: cert, caKey: key, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (p *pki) issue(t *testing.T, serial int64, server bool, uri string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"localhost"}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		u, _ := url.Parse(uri)
		template.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func startVault(t *testing.T) (*fakeVault, string, TLSFiles) {
	t.Helper()
	authority := newPKI(t)
	serverCert, serverKey := authority.issue(t, 2, true, "")
	clientCert, clientKey := authority.issue(t, 3, false, gatewayID)

	pair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clients := x509.NewCertPool()
	clients.AddCert(authority.caCert)
	vault := &fakeVault{}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientCAs:    clients,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	})))
	vaultv1.RegisterVaultServiceServer(grpcServer, vault)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)

	dir := t.TempDir()
	files := TLSFiles{CA: filepath.Join(dir, "ca.pem"), Cert: filepath.Join(dir, "gw.pem"), Key: filepath.Join(dir, "gw-key.pem")}
	for path, data := range map[string][]byte{files.CA: authority.caPEM, files.Cert: clientCert, files.Key: clientKey} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return vault, listener.Addr().String(), files
}

func TestKeysAreFetchedOverMutualTLS(t *testing.T) {
	vault, addr, files := startVault(t)
	client, err := Dial(addr, "localhost", files)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	secret, err := client.ProviderKey(context.Background(), "session-123", "with-key", commonv1.Provider_PROVIDER_XAI)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "xai-secret" {
		t.Fatalf("secret %q", secret)
	}
	if vault.caller != gatewayID {
		t.Fatalf("vault saw caller %q, want %q", vault.caller, gatewayID)
	}
	if vault.requestID != "session-123" {
		t.Fatalf("x-request-id %q not propagated", vault.requestID)
	}
}

func TestMissingAndRevokedKeysMapToErrNoKey(t *testing.T) {
	_, addr, files := startVault(t)
	client, err := Dial(addr, "localhost", files)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()

	for _, tenant := range []string{"nobody", "revoked"} {
		if _, err := client.ProviderKey(ctx, "r", tenant, commonv1.Provider_PROVIDER_XAI); !errors.Is(err, ErrNoKey) {
			t.Fatalf("%s: got %v, want ErrNoKey", tenant, err)
		}
	}
	if _, err := client.ProviderKey(ctx, "r", "broken", commonv1.Provider_PROVIDER_XAI); err == nil || errors.Is(err, ErrNoKey) {
		t.Fatalf("an internal vault error must not look like a missing key: %v", err)
	}
}

func TestWrongServerNameIsRejected(t *testing.T) {
	_, addr, files := startVault(t)
	client, err := Dial(addr, "not-the-vault", files)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.ProviderKey(ctx, "r", "with-key", commonv1.Provider_PROVIDER_XAI); err == nil {
		t.Fatal("certificate name mismatch must fail")
	}
}

func TestSealAndOpenMapErrors(t *testing.T) {
	_, addr, files := startVault(t)
	client, err := Dial(addr, "localhost", files)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	binding := Binding{TenantID: "t", Purpose: "mcp.oauth-tokens", Subject: "i1"}

	sealed, err := client.Seal(ctx, "r", binding, []byte("tokens"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := client.Open(ctx, "r", binding, sealed)
	if err != nil || string(opened) != "tokens" {
		t.Fatalf("open: %q %v", opened, err)
	}
	other := binding
	other.Subject = "i2"
	if _, err := client.Open(ctx, "r", other, sealed); !errors.Is(err, ErrSealedDataInvalid) {
		t.Fatalf("got %v, want ErrSealedDataInvalid", err)
	}
}
