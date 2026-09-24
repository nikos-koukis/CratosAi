// Package mtls gives Jarvis Go services the same zero-trust calling model as
// the Rust services: mutual TLS, a caller identity taken only from the single
// URI SAN of the verified client certificate (e.g.
// spiffe://jarvis.local/orchestrator), and a per-principal allowlist of RPCs.
package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ServerConfig requires client certificates chaining to the CA in caFile.
func ServerConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	clients, err := loadPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    clients,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientConfig presents the client certificate and trusts only caFile.
func ClientConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	roots, err := loadPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func loadPool(caFile string) (*x509.CertPool, error) {
	pemData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("%s contains no certificates", caFile)
	}
	return pool, nil
}

// ErrUnauthenticated means no usable client identity was presented.
var ErrUnauthenticated = errors.New("caller identity could not be established from the client certificate")

// PeerPrincipal returns the single URI SAN of the verified client certificate.
func PeerPrincipal(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", ErrUnauthenticated
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 || len(info.State.PeerCertificates) == 0 {
		return "", ErrUnauthenticated
	}
	uris := info.State.PeerCertificates[0].URIs
	if len(uris) != 1 || uris[0].Scheme == "" || uris[0].Host == "" {
		return "", ErrUnauthenticated
	}
	return uris[0].String(), nil
}

type principalKey struct{}

// Principal returns the caller set by the Policy interceptor.
func Principal(ctx context.Context) string {
	principal, _ := ctx.Value(principalKey{}).(string)
	return principal
}

// Policy maps a principal to the RPC method names it may call. Anything not
// listed is denied.
type Policy struct {
	grants map[string]map[string]bool
}

type policyFile struct {
	Principal []struct {
		ID    string   `toml:"id"`
		Allow []string `toml:"allow"`
	} `toml:"principal"`
}

// LoadPolicy reads `[[principal]] id = "..." allow = ["Method", ...]` TOML,
// accepting only method names in `known`.
func LoadPolicy(path string, known []string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authorization policy: %w", err)
	}
	return ParsePolicy(string(data), known)
}

// ParsePolicy is LoadPolicy for TOML text.
func ParsePolicy(text string, known []string) (*Policy, error) {
	var file policyFile
	meta, err := toml.Decode(text, &file)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization policy: %w", err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("invalid authorization policy: unknown field %s", undecoded[0])
	}
	valid := map[string]bool{}
	for _, name := range known {
		valid[name] = true
	}
	policy := &Policy{grants: map[string]map[string]bool{}}
	for _, grant := range file.Principal {
		if scheme, rest, ok := strings.Cut(grant.ID, "://"); !ok || scheme == "" || rest == "" {
			return nil, fmt.Errorf("invalid authorization policy: principal %q is not a URI", grant.ID)
		}
		if _, dup := policy.grants[grant.ID]; dup {
			return nil, fmt.Errorf("invalid authorization policy: principal %s listed twice", grant.ID)
		}
		if len(grant.Allow) == 0 {
			return nil, fmt.Errorf("invalid authorization policy: principal %s has an empty allow list", grant.ID)
		}
		methods := map[string]bool{}
		for _, method := range grant.Allow {
			if !valid[method] {
				return nil, fmt.Errorf("invalid authorization policy: unknown method %q", method)
			}
			methods[method] = true
		}
		policy.grants[grant.ID] = methods
	}
	return policy, nil
}

// Allowed reports whether principal may call method (short name).
func (p *Policy) Allowed(principal, method string) bool {
	return p.grants[principal][method]
}

// Principals is the number of principals with grants.
func (p *Policy) Principals() int { return len(p.grants) }

// UnaryInterceptor authenticates the caller and enforces the policy for
// methods of `service` (e.g. "jarvis.mcp.v1.McpRouterService"). Other
// services on the same server (health, reflection) only need a valid
// client certificate.
func (p *Policy) UnaryInterceptor(service string) grpc.UnaryServerInterceptor {
	prefix := "/" + service + "/"
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		principal, err := PeerPrincipal(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		if method, ok := strings.CutPrefix(info.FullMethod, prefix); ok && !p.Allowed(principal, method) {
			return nil, status.Error(codes.PermissionDenied, "caller is not allowed to call this method")
		}
		return handler(context.WithValue(ctx, principalKey{}, principal), req)
	}
}

// StreamInterceptor is UnaryInterceptor for streaming RPCs.
func (p *Policy) StreamInterceptor(service string) grpc.StreamServerInterceptor {
	prefix := "/" + service + "/"
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		principal, err := PeerPrincipal(ss.Context())
		if err != nil {
			return status.Error(codes.Unauthenticated, err.Error())
		}
		if method, ok := strings.CutPrefix(info.FullMethod, prefix); ok && !p.Allowed(principal, method) {
			return status.Error(codes.PermissionDenied, "caller is not allowed to call this method")
		}
		return handler(srv, &principalStream{ServerStream: ss, ctx: context.WithValue(ss.Context(), principalKey{}, principal)})
	}
}

type principalStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *principalStream) Context() context.Context { return s.ctx }
