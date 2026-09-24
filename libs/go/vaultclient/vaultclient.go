// Package vaultclient talks to the BYOK Vault over gRPC with mutual TLS. The
// caller's client certificate identifies it to the Vault (e.g.
// spiffe://jarvis.local/voice-gateway), whose policy decides which RPCs it may
// use: provider keys (GetDecryptedKey) and/or sealing its own secrets
// (SealData / OpenData).
package vaultclient

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	vaultv1 "jarvis.internal/gen/go/jarvis/vault/v1"
	"jarvis.internal/libs/go/mtls"
)

// ErrNoKey means the tenant has no active key for the provider.
var ErrNoKey = errors.New("tenant has no active key for this provider")

// ErrSealedDataInvalid means sealed data did not open under the binding
// given (different tenant, purpose or subject, or tampered).
var ErrSealedDataInvalid = errors.New("sealed data does not open under this binding")

// KeySource returns a tenant's provider key. The caller must clear the
// returned slice as soon as it has used it.
type KeySource interface {
	ProviderKey(ctx context.Context, requestID, tenantID string, provider commonv1.Provider) ([]byte, error)
}

// Sealer encrypts secrets a service stores itself, bound to a tenant, a
// purpose and a subject. Callers must clear plaintexts after use.
type Sealer interface {
	Seal(ctx context.Context, requestID string, b Binding, plaintext []byte) ([]byte, error)
	Open(ctx context.Context, requestID string, b Binding, sealed []byte) ([]byte, error)
}

// Binding is what sealed data is bound to.
type Binding struct {
	TenantID string
	Purpose  string
	Subject  string
}

// TLSFiles are PEM files for the mTLS connection.
type TLSFiles struct {
	CA   string
	Cert string
	Key  string
}

// Client is a KeySource backed by the Vault.
type Client struct {
	conn   *grpc.ClientConn
	client vaultv1.VaultServiceClient
}

// Dial prepares a connection (established lazily on first use).
func Dial(addr, serverName string, files TLSFiles) (*Client, error) {
	tlsConfig, err := mtls.ClientConfig(files.Cert, files.Key, files.CA, serverName)
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}
	return &Client{conn: conn, client: vaultv1.NewVaultServiceClient(conn)}, nil
}

// ProviderKey returns the tenant's active key for the provider.
func (c *Client) ProviderKey(ctx context.Context, requestID, tenantID string, provider commonv1.Provider) ([]byte, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "x-request-id", requestID)
	response, err := c.client.GetDecryptedKey(ctx, &vaultv1.GetDecryptedKeyRequest{
		TenantId: tenantID,
		Selector: &vaultv1.GetDecryptedKeyRequest_Provider{Provider: provider},
	})
	switch status.Code(err) {
	case codes.OK:
		return response.GetSecret(), nil
	case codes.NotFound, codes.FailedPrecondition:
		return nil, ErrNoKey
	default:
		return nil, fmt.Errorf("vault GetDecryptedKey: %w", err)
	}
}

// Seal encrypts plaintext under the binding.
func (c *Client) Seal(ctx context.Context, requestID string, b Binding, plaintext []byte) ([]byte, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "x-request-id", requestID)
	response, err := c.client.SealData(ctx, &vaultv1.SealDataRequest{
		TenantId: b.TenantID, Purpose: b.Purpose, SubjectId: b.Subject, Plaintext: plaintext,
	})
	if err != nil {
		return nil, fmt.Errorf("vault SealData: %w", err)
	}
	return response.GetSealed(), nil
}

// Open decrypts data from Seal under the same binding.
func (c *Client) Open(ctx context.Context, requestID string, b Binding, sealed []byte) ([]byte, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "x-request-id", requestID)
	response, err := c.client.OpenData(ctx, &vaultv1.OpenDataRequest{
		TenantId: b.TenantID, Purpose: b.Purpose, SubjectId: b.Subject, Sealed: sealed,
	})
	switch status.Code(err) {
	case codes.OK:
		return response.GetPlaintext(), nil
	case codes.FailedPrecondition:
		return nil, ErrSealedDataInvalid
	default:
		return nil, fmt.Errorf("vault OpenData: %w", err)
	}
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }
