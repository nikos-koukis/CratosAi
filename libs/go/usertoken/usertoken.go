// Package usertoken issues and verifies the access tokens of end users:
// short-lived JWTs signed with Ed25519 (alg EdDSA) by the app API, verified
// against a JWKS of trusted public keys. Each service checks its own audience
// (e.g. jarvis-voice-gateway, jarvis-app-api).
//
// Required claims: iss, aud, sub (user id), tenant_id (UUID), iat, exp, with
// exp - iat no longer than the configured maximum lifetime. Tokens issued for
// an app session also carry sid, the session id.
package usertoken

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	maxTokenBytes = 4096
	clockLeeway   = 30 * time.Second
)

// ErrUnauthenticated covers every token failure; details stay in logs.
var ErrUnauthenticated = errors.New("unauthenticated")

// Identity is the authenticated caller.
type Identity struct {
	TenantID string
	UserID   string
	// SessionID is the app session the token was issued for; empty for
	// tokens not tied to a session (development tooling).
	SessionID string
	TokenID   string
	ExpiresAt time.Time
}

type claims struct {
	jwt.RegisteredClaims
	TenantID  string `json:"tenant_id"`
	SessionID string `json:"sid,omitempty"`
}

// Verifier checks access tokens.
type Verifier struct {
	keys        map[string]ed25519.PublicKey
	issuer      string
	audience    string
	maxLifetime time.Duration
	parser      *jwt.Parser
}

// NewVerifier trusts `keys` (by key id) for tokens from `issuer` to `audience`.
func NewVerifier(keys map[string]ed25519.PublicKey, issuer, audience string, maxLifetime time.Duration) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, errors.New("no token verification keys")
	}
	if issuer == "" || audience == "" || maxLifetime <= 0 {
		return nil, errors.New("issuer, audience and a positive maximum lifetime are required")
	}
	return &Verifier{
		keys:        keys,
		issuer:      issuer,
		audience:    audience,
		maxLifetime: maxLifetime,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
			jwt.WithIssuer(issuer),
			jwt.WithAudience(audience),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithLeeway(clockLeeway),
		),
	}, nil
}

// Verify returns the caller's identity, or an error wrapping ErrUnauthenticated.
func (v *Verifier) Verify(token string) (Identity, error) {
	if len(token) > maxTokenBytes {
		return Identity{}, fmt.Errorf("%w: token too large", ErrUnauthenticated)
	}
	var c claims
	_, err := v.parser.ParseWithClaims(token, &c, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, ok := v.keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown key id %q", kid)
		}
		return key, nil
	})
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	if c.Subject == "" {
		return Identity{}, fmt.Errorf("%w: missing sub", ErrUnauthenticated)
	}
	tenant, err := uuid.Parse(c.TenantID)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: tenant_id is not a UUID", ErrUnauthenticated)
	}
	if c.IssuedAt == nil {
		return Identity{}, fmt.Errorf("%w: missing iat", ErrUnauthenticated)
	}
	if lifetime := c.ExpiresAt.Sub(c.IssuedAt.Time); lifetime > v.maxLifetime {
		return Identity{}, fmt.Errorf("%w: token lifetime %s exceeds %s", ErrUnauthenticated, lifetime, v.maxLifetime)
	}
	return Identity{
		TenantID:  tenant.String(),
		UserID:    c.Subject,
		SessionID: c.SessionID,
		TokenID:   c.ID,
		ExpiresAt: c.ExpiresAt.Time,
	}, nil
}

// BearerToken extracts the token from "Authorization: Bearer <token>".
func BearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

// --- JWKS ----------------------------------------------------------------------

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// LoadJWKS reads Ed25519 (OKP) keys from a JWKS file.
func LoadJWKS(path string) (map[string]ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read token keys: %w", err)
	}
	return ParseJWKS(data)
}

// ParseJWKS parses Ed25519 (OKP) keys from JWKS JSON.
func ParseJWKS(data []byte) (map[string]ed25519.PublicKey, error) {
	var set jwks
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			return nil, fmt.Errorf("key %q: only OKP/Ed25519 keys are supported", k.Kid)
		}
		if k.Kid == "" {
			return nil, errors.New("every key needs a kid")
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q: invalid x", k.Kid)
		}
		if _, dup := keys[k.Kid]; dup {
			return nil, fmt.Errorf("duplicate kid %q", k.Kid)
		}
		keys[k.Kid] = ed25519.PublicKey(raw)
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS has no keys")
	}
	return keys, nil
}

// --- issuing ----------------------------------------------------------------------

// Issuer signs access tokens for one audience.
type Issuer struct {
	Key      ed25519.PrivateKey
	KeyID    string
	Issuer   string
	Audience string
}

// Issue signs a token for the user and tenant, valid for ttl.
func (i Issuer) Issue(userID, tenantID string, ttl time.Duration) (string, error) {
	return i.IssueForSession(userID, tenantID, "", ttl)
}

// IssueForSession signs a token tied to an app session (claim sid).
func (i Issuer) IssueForSession(userID, tenantID, sessionID string, ttl time.Duration) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.Issuer,
			Audience:  jwt.ClaimStrings{i.Audience},
			Subject:   userID,
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		TenantID:  tenantID,
		SessionID: sessionID,
	})
	token.Header["kid"] = i.KeyID
	return token.SignedString(i.Key)
}

// GenerateKey returns a new signing key as PKCS#8 PEM and its JWKS entry.
func GenerateKey(kid string) (privatePEM []byte, jwksJSON []byte, err error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, nil, err
	}
	privatePEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	jwksJSON, err = json.MarshalIndent(jwks{Keys: []jwk{{
		Kty: "OKP", Crv: "Ed25519", Kid: kid, Use: "sig", Alg: "EdDSA",
		X: base64.RawURLEncoding.EncodeToString(public),
	}}}, "", "  ")
	return privatePEM, jwksJSON, err
}

// PublicJWKS is the JWKS of a signing key's public half, as the token
// issuer publishes it.
func PublicJWKS(kid string, key ed25519.PrivateKey) ([]byte, error) {
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok || kid == "" {
		return nil, errors.New("an Ed25519 key and a key id are required")
	}
	return json.Marshal(jwks{Keys: []jwk{{
		Kty: "OKP", Crv: "Ed25519", Kid: kid, Use: "sig", Alg: "EdDSA",
		X: base64.RawURLEncoding.EncodeToString(public),
	}}})
}

// LoadSigningKey reads a PKCS#8 PEM Ed25519 private key.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 private key")
	}
	return private, nil
}
