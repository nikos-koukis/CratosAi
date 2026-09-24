package api

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"jarvis.internal/app-api/internal/store"
	"jarvis.internal/libs/go/usertoken"
)

// Token audiences: the app API itself and the voice gateway.
const (
	AccessAudience = "jarvis-app-api"
	VoiceAudience  = "jarvis-voice-gateway"
)

// Minter issues a session's short-lived tokens and verifies access tokens.
type Minter struct {
	access   usertoken.Issuer
	voice    usertoken.Issuer
	verifier *usertoken.Verifier
	ttl      time.Duration
	jwks     []byte
}

// NewMinter signs with key (published as kid) for issuer.
func NewMinter(key ed25519.PrivateKey, kid, issuer string, ttl time.Duration) (*Minter, error) {
	jwks, err := usertoken.PublicJWKS(kid, key)
	if err != nil {
		return nil, err
	}
	keys, err := usertoken.ParseJWKS(jwks)
	if err != nil {
		return nil, err
	}
	verifier, err := usertoken.NewVerifier(keys, issuer, AccessAudience, ttl)
	if err != nil {
		return nil, err
	}
	return &Minter{
		access:   usertoken.Issuer{Key: key, KeyID: kid, Issuer: issuer, Audience: AccessAudience},
		voice:    usertoken.Issuer{Key: key, KeyID: kid, Issuer: issuer, Audience: VoiceAudience},
		verifier: verifier,
		ttl:      ttl,
		jwks:     jwks,
	}, nil
}

// Mint issues an access token and a voice token for the session.
func (m *Minter) Mint(s store.Session) (access, voice string, expires time.Time, err error) {
	expires = time.Now().Add(m.ttl)
	tenant, user, id := s.TenantID.String(), s.UserID, s.ID.String()
	if access, err = m.access.IssueForSession(user, tenant, id, m.ttl); err != nil {
		return "", "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}
	if voice, err = m.voice.IssueForSession(user, tenant, id, m.ttl); err != nil {
		return "", "", time.Time{}, fmt.Errorf("sign voice token: %w", err)
	}
	return access, voice, expires, nil
}

// Verify checks an access token (not a voice token: the audience differs).
func (m *Minter) Verify(token string) (usertoken.Identity, error) {
	return m.verifier.Verify(token)
}

// JWKS is the public key set that verifies every token the minter issues;
// the voice gateway trusts it.
func (m *Minter) JWKS() []byte { return m.jwks }
