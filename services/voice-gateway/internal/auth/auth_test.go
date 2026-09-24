package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	issuer   = "https://id.jarvis.test"
	audience = "jarvis-voice-gateway"
	tenant   = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
)

func setup(t *testing.T) (*Verifier, Issuer) {
	t.Helper()
	privatePEM, jwksJSON, err := GenerateKey("k1")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseJWKS(jwksJSON)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(keys, issuer, audience, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(privatePEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, Issuer{Key: key.(ed25519.PrivateKey), KeyID: "k1", Issuer: issuer, Audience: audience}
}

func TestValidTokenYieldsIdentity(t *testing.T) {
	verifier, iss := setup(t)
	token, err := iss.Issue("user-42", tenant, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := verifier.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if identity.UserID != "user-42" || identity.TenantID != tenant || identity.TokenID == "" {
		t.Fatalf("identity: %+v", identity)
	}
}

func TestInvalidTokensAreRejected(t *testing.T) {
	verifier, iss := setup(t)
	_, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)

	sign := func(mutate func(*claims), header map[string]any, key ed25519.PrivateKey) string {
		now := time.Now()
		c := claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer: issuer, Audience: jwt.ClaimStrings{audience}, Subject: "u",
				IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			},
			TenantID: tenant,
		}
		mutate(&c)
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
		token.Header["kid"] = "k1"
		for k, v := range header {
			token.Header[k] = v
		}
		signed, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	noop := func(*claims) {}

	cases := map[string]string{
		"wrong signing key": sign(noop, nil, otherPrivate),
		"unknown kid":       sign(noop, map[string]any{"kid": "k2"}, iss.Key),
		"expired": sign(func(c *claims) {
			c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-20 * time.Minute))
			c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))
		}, nil, iss.Key),
		"wrong audience": sign(func(c *claims) { c.Audience = jwt.ClaimStrings{"billing"} }, nil, iss.Key),
		"wrong issuer":   sign(func(c *claims) { c.Issuer = "https://evil" }, nil, iss.Key),
		"no subject":     sign(func(c *claims) { c.Subject = "" }, nil, iss.Key),
		"bad tenant":     sign(func(c *claims) { c.TenantID = "acme" }, nil, iss.Key),
		"no iat":         sign(func(c *claims) { c.IssuedAt = nil }, nil, iss.Key),
		"too long-lived": sign(func(c *claims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(24 * time.Hour)) }, nil, iss.Key),
		"alg none":       "eyJhbGciOiJub25lIiwia2lkIjoiazEifQ." + strings.Split(sign(noop, nil, iss.Key), ".")[1] + ".",
		"garbage":        "not-a-token",
		"oversized":      strings.Repeat("a", maxTokenBytes+1),
	}
	for name, token := range cases {
		if _, err := verifier.Verify(token); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: got %v, want ErrUnauthenticated", name, err)
		}
	}
}

func TestBearerTokenParsing(t *testing.T) {
	for header, want := range map[string]string{
		"Bearer abc": "abc",
		"bearer abc": "abc",
		"Basic abc":  "",
		"Bearer":     "",
		"":           "",
	} {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		got, _ := BearerToken(r)
		if got != want {
			t.Errorf("%q: got %q, want %q", header, got, want)
		}
	}
}

func TestJWKSValidation(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":   "{",
		"empty":      `{"keys":[]}`,
		"rsa":        `{"keys":[{"kty":"RSA","kid":"a","n":"x","e":"AQAB"}]}`,
		"no kid":     `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`,
		"short x":    `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","x":"AAAA"}]}`,
		"duplicates": `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},{"kty":"OKP","crv":"Ed25519","kid":"a","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`,
	} {
		if _, err := ParseJWKS([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
