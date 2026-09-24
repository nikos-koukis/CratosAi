// Package oauthflow implements the MCP authorization flow (OAuth 2.1
// authorization code + PKCE) for a server-side client.
//
// The flow is split in two because the user consents in a browser, possibly
// minutes later and via another router instance:
//
//	Begin:    discover the authorization server from the MCP server (401 +
//	          protected resource metadata), obtain an OAuth client (operator
//	          pre-registration, else dynamic registration), and return an
//	          authorization URL with PKCE (S256) and the RFC 8707 resource.
//	          State lives in the database; the PKCE verifier is Vault-sealed.
//	Complete: consume the single-use state, check `iss` (RFC 9207), exchange
//	          the code and store the Vault-sealed tokens.
//
// At call time TokenSource refreshes tokens automatically and re-seals
// rotated ones; a refresh the authorization server refuses marks the
// integration NEEDS_REAUTH (network failures do not).
package oauthflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"

	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/mcp-router/internal/catalog"
	"jarvis.internal/mcp-router/internal/netguard"
	"jarvis.internal/mcp-router/internal/store"
	"jarvis.internal/mcp-router/internal/upstream"
)

const (
	purposeCredentials  = "mcp.credentials"
	purposeVerifier     = "mcp.pkce-verifier"
	purposeClientSecret = "mcp.oauth-client-secret"
	// Platform-level secrets (OAuth client registrations) are not tenant data.
	platformTenant = "00000000-0000-0000-0000-000000000000"
	pendingTTL     = 10 * time.Minute
	// A dynamic registration expiring sooner than this is renewed, so it
	// outlives the authorization it is used for.
	registrationMargin = 15 * time.Minute
	// Version the discovery probe claims; servers answer 401 either way.
	probeProtocolVersion = "2025-11-25"
)

var (
	// ErrAuthorization covers discovery, registration, consent and exchange failures.
	ErrAuthorization = errors.New("authorization failed")
	// ErrNotConfigured means the server needs an operator-registered OAuth app.
	ErrNotConfigured = errors.New("OAuth client credentials are not configured for this server")
	// ErrNeedsReauth means stored tokens stopped working.
	ErrNeedsReauth = errors.New("stored authorization is no longer valid; reauthorize")
)

// Credentials are what gets sealed per integration.
type Credentials struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Expiry       time.Time `json:"expiry,omitzero"`
}

// Flow holds the collaborators of the OAuth flow.
type Flow struct {
	Store       *store.Store
	Sealer      vaultclient.Sealer
	Catalog     *catalog.Catalog
	HTTP        *http.Client // guarded: public destinations only
	Guard       netguard.Guard
	RedirectURI string
	ClientName  string
	Log         *slog.Logger

	mu   sync.Mutex
	live map[uuid.UUID]*liveToken
}

// Begin starts an authorization for the integration and returns the URL to
// send the user to.
func (f *Flow) Begin(ctx context.Context, requestID string, integration store.Integration) (string, error) {
	prm, challengeScope, err := f.protectedResource(ctx, integration.ServerURL)
	if err != nil {
		return "", err
	}
	if len(prm.AuthorizationServers) == 0 {
		return "", fmt.Errorf("%w: the server names no authorization server", ErrAuthorization)
	}
	issuer := prm.AuthorizationServers[0]
	if _, err := f.Guard.CheckURL(issuer); err != nil {
		return "", fmt.Errorf("%w: authorization server: %v", ErrAuthorization, err)
	}
	asm, err := auth.GetAuthServerMetadata(ctx, issuer, f.HTTP)
	if err != nil || asm == nil {
		return "", fmt.Errorf("%w: authorization server metadata for %s: %v", ErrAuthorization, issuer, err)
	}
	clientID, clientSecret, err := f.client(ctx, requestID, integration.CatalogSlug, issuer, asm)
	if err != nil {
		return "", err
	}

	scopes := strings.Fields(challengeScope)
	if len(scopes) == 0 {
		scopes = prm.ScopesSupported
	}
	verifier := oauth2.GenerateVerifier()
	state, err := randomToken()
	if err != nil {
		return "", err
	}
	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     oauth2.Endpoint{AuthURL: asm.AuthorizationEndpoint, TokenURL: asm.TokenEndpoint},
		RedirectURL:  f.RedirectURI,
		Scopes:       scopes,
	}
	authURL := config.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("resource", prm.Resource))

	sealedVerifier, err := f.Sealer.Seal(ctx, requestID, f.binding(integration.TenantID, purposeVerifier, integration.ID.String()), []byte(verifier))
	if err != nil {
		return "", fmt.Errorf("seal PKCE verifier: %w", err)
	}
	if err := f.Store.SavePending(ctx, state, store.Pending{
		IntegrationID:  integration.ID,
		Issuer:         issuer,
		TokenEndpoint:  asm.TokenEndpoint,
		Resource:       prm.Resource,
		RedirectURI:    f.RedirectURI,
		IssRequired:    asm.AuthorizationResponseIssParameterSupported,
		VerifierSealed: sealedVerifier,
		ExpiresAt:      time.Now().Add(pendingTTL),
	}); err != nil {
		return "", err
	}
	return authURL, nil
}

// Complete finishes an authorization from the redirect's query parameters
// and returns the integration it connected.
func (f *Flow) Complete(ctx context.Context, requestID, state, code, iss, errorCode string) (uuid.UUID, error) {
	pending, err := f.Store.TakePending(ctx, state)
	if errors.Is(err, store.ErrNotFound) {
		return uuid.Nil, fmt.Errorf("%w: unknown, already used or expired authorization request", ErrAuthorization)
	}
	if err != nil {
		return uuid.Nil, err
	}
	integration, err := f.Store.IntegrationByID(ctx, pending.IntegrationID)
	if err != nil {
		return uuid.Nil, err
	}
	fail := func(detail string) (uuid.UUID, error) {
		_ = f.Store.SetStatus(ctx, integration.ID, integration.Status, "authorization failed: "+detail)
		return integration.ID, fmt.Errorf("%w: %s", ErrAuthorization, detail)
	}

	// RFC 9207: never act on a response from an unexpected issuer (and never
	// echo its error fields).
	switch {
	case iss != "" && iss != pending.Issuer:
		return fail("the response came from an unexpected issuer")
	case iss == "" && pending.IssRequired:
		return fail("the response is missing the required iss parameter")
	case errorCode != "":
		return fail("the authorization server returned " + sanitizeCode(errorCode))
	case code == "":
		return fail("no authorization code in the response")
	}

	verifier, err := f.Sealer.Open(ctx, requestID, f.binding(integration.TenantID, purposeVerifier, integration.ID.String()), pending.VerifierSealed)
	if err != nil {
		return fail("the authorization request could not be verified")
	}
	defer clear(verifier)
	clientID, clientSecret, err := f.storedClient(ctx, requestID, integration.CatalogSlug, pending.Issuer, pending.RedirectURI)
	if err != nil {
		return fail("no OAuth client for this authorization server")
	}
	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     oauth2.Endpoint{TokenURL: pending.TokenEndpoint},
		RedirectURL:  pending.RedirectURI,
	}
	token, err := config.Exchange(context.WithValue(ctx, oauth2.HTTPClient, f.HTTP), code,
		oauth2.VerifierOption(string(verifier)),
		oauth2.SetAuthURLParam("resource", pending.Resource))
	if err != nil {
		f.Log.Warn("OAuth token exchange failed", "integration_id", integration.ID, "error", err)
		f.forgetRejectedClient(ctx, err, pending.Issuer, pending.RedirectURI, clientID)
		return fail("the token exchange failed")
	}
	sealed, err := f.seal(ctx, requestID, integration, fromToken(token))
	if err != nil {
		return integration.ID, err
	}
	if _, err := f.Store.Connect(ctx, integration.ID, pending.Issuer, pending.TokenEndpoint, pending.RedirectURI, sealed); err != nil {
		return integration.ID, err
	}
	return integration.ID, nil
}

// SealBearer seals a static bearer token for an integration.
func (f *Flow) SealBearer(ctx context.Context, requestID string, integration store.Integration, token []byte) ([]byte, error) {
	return f.seal(ctx, requestID, integration, Credentials{AccessToken: string(token), TokenType: "Bearer"})
}

// TokenSource returns tokens for calls to the integration's server,
// refreshing (and re-sealing) them as needed.
func (f *Flow) TokenSource(ctx context.Context, requestID string, integration store.Integration) (upstream.Source, error) {
	if integration.Auth == store.AuthBearer {
		token, err := f.openToken(ctx, requestID, integration)
		if err != nil {
			return nil, err
		}
		return staticSource{token}, nil
	}
	clientID, clientSecret, err := f.storedClient(ctx, requestID, integration.CatalogSlug, integration.Issuer, integration.RedirectURI)
	if err != nil {
		return nil, err
	}
	live, err := f.liveToken(ctx, requestID, integration)
	if err != nil {
		return nil, err
	}
	return &savingSource{
		flow:        f,
		requestID:   requestID,
		integration: integration,
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     oauth2.Endpoint{TokenURL: integration.TokenEndpoint},
		},
		live: live,
	}, nil
}

// Forget drops the in-memory token of an integration (deleted, reauthorized).
func (f *Flow) Forget(integrationID uuid.UUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.live, integrationID)
}

// MarkNeedsReauth records that the stored authorization stopped working.
func (f *Flow) MarkNeedsReauth(ctx context.Context, integrationID uuid.UUID, detail string) {
	if err := f.Store.SetStatus(ctx, integrationID, store.StatusNeedsReauth, detail); err != nil {
		f.Log.Error("cannot record needs_reauth", "integration_id", integrationID, "error", err)
	}
}

func (f *Flow) openToken(ctx context.Context, requestID string, integration store.Integration) (*oauth2.Token, error) {
	plaintext, err := f.Sealer.Open(ctx, requestID, f.binding(integration.TenantID, purposeCredentials, integration.ID.String()), integration.CredentialsSealed)
	if err != nil {
		return nil, fmt.Errorf("open credentials: %w", err)
	}
	var creds Credentials
	err = json.Unmarshal(plaintext, &creds)
	clear(plaintext)
	if err != nil {
		return nil, fmt.Errorf("decode credentials: %w", err)
	}
	return &oauth2.Token{AccessToken: creds.AccessToken, RefreshToken: creds.RefreshToken, TokenType: creds.TokenType, Expiry: creds.Expiry}, nil
}

// liveToken is the current token of an OAuth integration, shared by all of
// its sessions in this process: refreshes are serialized, so a rotated
// refresh token is never used twice.
type liveToken struct {
	mu    sync.Mutex // held during refreshes
	token *oauth2.Token
	// updated is the store's updated_at for this token (guarded by Flow.mu).
	updated time.Time
}

// liveToken returns the integration's shared token, loading it from the
// store unless the one in memory is at least as recent.
func (f *Flow) liveToken(ctx context.Context, requestID string, integration store.Integration) (*liveToken, error) {
	current := func() (*liveToken, bool) {
		live, ok := f.live[integration.ID]
		return live, ok && !integration.UpdatedAt.After(live.updated)
	}
	f.mu.Lock()
	live, ok := current()
	f.mu.Unlock()
	if ok {
		return live, nil
	}
	token, err := f.openToken(ctx, requestID, integration)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if live, ok := current(); ok { // loaded concurrently
		return live, nil
	}
	if f.live == nil {
		f.live = map[uuid.UUID]*liveToken{}
	}
	live = &liveToken{token: token, updated: integration.UpdatedAt}
	f.live[integration.ID] = live
	return live, nil
}

// staticSource serves a bearer token, which cannot be refreshed.
type staticSource struct{ token *oauth2.Token }

func (s staticSource) Token() (*oauth2.Token, error) { return s.token, nil }

func (s staticSource) Refresh(string) error { return upstream.ErrCannotRefresh }

// savingSource refreshes OAuth tokens when they expire (or when the server
// rejects them) and persists rotated ones.
type savingSource struct {
	flow        *Flow
	requestID   string
	integration store.Integration
	config      oauth2.Config
	live        *liveToken
}

func (s *savingSource) Token() (*oauth2.Token, error) {
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	if !s.live.token.Valid() {
		if err := s.refreshLocked(); err != nil {
			return nil, err
		}
	}
	return s.live.token, nil
}

// Refresh replaces the rejected access token, unless another request already
// did.
func (s *savingSource) Refresh(rejected string) error {
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	if s.live.token.AccessToken != rejected {
		return nil
	}
	return s.refreshLocked()
}

// permanentRefreshErrors are token endpoint answers that mean the grant itself is
// gone (RFC 6749 section 5.2); anything else is treated as transient.
var permanentRefreshErrors = []string{"invalid_grant", "invalid_client", "unauthorized_client", "invalid_scope"}

func (s *savingSource) refreshLocked() error {
	if s.live.token.RefreshToken == "" {
		s.flow.MarkNeedsReauth(context.Background(), s.integration.ID, "the token expired and cannot be refreshed")
		return fmt.Errorf("%w: %w", ErrNeedsReauth, upstream.ErrCannotRefresh)
	}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), oauth2.HTTPClient, s.flow.HTTP), 30*time.Second)
	defer cancel()
	// A token without an access token forces a refresh; the library keeps
	// the old refresh token if the server does not rotate it.
	token, err := s.config.TokenSource(ctx, &oauth2.Token{RefreshToken: s.live.token.RefreshToken}).Token()
	if err != nil {
		var retrieve *oauth2.RetrieveError
		if errors.As(err, &retrieve) && slices.Contains(permanentRefreshErrors, retrieve.ErrorCode) {
			s.flow.Log.Warn("OAuth refresh rejected", "integration_id", s.integration.ID, "error_code", retrieve.ErrorCode)
			s.flow.forgetRejectedClient(context.Background(), err, s.integration.Issuer, s.integration.RedirectURI, s.config.ClientID)
			s.flow.MarkNeedsReauth(context.Background(), s.integration.ID, "the authorization was revoked or expired")
			return fmt.Errorf("%w: %w", ErrNeedsReauth, upstream.ErrCannotRefresh)
		}
		s.flow.Log.Warn("OAuth refresh failed; will retry", "integration_id", s.integration.ID, "error", err)
		return fmt.Errorf("token refresh: %w", err)
	}
	s.live.token = token

	// Refresh tokens may rotate; losing the new one would force a re-consent.
	persist, cancelPersist := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelPersist()
	sealed, err := s.flow.seal(persist, s.requestID, s.integration, fromToken(token))
	var updated time.Time
	if err == nil {
		updated, err = s.flow.Store.UpdateCredentials(persist, s.integration.ID, sealed)
	}
	if err != nil {
		s.flow.Log.Error("cannot persist refreshed tokens", "integration_id", s.integration.ID, "error", err)
		return nil
	}
	s.flow.mu.Lock()
	s.live.updated = updated
	s.flow.mu.Unlock()
	return nil
}

// --- discovery -----------------------------------------------------------------

// protectedResource finds the server's OAuth protected resource metadata:
// from the WWW-Authenticate challenge of an unauthenticated request, else
// from the well-known locations (path-specific first).
func (f *Flow) protectedResource(ctx context.Context, serverURL string) (*oauthex.ProtectedResourceMetadata, string, error) {
	metadataURL, scope, err := f.challenge(ctx, serverURL)
	if err != nil {
		return nil, "", err
	}
	candidates := wellKnownMetadataURLs(serverURL)
	if metadataURL != "" {
		candidates = []string{metadataURL}
	}
	var lastErr error
	for _, candidate := range candidates {
		if _, err := f.Guard.CheckURL(candidate); err != nil {
			return nil, "", fmt.Errorf("%w: resource metadata: %v", ErrAuthorization, err)
		}
		prm, err := oauthex.GetProtectedResourceMetadata(ctx, candidate, serverURL, f.HTTP)
		if err == nil && prm != nil {
			return prm, scope, nil
		}
		lastErr = err
	}
	return nil, "", fmt.Errorf("%w: no protected resource metadata for %s: %v", ErrAuthorization, serverURL, lastErr)
}

func (f *Flow) challenge(ctx context.Context, serverURL string) (metadataURL, scope string, err error) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL, strings.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", probeProtocolVersion)
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("%w: cannot reach %s: %w", ErrAuthorization, serverURL, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return "", "", nil
	}
	challenges, err := oauthex.ParseWWWAuthenticate(resp.Header.Values("WWW-Authenticate"))
	if err != nil {
		return "", "", nil
	}
	for _, c := range challenges {
		if strings.EqualFold(c.Scheme, "Bearer") {
			return c.Params["resource_metadata"], c.Params["scope"], nil
		}
	}
	return "", "", nil
}

func wellKnownMetadataURLs(serverURL string) []string {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil
	}
	origin := u.Scheme + "://" + u.Host
	var out []string
	if path := strings.TrimRight(u.Path, "/"); path != "" {
		out = append(out, origin+"/.well-known/oauth-protected-resource"+path)
	}
	return append(out, origin+"/.well-known/oauth-protected-resource")
}

// --- clients ----------------------------------------------------------------------

// client returns an OAuth client for the issuer: the operator's app for
// catalog servers that require one, else a stored or new dynamic registration.
func (f *Flow) client(ctx context.Context, requestID, slug, issuer string, asm *oauthex.AuthServerMeta) (string, string, error) {
	if creds, ok := f.Catalog.Client(slug); ok {
		return creds.ClientID, creds.ClientSecret, nil
	}
	if entry, ok := f.Catalog.Get(slug); ok && entry.Registration == catalog.Preregistered {
		return "", "", ErrNotConfigured
	}
	stored, err := f.Store.OAuthClient(ctx, issuer, f.RedirectURI)
	switch {
	case err == nil && (stored.SecretExpiresAt.IsZero() || stored.SecretExpiresAt.After(time.Now().Add(registrationMargin))):
		return f.clientCredentials(ctx, requestID, stored)
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return "", "", err
	}
	// None yet, or it expires before this authorization could complete.

	if asm.RegistrationEndpoint == "" {
		return "", "", fmt.Errorf("%w: %s does not support dynamic client registration; configure a pre-registered client", ErrAuthorization, issuer)
	}
	if _, err := f.Guard.CheckURL(asm.RegistrationEndpoint); err != nil {
		return "", "", fmt.Errorf("%w: registration endpoint: %v", ErrAuthorization, err)
	}
	method := "none"
	if len(asm.TokenEndpointAuthMethodsSupported) == 0 || slices.Contains(asm.TokenEndpointAuthMethodsSupported, "client_secret_basic") {
		method = "client_secret_basic"
	}
	registered, err := oauthex.RegisterClient(ctx, asm.RegistrationEndpoint, &oauthex.ClientRegistrationMetadata{
		RedirectURIs:            []string{f.RedirectURI},
		TokenEndpointAuthMethod: method,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              f.ClientName,
		ApplicationType:         "web",
	}, f.HTTP)
	if err != nil {
		return "", "", fmt.Errorf("%w: client registration at %s: %v", ErrAuthorization, issuer, err)
	}
	var secretSealed []byte
	if registered.ClientSecret != "" {
		secretSealed, err = f.Sealer.Seal(ctx, requestID, f.clientBinding(issuer, f.RedirectURI), []byte(registered.ClientSecret))
		if err != nil {
			return "", "", fmt.Errorf("seal client secret: %w", err)
		}
	}
	client := store.OAuthClient{
		Issuer: issuer, RedirectURI: f.RedirectURI, ClientID: registered.ClientID,
		ClientSecretSealed: secretSealed, Registration: "dynamic",
	}
	// RFC 7591: 0 (or absent) means the registration does not expire.
	if expires := registered.ClientSecretExpiresAt; !expires.IsZero() && expires.Unix() > 0 {
		client.SecretExpiresAt = expires
	}
	// Another instance may have registered concurrently; use what was stored.
	saved, err := f.Store.SaveOAuthClient(ctx, client, time.Now().Add(registrationMargin))
	if err != nil {
		return "", "", err
	}
	return f.clientCredentials(ctx, requestID, saved)
}

func (f *Flow) storedClient(ctx context.Context, requestID, slug, issuer, redirectURI string) (string, string, error) {
	if creds, ok := f.Catalog.Client(slug); ok {
		return creds.ClientID, creds.ClientSecret, nil
	}
	stored, err := f.Store.OAuthClient(ctx, issuer, redirectURI)
	if err != nil {
		return "", "", err
	}
	return f.clientCredentials(ctx, requestID, stored)
}

func (f *Flow) clientCredentials(ctx context.Context, requestID string, stored store.OAuthClient) (string, string, error) {
	if len(stored.ClientSecretSealed) == 0 {
		return stored.ClientID, "", nil
	}
	secret, err := f.Sealer.Open(ctx, requestID, f.clientBinding(stored.Issuer, stored.RedirectURI), stored.ClientSecretSealed)
	if err != nil {
		return "", "", fmt.Errorf("open client secret: %w", err)
	}
	defer clear(secret)
	return stored.ClientID, string(secret), nil
}

// forgetRejectedClient drops a dynamic registration the token endpoint
// answered invalid_client for (expired or deleted by the server), so the
// next authorization registers again instead of failing forever.
func (f *Flow) forgetRejectedClient(ctx context.Context, err error, issuer, redirectURI, clientID string) {
	var retrieve *oauth2.RetrieveError
	if !errors.As(err, &retrieve) || retrieve.ErrorCode != "invalid_client" {
		return
	}
	if delErr := f.Store.DeleteDynamicClient(context.WithoutCancel(ctx), issuer, redirectURI, clientID); delErr != nil {
		f.Log.Error("cannot forget rejected OAuth client", "issuer", issuer, "error", delErr)
		return
	}
	f.Log.Warn("authorization server rejected our client registration; will register again", "issuer", issuer)
}

// --- helpers ------------------------------------------------------------------------

func (f *Flow) seal(ctx context.Context, requestID string, integration store.Integration, creds Credentials) ([]byte, error) {
	plaintext, err := json.Marshal(creds)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	sealed, err := f.Sealer.Seal(ctx, requestID, f.binding(integration.TenantID, purposeCredentials, integration.ID.String()), plaintext)
	if err != nil {
		return nil, fmt.Errorf("seal credentials: %w", err)
	}
	return sealed, nil
}

func (f *Flow) binding(tenant uuid.UUID, purpose, subject string) vaultclient.Binding {
	return vaultclient.Binding{TenantID: tenant.String(), Purpose: purpose, Subject: subject}
}

func (f *Flow) clientBinding(issuer, redirectURI string) vaultclient.Binding {
	sum := sha256.Sum256([]byte(issuer + "\n" + redirectURI))
	return vaultclient.Binding{TenantID: platformTenant, Purpose: purposeClientSecret, Subject: hex.EncodeToString(sum[:])}
}

func fromToken(t *oauth2.Token) Credentials {
	return Credentials{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, TokenType: t.TokenType, Expiry: t.Expiry}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

var errorCodePattern = regexp.MustCompile(`^[a-z_]{1,64}$`)

// sanitizeCode keeps only well-formed OAuth error codes (e.g. access_denied).
func sanitizeCode(code string) string {
	if errorCodePattern.MatchString(code) {
		return code
	}
	return "an error"
}
