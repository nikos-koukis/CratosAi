// Package mcptest runs a fake OAuth 2.1 authorization server and a fake MCP
// server that requires its tokens, for tests and local development
// (`mcpctl dev-server`). The authorization server approves every request
// automatically but checks PKCE, redirect URIs, client credentials and the
// RFC 8707 resource like a real one.
package mcptest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

// Scopes the fake server supports.
var Scopes = []string{"tools:read", "tools:write"}

// AuthServer is a fake authorization server. Its exported knobs may be
// changed between requests.
type AuthServer struct {
	Issuer string

	mu      sync.Mutex
	clients map[string]registeredClient
	codes   map[string]grant
	access  map[string]issued
	refresh map[string]grant

	// Knobs.
	DenyAll        bool          // answer authorizations with error=access_denied
	WrongIss       bool          // send another issuer's iss
	AccessTTL      time.Duration // default 1h
	NoRegistration bool          // hide the registration endpoint
	RejectTokens   bool          // the resource refuses every token (refresh still works)
	SecretTTL      time.Duration // client_secret_expires_at of new registrations (0: never)

	// Counters.
	Registrations int
	Refreshes     int
	Exchanges     int
}

type registeredClient struct {
	secret       string
	redirectURIs []string
}

type grant struct {
	clientID  string
	redirect  string
	challenge string
	resource  string
	scope     string
}

type issued struct {
	resource string
	scope    string
	expiry   time.Time
}

// NewAuthServer creates an authorization server; mount Handler at Issuer.
func NewAuthServer(issuer string) *AuthServer {
	return &AuthServer{
		Issuer:  strings.TrimRight(issuer, "/"),
		clients: map[string]registeredClient{},
		codes:   map[string]grant{},
		access:  map[string]issued{},
		refresh: map[string]grant{},
	}
}

// Handler serves metadata, registration, authorization and token endpoints.
func (a *AuthServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", a.metadata)
	mux.HandleFunc("POST /register", a.register)
	mux.HandleFunc("GET /authorize", a.authorize)
	mux.HandleFunc("POST /token", a.token)
	return mux
}

// RevokeAll invalidates every access and refresh token (the user removed
// the app).
func (a *AuthServer) RevokeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.access = map[string]issued{}
	a.refresh = map[string]grant{}
}

// ForgetClients deletes every client registration (as servers that expire
// or clean up dynamic registrations do).
func (a *AuthServer) ForgetClients() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clients = map[string]registeredClient{}
}

// ExpireAccessTokens makes every access token expired (refresh still works).
func (a *AuthServer) ExpireAccessTokens() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for token, info := range a.access {
		info.expiry = time.Now().Add(-time.Second)
		a.access[token] = info
	}
}

// Verify is an auth.TokenVerifier for resource.
func (a *AuthServer) Verify(resource string) auth.TokenVerifier {
	return func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		a.mu.Lock()
		info, ok := a.access[token]
		reject := a.RejectTokens
		a.mu.Unlock()
		if !ok || reject || info.resource != resource || time.Now().After(info.expiry) {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{Scopes: strings.Fields(info.scope), Expiration: info.expiry}, nil
	}
}

func (a *AuthServer) metadata(w http.ResponseWriter, _ *http.Request) {
	meta := map[string]any{
		"issuer":                                         a.Issuer,
		"authorization_endpoint":                         a.Issuer + "/authorize",
		"token_endpoint":                                 a.Issuer + "/token",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "none"},
		"scopes_supported":                               Scopes,
		"authorization_response_iss_parameter_supported": true,
	}
	a.mu.Lock()
	if !a.NoRegistration {
		meta["registration_endpoint"] = a.Issuer + "/register"
	}
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, meta)
}

func (a *AuthServer) register(w http.ResponseWriter, r *http.Request) {
	var req oauthex.ClientRegistrationMetadata
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.RedirectURIs) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata")
		return
	}
	id, secret := random(), ""
	if req.TokenEndpointAuthMethod != "none" {
		secret = random()
	}
	a.mu.Lock()
	a.clients[id] = registeredClient{secret: secret, redirectURIs: req.RedirectURIs}
	a.Registrations++
	ttl := a.SecretTTL
	a.mu.Unlock()
	resp := map[string]any{
		"client_id":                  id,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": req.TokenEndpointAuthMethod,
		"client_id_issued_at":        time.Now().Unix(),
	}
	if secret != "" {
		resp["client_secret"] = secret
		resp["client_secret_expires_at"] = 0
		if ttl > 0 {
			resp["client_secret_expires_at"] = time.Now().Add(ttl).Unix()
		}
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (a *AuthServer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a.mu.Lock()
	defer a.mu.Unlock()
	client, ok := a.clients[q.Get("client_id")]
	redirect := q.Get("redirect_uri")
	// Never redirect to an unregistered URI.
	if !ok || !slices.Contains(client.redirectURIs, redirect) {
		http.Error(w, "unknown client or redirect_uri", http.StatusBadRequest)
		return
	}
	target, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	params := url.Values{"state": {q.Get("state")}}
	params.Set("iss", a.Issuer)
	if a.WrongIss {
		params.Set("iss", "https://evil.example")
	}
	switch {
	case a.DenyAll:
		params.Set("error", "access_denied")
	case q.Get("response_type") != "code", q.Get("code_challenge_method") != "S256",
		q.Get("code_challenge") == "", q.Get("resource") == "":
		params.Set("error", "invalid_request")
	default:
		code := random()
		a.codes[code] = grant{
			clientID: q.Get("client_id"), redirect: redirect, challenge: q.Get("code_challenge"),
			resource: q.Get("resource"), scope: q.Get("scope"),
		}
		params.Set("code", code)
	}
	target.RawQuery = params.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (a *AuthServer) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	clientID, secret, basic := r.BasicAuth()
	if !basic {
		clientID = r.PostForm.Get("client_id")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	client, ok := a.clients[clientID]
	if !ok || client.secret != secret {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}

	var g grant
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		code := r.PostForm.Get("code")
		g, ok = a.codes[code]
		delete(a.codes, code) // single use
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || g.clientID != clientID || g.redirect != r.PostForm.Get("redirect_uri") ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge ||
			r.PostForm.Get("resource") != g.resource {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		a.Exchanges++
	case "refresh_token":
		old := r.PostForm.Get("refresh_token")
		g, ok = a.refresh[old]
		if !ok || g.clientID != clientID {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		delete(a.refresh, old) // rotation
		a.Refreshes++
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	ttl := a.AccessTTL
	if ttl == 0 {
		ttl = time.Hour
	}
	access, refresh := random(), random()
	a.access[access] = issued{resource: g.resource, scope: g.scope, expiry: time.Now().Add(ttl)}
	a.refresh[refresh] = g
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(ttl.Seconds()),
		"refresh_token": refresh,
		"scope":         g.scope,
	})
}

// --- MCP server --------------------------------------------------------------------

// MCPHandler serves an MCP server at path "/mcp" of baseURL, protected by
// verifier, with its protected resource metadata naming issuer.
func MCPHandler(baseURL, issuer string, verifier auth.TokenVerifier) http.Handler {
	baseURL = strings.TrimRight(baseURL, "/")
	resource := baseURL + "/mcp"
	metadataURL := baseURL + "/.well-known/oauth-protected-resource/mcp"
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return NewServer() },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	mux := http.NewServeMux()
	mux.Handle("/mcp", auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: metadataURL,
	})(mcpHandler))
	mux.Handle("GET /.well-known/oauth-protected-resource/mcp", auth.ProtectedResourceMetadataHandler(
		&oauthex.ProtectedResourceMetadata{
			Resource:             resource,
			AuthorizationServers: []string{issuer},
			ScopesSupported:      Scopes,
		}))
	return mux
}

// StaticToken is a verifier accepting one bearer token (API key servers).
func StaticToken(token string) auth.TokenVerifier {
	return func(_ context.Context, got string, _ *http.Request) (*auth.TokenInfo, error) {
		if got != token {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{Expiration: time.Now().Add(time.Hour)}, nil
	}
}

type echoArgs struct {
	Text string `json:"text" jsonschema:"text to echo back"`
}

type issueArgs struct {
	Title string `json:"title" jsonschema:"issue title"`
}

type issue struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type slowArgs struct {
	Millis int `json:"millis" jsonschema:"how long to take"`
}

type bigArgs struct {
	Bytes int `json:"bytes" jsonschema:"how much text to return"`
}

// NewServer builds the fake MCP server's tools.
func NewServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "jarvis-fake-mcp", Version: "1.0.0"}, nil)
	no := false
	mcp.AddTool(server, &mcp.Tool{
		Name: "echo", Title: "Echo", Description: "Returns the text it is given.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &no},
	}, func(_ context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: in.Text}}}, nil, nil
	})
	mcp.AddTool(server, &mcp.Tool{
		Name: "create_issue", Description: "Creates an issue.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &no},
	}, func(_ context.Context, _ *mcp.CallToolRequest, in issueArgs) (*mcp.CallToolResult, issue, error) {
		return nil, issue{ID: "JAR-1", Title: in.Title}, nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "fail", Description: "Always fails."},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
			return nil, nil, errors.New("the tracker is read-only today")
		})
	mcp.AddTool(server, &mcp.Tool{Name: "slow", Description: "Waits before answering."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in slowArgs) (*mcp.CallToolResult, any, error) {
			select {
			case <-time.After(time.Duration(in.Millis) * time.Millisecond):
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "done"}}}, nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "big", Description: "Returns a lot of text."},
		func(_ context.Context, _ *mcp.CallToolRequest, in bigArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{
				&mcp.TextContent{Text: strings.Repeat("é", in.Bytes/2)},
				&mcp.ImageContent{MIMEType: "image/png", Data: []byte("not really a png")},
			}}, nil, nil
		})
	return server
}

// --- helpers -------------------------------------------------------------------

func random() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, code int, errorCode string) {
	writeJSON(w, code, map[string]string{"error": errorCode})
}

// Env is an authorization server and an OAuth-protected MCP server on one
// HTTP handler (e.g. an httptest.Server).
type Env struct {
	Auth *AuthServer
	// MCPURL is the MCP endpoint.
	MCPURL string
}

// NewEnv mounts both servers under baseURL: the authorization server at
// /as, the MCP server at /mcp.
func NewEnv(baseURL string) (*Env, http.Handler) {
	return NewEnvAt(baseURL, "/as")
}

// NewEnvAt is NewEnv with the authorization server at issuerPath.
func NewEnvAt(baseURL, issuerPath string) (*Env, http.Handler) {
	baseURL = strings.TrimRight(baseURL, "/")
	as := NewAuthServer(baseURL + issuerPath)
	mux := http.NewServeMux()
	mux.Handle(issuerPath+"/", http.StripPrefix(issuerPath, as.Handler()))
	// RFC 8414 metadata for an issuer with a path lives at the origin.
	mux.Handle("GET /.well-known/oauth-authorization-server"+issuerPath, http.HandlerFunc(as.metadata))
	mux.Handle("/", MCPHandler(baseURL, as.Issuer, as.Verify(baseURL+"/mcp")))
	return &Env{Auth: as, MCPURL: baseURL + "/mcp"}, mux
}

// String describes the environment.
func (e *Env) String() string { return fmt.Sprintf("MCP %s, issuer %s", e.MCPURL, e.Auth.Issuer) }
