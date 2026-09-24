// Package upstream keeps MCP client sessions to remote servers, one per
// integration, so calls skip the connection handshake. Sessions close after
// being idle and whenever they fail or their credentials change.
package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
)

var (
	// ErrNeedsReauth means the server rejected the integration's credentials.
	ErrNeedsReauth = errors.New("the server rejected the stored authorization")
	// ErrCannotRefresh is returned by Source.Refresh when no new credentials
	// can be obtained without the user.
	ErrCannotRefresh = errors.New("credentials cannot be refreshed")
)

const maxConcurrentPerIntegration = 8

// Source supplies credentials and can be asked for new ones after the server
// rejected an access token.
type Source interface {
	oauth2.TokenSource
	// Refresh replaces the rejected access token if it is still the current
	// one. It returns an error wrapping ErrCannotRefresh when only the user
	// can provide new credentials.
	Refresh(rejected string) error
}

// Tokens yields credentials for a new session.
type Tokens func(context.Context) (Source, error)

// Pool holds live sessions.
type Pool struct {
	client *mcp.Client
	http   *http.Client
	idle   time.Duration

	mu        sync.Mutex
	entries   map[uuid.UUID]*entry
	stop      chan struct{}
	closeOnce sync.Once
}

type entry struct {
	session  *mcp.ClientSession
	lastUsed time.Time
	slots    chan struct{}
}

// NewPool creates a pool. Tool lists are cached with a TTL by the caller,
// so sessions do not subscribe to change notifications (which would hold a
// stream open per integration).
func NewPool(httpClient *http.Client, version string, idle time.Duration) *Pool {
	p := &Pool{
		client:  mcp.NewClient(&mcp.Implementation{Name: "jarvis-mcp-router", Version: version}, nil),
		http:    httpClient,
		idle:    idle,
		entries: map[uuid.UUID]*entry{},
		stop:    make(chan struct{}),
	}
	go p.reap()
	return p
}

// Session returns a session for the integration and a release function to
// call when the request is done. It waits for a free slot if the
// integration already has the maximum number of calls in flight.
func (p *Pool) Session(ctx context.Context, id uuid.UUID, endpoint string, tokens Tokens, onRejected func()) (*mcp.ClientSession, func(), error) {
	e, err := p.entry(ctx, id, endpoint, tokens, onRejected)
	if err != nil {
		return nil, nil, err
	}
	select {
	case e.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	var once sync.Once
	return e.session, func() {
		once.Do(func() {
			<-e.slots
			p.mu.Lock()
			e.lastUsed = time.Now()
			p.mu.Unlock()
		})
	}, nil
}

func (p *Pool) entry(ctx context.Context, id uuid.UUID, endpoint string, tokens Tokens, onRejected func()) (*entry, error) {
	p.mu.Lock()
	if e, ok := p.entries[id]; ok {
		e.lastUsed = time.Now()
		p.mu.Unlock()
		return e, nil
	}
	p.mu.Unlock()

	source, err := tokens(ctx)
	if err != nil {
		return nil, err
	}
	creds := &credentials{base: p.http.Transport, source: source, onRejected: onRejected}
	httpClient := *p.http
	httpClient.Transport = creds
	session, err := p.client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:     endpoint,
		HTTPClient:   &httpClient,
		OAuthHandler: creds,
		MaxRetries:   1,
		// Likewise no standing GET stream (pre-2026 protocol versions).
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.entries[id]; ok { // lost a race; keep the first
		_ = session.Close()
		return existing, nil
	}
	e := &entry{session: session, lastUsed: time.Now(), slots: make(chan struct{}, maxConcurrentPerIntegration)}
	p.entries[id] = e
	return e, nil
}

// Invalidate closes the integration's session (after failures, credential
// changes or deletion); the next call reconnects.
func (p *Pool) Invalidate(id uuid.UUID) {
	p.mu.Lock()
	e, ok := p.entries[id]
	if ok {
		delete(p.entries, id)
	}
	p.mu.Unlock()
	if ok {
		go func() { _ = e.session.Close() }()
	}
}

// Close ends every session. It is safe to call more than once.
func (p *Pool) Close() {
	p.closeOnce.Do(func() { close(p.stop) })
	p.mu.Lock()
	entries := p.entries
	p.entries = map[uuid.UUID]*entry{}
	p.mu.Unlock()
	for _, e := range entries {
		_ = e.session.Close()
	}
}

func (p *Pool) reap() {
	ticker := time.NewTicker(max(p.idle/4, time.Second))
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
		}
		var idle []*entry
		p.mu.Lock()
		for id, e := range p.entries {
			if len(e.slots) == 0 && time.Since(e.lastUsed) > p.idle {
				idle = append(idle, e)
				delete(p.entries, id)
			}
		}
		p.mu.Unlock()
		for _, e := range idle {
			_ = e.session.Close()
		}
	}
}

// credentials authenticates one session. When the server rejects the
// current token it refreshes once (the SDK then retries the request); if
// the refreshed token is rejected as well, or there is nothing to refresh,
// the integration is reported instead of starting an interactive flow: the
// user reauthorizes from the dashboard.
type credentials struct {
	base       http.RoundTripper
	source     Source
	onRejected func()

	mu sync.Mutex
	// unproven is an access token from a forced refresh that the server has
	// not accepted yet.
	unproven string
}

// TokenSource implements auth.OAuthHandler.
func (c *credentials) TokenSource(context.Context) (oauth2.TokenSource, error) {
	return c.source, nil
}

// Authorize implements auth.OAuthHandler; the SDK calls it on 401 and 403.
func (c *credentials) Authorize(_ context.Context, req *http.Request, resp *http.Response) error {
	status := 0
	if resp != nil {
		status = resp.StatusCode
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
	// 403 means missing scopes (step-up authorization): only the user can fix it.
	if status == http.StatusUnauthorized {
		rejected := ""
		if req != nil {
			rejected = strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		}
		// A no-op when the request carried a token that a concurrent refresh
		// already replaced; either way the SDK retries with the current one.
		err := c.source.Refresh(rejected)
		if err == nil {
			var token *oauth2.Token
			if token, err = c.source.Token(); err == nil {
				c.mu.Lock()
				c.unproven = token.AccessToken
				c.mu.Unlock()
				return nil
			}
		}
		if !errors.Is(err, ErrCannotRefresh) {
			return err // transient: the authorization may still be good
		}
	}
	c.reject()
	return ErrNeedsReauth
}

// RoundTrip watches answers to requests made with a freshly refreshed token.
func (c *credentials) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	c.mu.Lock()
	fresh := c.unproven != "" && token == c.unproven
	if fresh && resp.StatusCode < http.StatusBadRequest {
		c.unproven = ""
	}
	c.mu.Unlock()
	if fresh && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		c.reject()
		return nil, ErrNeedsReauth
	}
	return resp, nil
}

func (c *credentials) reject() {
	if c.onRejected != nil {
		c.onRejected()
	}
}
