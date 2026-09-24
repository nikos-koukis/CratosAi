// Package server exposes the voice WebSocket endpoint and the admin endpoints
// (health, readiness, metrics).
package server

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"jarvis.internal/libs/go/usertoken"
	"jarvis.internal/voice-gateway/internal/session"
)

// Subprotocol is the WebSocket subprotocol clients must request.
const Subprotocol = "jarvis.voice.v1"

// maxClientFrame bounds a single client message (100 ms of audio is 4.8 KB).
const maxClientFrame = 64 << 10

// Server owns the voice sessions.
type Server struct {
	verifier   *usertoken.Verifier
	sessionCfg session.Config
	deps       session.Deps
	log        *slog.Logger

	base     context.Context
	stop     context.CancelFunc
	sessions sync.WaitGroup
	draining atomic.Bool
}

// New creates a server; call Shutdown to end its sessions.
func New(verifier *usertoken.Verifier, cfg session.Config, deps session.Deps) *Server {
	base, stop := context.WithCancel(context.Background())
	return &Server{verifier: verifier, sessionCfg: cfg, deps: deps, log: deps.Logger, base: base, stop: stop}
}

// Handler serves the public voice endpoint.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/voice", s.handleVoice)
	return mux
}

// AdminHandler serves /healthz, /readyz and /metrics; keep it off the public network.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.draining.Load() {
			http.Error(w, "draining", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(s.deps.Metrics.Registry, promhttp.HandlerOpts{}))
	return mux
}

func (s *Server) handleVoice(w http.ResponseWriter, r *http.Request) {
	if s.draining.Load() {
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}
	token, ok := usertoken.BearerToken(r)
	if !ok {
		unauthorized(w)
		return
	}
	identity, err := s.verifier.Verify(token)
	if err != nil {
		s.log.Info("rejected voice connection", "reason", err, "remote", r.RemoteAddr)
		unauthorized(w)
		return
	}
	if !offersSubprotocol(r) {
		http.Error(w, "the "+Subprotocol+" WebSocket subprotocol is required", http.StatusBadRequest)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}})
	if err != nil {
		return // Accept has already answered the request
	}
	ws.SetReadLimit(maxClientFrame)

	s.sessions.Add(1)
	defer s.sessions.Done()
	session.Run(s.base, ws, identity, s.sessionCfg, s.deps)
}

func offersSubprotocol(r *http.Request) bool {
	for _, header := range r.Header.Values("Sec-WebSocket-Protocol") {
		offered := strings.Split(header, ",")
		for i := range offered {
			offered[i] = strings.TrimSpace(offered[i])
		}
		if slices.Contains(offered, Subprotocol) {
			return true
		}
	}
	return false
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="jarvis-voice"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// Shutdown stops accepting sessions, tells open ones to reconnect elsewhere
// and waits for them to close (or for ctx to end).
func (s *Server) Shutdown(ctx context.Context) error {
	s.draining.Store(true)
	s.stop()
	done := make(chan struct{})
	go func() {
		s.sessions.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
