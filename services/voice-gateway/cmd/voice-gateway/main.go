// Command voice-gateway relays real-time voice between client apps and LLM
// realtime APIs, using each tenant's own provider key from the BYOK Vault.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	"jarvis.internal/libs/go/mtls"
	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/voice-gateway/internal/auth"
	"jarvis.internal/voice-gateway/internal/config"
	"jarvis.internal/voice-gateway/internal/metrics"
	"jarvis.internal/voice-gateway/internal/server"
	"jarvis.internal/voice-gateway/internal/session"
)

const shutdownGrace = 15 * time.Second

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "voice-gateway:", err)
		return 1
	}
	logger := newLogger(cfg.LogFormat, cfg.LogLevel)
	if err := serve(cfg, logger); err != nil {
		logger.Error("voice gateway failed", "error", err)
		return 1
	}
	logger.Info("voice gateway stopped")
	return 0
}

func serve(cfg config.Config, logger *slog.Logger) error {
	keys, err := auth.LoadJWKS(cfg.TokenJWKS)
	if err != nil {
		return err
	}
	verifier, err := auth.NewVerifier(keys, cfg.TokenIssuer, cfg.TokenAudience, cfg.TokenMaxLifetime)
	if err != nil {
		return err
	}
	vault, err := vaultclient.Dial(cfg.VaultAddr, cfg.VaultServerName, vaultclient.TLSFiles{
		CA: cfg.VaultCA, Cert: cfg.VaultCert, Key: cfg.VaultKey,
	})
	if err != nil {
		return err
	}
	defer func() { _ = vault.Close() }()

	var orchestrator orchv1.OrchestratorServiceClient
	if cfg.OrchestratorAddr != "" {
		conn, err := dialOrchestrator(cfg)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		orchestrator = orchv1.NewOrchestratorServiceClient(conn)
	} else {
		logger.Warn("GATEWAY_ORCHESTRATOR_ADDR is not set: voice sessions run without Jarvis tools")
	}

	gateway := server.New(verifier, session.Config{
		Providers:       cfg.Providers,
		DefaultProvider: cfg.DefaultProvider,
		Instructions:    cfg.Instructions,
		StartTimeout:    cfg.StartTimeout,
		MaxDuration:     cfg.MaxSessionDuration,
		IdleTimeout:     cfg.IdleTimeout,
		ToolTimeout:     cfg.ToolTimeout,
	}, session.Deps{
		Keys:         vault,
		Orchestrator: orchestrator,
		Limiter:      session.NewLimiter(cfg.MaxSessions, cfg.MaxSessionsPerTenant),
		Metrics:      metrics.New(),
		Logger:       logger,
	})

	public := &http.Server{
		Handler:           gateway.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	admin := &http.Server{Handler: gateway.AdminHandler(), ReadHeaderTimeout: 5 * time.Second}

	publicListener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.ListenAddr, err)
	}
	adminListener, err := net.Listen("tcp", cfg.AdminAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.AdminAddr, err)
	}

	errs := make(chan error, 2)
	go func() {
		if cfg.TLSCert != "" {
			public.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			errs <- public.ServeTLS(publicListener, cfg.TLSCert, cfg.TLSKey)
		} else {
			errs <- public.Serve(publicListener)
		}
	}()
	go func() { errs <- admin.Serve(adminListener) }()

	providers := make([]string, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		providers = append(providers, p.Name)
	}
	logger.Info("voice gateway listening",
		"addr", publicListener.Addr().String(),
		"tls", cfg.TLSCert != "",
		"admin_addr", adminListener.Addr().String(),
		"providers", providers,
		"vault", cfg.VaultAddr,
		"orchestrator", cfg.OrchestratorAddr,
	)

	signals, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var serveErr error
	select {
	case <-signals.Done():
		logger.Info("shutdown requested; telling clients to reconnect")
	case serveErr = <-errs:
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	_ = public.Shutdown(ctx) // stop accepting; upgraded sockets are handled below
	if err := gateway.Shutdown(ctx); err != nil {
		logger.Warn("sessions did not close in time", "error", err)
	}
	_ = admin.Shutdown(ctx)
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}

// dialOrchestrator prepares the mTLS connection (established lazily); the
// gateway's client certificate is its identity in the orchestrator's policy.
func dialOrchestrator(cfg config.Config) (*grpc.ClientConn, error) {
	tlsConfig, err := mtls.ClientConfig(cfg.OrchestratorCert, cfg.OrchestratorKey, cfg.OrchestratorCA,
		cfg.OrchestratorServerName)
	if err != nil {
		return nil, fmt.Errorf("orchestrator client: %w", err)
	}
	conn, err := grpc.NewClient(cfg.OrchestratorAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("orchestrator client: %w", err)
	}
	return conn, nil
}

func newLogger(format, level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if format == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}
