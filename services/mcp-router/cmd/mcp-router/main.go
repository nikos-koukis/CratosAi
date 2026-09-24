// Command mcp-router connects Jarvis to external MCP servers (Jira, ClickUp,
// Linear, Notion, GitHub, Slack, Gmail, ...) on behalf of each user, with
// Vault-sealed credentials and a guard that keeps outbound traffic on the
// public internet.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	mcpv1 "jarvis.internal/gen/go/jarvis/mcp/v1"
	"jarvis.internal/libs/go/auditlog"
	"jarvis.internal/libs/go/mtls"
	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/mcp-router/internal/catalog"
	"jarvis.internal/mcp-router/internal/config"
	"jarvis.internal/mcp-router/internal/limits"
	"jarvis.internal/mcp-router/internal/metrics"
	"jarvis.internal/mcp-router/internal/netguard"
	"jarvis.internal/mcp-router/internal/oauthflow"
	"jarvis.internal/mcp-router/internal/router"
	"jarvis.internal/mcp-router/internal/store"
	"jarvis.internal/mcp-router/internal/upstream"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	shutdownGrace   = 15 * time.Second
	sessionIdle     = 5 * time.Minute
	oauthHTTPLimit  = 30 * time.Second
	maxRequestBytes = 1 << 20
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcp-router:", err)
		return 1
	}
	logger := newLogger(cfg.LogFormat, cfg.LogLevel)
	if err := serve(cfg, logger); err != nil {
		logger.Error("mcp router failed", "error", err)
		return 1
	}
	logger.Info("mcp router stopped")
	return 0
}

func serve(cfg config.Config, logger *slog.Logger) error {
	methods := make([]string, 0, len(mcpv1.McpRouterService_ServiceDesc.Methods))
	for _, m := range mcpv1.McpRouterService_ServiceDesc.Methods {
		methods = append(methods, m.MethodName)
	}
	policy, err := mtls.LoadPolicy(cfg.Policy, methods)
	if err != nil {
		return err
	}
	serverTLS, err := mtls.ServerConfig(cfg.TLSCert, cfg.TLSKey, cfg.TLSCA)
	if err != nil {
		return err
	}

	startup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := pgxpool.New(startup, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer db.Close()
	st := store.New(db)
	if err := st.Migrate(startup); err != nil {
		return fmt.Errorf("database migration: %w", err)
	}

	rdb := limits.NewClient(cfg.RedisAddr, cfg.RedisPassword)
	defer func() { _ = rdb.Close() }()
	if err := rdb.Ping(startup).Err(); err != nil {
		// Not fatal: limits fail open and the tool cache is bypassed.
		logger.Warn("redis unavailable at startup; continuing without rate limits and cache", "error", err)
	}

	vault, err := vaultclient.Dial(cfg.VaultAddr, cfg.VaultServerName, vaultclient.TLSFiles{
		CA: cfg.VaultCA, Cert: cfg.VaultCert, Key: cfg.VaultKey,
	})
	if err != nil {
		return err
	}
	defer func() { _ = vault.Close() }()

	m := metrics.New()
	guard := netguard.Guard{AllowLoopback: cfg.AllowLoopback}
	cat := catalog.New(cfg.OAuthClients)
	lim := limits.New(rdb, cfg.RatePerTenant, cfg.RatePerIntegration, cfg.ToolsCacheTTL, logger)
	pool := upstream.NewPool(guard.StreamingClient(), version, sessionIdle)
	defer pool.Close()
	var audit *auditlog.Recorder
	if cfg.AuditAddr != "" {
		recorder, closeAudit, err := auditlog.Dial(cfg.AuditAddr, cfg.VaultCert, cfg.VaultKey, cfg.VaultCA,
			cfg.AuditServerName, logger)
		if err != nil {
			return fmt.Errorf("audit client: %w", err)
		}
		audit = recorder
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			closeAudit(ctx)
		}()
	} else {
		logger.Warn("no audit service configured (MCP_AUDIT_ADDR): tool calls are not audited")
	}

	service := router.New(router.Deps{
		Store: st,
		Flow: &oauthflow.Flow{
			Store: st, Sealer: vault, Catalog: cat, HTTP: guard.Client(oauthHTTPLimit), Guard: guard,
			RedirectURI: cfg.RedirectURI, ClientName: cfg.ClientName, Log: logger,
		},
		Catalog: cat,
		Pool:    pool,
		Limits:  lim,
		Guard:   guard,
		Metrics: m,
		Log:     logger,
		Audit:   audit,
	}, router.Options{
		AllowCustomServers: cfg.AllowCustom,
		DefaultCallTimeout: cfg.DefaultCallTimeout,
		MaxCallTimeout:     cfg.MaxCallTimeout,
	})

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(serverTLS)),
		grpc.ChainUnaryInterceptor(
			router.Interceptor(logger, m),
			policy.UnaryInterceptor(mcpv1.McpRouterService_ServiceDesc.ServiceName),
		),
		grpc.MaxRecvMsgSize(maxRequestBytes),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	)
	mcpv1.RegisterMcpRouterServiceServer(grpcServer, service)
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus(mcpv1.McpRouterService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	if cfg.Reflection {
		reflection.Register(grpcServer)
	}

	adminMux := http.NewServeMux()
	adminMux.Handle("GET /metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))
	adminMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := st.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	admin := &http.Server{Handler: adminMux, ReadHeaderTimeout: 5 * time.Second}

	grpcListener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.ListenAddr, err)
	}
	adminListener, err := net.Listen("tcp", cfg.AdminAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.AdminAddr, err)
	}

	errs := make(chan error, 2)
	go func() { errs <- grpcServer.Serve(grpcListener) }()
	go func() { errs <- admin.Serve(adminListener) }()
	logger.Info("mcp router listening",
		"addr", grpcListener.Addr().String(),
		"admin_addr", adminListener.Addr().String(),
		"version", version,
		"principals", policy.Principals(),
		"custom_servers", cfg.AllowCustom,
		"loopback_servers", cfg.AllowLoopback,
		"preregistered_oauth_apps", len(cfg.OAuthClients),
		"vault", cfg.VaultAddr,
	)
	if cfg.AllowLoopback {
		logger.Warn("MCP_ALLOW_LOOPBACK_SERVERS is on: servers on this machine are reachable (development only)")
	}

	signals, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var serveErr error
	select {
	case <-signals.Done():
		logger.Info("shutdown requested")
	case serveErr = <-errs:
	}

	healthServer.Shutdown()
	stopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(shutdownGrace):
		logger.Warn("in-flight calls did not finish in time; stopping")
		grpcServer.Stop()
	}
	ctx, cancelAdmin := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelAdmin()
	_ = admin.Shutdown(ctx)
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, grpc.ErrServerStopped) {
		return serveErr
	}
	return nil
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
