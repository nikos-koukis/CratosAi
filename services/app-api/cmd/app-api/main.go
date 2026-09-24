// Command app-api serves Jarvis's apps: the public AppService (Connect, gRPC
// and gRPC-Web over HTTPS) for pairing, sessions, tasks and approvals, and the
// internal AppAdminService (gRPC + mTLS) for the dashboard backend.
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
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"jarvis.internal/app-api/internal/admin"
	"jarvis.internal/app-api/internal/api"
	"jarvis.internal/app-api/internal/apns"
	"jarvis.internal/app-api/internal/config"
	"jarvis.internal/app-api/internal/metrics"
	"jarvis.internal/app-api/internal/push"
	"jarvis.internal/app-api/internal/ratelimit"
	"jarvis.internal/app-api/internal/store"
	appv1 "jarvis.internal/gen/go/jarvis/app/v1"
	"jarvis.internal/gen/go/jarvis/app/v1/appv1connect"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	"jarvis.internal/libs/go/mtls"
	"jarvis.internal/libs/go/usertoken"
)

const (
	shutdownGrace = 15 * time.Second
	maxBodyBytes  = 1 << 20
	// Ended sessions and used pairing codes are kept this long for support.
	retention = 30 * 24 * time.Hour
)

func main() { os.Exit(run()) }

func run() int {
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "app-api:", err)
		return 1
	}
	logger := newLogger(cfg.LogFormat, cfg.LogLevel)
	if err := serve(cfg, logger); err != nil {
		logger.Error("app API failed", "error", err)
		return 1
	}
	logger.Info("app API stopped")
	return 0
}

func serve(cfg config.Config, logger *slog.Logger) error {
	methods := make([]string, 0, len(appv1.AppAdminService_ServiceDesc.Methods))
	for _, m := range appv1.AppAdminService_ServiceDesc.Methods {
		methods = append(methods, m.MethodName)
	}
	policy, err := mtls.LoadPolicy(cfg.Policy, methods)
	if err != nil {
		return err
	}
	adminTLS, err := mtls.ServerConfig(cfg.AdminCert, cfg.AdminKey, cfg.AdminCA)
	if err != nil {
		return err
	}
	signingKey, err := usertoken.LoadSigningKey(cfg.SigningKey)
	if err != nil {
		return fmt.Errorf("token signing key: %w", err)
	}
	minter, err := api.NewMinter(signingKey, cfg.SigningKeyID, cfg.TokenIssuer, cfg.AccessTokenTTL)
	if err != nil {
		return fmt.Errorf("token signing key: %w", err)
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

	orchTLS, err := mtls.ClientConfig(cfg.ClientCert, cfg.ClientKey, cfg.ClientCA, cfg.OrchestratorServerName)
	if err != nil {
		return fmt.Errorf("orchestrator client: %w", err)
	}
	orchConn, err := grpc.NewClient(cfg.OrchestratorAddr, grpc.WithTransportCredentials(credentials.NewTLS(orchTLS)))
	if err != nil {
		return fmt.Errorf("orchestrator client: %w", err)
	}
	defer func() { _ = orchConn.Close() }()

	m := metrics.New()
	service := &api.Service{
		Store: st, Minter: minter, Orchestrator: orchv1.NewOrchestratorServiceClient(orchConn), Metrics: m,
		Log: logger, VoiceURL: cfg.VoiceURL, RefreshTTL: cfg.RefreshIdleTTL,
	}
	path, handler := appv1connect.NewAppServiceHandler(service,
		connect.WithInterceptors(
			api.Logging(logger, m),
			api.RateLimit(ratelimit.New(10, 20), m, logger),
			api.Auth(minter, st, logger),
		),
		connect.WithRecover(api.Recover(logger)),
		connect.WithReadMaxBytes(maxBodyBytes),
	)
	publicMux := http.NewServeMux()
	publicMux.Handle(path, handler)
	jwks := minter.JWKS()
	publicMux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(jwks)
	})
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	if cfg.TLSCert == "" {
		protocols.SetUnencryptedHTTP2(true) // loopback development, or behind a TLS proxy
	}
	public := &http.Server{
		Handler:           publicMux,
		Protocols:         protocols,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	adminService := &admin.Service{Store: st, Metrics: m, Log: logger, PublicURL: cfg.PublicURL,
		PairingTTL: cfg.PairingCodeTTL}
	serviceName := appv1.AppAdminService_ServiceDesc.ServiceName
	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(adminTLS)),
		grpc.ChainUnaryInterceptor(admin.UnaryInterceptor(logger, m), policy.UnaryInterceptor(serviceName)),
		grpc.MaxRecvMsgSize(maxBodyBytes),
	)
	appv1.RegisterAppAdminServiceServer(grpcServer, adminService)
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus(serviceName, healthpb.HealthCheckResponse_SERVING)
	if cfg.Reflection {
		reflection.Register(grpcServer)
	}

	metricsMux := http.NewServeMux()
	metricsMux.Handle("GET /metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))
	metricsMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := st.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	metricsServer := &http.Server{Handler: metricsMux, ReadHeaderTimeout: 5 * time.Second}

	publicListener, err := net.Listen("tcp", cfg.PublicAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.PublicAddr, err)
	}
	adminListener, err := net.Listen("tcp", cfg.AdminAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.AdminAddr, err)
	}
	metricsListener, err := net.Listen("tcp", cfg.MetricsAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.MetricsAddr, err)
	}

	errs := make(chan error, 3)
	go func() {
		if cfg.TLSCert != "" {
			public.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			errs <- public.ServeTLS(publicListener, cfg.TLSCert, cfg.TLSKey)
		} else {
			errs <- public.Serve(publicListener)
		}
	}()
	go func() { errs <- grpcServer.Serve(adminListener) }()
	go func() { errs <- metricsServer.Serve(metricsListener) }()

	background, stopBackground := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { purge(background, st, logger) })
	if cfg.PushEnabled() {
		sender, err := apns.New(apns.Config{KeyFile: cfg.APNsKeyFile, KeyID: cfg.APNsKeyID, TeamID: cfg.APNsTeamID,
			Topic: cfg.APNsTopic})
		if err != nil {
			stopBackground()
			return err
		}
		host, _ := os.Hostname()
		notifier := &push.Notifier{Orchestrator: orchv1.NewOrchestratorServiceClient(orchConn), Tokens: st, APNs: sender,
			Consumer: fmt.Sprintf("%s/%d", host, os.Getpid()), Metrics: m, Log: logger}
		wg.Go(func() { notifier.Run(background) })
	} else {
		logger.Warn("APNs is not configured (APP_APNS_*): no push notifications")
	}

	logger.Info("app API listening",
		"public_addr", publicListener.Addr().String(), "public_url", cfg.PublicURL, "tls", cfg.TLSCert != "",
		"admin_addr", adminListener.Addr().String(), "metrics_addr", metricsListener.Addr().String(),
		"principals", policy.Principals(), "voice_url", cfg.VoiceURL, "orchestrator", cfg.OrchestratorAddr,
		"push", cfg.PushEnabled())

	signals, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var serveErr error
	select {
	case <-signals.Done():
		logger.Info("shutdown requested")
	case serveErr = <-errs:
	}
	stopBackground()
	wg.Wait()
	healthServer.Shutdown()
	ctx, cancelShutdown := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancelShutdown()
	_ = public.Shutdown(ctx)
	stopped := make(chan struct{})
	go func() { grpcServer.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-ctx.Done():
		grpcServer.Stop()
	}
	_ = metricsServer.Shutdown(ctx)
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, grpc.ErrServerStopped) {
		return serveErr
	}
	return nil
}

// purge deletes used pairing codes and ended sessions after the retention
// period, hourly.
func purge(ctx context.Context, st *store.Store, logger *slog.Logger) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		n, err := st.Purge(ctx, retention)
		switch {
		case err != nil && ctx.Err() == nil:
			logger.Error("cannot purge old sessions", "error", err)
		case n > 0:
			logger.Info("old pairing codes and sessions purged", "rows", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
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
