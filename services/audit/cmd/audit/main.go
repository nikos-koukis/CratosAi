// Command audit keeps Jarvis's audit trail: AuditService over gRPC with
// mutual TLS. Services record what happened; the dashboard reads it back and
// verifies each tenant's hash chain.
package main

import (
	"context"
	"encoding/hex"
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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"jarvis.internal/audit/internal/config"
	"jarvis.internal/audit/internal/metrics"
	"jarvis.internal/audit/internal/server"
	"jarvis.internal/audit/internal/store"
	auditv1 "jarvis.internal/gen/go/jarvis/audit/v1"
	"jarvis.internal/libs/go/mtls"
)

const (
	shutdownGrace = 15 * time.Second
	// A batch of 500 events with 16 details each stays well below this.
	maxMessageBytes = 4 << 20
	// How often the chain heads are logged (see logHeads).
	headInterval = time.Hour
)

func main() { os.Exit(run()) }

func run() int {
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit:", err)
		return 1
	}
	logger := newLogger(cfg.LogFormat, cfg.LogLevel)
	if err := serve(cfg, logger); err != nil {
		logger.Error("audit service failed", "error", err)
		return 1
	}
	logger.Info("audit service stopped")
	return 0
}

func serve(cfg config.Config, logger *slog.Logger) error {
	methods := make([]string, 0, len(auditv1.AuditService_ServiceDesc.Methods))
	for _, m := range auditv1.AuditService_ServiceDesc.Methods {
		methods = append(methods, m.MethodName)
	}
	policy, err := mtls.LoadPolicy(cfg.Policy, methods)
	if err != nil {
		return err
	}
	tlsConfig, err := mtls.ServerConfig(cfg.TLSCert, cfg.TLSKey, cfg.ClientCA)
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

	m := metrics.New()
	service := &server.Service{Store: st, Metrics: m, Log: logger, Now: time.Now}
	serviceName := auditv1.AuditService_ServiceDesc.ServiceName
	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.ChainUnaryInterceptor(server.UnaryInterceptor(logger, m), policy.UnaryInterceptor(serviceName)),
		grpc.MaxRecvMsgSize(maxMessageBytes),
	)
	auditv1.RegisterAuditServiceServer(grpcServer, service)
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

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.ListenAddr, err)
	}
	metricsListener, err := net.Listen("tcp", cfg.MetricsAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.MetricsAddr, err)
	}
	errs := make(chan error, 2)
	go func() { errs <- grpcServer.Serve(listener) }()
	go func() { errs <- metricsServer.Serve(metricsListener) }()

	background, stopBackground := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { logHeads(background, st, logger) })

	logger.Info("audit service listening", "addr", listener.Addr().String(),
		"metrics_addr", metricsListener.Addr().String(), "principals", policy.Principals())

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

// logHeads logs every tenant's chain head hourly. Kept by the log pipeline,
// these records anchor the chains outside the database.
func logHeads(ctx context.Context, st *store.Store, logger *slog.Logger) {
	ticker := time.NewTicker(headInterval)
	defer ticker.Stop()
	for {
		heads, err := st.Heads(ctx)
		if err != nil && ctx.Err() == nil {
			logger.Error("cannot read chain heads", "error", err)
		}
		for _, h := range heads {
			logger.Info("audit chain head", "tenant_id", h.TenantID, "sequence", h.Sequence,
				"hash", hex.EncodeToString(h.Hash))
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
