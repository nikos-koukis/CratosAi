// Command orchestrator is Jarvis's execution engine: tools for voice
// conversations, background tasks and memory, over gRPC with mutual TLS.
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
	"sync"
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

	knowledgev1 "jarvis.internal/gen/go/jarvis/knowledge/v1"
	mcpv1 "jarvis.internal/gen/go/jarvis/mcp/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	"jarvis.internal/libs/go/mtls"
	"jarvis.internal/libs/go/vaultclient"
	"jarvis.internal/orchestrator/internal/clients"
	"jarvis.internal/orchestrator/internal/config"
	"jarvis.internal/orchestrator/internal/engine"
	"jarvis.internal/orchestrator/internal/metrics"
	"jarvis.internal/orchestrator/internal/server"
	"jarvis.internal/orchestrator/internal/store"
)

const shutdownGrace = 15 * time.Second

func main() { os.Exit(run()) }

func run() int {
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "orchestrator:", err)
		return 1
	}
	logger := newLogger(cfg.LogFormat, cfg.LogLevel)
	if err := serve(cfg, logger); err != nil {
		logger.Error("orchestrator failed", "error", err)
		return 1
	}
	logger.Info("orchestrator stopped")
	return 0
}

func serve(cfg config.Config, logger *slog.Logger) error {
	methods := make([]string, 0, len(orchv1.OrchestratorService_ServiceDesc.Methods)+1)
	for _, m := range orchv1.OrchestratorService_ServiceDesc.Methods {
		methods = append(methods, m.MethodName)
	}
	for _, s := range orchv1.OrchestratorService_ServiceDesc.Streams {
		methods = append(methods, s.StreamName)
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

	identity := clients.Identity{Cert: cfg.ClientCert, Key: cfg.ClientKey, CA: cfg.ClientCA}
	vault, err := vaultclient.Dial(cfg.Vault.Addr, cfg.Vault.ServerName, vaultclient.TLSFiles{
		CA: cfg.ClientCA, Cert: cfg.ClientCert, Key: cfg.ClientKey})
	if err != nil {
		return err
	}
	defer func() { _ = vault.Close() }()
	mcpConn, err := clients.Dial(cfg.MCPRouter.Addr, cfg.MCPRouter.ServerName, identity)
	if err != nil {
		return err
	}
	defer func() { _ = mcpConn.Close() }()
	knowledgeConn, err := clients.Dial(cfg.Knowledge.Addr, cfg.Knowledge.ServerName, identity)
	if err != nil {
		return err
	}
	defer func() { _ = knowledgeConn.Close() }()
	agent, agentConn, err := clients.DialAgent(cfg.AgentSocket)
	if err != nil {
		return err
	}
	defer func() { _ = agentConn.Close() }()
	guard := clients.DeviceGuard{AllowLoopback: cfg.AllowLoopbackDevices}
	devices := &clients.Devices{Sealer: vault, Guard: guard}
	defer devices.Close()

	m := metrics.New()
	eng := engine.New(engine.Deps{
		Store: st, Keys: vault, Sealer: vault, MCP: mcpv1.NewMcpRouterServiceClient(mcpConn),
		Knowledge: knowledgev1.NewKnowledgeServiceClient(knowledgeConn), Agent: agent, Devices: devices,
		Metrics: m, Log: logger,
	}, engine.Options{
		OpenAIModel: cfg.OpenAIModel, XAIModel: cfg.XAIModel, Workers: cfg.Workers, TaskMaxSteps: cfg.TaskMaxSteps,
		TaskTimeout: cfg.TaskTimeout, ToolTimeout: cfg.ToolTimeout, ConfirmationTTL: cfg.ConfirmationTTL,
		TranscriptRetention: cfg.TranscriptRetention, MaxVoiceTools: cfg.MaxVoiceTools,
	})
	service := &server.Service{Engine: eng, Store: st, Sealer: vault, Guard: guard, Devices: devices, Log: logger}

	serviceName := orchv1.OrchestratorService_ServiceDesc.ServiceName
	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(serverTLS)),
		grpc.ChainUnaryInterceptor(server.UnaryInterceptor(logger, m), policy.UnaryInterceptor(serviceName)),
		grpc.ChainStreamInterceptor(server.StreamInterceptor(logger, m), policy.StreamInterceptor(serviceName)),
		grpc.MaxRecvMsgSize(1<<20),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	)
	orchv1.RegisterOrchestratorServiceServer(grpcServer, service)
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus(serviceName, healthpb.HealthCheckResponse_SERVING)
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

	workers, stopWorkers := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { eng.Run(workers) })
	errs := make(chan error, 2)
	go func() { errs <- grpcServer.Serve(grpcListener) }()
	go func() { errs <- admin.Serve(adminListener) }()
	logger.Info("orchestrator listening", "addr", grpcListener.Addr().String(), "admin_addr", adminListener.Addr().String(),
		"principals", policy.Principals(), "workers", cfg.Workers, "openai_model", cfg.OpenAIModel, "xai_model", cfg.XAIModel)

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
	go func() { grpcServer.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(shutdownGrace):
		grpcServer.Stop() // WatchConversation streams would otherwise hold shutdown
	}
	// Tasks in flight keep their state; their leases expire and another
	// instance (or this one, restarted) resumes them.
	stopWorkers()
	wg.Wait()
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
