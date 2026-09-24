// Command mcpctl drives the MCP router from a terminal: it plays the
// dashboard (connect servers, complete OAuth in the browser) and the
// orchestrator (list and call tools), and can run a local fake OAuth + MCP
// server for end-to-end tests.
//
//	mcpctl catalog
//	mcpctl connect      -tenant T -user U (-slug linear | -url https://...) [-name N] [-token-file F] [-open]
//	mcpctl reauthorize  -tenant T -user U -integration ID [-open]
//	mcpctl integrations -tenant T -user U
//	mcpctl tools        -tenant T -user U [-refresh]
//	mcpctl call         -tenant T -user U -integration ID -tool NAME [-args JSON] [-timeout 30s]
//	mcpctl delete       -tenant T -user U -integration ID
//	mcpctl dev-server   [-addr 127.0.0.1:8931]
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	mcpv1 "jarvis.internal/gen/go/jarvis/mcp/v1"
	"jarvis.internal/libs/go/mtls"
	"jarvis.internal/mcp-router/internal/mcptest"
)

const usage = `usage: mcpctl [global flags] <command> [flags]

commands (identity used):
  catalog         list catalog servers                          (dashboard-api)
  connect         connect a server; completes OAuth via a local callback
  reauthorize     start a new OAuth authorization for an integration
  integrations    list a user's integrations
  delete          delete an integration
  tools           list a user's tools                           (orchestrator)
  call            call a tool
  dev-server      run a fake OAuth authorization server + MCP server

global flags:
`

type global struct {
	addr       string
	serverName string
	certs      string
	identity   string
	timeout    time.Duration
}

func main() {
	var g global
	fs := flag.NewFlagSet("mcpctl", flag.ExitOnError)
	fs.StringVar(&g.addr, "addr", "127.0.0.1:50052", "router address")
	fs.StringVar(&g.serverName, "server-name", "localhost", "router TLS server name")
	fs.StringVar(&g.certs, "certs", ".dev/certs", "directory with ca.pem and <identity>.pem / <identity>-key.pem")
	fs.StringVar(&g.identity, "as", "", "client identity (default: dashboard-api for management, orchestrator for tools)")
	fs.DurationVar(&g.timeout, "rpc-timeout", 2*time.Minute, "per-RPC timeout")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])
	if fs.NArg() == 0 {
		fs.Usage()
		os.Exit(2)
	}
	if err := run(g, fs.Arg(0), fs.Args()[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mcpctl:", err)
		os.Exit(1)
	}
}

func run(g global, command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	tenant := fs.String("tenant", "", "tenant id (UUID)")
	user := fs.String("user", "", "user id")
	integration := fs.String("integration", "", "integration id")
	switch command {
	case "catalog":
		_ = fs.Parse(args)
		return withClient(g, "dashboard-api", func(ctx context.Context, c mcpv1.McpRouterServiceClient) error {
			resp, err := c.ListCatalog(ctx, &mcpv1.ListCatalogRequest{})
			return show(resp, err)
		})

	case "connect":
		slug := fs.String("slug", "", "catalog server slug")
		serverURL := fs.String("url", "", "custom MCP server URL")
		name := fs.String("name", "", "display name")
		tokenFile := fs.String("token-file", "", "bearer token file for token servers ('-' reads stdin)")
		callback := fs.String("callback", "http://127.0.0.1:8765/callback", "OAuth redirect URI (must equal the router's MCP_OAUTH_REDIRECT_URI)")
		openBrowser := fs.Bool("open", false, "open the authorization URL in the browser")
		_ = fs.Parse(args)
		req := &mcpv1.CreateIntegrationRequest{TenantId: *tenant, UserId: *user, DisplayName: *name}
		switch {
		case *slug != "" && *serverURL == "":
			req.Server = &mcpv1.CreateIntegrationRequest_CatalogSlug{CatalogSlug: *slug}
		case *serverURL != "" && *slug == "":
			req.Server = &mcpv1.CreateIntegrationRequest_ServerUrl{ServerUrl: *serverURL}
		default:
			return errors.New("connect needs exactly one of -slug or -url")
		}
		if *tokenFile != "" {
			token, err := readToken(*tokenFile)
			if err != nil {
				return err
			}
			req.BearerToken = token
			defer clear(token)
		}
		var listener net.Listener
		if len(req.BearerToken) == 0 {
			var err error
			if listener, err = listenCallback(*callback); err != nil {
				return err
			}
			defer func() { _ = listener.Close() }()
		}
		return withClient(g, "dashboard-api", func(ctx context.Context, c mcpv1.McpRouterServiceClient) error {
			resp, err := c.CreateIntegration(ctx, req)
			if err != nil || resp.GetAuthorizationUrl() == "" {
				return show(resp, err)
			}
			return authorize(g, c, listener, *callback, resp.GetAuthorizationUrl(), *openBrowser)
		})

	case "reauthorize":
		callback := fs.String("callback", "http://127.0.0.1:8765/callback", "OAuth redirect URI (must equal the router's MCP_OAUTH_REDIRECT_URI)")
		openBrowser := fs.Bool("open", false, "open the authorization URL in the browser")
		_ = fs.Parse(args)
		listener, err := listenCallback(*callback)
		if err != nil {
			return err
		}
		defer func() { _ = listener.Close() }()
		return withClient(g, "dashboard-api", func(ctx context.Context, c mcpv1.McpRouterServiceClient) error {
			resp, err := c.ReauthorizeIntegration(ctx, &mcpv1.ReauthorizeIntegrationRequest{TenantId: *tenant, UserId: *user, IntegrationId: *integration})
			if err != nil {
				return err
			}
			return authorize(g, c, listener, *callback, resp.GetAuthorizationUrl(), *openBrowser)
		})

	case "integrations":
		_ = fs.Parse(args)
		return withClient(g, "dashboard-api", func(ctx context.Context, c mcpv1.McpRouterServiceClient) error {
			resp, err := c.ListIntegrations(ctx, &mcpv1.ListIntegrationsRequest{TenantId: *tenant, UserId: *user})
			return show(resp, err)
		})

	case "delete":
		_ = fs.Parse(args)
		return withClient(g, "dashboard-api", func(ctx context.Context, c mcpv1.McpRouterServiceClient) error {
			resp, err := c.DeleteIntegration(ctx, &mcpv1.DeleteIntegrationRequest{TenantId: *tenant, UserId: *user, IntegrationId: *integration})
			return show(resp, err)
		})

	case "tools":
		refresh := fs.Bool("refresh", false, "bypass the tool cache")
		_ = fs.Parse(args)
		return withClient(g, "orchestrator", func(ctx context.Context, c mcpv1.McpRouterServiceClient) error {
			resp, err := c.ListTools(ctx, &mcpv1.ListToolsRequest{TenantId: *tenant, UserId: *user, Refresh: *refresh})
			return show(resp, err)
		})

	case "call":
		tool := fs.String("tool", "", "tool name")
		arguments := fs.String("args", "{}", "arguments as a JSON object")
		timeout := fs.Duration("timeout", 0, "tool timeout (default: the router's)")
		_ = fs.Parse(args)
		req := &mcpv1.CallToolRequest{TenantId: *tenant, UserId: *user, IntegrationId: *integration, ToolName: *tool, ArgumentsJson: *arguments}
		if *timeout > 0 {
			req.Timeout = durationpb.New(*timeout)
		}
		return withClient(g, "orchestrator", func(ctx context.Context, c mcpv1.McpRouterServiceClient) error {
			resp, err := c.CallTool(ctx, req)
			return show(resp, err)
		})

	case "dev-server":
		addr := fs.String("addr", "127.0.0.1:8931", "listen address (loopback)")
		_ = fs.Parse(args)
		return devServer(*addr)

	default:
		return fmt.Errorf("unknown command %q (run mcpctl -h)", command)
	}
}

func withClient(g global, defaultIdentity string, fn func(context.Context, mcpv1.McpRouterServiceClient) error) error {
	identity := g.identity
	if identity == "" {
		identity = defaultIdentity
	}
	tlsConfig, err := mtls.ClientConfig(filepath.Join(g.certs, identity+".pem"), filepath.Join(g.certs, identity+"-key.pem"),
		filepath.Join(g.certs, "ca.pem"), g.serverName)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(g.addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "x-request-id", fmt.Sprintf("mcpctl-%d", time.Now().UnixNano()))
	return fn(ctx, mcpv1.NewMcpRouterServiceClient(conn))
}

func show(m proto.Message, err error) error {
	if err != nil {
		return err
	}
	out, err := protojson.MarshalOptions{Multiline: true, EmitUnpopulated: false}.Marshal(m)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func readToken(path string) ([]byte, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, 16<<10))
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read token: %w", err)
	}
	return []byte(strings.TrimSpace(string(data))), nil
}

// listenCallback binds the loopback redirect URI before the authorization
// starts, so the browser can never be redirected to a port nobody listens on.
func listenCallback(callback string) (net.Listener, error) {
	u, err := url.Parse(callback)
	if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || u.Port() == "" {
		return nil, errors.New("-callback must be http://127.0.0.1:<port>/<path>")
	}
	return net.Listen("tcp", net.JoinHostPort("127.0.0.1", u.Port()))
}

// authorize sends the user to the authorization URL, waits for the redirect
// back on the loopback listener and relays it to CompleteAuthorization.
func authorize(g global, c mcpv1.McpRouterServiceClient, listener net.Listener, callback, authURL string, openBrowser bool) error {
	parsed, err := url.Parse(authURL)
	if err != nil {
		return err
	}
	wantState := parsed.Query().Get("state")
	cb, _ := url.Parse(callback)
	fmt.Fprintf(os.Stderr, "Open this URL to authorize (valid 10 minutes):\n\n  %s\n\nWaiting for the redirect to %s ...\n", authURL, callback)
	if openBrowser {
		openURL(authURL)
	}

	type result struct{ state, code, iss, errorCode string }
	results := make(chan result, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+cb.EscapedPath(), func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != wantState {
			http.Error(w, "unexpected state", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><title>Jarvis</title><p>%s You can close this window.</p>",
			html.EscapeString("Authorization received by mcpctl."))
		select {
		case results <- result{q.Get("state"), q.Get("code"), q.Get("iss"), q.Get("error")}:
		default:
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	var got result
	select {
	case got = <-results:
	case <-time.After(10 * time.Minute):
		return errors.New("timed out waiting for the authorization redirect")
	}
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()
	resp, err := c.CompleteAuthorization(ctx, &mcpv1.CompleteAuthorizationRequest{
		State: got.state, Code: got.code, Iss: got.iss, Error: got.errorCode,
	})
	return show(resp, err)
}

func openURL(u string) {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	if err := exec.Command(name, u).Start(); err != nil {
		fmt.Fprintln(os.Stderr, "cannot open the browser:", err)
	}
}

func devServer(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || (host != "127.0.0.1" && host != "localhost") {
		return errors.New("dev-server listens on loopback only (e.g. 127.0.0.1:8931)")
	}
	// A new issuer per run: registrations of a previous run (kept by the
	// router) are unknown to this in-memory authorization server.
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	env, handler := mcptest.NewEnvAt("http://"+addr, "/as-"+hex.EncodeToString(suffix))
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	fmt.Fprintf(os.Stderr, "Fake OAuth + MCP server (auto-approves every authorization):\n  MCP endpoint:  %s\n  issuer:        %s\n"+
		"Start the router with LOCAL_MCP=1 so it may connect to loopback servers.\n", env.MCPURL, env.Auth.Issuer)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, 1)
	go func() { errs <- server.ListenAndServe() }()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdown)
}
