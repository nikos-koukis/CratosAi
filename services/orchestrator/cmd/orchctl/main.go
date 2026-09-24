// Command orchctl drives the orchestrator from a terminal. It plays the
// dashboard (tasks, devices, approvals) and, with `converse`, the voice
// gateway: a text conversation that uses the same tools, confirmations and
// background tasks as a voice session, without audio or a realtime model.
//
//	orchctl tasks           -tenant T -user U [-limit 20]
//	orchctl task            -tenant T -user U -id TASK
//	orchctl cancel          -tenant T -user U -id TASK
//	orchctl devices         -tenant T -user U
//	orchctl register-device -tenant T -user U -name N -address HOST:PORT -device-server-name S \
//	                        -device-ca F -device-cert F -device-key F
//	orchctl remove-device   -tenant T -user U -id DEVICE
//	orchctl approve         -tenant T -user U -approval ID -approver ID -signature BASE64
//	orchctl converse        -tenant T -user U [-provider openai|xai] [-locale el-GR]
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	orchv1 "jarvis.internal/gen/go/jarvis/orchestrator/v1"
	"jarvis.internal/libs/go/mtls"
)

const usage = `usage: orchctl [global flags] <command> [flags]

commands (identity used):
  tasks            list a user's recent tasks                 (dashboard-api)
  task             show a task (with a pending approval's payload)
  cancel           cancel a task
  devices          list a user's devices
  register-device  add or replace a device running the Jarvis daemon
  remove-device    forget a device
  approve          submit an approver's signature (from jarvis-approve)
  converse         text conversation with Jarvis's tools      (voice-gateway)

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
	fs := flag.NewFlagSet("orchctl", flag.ExitOnError)
	fs.StringVar(&g.addr, "addr", "127.0.0.1:50054", "orchestrator address")
	fs.StringVar(&g.serverName, "server-name", "localhost", "orchestrator TLS server name")
	fs.StringVar(&g.certs, "certs", ".dev/certs", "directory with ca.pem and <identity>.pem / <identity>-key.pem")
	fs.StringVar(&g.identity, "as", "", "client identity (default: dashboard-api, or voice-gateway for converse)")
	fs.DurationVar(&g.timeout, "rpc-timeout", time.Minute, "per-RPC timeout")
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
		fmt.Fprintln(os.Stderr, "orchctl:", err)
		os.Exit(1)
	}
}

func run(g global, command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	tenant := fs.String("tenant", "", "tenant id (UUID)")
	user := fs.String("user", "", "user id")
	id := fs.String("id", "", "task or device id")
	switch command {
	case "tasks":
		limit := fs.Int("limit", 20, "how many (1-100)")
		_ = fs.Parse(args)
		return withClient(g, "dashboard-api", func(ctx context.Context, c orchv1.OrchestratorServiceClient) error {
			return show(c.ListTasks(ctx, &orchv1.ListTasksRequest{TenantId: *tenant, UserId: *user, Limit: int32(*limit)}))
		})
	case "task":
		_ = fs.Parse(args)
		return withClient(g, "dashboard-api", func(ctx context.Context, c orchv1.OrchestratorServiceClient) error {
			return show(c.GetTask(ctx, &orchv1.GetTaskRequest{TenantId: *tenant, UserId: *user, TaskId: *id}))
		})
	case "cancel":
		_ = fs.Parse(args)
		return withClient(g, "dashboard-api", func(ctx context.Context, c orchv1.OrchestratorServiceClient) error {
			return show(c.CancelTask(ctx, &orchv1.CancelTaskRequest{TenantId: *tenant, UserId: *user, TaskId: *id}))
		})
	case "devices":
		_ = fs.Parse(args)
		return withClient(g, "dashboard-api", func(ctx context.Context, c orchv1.OrchestratorServiceClient) error {
			return show(c.ListDevices(ctx, &orchv1.ListDevicesRequest{TenantId: *tenant, UserId: *user}))
		})
	case "register-device":
		name := fs.String("name", "", "device name, e.g. MacBook")
		address := fs.String("address", "", "daemon address host:port (tailnet, or loopback in development)")
		serverName := fs.String("device-server-name", "", "the daemon certificate's DNS name")
		caFile := fs.String("device-ca", "", "CA that signed the daemon's certificate (PEM)")
		certFile := fs.String("device-cert", "", "client certificate the daemon trusts (PEM)")
		keyFile := fs.String("device-key", "", "its private key (PEM); sealed by the Vault before storage")
		_ = fs.Parse(args)
		ca, err := os.ReadFile(*caFile)
		if err != nil {
			return err
		}
		cert, err := os.ReadFile(*certFile)
		if err != nil {
			return err
		}
		key, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		defer clear(key)
		return withClient(g, "dashboard-api", func(ctx context.Context, c orchv1.OrchestratorServiceClient) error {
			return show(c.RegisterDevice(ctx, &orchv1.RegisterDeviceRequest{TenantId: *tenant, UserId: *user,
				Name: *name, Address: *address, ServerName: *serverName, CaPem: string(ca), ClientCertPem: string(cert), ClientKeyPem: key}))
		})
	case "remove-device":
		_ = fs.Parse(args)
		return withClient(g, "dashboard-api", func(ctx context.Context, c orchv1.OrchestratorServiceClient) error {
			return show(c.RemoveDevice(ctx, &orchv1.RemoveDeviceRequest{TenantId: *tenant, UserId: *user, DeviceId: *id}))
		})
	case "approve":
		approval := fs.String("approval", "", "approval id (from `orchctl task`)")
		approver := fs.String("approver", "dev-cli", "approver id configured on the device")
		signature := fs.String("signature", "", "signature printed by jarvis-approve (base64)")
		_ = fs.Parse(args)
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(*signature))
		if err != nil {
			return fmt.Errorf("-signature: %w", err)
		}
		return withClient(g, "dashboard-api", func(ctx context.Context, c orchv1.OrchestratorServiceClient) error {
			return show(c.SubmitDeviceApproval(ctx, &orchv1.SubmitDeviceApprovalRequest{TenantId: *tenant, UserId: *user,
				ApprovalId: *approval, ApproverId: *approver, Signature: sig}))
		})
	case "converse":
		provider := fs.String("provider", "openai", "openai or xai (background tasks use its key)")
		locale := fs.String("locale", "", "user locale, e.g. el-GR")
		_ = fs.Parse(args)
		kind := map[string]commonv1.Provider{"openai": commonv1.Provider_PROVIDER_OPENAI, "xai": commonv1.Provider_PROVIDER_XAI}[*provider]
		if kind == commonv1.Provider_PROVIDER_UNSPECIFIED {
			return errors.New("-provider must be openai or xai")
		}
		conn, err := dial(g, "voice-gateway")
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		return converse(g, orchv1.NewOrchestratorServiceClient(conn), &orchv1.OpenConversationRequest{
			TenantId: *tenant, UserId: *user, SessionId: fmt.Sprintf("orchctl-%d", time.Now().UnixNano()),
			Provider: kind, Locale: *locale,
		})
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func dial(g global, defaultIdentity string) (*grpc.ClientConn, error) {
	identity := g.identity
	if identity == "" {
		identity = defaultIdentity
	}
	tlsConfig, err := mtls.ClientConfig(filepath.Join(g.certs, identity+".pem"), filepath.Join(g.certs, identity+"-key.pem"),
		filepath.Join(g.certs, "ca.pem"), g.serverName)
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(g.addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
}

func withClient(g global, defaultIdentity string, fn func(context.Context, orchv1.OrchestratorServiceClient) error) error {
	conn, err := dial(g, defaultIdentity)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(outgoing(context.Background()), g.timeout)
	defer cancel()
	return fn(ctx, orchv1.NewOrchestratorServiceClient(conn))
}

func outgoing(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "x-request-id", fmt.Sprintf("orchctl-%d", time.Now().UnixNano()))
}

func show[M proto.Message](m M, err error) error {
	if err != nil {
		return err
	}
	out, err := protojson.MarshalOptions{Multiline: true}.Marshal(m)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// --- converse -----------------------------------------------------------------------

const converseHelp = `commands:
  say <text>           you speak (a new user turn)
  call <tool> [json]   the model calls a tool in the current turn
  tools                list the tools
  help                 this text
  quit                 end the conversation (it becomes memory)

Questions (confirmations) and events are treated as spoken right away, as
the gateway would: answer them with "say ...", then "call confirm_action ...".`

// converse plays the voice gateway: it keeps the user-turn counter and
// acknowledges questions and events at the current turn.
func converse(g global, client orchv1.OrchestratorServiceClient, open *orchv1.OpenConversationRequest) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	call := func(fn func(context.Context) error) error {
		rpcCtx, cancel := context.WithTimeout(outgoing(ctx), g.timeout)
		defer cancel()
		return fn(rpcCtx)
	}

	var opened *orchv1.OpenConversationResponse
	if err := call(func(ctx context.Context) (err error) {
		opened, err = client.OpenConversation(ctx, open)
		return err
	}); err != nil {
		return err
	}
	conversation := opened.GetConversationId()
	fmt.Printf("conversation %s with %d tools. Type help.\n", conversation, len(opened.GetTools()))
	defer func() {
		closeCtx, cancel := context.WithTimeout(outgoing(context.Background()), 10*time.Second)
		defer cancel()
		if _, err := client.CloseConversation(closeCtx, &orchv1.CloseConversationRequest{ConversationId: conversation}); err != nil {
			fmt.Fprintln(os.Stderr, "close:", err)
			return
		}
		fmt.Println("conversation closed; its memory is extracted in the background")
	}()

	var turn atomic.Int64
	var out sync.Mutex
	say := func(format string, args ...any) {
		out.Lock()
		defer out.Unlock()
		fmt.Printf(format+"\n", args...)
	}

	watchCtx, stopWatch := context.WithCancel(outgoing(ctx))
	defer stopWatch()
	go func() {
		stream, err := client.WatchConversation(watchCtx, &orchv1.WatchConversationRequest{ConversationId: conversation})
		if err != nil {
			say("events unavailable: %v", err)
			return
		}
		for {
			resp, err := stream.Recv()
			if err != nil {
				if watchCtx.Err() == nil && !errors.Is(err, io.EOF) {
					say("event stream ended: %v", err)
				}
				return
			}
			event := resp.GetEvent()
			say("\n[event %d] %s", event.GetEventId(), event.GetMessage())
			if err := call(func(ctx context.Context) error {
				_, err := client.AckEvent(ctx, &orchv1.AckEventRequest{ConversationId: conversation,
					EventId: event.GetEventId(), UserTurn: turn.Load()})
				return err
			}); err != nil {
				say("ack event: %v", err)
			}
		}
	}()

	lines := bufio.NewScanner(os.Stdin)
	lines.Buffer(make([]byte, 64<<10), 64<<10)
	calls := 0
	for {
		fmt.Print("> ")
		if !lines.Scan() {
			return lines.Err()
		}
		command, rest, _ := strings.Cut(strings.TrimSpace(lines.Text()), " ")
		rest = strings.TrimSpace(rest)
		switch command {
		case "":
		case "quit", "exit":
			return nil
		case "help":
			say("%s", converseHelp)
		case "tools":
			for _, t := range opened.GetTools() {
				say("  %-40s %s", t.GetName(), firstLine(t.GetDescription()))
			}
		case "say":
			n := turn.Add(1)
			if err := call(func(ctx context.Context) error {
				_, err := client.RecordTurn(ctx, &orchv1.RecordTurnRequest{ConversationId: conversation,
					Role: orchv1.Role_ROLE_USER, UserTurn: n, ItemId: fmt.Sprintf("orchctl-user-%d", n), Text: rest})
				return err
			}); err != nil {
				say("record: %v", err)
			}
		case "call":
			name, arguments, _ := strings.Cut(rest, " ")
			if strings.TrimSpace(arguments) == "" {
				arguments = "{}"
			}
			calls++
			callID := fmt.Sprintf("orchctl-call-%d", calls)
			var resp *orchv1.CallToolResponse
			err := call(func(ctx context.Context) (err error) {
				resp, err = client.CallTool(ctx, &orchv1.CallToolRequest{ConversationId: conversation, CallId: callID,
					Name: name, ArgumentsJson: arguments, UserTurn: turn.Load()})
				return err
			})
			if err != nil {
				say("call: %v", err)
				continue
			}
			label := "result"
			if resp.GetIsError() {
				label = "tool error"
			}
			say("%s: %s", label, resp.GetOutput())
			if resp.GetAckRequired() {
				// The model would speak the question now.
				if err := call(func(ctx context.Context) error {
					_, err := client.AckToolOutput(ctx, &orchv1.AckToolOutputRequest{ConversationId: conversation,
						CallId: callID, UserTurn: turn.Load()})
					return err
				}); err != nil {
					say("ack: %v", err)
				} else {
					say("(question asked at turn %d; answer with say, then call confirm_action)", turn.Load())
				}
			}
		default:
			say("unknown command %q; type help", command)
		}
	}
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(text, "\n")
	if len(line) > 80 {
		return line[:80] + "…"
	}
	return line
}
