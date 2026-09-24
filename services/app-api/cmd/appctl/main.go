// Command appctl drives the app API's internal side from a terminal, as the
// dashboard backend would (identity dashboard-api):
//
//	appctl pair     -tenant T -user U      issue a pairing code, shown as a QR code
//	appctl sessions -tenant T -user U      list the user's paired apps
//	appctl revoke   -tenant T -user U -session ID
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"rsc.io/qr"

	appv1 "jarvis.internal/gen/go/jarvis/app/v1"
	"jarvis.internal/libs/go/mtls"
)

const usage = `usage: appctl [global flags] <command> [flags]

commands:
  pair       issue a one-time pairing code for a user and show it as a QR code
  sessions   list a user's paired apps
  revoke     sign a paired app out

global flags:
`

type global struct {
	addr       string
	serverName string
	certs      string
	identity   string
}

func main() {
	var g global
	fs := flag.NewFlagSet("appctl", flag.ExitOnError)
	fs.StringVar(&g.addr, "addr", "127.0.0.1:50055", "app API admin address")
	fs.StringVar(&g.serverName, "server-name", "localhost", "its TLS server name")
	fs.StringVar(&g.certs, "certs", ".dev/certs", "directory with ca.pem and <identity>.pem / <identity>-key.pem")
	fs.StringVar(&g.identity, "as", "dashboard-api", "client identity")
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
		fmt.Fprintln(os.Stderr, "appctl:", err)
		os.Exit(1)
	}
}

func run(g global, command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	tenant := fs.String("tenant", "", "tenant id (UUID)")
	user := fs.String("user", "", "user id")
	session := fs.String("session", "", "session id (revoke)")
	_ = fs.Parse(args)

	tlsConfig, err := mtls.ClientConfig(filepath.Join(g.certs, g.identity+".pem"), filepath.Join(g.certs, g.identity+"-key.pem"),
		filepath.Join(g.certs, "ca.pem"), g.serverName)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(g.addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	client := appv1.NewAppAdminServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "x-request-id", fmt.Sprintf("appctl-%d", time.Now().UnixNano()))

	switch command {
	case "pair":
		resp, err := client.CreatePairingCode(ctx, &appv1.CreatePairingCodeRequest{TenantId: *tenant, UserId: *user})
		if err != nil {
			return err
		}
		code, err := qr.Encode(resp.GetPairingUrl(), qr.M)
		if err != nil {
			return err
		}
		fmt.Println(render(code))
		fmt.Printf("Scan it with the iPhone's camera, or type the code in the Jarvis app.\n\n")
		fmt.Printf("  code:    %s\n  link:    %s\n  expires: %s\n", resp.GetCode(), resp.GetPairingUrl(),
			resp.GetExpireTime().AsTime().Local().Format("15:04:05"))
		return nil
	case "sessions":
		return show(client.ListSessions(ctx, &appv1.ListSessionsRequest{TenantId: *tenant, UserId: *user}))
	case "revoke":
		return show(client.RevokeSession(ctx, &appv1.RevokeSessionRequest{TenantId: *tenant, UserId: *user,
			SessionId: *session}))
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

// render draws a QR code with half-block characters (two modules per line)
// and a quiet zone, dark on light so phones read it on dark terminals too.
func render(code *qr.Code) string {
	const quiet = 2
	dark := func(x, y int) bool {
		return x >= 0 && y >= 0 && x < code.Size && y < code.Size && code.Black(x, y)
	}
	var b strings.Builder
	for y := -quiet; y < code.Size+quiet; y += 2 {
		for x := -quiet; x < code.Size+quiet; x++ {
			top, bottom := dark(x, y), dark(x, y+1)
			switch {
			case top && bottom:
				b.WriteRune(' ')
			case top:
				b.WriteRune('▄')
			case bottom:
				b.WriteRune('▀')
			default:
				b.WriteRune('█')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
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
