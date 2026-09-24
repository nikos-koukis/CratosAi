// Command voicectl is the voice gateway's development tool:
//
//	voicectl keygen         create a token-signing key and its JWKS
//	voicectl token          issue an access token for a tenant and user
//	voicectl talk           send a WAV file as speech and save the spoken reply
//	voicectl echo-provider  run a local fake realtime provider that echoes you
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"jarvis.internal/libs/go/usertoken"
)

const usage = `usage: voicectl <command> [flags]

commands:
  keygen         create a token-signing key (PKCS#8 PEM) and its JWKS
  token          issue a short-lived access token
  talk           stream a WAV file to the gateway and save the reply
  echo-provider  run a local fake realtime provider that echoes speech back

run "voicectl <command> -h" for flags`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	commands := map[string]func([]string) error{
		"keygen":        keygen,
		"token":         token,
		"talk":          talk,
		"echo-provider": echoProvider,
	}
	command, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err := command(os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "voicectl:", err)
		os.Exit(1)
	}
}

func keygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	dir := flags.String("out", ".dev/tokens", "output directory")
	kid := flags.String("kid", "dev", "key id")
	if err := flags.Parse(args); err != nil {
		return err
	}
	privatePEM, jwks, err := usertoken.GenerateKey(*kid)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	keyPath := filepath.Join(*dir, "signing-key.pem")
	file, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%w (delete it first to rotate)", err)
	}
	if _, err := file.Write(privatePEM); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	jwksPath := filepath.Join(*dir, "jwks.json")
	if err := os.WriteFile(jwksPath, jwks, 0o644); err != nil {
		return err
	}
	fmt.Printf("signing key: %s\npublic JWKS: %s  (GATEWAY_TOKEN_JWKS)\n", keyPath, jwksPath)
	return nil
}

func token(args []string) error {
	flags := flag.NewFlagSet("token", flag.ContinueOnError)
	keyPath := flags.String("key", ".dev/tokens/signing-key.pem", "signing key")
	kid := flags.String("kid", "dev", "key id")
	issuer := flags.String("issuer", "https://id.jarvis.local", "issuer (GATEWAY_TOKEN_ISSUER)")
	audience := flags.String("audience", "jarvis-voice-gateway", "audience")
	tenant := flags.String("tenant", "", "tenant UUID (required)")
	user := flags.String("user", "dev-user", "user id")
	ttl := flags.Duration("ttl", 15*time.Minute, "lifetime")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if _, err := uuid.Parse(*tenant); err != nil {
		return errors.New("-tenant must be a UUID")
	}
	key, err := usertoken.LoadSigningKey(*keyPath)
	if err != nil {
		return err
	}
	signed, err := usertoken.Issuer{Key: key, KeyID: *kid, Issuer: *issuer, Audience: *audience}.
		Issue(strings.TrimSpace(*user), *tenant, *ttl)
	if err != nil {
		return err
	}
	fmt.Println(signed)
	return nil
}
