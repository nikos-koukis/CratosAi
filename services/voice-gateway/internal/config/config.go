// Package config reads the gateway's configuration from GATEWAY_* environment
// variables and validates it before anything starts.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
	"jarvis.internal/voice-gateway/internal/realtime"
)

// DefaultInstructions is the assistant's base system prompt; the
// orchestrator appends how to use Jarvis's tools.
const DefaultInstructions = "You are Jarvis, a concise and friendly voice assistant. " +
	"Answer in the language the user speaks. Keep answers short and conversational."

// Config is the validated configuration.
type Config struct {
	ListenAddr     string
	AdminAddr      string
	TLSCert        string
	TLSKey         string
	AllowPlaintext bool

	TokenJWKS        string
	TokenIssuer      string
	TokenAudience    string
	TokenMaxLifetime time.Duration

	VaultAddr       string
	VaultServerName string
	VaultCA         string
	VaultCert       string
	VaultKey        string

	// Orchestrator gives the model Jarvis's tools; empty OrchestratorAddr
	// runs plain voice sessions without tools. The mTLS files default to the
	// Vault client's.
	OrchestratorAddr       string
	OrchestratorServerName string
	OrchestratorCA         string
	OrchestratorCert       string
	OrchestratorKey        string
	ToolTimeout            time.Duration

	Providers       map[commonv1.Provider]realtime.Provider
	DefaultProvider commonv1.Provider
	Instructions    string

	StartTimeout         time.Duration
	MaxSessionDuration   time.Duration
	IdleTimeout          time.Duration
	MaxSessions          int
	MaxSessionsPerTenant int
	LogFormat            string
	LogLevel             string
}

// Lookup returns an environment variable's value and whether it is set.
type Lookup func(string) (string, bool)

// FromEnv reads the process environment.
func FromEnv() (Config, error) { return Load(os.LookupEnv) }

// Load builds a validated Config; every problem is reported at once.
func Load(lookup Lookup) (Config, error) {
	r := reader{lookup: lookup}
	c := Config{
		ListenAddr:     r.str("GATEWAY_LISTEN_ADDR", "127.0.0.1:8080"),
		AdminAddr:      r.str("GATEWAY_ADMIN_ADDR", "127.0.0.1:9091"),
		TLSCert:        r.str("GATEWAY_TLS_CERT", ""),
		TLSKey:         r.str("GATEWAY_TLS_KEY", ""),
		AllowPlaintext: r.boolean("GATEWAY_ALLOW_PLAINTEXT", false),

		TokenJWKS:        r.required("GATEWAY_TOKEN_JWKS"),
		TokenIssuer:      r.required("GATEWAY_TOKEN_ISSUER"),
		TokenAudience:    r.str("GATEWAY_TOKEN_AUDIENCE", "jarvis-voice-gateway"),
		TokenMaxLifetime: r.duration("GATEWAY_TOKEN_MAX_LIFETIME", time.Hour),

		VaultAddr:    r.required("GATEWAY_VAULT_ADDR"),
		VaultCA:      r.required("GATEWAY_VAULT_CA"),
		VaultCert:    r.required("GATEWAY_VAULT_CERT"),
		VaultKey:     r.required("GATEWAY_VAULT_KEY"),
		Instructions: r.str("GATEWAY_INSTRUCTIONS", DefaultInstructions),

		StartTimeout:         r.duration("GATEWAY_START_TIMEOUT", 10*time.Second),
		MaxSessionDuration:   r.duration("GATEWAY_MAX_SESSION_DURATION", 30*time.Minute),
		IdleTimeout:          r.duration("GATEWAY_IDLE_TIMEOUT", 5*time.Minute),
		MaxSessions:          r.integer("GATEWAY_MAX_SESSIONS", 1000),
		MaxSessionsPerTenant: r.integer("GATEWAY_MAX_SESSIONS_PER_TENANT", 3),
		LogFormat:            r.str("GATEWAY_LOG_FORMAT", "json"),
		LogLevel:             r.str("GATEWAY_LOG_LEVEL", "info"),
	}
	c.VaultServerName = r.str("GATEWAY_VAULT_SERVER_NAME", hostOf(c.VaultAddr))
	c.OrchestratorAddr = r.str("GATEWAY_ORCHESTRATOR_ADDR", "")
	c.OrchestratorServerName = r.str("GATEWAY_ORCHESTRATOR_SERVER_NAME", hostOf(c.OrchestratorAddr))
	c.OrchestratorCA = r.str("GATEWAY_ORCHESTRATOR_CA", c.VaultCA)
	c.OrchestratorCert = r.str("GATEWAY_ORCHESTRATOR_CERT", c.VaultCert)
	c.OrchestratorKey = r.str("GATEWAY_ORCHESTRATOR_KEY", c.VaultKey)
	c.ToolTimeout = r.duration("GATEWAY_TOOL_TIMEOUT", 30*time.Second)

	vadSilence := r.integer("GATEWAY_VAD_SILENCE_MS", 500)
	c.Providers = map[commonv1.Provider]realtime.Provider{}
	for _, name := range r.list("GATEWAY_PROVIDERS", "openai,xai") {
		switch name {
		case "openai":
			c.Providers[commonv1.Provider_PROVIDER_OPENAI] = realtime.Provider{
				Name:               "openai",
				URL:                r.providerURL("GATEWAY_OPENAI_URL", "wss://api.openai.com/v1/realtime", r.str("GATEWAY_OPENAI_MODEL", "gpt-realtime-2.1")),
				Dialect:            realtime.DialectOpenAI,
				DefaultVoice:       r.str("GATEWAY_OPENAI_VOICE", "marin"),
				TranscriptionModel: r.str("GATEWAY_OPENAI_TRANSCRIPTION_MODEL", "gpt-transcribe"),
				VADSilenceMs:       vadSilence,
			}
		case "xai":
			c.Providers[commonv1.Provider_PROVIDER_XAI] = realtime.Provider{
				Name:         "xai",
				URL:          r.providerURL("GATEWAY_XAI_URL", "wss://api.x.ai/v1/realtime", r.str("GATEWAY_XAI_MODEL", "grok-voice-think-fast-2.0")),
				Dialect:      realtime.DialectXAI,
				DefaultVoice: r.str("GATEWAY_XAI_VOICE", "eve"),
				VADSilenceMs: vadSilence,
			}
		default:
			r.fail("GATEWAY_PROVIDERS: unknown provider %q (use openai, xai)", name)
		}
	}
	if len(c.Providers) == 0 {
		r.fail("GATEWAY_PROVIDERS: enable at least one provider")
	}
	defaultName := r.str("GATEWAY_DEFAULT_PROVIDER", firstOf(r.list("GATEWAY_PROVIDERS", "openai,xai")))
	c.DefaultProvider = map[string]commonv1.Provider{
		"openai": commonv1.Provider_PROVIDER_OPENAI,
		"xai":    commonv1.Provider_PROVIDER_XAI,
	}[defaultName]
	if _, ok := c.Providers[c.DefaultProvider]; !ok {
		r.fail("GATEWAY_DEFAULT_PROVIDER: %q is not an enabled provider", defaultName)
	}

	if (c.TLSCert == "") != (c.TLSKey == "") {
		r.fail("GATEWAY_TLS_CERT and GATEWAY_TLS_KEY must be set together")
	}
	if c.TLSCert == "" && !isLoopback(c.ListenAddr) && !c.AllowPlaintext {
		r.fail("GATEWAY_LISTEN_ADDR %s is not loopback: configure GATEWAY_TLS_CERT/KEY, "+
			"or set GATEWAY_ALLOW_PLAINTEXT=true only behind a TLS-terminating proxy", c.ListenAddr)
	}
	if !isLoopback(c.AdminAddr) {
		r.fail("GATEWAY_ADMIN_ADDR must be a loopback address (metrics are not public)")
	}
	if c.MaxSessions < 1 || c.MaxSessionsPerTenant < 1 || c.MaxSessionsPerTenant > c.MaxSessions {
		r.fail("session limits must satisfy 1 <= GATEWAY_MAX_SESSIONS_PER_TENANT <= GATEWAY_MAX_SESSIONS")
	}
	if vadSilence < 200 || vadSilence > 3000 {
		r.fail("GATEWAY_VAD_SILENCE_MS must be 200 to 3000")
	}
	for name, d := range map[string]time.Duration{
		"GATEWAY_START_TIMEOUT":        c.StartTimeout,
		"GATEWAY_MAX_SESSION_DURATION": c.MaxSessionDuration,
		"GATEWAY_IDLE_TIMEOUT":         c.IdleTimeout,
		"GATEWAY_TOKEN_MAX_LIFETIME":   c.TokenMaxLifetime,
		"GATEWAY_TOOL_TIMEOUT":         c.ToolTimeout,
	} {
		if d <= 0 {
			r.fail("%s must be positive", name)
		}
	}
	if c.MaxSessionDuration > time.Hour {
		r.fail("GATEWAY_MAX_SESSION_DURATION must be at most 1h (providers end sessions at 60 minutes)")
	}
	if c.ToolTimeout > 2*time.Minute {
		r.fail("GATEWAY_TOOL_TIMEOUT must be at most 2m (the user is waiting on the line)")
	}
	if c.OrchestratorAddr != "" {
		if _, _, err := net.SplitHostPort(c.OrchestratorAddr); err != nil {
			r.fail("GATEWAY_ORCHESTRATOR_ADDR must be host:port")
		}
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		r.fail("GATEWAY_LOG_FORMAT must be json or text")
	}
	return c, r.err()
}

type reader struct {
	lookup Lookup
	errs   []string
}

func (r *reader) fail(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func (r *reader) err() error {
	if len(r.errs) == 0 {
		return nil
	}
	return errors.New("invalid configuration:\n  " + strings.Join(r.errs, "\n  "))
}

func (r *reader) str(name, fallback string) string {
	if value, ok := r.lookup(name); ok && value != "" {
		return value
	}
	return fallback
}

func (r *reader) required(name string) string {
	value := r.str(name, "")
	if value == "" {
		r.fail("%s is required", name)
	}
	return value
}

func (r *reader) boolean(name string, fallback bool) bool {
	value := r.str(name, "")
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		r.fail("%s must be true or false", name)
	}
	return parsed
}

func (r *reader) integer(name string, fallback int) int {
	value := r.str(name, "")
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		r.fail("%s must be an integer", name)
	}
	return parsed
}

func (r *reader) duration(name string, fallback time.Duration) time.Duration {
	value := r.str(name, "")
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		r.fail("%s must be a duration such as 30s or 5m", name)
	}
	return parsed
}

func (r *reader) list(name, fallback string) []string {
	var out []string
	for _, item := range strings.Split(r.str(name, fallback), ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// providerURL appends ?model= and refuses plaintext except to loopback
// (tests and local fakes): the tenant's key travels in the handshake.
func (r *reader) providerURL(name, fallback, model string) string {
	raw := r.str(name, fallback)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "wss" && u.Scheme != "ws") || u.Host == "" {
		r.fail("%s must be a ws(s):// URL", name)
		return raw
	}
	if u.Scheme == "ws" && !isLoopback(u.Host) {
		r.fail("%s must use wss:// (API keys must not travel in plaintext)", name)
	}
	query := u.Query()
	if query.Get("model") == "" {
		query.Set("model", model)
	}
	u.RawQuery = query.Encode()
	return u.String()
}

func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func isLoopback(addr string) bool {
	host := hostOf(addr)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func firstOf(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return items[0]
}
