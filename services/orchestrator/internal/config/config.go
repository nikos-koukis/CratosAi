// Package config reads the orchestrator's ORCH_* environment variables.
// Secrets may instead be given as a file path in <NAME>_FILE. Every problem
// is reported at once.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Endpoint is an internal gRPC service reached with the orchestrator's
// client certificate.
type Endpoint struct {
	Addr       string
	ServerName string
}

// Config is the validated configuration.
type Config struct {
	ListenAddr string
	AdminAddr  string
	TLSCert    string
	TLSKey     string
	TLSCA      string
	Policy     string
	Reflection bool

	DatabaseURL string

	// The orchestrator's identity towards internal services
	// (spiffe://jarvis.local/orchestrator) and the CA they chain to.
	ClientCert string
	ClientKey  string
	ClientCA   string
	Vault      Endpoint
	MCPRouter  Endpoint
	Knowledge  Endpoint
	// The LLM sidecar's Unix socket.
	AgentSocket string

	OpenAIModel string
	XAIModel    string

	Workers              int
	TaskMaxSteps         int
	TaskTimeout          time.Duration
	ToolTimeout          time.Duration
	ConfirmationTTL      time.Duration
	TranscriptRetention  time.Duration
	MaxVoiceTools        int
	AllowLoopbackDevices bool

	LogFormat string
	LogLevel  string
}

// Lookup returns an environment variable's value and whether it is set.
type Lookup func(string) (string, bool)

// FromEnv reads the process environment.
func FromEnv() (Config, error) { return Load(os.LookupEnv) }

// Load builds a validated Config.
func Load(lookup Lookup) (Config, error) {
	r := &reader{lookup: lookup}
	c := Config{
		ListenAddr: r.str("ORCH_LISTEN_ADDR", "127.0.0.1:50054"),
		AdminAddr:  r.str("ORCH_ADMIN_ADDR", "127.0.0.1:9094"),
		TLSCert:    r.required("ORCH_TLS_CERT"),
		TLSKey:     r.required("ORCH_TLS_KEY"),
		TLSCA:      r.required("ORCH_TLS_CLIENT_CA"),
		Policy:     r.required("ORCH_AUTHZ_POLICY"),
		Reflection: r.boolean("ORCH_REFLECTION", false),

		DatabaseURL: r.secret("ORCH_DATABASE_URL"),

		ClientCert:  r.required("ORCH_CLIENT_CERT"),
		ClientKey:   r.required("ORCH_CLIENT_KEY"),
		ClientCA:    r.required("ORCH_CLIENT_CA"),
		Vault:       r.endpoint("ORCH_VAULT"),
		MCPRouter:   r.endpoint("ORCH_MCP_ROUTER"),
		Knowledge:   r.endpoint("ORCH_KNOWLEDGE"),
		AgentSocket: r.required("ORCH_AGENT_SOCKET"),

		OpenAIModel: r.str("ORCH_OPENAI_MODEL", "gpt-6-luna"),
		XAIModel:    r.str("ORCH_XAI_MODEL", "grok-4.6"),

		Workers:              r.integer("ORCH_WORKERS", 8, 1, 256),
		TaskMaxSteps:         r.integer("ORCH_TASK_MAX_STEPS", 12, 1, 100),
		TaskTimeout:          r.duration("ORCH_TASK_TIMEOUT", 10*time.Minute),
		ToolTimeout:          r.duration("ORCH_TOOL_TIMEOUT", 20*time.Second),
		ConfirmationTTL:      r.duration("ORCH_CONFIRMATION_TTL", 10*time.Minute),
		TranscriptRetention:  r.duration("ORCH_TRANSCRIPT_RETENTION", 30*24*time.Hour),
		MaxVoiceTools:        r.integer("ORCH_MAX_VOICE_TOOLS", 40, 5, 120),
		AllowLoopbackDevices: r.boolean("ORCH_ALLOW_LOOPBACK_DEVICES", false),

		LogFormat: r.str("ORCH_LOG_FORMAT", "json"),
		LogLevel:  r.str("ORCH_LOG_LEVEL", "info"),
	}
	if !isLoopback(hostOf(c.AdminAddr)) {
		r.fail("ORCH_ADMIN_ADDR must be a loopback address (metrics are not public)")
	}
	if c.AgentSocket != "" && len(c.AgentSocket) > 103 {
		r.fail("ORCH_AGENT_SOCKET must be at most 103 bytes (a Unix socket limit)")
	}
	for name, d := range map[string]time.Duration{
		"ORCH_TASK_TIMEOUT": c.TaskTimeout, "ORCH_TOOL_TIMEOUT": c.ToolTimeout,
		"ORCH_CONFIRMATION_TTL": c.ConfirmationTTL, "ORCH_TRANSCRIPT_RETENTION": c.TranscriptRetention,
	} {
		if d <= 0 {
			r.fail("%s must be positive", name)
		}
	}
	if c.ToolTimeout > time.Minute {
		r.fail("ORCH_TOOL_TIMEOUT must be at most 1m (the voice model waits for it)")
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		r.fail("ORCH_LOG_FORMAT must be json or text")
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

func (r *reader) endpoint(prefix string) Endpoint {
	addr := r.required(prefix + "_ADDR")
	return Endpoint{Addr: addr, ServerName: r.str(prefix+"_SERVER_NAME", hostOf(addr))}
}

// secret reads NAME or the file named by NAME_FILE (not both); required.
func (r *reader) secret(name string) string {
	inline, file := r.str(name, ""), r.str(name+"_FILE", "")
	switch {
	case inline != "" && file != "":
		r.fail("%s and %s_FILE are both set; use one", name, name)
	case file != "":
		data, err := os.ReadFile(file)
		if err != nil {
			r.fail("%s_FILE: %v", name, err)
			return ""
		}
		return strings.TrimRight(string(data), "\r\n")
	case inline == "":
		r.fail("%s or %s_FILE is required", name, name)
	}
	return inline
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

func (r *reader) integer(name string, fallback, low, high int) int {
	value := r.str(name, "")
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < low || parsed > high {
		r.fail("%s must be an integer from %d to %d", name, low, high)
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
		r.fail("%s must be a duration such as 30s", name)
	}
	return parsed
}

func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
