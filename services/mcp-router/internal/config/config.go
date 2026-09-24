// Package config reads the router's MCP_* environment variables. Secrets may
// instead be given as a file path in <NAME>_FILE. Every problem is reported
// at once.
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

	"jarvis.internal/mcp-router/internal/catalog"
)

// Config is the validated configuration.
type Config struct {
	ListenAddr string
	AdminAddr  string
	TLSCert    string
	TLSKey     string
	TLSCA      string
	Policy     string
	Reflection bool

	DatabaseURL   string
	RedisAddr     string
	RedisPassword string

	VaultAddr       string
	VaultServerName string
	VaultCA         string
	VaultCert       string
	VaultKey        string
	// The audit service (optional), with the same client identity as for the Vault.
	AuditAddr       string
	AuditServerName string

	RedirectURI        string
	ClientName         string
	OAuthClients       map[string]catalog.ClientCredentials
	AllowCustom        bool
	AllowLoopback      bool
	RatePerTenant      int
	RatePerIntegration int
	ToolsCacheTTL      time.Duration
	DefaultCallTimeout time.Duration
	MaxCallTimeout     time.Duration

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
		ListenAddr: r.str("MCP_LISTEN_ADDR", "127.0.0.1:50052"),
		AdminAddr:  r.str("MCP_ADMIN_ADDR", "127.0.0.1:9092"),
		TLSCert:    r.required("MCP_TLS_CERT"),
		TLSKey:     r.required("MCP_TLS_KEY"),
		TLSCA:      r.required("MCP_TLS_CLIENT_CA"),
		Policy:     r.required("MCP_AUTHZ_POLICY"),
		Reflection: r.boolean("MCP_REFLECTION", false),

		DatabaseURL:   r.secret("MCP_DATABASE_URL", true),
		RedisAddr:     r.str("MCP_REDIS_ADDR", "127.0.0.1:56379"),
		RedisPassword: r.secret("MCP_REDIS_PASSWORD", false),

		VaultAddr: r.required("MCP_VAULT_ADDR"),
		VaultCA:   r.required("MCP_VAULT_CA"),
		VaultCert: r.required("MCP_VAULT_CERT"),
		VaultKey:  r.required("MCP_VAULT_KEY"),
		AuditAddr: r.str("MCP_AUDIT_ADDR", ""),

		RedirectURI:        r.required("MCP_OAUTH_REDIRECT_URI"),
		ClientName:         r.str("MCP_OAUTH_CLIENT_NAME", "Jarvis"),
		AllowCustom:        r.boolean("MCP_ALLOW_CUSTOM_SERVERS", false),
		AllowLoopback:      r.boolean("MCP_ALLOW_LOOPBACK_SERVERS", false),
		RatePerTenant:      r.integer("MCP_RATE_PER_TENANT_PER_MINUTE", 120),
		RatePerIntegration: r.integer("MCP_RATE_PER_INTEGRATION_PER_MINUTE", 60),
		ToolsCacheTTL:      r.duration("MCP_TOOLS_CACHE_TTL", 5*time.Minute),
		DefaultCallTimeout: r.duration("MCP_DEFAULT_CALL_TIMEOUT", 30*time.Second),
		MaxCallTimeout:     r.duration("MCP_MAX_CALL_TIMEOUT", 120*time.Second),

		LogFormat: r.str("MCP_LOG_FORMAT", "json"),
		LogLevel:  r.str("MCP_LOG_LEVEL", "info"),
	}
	c.VaultServerName = r.str("MCP_VAULT_SERVER_NAME", hostOf(c.VaultAddr))
	c.AuditServerName = r.str("MCP_AUDIT_SERVER_NAME", hostOf(c.AuditAddr))

	c.OAuthClients = map[string]catalog.ClientCredentials{}
	for _, slug := range catalog.Slugs() {
		prefix := "MCP_OAUTH_" + strings.ToUpper(slug) + "_CLIENT_"
		id := r.str(prefix+"ID", "")
		secret := r.secret(prefix+"SECRET", false)
		switch {
		case id != "":
			c.OAuthClients[slug] = catalog.ClientCredentials{ClientID: id, ClientSecret: secret}
		case secret != "":
			r.fail("%sSECRET is set without %sID", prefix, prefix)
		}
	}

	if u, err := url.Parse(c.RedirectURI); c.RedirectURI != "" && (err != nil || u.Host == "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())))) {
		r.fail("MCP_OAUTH_REDIRECT_URI must be https (or http on a loopback address for development)")
	}
	if !isLoopback(hostOf(c.AdminAddr)) {
		r.fail("MCP_ADMIN_ADDR must be a loopback address (metrics are not public)")
	}
	if c.RatePerTenant < 1 || c.RatePerIntegration < 1 {
		r.fail("rate limits must be at least 1 per minute")
	}
	if c.DefaultCallTimeout <= 0 || c.MaxCallTimeout < c.DefaultCallTimeout || c.MaxCallTimeout > 10*time.Minute {
		r.fail("call timeouts must satisfy 0 < MCP_DEFAULT_CALL_TIMEOUT <= MCP_MAX_CALL_TIMEOUT <= 10m")
	}
	if c.ToolsCacheTTL <= 0 {
		r.fail("MCP_TOOLS_CACHE_TTL must be positive")
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		r.fail("MCP_LOG_FORMAT must be json or text")
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

// secret reads NAME or the file named by NAME_FILE (not both).
func (r *reader) secret(name string, required bool) string {
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
	case inline == "" && required:
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
