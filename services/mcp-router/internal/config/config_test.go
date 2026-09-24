package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func base() map[string]string {
	return map[string]string{
		"MCP_TLS_CERT":           "/etc/mcp/router.pem",
		"MCP_TLS_KEY":            "/etc/mcp/router-key.pem",
		"MCP_TLS_CLIENT_CA":      "/etc/mcp/ca.pem",
		"MCP_AUTHZ_POLICY":       "/etc/mcp/authz.toml",
		"MCP_DATABASE_URL":       "postgres://mcp_router@db/mcp",
		"MCP_VAULT_ADDR":         "vault.internal:50051",
		"MCP_VAULT_CA":           "/etc/mcp/ca.pem",
		"MCP_VAULT_CERT":         "/etc/mcp/router.pem",
		"MCP_VAULT_KEY":          "/etc/mcp/router-key.pem",
		"MCP_OAUTH_REDIRECT_URI": "https://app.jarvis.test/oauth/mcp/callback",
	}
}

func load(env map[string]string) (Config, error) {
	return Load(func(name string) (string, bool) {
		value, ok := env[name]
		return value, ok
	})
}

func TestDefaults(t *testing.T) {
	c, err := load(base())
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != "127.0.0.1:50052" || c.AdminAddr != "127.0.0.1:9092" || c.VaultServerName != "vault.internal" {
		t.Fatalf("addresses: %+v", c)
	}
	if c.AllowCustom || c.AllowLoopback || c.Reflection {
		t.Fatal("permissive defaults")
	}
	if c.DefaultCallTimeout != 30*time.Second || c.MaxCallTimeout != 120*time.Second || c.ToolsCacheTTL != 5*time.Minute {
		t.Fatalf("timeouts: %+v", c)
	}
	if c.RatePerTenant != 120 || c.RatePerIntegration != 60 || len(c.OAuthClients) != 0 || c.ClientName != "Jarvis" {
		t.Fatalf("limits/clients: %+v", c)
	}
}

func TestOAuthClientsAndSecretFiles(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "slack-secret")
	if err := os.WriteFile(secretFile, []byte("s3cr3t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := base()
	env["MCP_OAUTH_SLACK_CLIENT_ID"] = "123.456"
	env["MCP_OAUTH_SLACK_CLIENT_SECRET_FILE"] = secretFile
	env["MCP_OAUTH_REDIRECT_URI"] = "http://127.0.0.1:8765/callback"
	c, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.OAuthClients["slack"]; got.ClientID != "123.456" || got.ClientSecret != "s3cr3t" {
		t.Fatalf("slack client: %+v", got)
	}
}

func TestUnsafeOrInvalidSettingsAreRefused(t *testing.T) {
	cases := map[string]map[string]string{
		"missing vault":            {"MCP_VAULT_ADDR": ""},
		"missing database":         {"MCP_DATABASE_URL": ""},
		"missing policy":           {"MCP_AUTHZ_POLICY": ""},
		"plaintext redirect":       {"MCP_OAUTH_REDIRECT_URI": "http://app.jarvis.test/callback"},
		"relative redirect":        {"MCP_OAUTH_REDIRECT_URI": "/callback"},
		"public admin":             {"MCP_ADMIN_ADDR": "0.0.0.0:9092"},
		"secret twice":             {"MCP_DATABASE_URL_FILE": "/run/secrets/db"},
		"secret without id":        {"MCP_OAUTH_GMAIL_CLIENT_SECRET": "x"},
		"zero rate":                {"MCP_RATE_PER_TENANT_PER_MINUTE": "0"},
		"bad rate":                 {"MCP_RATE_PER_INTEGRATION_PER_MINUTE": "many"},
		"default above max":        {"MCP_DEFAULT_CALL_TIMEOUT": "3m"},
		"max above ten minutes":    {"MCP_MAX_CALL_TIMEOUT": "11m"},
		"bad duration":             {"MCP_TOOLS_CACHE_TTL": "soon"},
		"bad boolean":              {"MCP_ALLOW_CUSTOM_SERVERS": "maybe"},
		"bad log format":           {"MCP_LOG_FORMAT": "xml"},
		"unreadable secret file":   {"MCP_DATABASE_URL": "", "MCP_DATABASE_URL_FILE": "/nonexistent/secret"},
		"non-positive cache ttl":   {"MCP_TOOLS_CACHE_TTL": "0s"},
		"non-positive default ttl": {"MCP_DEFAULT_CALL_TIMEOUT": "0s"},
	}
	for name, overrides := range cases {
		env := base()
		for k, v := range overrides {
			env[k] = v
		}
		if _, err := load(env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAllProblemsAreReportedAtOnce(t *testing.T) {
	_, err := load(map[string]string{})
	if err == nil {
		t.Fatal("empty environment accepted")
	}
	for _, name := range []string{"MCP_TLS_CERT", "MCP_VAULT_ADDR", "MCP_OAUTH_REDIRECT_URI", "MCP_DATABASE_URL"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error does not mention %s:\n%v", name, err)
		}
	}
}
