package config

import (
	"strings"
	"testing"
	"time"
)

func base() map[string]string {
	return map[string]string{
		"ORCH_TLS_CERT": "/s.pem", "ORCH_TLS_KEY": "/s-key.pem", "ORCH_TLS_CLIENT_CA": "/ca.pem",
		"ORCH_AUTHZ_POLICY": "/authz.toml", "ORCH_DATABASE_URL": "postgres://orchestrator@db/orchestrator",
		"ORCH_CLIENT_CERT": "/c.pem", "ORCH_CLIENT_KEY": "/c-key.pem", "ORCH_CLIENT_CA": "/ca.pem",
		"ORCH_VAULT_ADDR": "vault.internal:50051", "ORCH_MCP_ROUTER_ADDR": "127.0.0.1:50052",
		"ORCH_KNOWLEDGE_ADDR": "127.0.0.1:50053", "ORCH_AGENT_SOCKET": "/run/jarvis/agent.sock",
	}
}

func load(env map[string]string) (Config, error) {
	return Load(func(name string) (string, bool) { v, ok := env[name]; return v, ok })
}

func TestDefaults(t *testing.T) {
	c, err := load(base())
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != "127.0.0.1:50054" || c.Vault.ServerName != "vault.internal" || c.OpenAIModel != "gpt-6-luna" ||
		c.XAIModel != "grok-4.6" || c.TaskMaxSteps != 12 || c.ToolTimeout != 20*time.Second || c.AllowLoopbackDevices {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestInvalidSettings(t *testing.T) {
	for name, overrides := range map[string]map[string]string{
		"public admin":      {"ORCH_ADMIN_ADDR": "0.0.0.0:9094"},
		"long socket":       {"ORCH_AGENT_SOCKET": "/" + strings.Repeat("s", 120)},
		"slow tools":        {"ORCH_TOOL_TIMEOUT": "2m"},
		"zero workers":      {"ORCH_WORKERS": "0"},
		"bad duration":      {"ORCH_TASK_TIMEOUT": "soon"},
		"negative ttl":      {"ORCH_CONFIRMATION_TTL": "-1s"},
		"bad log format":    {"ORCH_LOG_FORMAT": "xml"},
		"missing knowledge": {"ORCH_KNOWLEDGE_ADDR": ""},
		"database twice":    {"ORCH_DATABASE_URL_FILE": "/run/secrets/db"},
	} {
		env := base()
		for k, v := range overrides {
			env[k] = v
		}
		if _, err := load(env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err := load(map[string]string{})
	for _, name := range []string{"ORCH_TLS_CERT", "ORCH_VAULT_ADDR", "ORCH_AGENT_SOCKET", "ORCH_DATABASE_URL"} {
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("empty environment: %s not reported", name)
		}
	}
}
