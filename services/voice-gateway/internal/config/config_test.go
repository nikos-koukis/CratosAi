package config

import (
	"strings"
	"testing"

	commonv1 "jarvis.internal/gen/go/jarvis/common/v1"
)

func base() map[string]string {
	return map[string]string{
		"GATEWAY_TOKEN_JWKS":   "/etc/gw/jwks.json",
		"GATEWAY_TOKEN_ISSUER": "https://id.jarvis.test",
		"GATEWAY_VAULT_ADDR":   "vault.internal:50051",
		"GATEWAY_VAULT_CA":     "/etc/gw/ca.pem",
		"GATEWAY_VAULT_CERT":   "/etc/gw/gw.pem",
		"GATEWAY_VAULT_KEY":    "/etc/gw/gw-key.pem",
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
	if c.VaultServerName != "vault.internal" {
		t.Fatalf("server name derived from address: %q", c.VaultServerName)
	}
	if c.DefaultProvider != commonv1.Provider_PROVIDER_OPENAI || len(c.Providers) != 2 {
		t.Fatalf("providers: %v default %v", c.Providers, c.DefaultProvider)
	}
	openai := c.Providers[commonv1.Provider_PROVIDER_OPENAI]
	if openai.URL != "wss://api.openai.com/v1/realtime?model=gpt-realtime-2.1" {
		t.Fatalf("openai url %q", openai.URL)
	}
	xai := c.Providers[commonv1.Provider_PROVIDER_XAI]
	if xai.URL != "wss://api.x.ai/v1/realtime?model=grok-voice-think-fast-2.0" || xai.DefaultVoice != "eve" {
		t.Fatalf("xai %+v", xai)
	}
	if c.OrchestratorAddr != "" {
		t.Fatal("the orchestrator is optional and off by default")
	}
}

func TestOrchestratorReusesTheVaultClientIdentity(t *testing.T) {
	env := base()
	env["GATEWAY_ORCHESTRATOR_ADDR"] = "orchestrator.internal:50054"
	c, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if c.OrchestratorServerName != "orchestrator.internal" || c.OrchestratorCA != "/etc/gw/ca.pem" ||
		c.OrchestratorCert != "/etc/gw/gw.pem" || c.OrchestratorKey != "/etc/gw/gw-key.pem" {
		t.Fatalf("orchestrator client: %+v", c)
	}
	if c.ToolTimeout.Seconds() != 30 {
		t.Fatalf("tool timeout %v", c.ToolTimeout)
	}
}

func TestUnsafeOrInvalidSettingsAreRefused(t *testing.T) {
	cases := map[string]map[string]string{
		"missing vault":         {"GATEWAY_VAULT_ADDR": ""},
		"public plaintext":      {"GATEWAY_LISTEN_ADDR": "0.0.0.0:8080"},
		"public admin":          {"GATEWAY_ADMIN_ADDR": "0.0.0.0:9091"},
		"plaintext provider":    {"GATEWAY_OPENAI_URL": "ws://api.openai.com/v1/realtime"},
		"unknown provider":      {"GATEWAY_PROVIDERS": "openai,gemini"},
		"default not enabled":   {"GATEWAY_PROVIDERS": "xai", "GATEWAY_DEFAULT_PROVIDER": "openai"},
		"half TLS":              {"GATEWAY_TLS_CERT": "/c.pem"},
		"bad duration":          {"GATEWAY_IDLE_TIMEOUT": "soon"},
		"session over provider": {"GATEWAY_MAX_SESSION_DURATION": "2h"},
		"limits inverted":       {"GATEWAY_MAX_SESSIONS": "2", "GATEWAY_MAX_SESSIONS_PER_TENANT": "5"},
		"orchestrator no port":  {"GATEWAY_ORCHESTRATOR_ADDR": "orchestrator.internal"},
		"endless tool calls":    {"GATEWAY_TOOL_TIMEOUT": "10m"},
		"vad out of range":      {"GATEWAY_VAD_SILENCE_MS": "50"},
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

func TestPlaintextBehindAProxyIsAnExplicitChoice(t *testing.T) {
	env := base()
	env["GATEWAY_LISTEN_ADDR"] = "0.0.0.0:8080"
	env["GATEWAY_ALLOW_PLAINTEXT"] = "true"
	if _, err := load(env); err != nil {
		t.Fatal(err)
	}
}

func TestLoopbackFakeProvidersMayUsePlainWebSocket(t *testing.T) {
	env := base()
	env["GATEWAY_OPENAI_URL"] = "ws://127.0.0.1:9900/v1/realtime"
	c, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.Providers[commonv1.Provider_PROVIDER_OPENAI].URL, "ws://127.0.0.1:9900") {
		t.Fatal("loopback URL not kept")
	}
}

func TestAllProblemsAreReportedTogether(t *testing.T) {
	_, err := load(map[string]string{})
	if err == nil || strings.Count(err.Error(), "is required") < 5 {
		t.Fatalf("expected every missing variable listed, got: %v", err)
	}
}
