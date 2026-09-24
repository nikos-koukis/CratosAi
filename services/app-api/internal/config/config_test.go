package config

import (
	"strings"
	"testing"
	"time"
)

func base() map[string]string {
	return map[string]string{
		"APP_ADMIN_TLS_CERT":      "/certs/server.pem",
		"APP_ADMIN_TLS_KEY":       "/certs/server-key.pem",
		"APP_ADMIN_TLS_CLIENT_CA": "/certs/ca.pem",
		"APP_AUTHZ_POLICY":        "/config/authz.toml",
		"APP_DATABASE_URL":        "postgres://app@db/app",
		"APP_TOKEN_SIGNING_KEY":   "/keys/signing.pem",
		"APP_TOKEN_KEY_ID":        "k1",
		"APP_TOKEN_ISSUER":        "https://id.jarvis.test",
		"APP_VOICE_URL":           "wss://voice.jarvis.test/v1/voice",
		"APP_ORCHESTRATOR_ADDR":   "orchestrator.internal:50054",
		"APP_CLIENT_CERT":         "/certs/app-api.pem",
		"APP_CLIENT_KEY":          "/certs/app-api-key.pem",
		"APP_CLIENT_CA":           "/certs/ca.pem",
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
	if c.PublicURL != "http://127.0.0.1:8081" || c.AccessTokenTTL != 15*time.Minute ||
		c.RefreshIdleTTL != 30*24*time.Hour || c.PairingCodeTTL != 10*time.Minute {
		t.Fatalf("defaults: %+v", c)
	}
	if c.OrchestratorServerName != "orchestrator.internal" {
		t.Fatalf("server name %q", c.OrchestratorServerName)
	}
}

func TestUnsafeOrInvalidSettingsAreRefused(t *testing.T) {
	cases := map[string]map[string]string{
		"public plaintext":      {"APP_PUBLIC_ADDR": "0.0.0.0:8081"},
		"public metrics":        {"APP_METRICS_ADDR": "0.0.0.0:9096"},
		"half TLS":              {"APP_TLS_CERT": "/c.pem"},
		"plaintext voice url":   {"APP_VOICE_URL": "ws://voice.jarvis.test/v1/voice"},
		"plaintext public url":  {"APP_PUBLIC_URL": "http://api.jarvis.test"},
		"not a url":             {"APP_PUBLIC_URL": "api.jarvis.test"},
		"long access tokens":    {"APP_ACCESS_TOKEN_TTL": "2h"},
		"short refresh":         {"APP_REFRESH_IDLE_TTL": "5m"},
		"endless pairing codes": {"APP_PAIRING_CODE_TTL": "24h"},
		"missing signing key":   {"APP_TOKEN_SIGNING_KEY": ""},
		"two database urls":     {"APP_DATABASE_URL_FILE": "/run/secrets/db"},
		"half of APNs":          {"APP_APNS_KEY_FILE": "/keys/AuthKey.p8", "APP_APNS_KEY_ID": "ABCDE12345"},
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

func TestLoopbackDevelopmentURLsAreAllowed(t *testing.T) {
	env := base()
	env["APP_VOICE_URL"] = "ws://127.0.0.1:8080/v1/voice"
	env["APP_PUBLIC_URL"] = "http://localhost:8081/"
	c, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "http://localhost:8081" {
		t.Fatalf("trailing slash kept: %q", c.PublicURL)
	}
}

func TestAllProblemsAreReportedTogether(t *testing.T) {
	_, err := load(map[string]string{})
	if err == nil || strings.Count(err.Error(), "\n") < 10 {
		t.Fatalf("expected every missing variable, got %v", err)
	}
}
