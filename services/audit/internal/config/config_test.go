package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func env(values map[string]string) Lookup {
	return func(name string) (string, bool) {
		v, ok := values[name]
		return v, ok
	}
}

var minimal = map[string]string{
	"AUDIT_TLS_CERT":      "server.pem",
	"AUDIT_TLS_KEY":       "server-key.pem",
	"AUDIT_TLS_CLIENT_CA": "ca.pem",
	"AUDIT_AUTHZ_POLICY":  "authz.toml",
	"AUDIT_DATABASE_URL":  "postgres://audit:secret-password@127.0.0.1/audit",
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != "127.0.0.1:50056" || c.MetricsAddr != "127.0.0.1:9097" || c.LogFormat != "json" {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestEveryProblemAtOnceWithoutSecrets(t *testing.T) {
	values := map[string]string{
		"AUDIT_METRICS_ADDR": "0.0.0.0:9097",
		"AUDIT_LOG_FORMAT":   "xml",
		"AUDIT_DATABASE_URL": "postgres://audit:secret-password@db/audit",
	}
	_, err := Load(env(values))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"AUDIT_TLS_CERT", "AUDIT_AUTHZ_POLICY", "AUDIT_METRICS_ADDR", "AUDIT_LOG_FORMAT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %s in %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "secret-password") {
		t.Fatal("a secret leaked into the error")
	}
}

func TestDatabaseURLFromFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "url")
	if err := os.WriteFile(file, []byte("postgres://from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for k, v := range minimal {
		values[k] = v
	}
	delete(values, "AUDIT_DATABASE_URL")
	values["AUDIT_DATABASE_URL_FILE"] = file
	c, err := Load(env(values))
	if err != nil || c.DatabaseURL != "postgres://from-file" {
		t.Fatalf("%v %q", err, c.DatabaseURL)
	}
	values["AUDIT_DATABASE_URL"] = "postgres://inline"
	if _, err := Load(env(values)); err == nil {
		t.Fatal("both inline and file accepted")
	}
}
