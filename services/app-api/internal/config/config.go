// Package config reads the app API's APP_* environment variables. Secrets
// may instead be given as a file path in <NAME>_FILE. Every problem is
// reported at once.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Config is the validated configuration.
type Config struct {
	// Public listener (Connect/gRPC over HTTPS) for the apps.
	PublicAddr     string
	PublicURL      string // how apps reach it, used in pairing links
	TLSCert        string
	TLSKey         string
	AllowPlaintext bool // behind a TLS-terminating proxy

	// Internal listener (gRPC + mTLS) for the dashboard backend.
	AdminAddr  string
	AdminCert  string
	AdminKey   string
	AdminCA    string
	Policy     string
	Reflection bool

	MetricsAddr string
	DatabaseURL string

	// Token signing: the voice gateway trusts the same key (JWKS).
	SigningKey     string
	SigningKeyID   string
	TokenIssuer    string
	AccessTokenTTL time.Duration
	RefreshIdleTTL time.Duration
	PairingCodeTTL time.Duration
	VoiceURL       string

	// The app API's identity towards the orchestrator
	// (spiffe://jarvis.local/app-api).
	OrchestratorAddr       string
	OrchestratorServerName string
	ClientCert             string
	ClientKey              string
	ClientCA               string
	// The audit service (optional), with the same client identity.
	AuditAddr       string
	AuditServerName string

	// APNs (optional, all or none): the team's auth key, its id, the team
	// id, and the app's bundle id. Without them no push notifications.
	APNsKeyFile string
	APNsKeyID   string
	APNsTeamID  string
	APNsTopic   string

	LogFormat string
	LogLevel  string
}

// PushEnabled reports whether APNs is configured.
func (c Config) PushEnabled() bool { return c.APNsKeyFile != "" }

// Lookup returns an environment variable's value and whether it is set.
type Lookup func(string) (string, bool)

// FromEnv reads the process environment.
func FromEnv() (Config, error) { return Load(os.LookupEnv) }

// Load builds a validated Config.
func Load(lookup Lookup) (Config, error) {
	r := &reader{lookup: lookup}
	c := Config{
		PublicAddr:     r.str("APP_PUBLIC_ADDR", "127.0.0.1:8081"),
		TLSCert:        r.str("APP_TLS_CERT", ""),
		TLSKey:         r.str("APP_TLS_KEY", ""),
		AllowPlaintext: r.boolean("APP_ALLOW_PLAINTEXT", false),

		AdminAddr:  r.str("APP_ADMIN_ADDR", "127.0.0.1:50055"),
		AdminCert:  r.required("APP_ADMIN_TLS_CERT"),
		AdminKey:   r.required("APP_ADMIN_TLS_KEY"),
		AdminCA:    r.required("APP_ADMIN_TLS_CLIENT_CA"),
		Policy:     r.required("APP_AUTHZ_POLICY"),
		Reflection: r.boolean("APP_REFLECTION", false),

		MetricsAddr: r.str("APP_METRICS_ADDR", "127.0.0.1:9096"),
		DatabaseURL: r.secret("APP_DATABASE_URL"),

		SigningKey:     r.required("APP_TOKEN_SIGNING_KEY"),
		SigningKeyID:   r.required("APP_TOKEN_KEY_ID"),
		TokenIssuer:    r.required("APP_TOKEN_ISSUER"),
		AccessTokenTTL: r.duration("APP_ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshIdleTTL: r.duration("APP_REFRESH_IDLE_TTL", 30*24*time.Hour),
		PairingCodeTTL: r.duration("APP_PAIRING_CODE_TTL", 10*time.Minute),
		VoiceURL:       r.required("APP_VOICE_URL"),

		OrchestratorAddr: r.required("APP_ORCHESTRATOR_ADDR"),
		ClientCert:       r.required("APP_CLIENT_CERT"),
		ClientKey:        r.required("APP_CLIENT_KEY"),
		ClientCA:         r.required("APP_CLIENT_CA"),
		AuditAddr:        r.str("APP_AUDIT_ADDR", ""),

		APNsKeyFile: r.str("APP_APNS_KEY_FILE", ""),
		APNsKeyID:   r.str("APP_APNS_KEY_ID", ""),
		APNsTeamID:  r.str("APP_APNS_TEAM_ID", ""),
		APNsTopic:   r.str("APP_APNS_TOPIC", ""),

		LogFormat: r.str("APP_LOG_FORMAT", "json"),
		LogLevel:  r.str("APP_LOG_LEVEL", "info"),
	}
	c.PublicURL = strings.TrimRight(r.str("APP_PUBLIC_URL", "http://"+c.PublicAddr), "/")
	c.OrchestratorServerName = r.str("APP_ORCHESTRATOR_SERVER_NAME", hostOf(c.OrchestratorAddr))
	c.AuditServerName = r.str("APP_AUDIT_SERVER_NAME", hostOf(c.AuditAddr))

	if (c.TLSCert == "") != (c.TLSKey == "") {
		r.fail("APP_TLS_CERT and APP_TLS_KEY must be set together")
	}
	if c.TLSCert == "" && !isLoopback(hostOf(c.PublicAddr)) && !c.AllowPlaintext {
		r.fail("APP_PUBLIC_ADDR %s is not loopback: configure APP_TLS_CERT/KEY, or set APP_ALLOW_PLAINTEXT=true "+
			"only behind a TLS-terminating proxy", c.PublicAddr)
	}
	if !isLoopback(hostOf(c.MetricsAddr)) {
		r.fail("APP_METRICS_ADDR must be a loopback address (metrics are not public)")
	}
	checkURL(r, "APP_PUBLIC_URL", c.PublicURL, "https", "http")
	checkURL(r, "APP_VOICE_URL", c.VoiceURL, "wss", "ws")
	switch {
	case c.AccessTokenTTL < time.Minute || c.AccessTokenTTL > time.Hour:
		r.fail("APP_ACCESS_TOKEN_TTL must be 1m to 1h (the voice gateway accepts at most 1h)")
	case c.RefreshIdleTTL < time.Hour || c.RefreshIdleTTL > 365*24*time.Hour:
		r.fail("APP_REFRESH_IDLE_TTL must be 1h to 8760h")
	case c.PairingCodeTTL < time.Minute || c.PairingCodeTTL > time.Hour:
		r.fail("APP_PAIRING_CODE_TTL must be 1m to 1h")
	}
	apns := []string{c.APNsKeyFile, c.APNsKeyID, c.APNsTeamID, c.APNsTopic}
	if set := len(slices.DeleteFunc(slices.Clone(apns), func(v string) bool { return v == "" })); set != 0 && set != 4 {
		r.fail("APP_APNS_KEY_FILE, APP_APNS_KEY_ID, APP_APNS_TEAM_ID and APP_APNS_TOPIC go together")
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		r.fail("APP_LOG_FORMAT must be json or text")
	}
	return c, r.err()
}

// checkURL requires `secure` except for loopback hosts, where `plain` is
// allowed (development): tokens and pairing codes travel on these URLs.
func checkURL(r *reader, name, raw, secure, plain string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != secure && u.Scheme != plain) {
		r.fail("%s must be a %s:// URL", name, secure)
		return
	}
	if u.Scheme == plain && !isLoopback(u.Hostname()) {
		r.fail("%s must use %s:// (tokens must not travel in plaintext)", name, secure)
	}
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

func (r *reader) duration(name string, fallback time.Duration) time.Duration {
	value := r.str(name, "")
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		r.fail("%s must be a duration such as 15m", name)
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
