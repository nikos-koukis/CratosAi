// Package config reads the audit service's AUDIT_* environment variables.
// The database URL may instead be given as a file path in
// AUDIT_DATABASE_URL_FILE. Every problem is reported at once.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Config is the validated configuration.
type Config struct {
	// gRPC listener, mutual TLS only.
	ListenAddr string
	TLSCert    string
	TLSKey     string
	ClientCA   string
	Policy     string
	Reflection bool

	// Prometheus metrics and health; loopback only.
	MetricsAddr string
	DatabaseURL string

	LogFormat string
	LogLevel  string
}

// Lookup reads one environment variable.
type Lookup func(string) (string, bool)

// FromEnv reads the process environment.
func FromEnv() (Config, error) { return Load(os.LookupEnv) }

// Load reads and checks the configuration.
func Load(lookup Lookup) (Config, error) {
	r := &reader{lookup: lookup}
	c := Config{
		ListenAddr:  r.str("AUDIT_LISTEN_ADDR", "127.0.0.1:50056"),
		TLSCert:     r.required("AUDIT_TLS_CERT"),
		TLSKey:      r.required("AUDIT_TLS_KEY"),
		ClientCA:    r.required("AUDIT_TLS_CLIENT_CA"),
		Policy:      r.required("AUDIT_AUTHZ_POLICY"),
		Reflection:  r.boolean("AUDIT_REFLECTION", false),
		MetricsAddr: r.str("AUDIT_METRICS_ADDR", "127.0.0.1:9097"),
		DatabaseURL: r.secret("AUDIT_DATABASE_URL"),
		LogFormat:   r.str("AUDIT_LOG_FORMAT", "json"),
		LogLevel:    r.str("AUDIT_LOG_LEVEL", "info"),
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		r.fail("AUDIT_LISTEN_ADDR must be host:port")
	}
	if host, _, err := net.SplitHostPort(c.MetricsAddr); err != nil || !isLoopback(host) {
		r.fail("AUDIT_METRICS_ADDR must be a loopback host:port (metrics are not authenticated)")
	}
	if !slices.Contains([]string{"json", "text"}, c.LogFormat) {
		r.fail("AUDIT_LOG_FORMAT must be json or text")
	}
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, c.LogLevel) {
		r.fail("AUDIT_LOG_LEVEL must be debug, info, warn or error")
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

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
