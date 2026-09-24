// Package metrics holds the app API's Prometheus metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics are served on the loopback metrics listener at /metrics.
type Metrics struct {
	Registry *prometheus.Registry

	RPCs       *prometheus.CounterVec
	RPCSeconds *prometheus.HistogramVec
	Pairings   *prometheus.CounterVec
	Refreshes  *prometheus.CounterVec
	Revoked    *prometheus.CounterVec
	Limited    *prometheus.CounterVec
	Pushes     *prometheus.CounterVec
}

// New registers every metric on a fresh registry.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		RPCs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "app_api_rpcs_total",
			Help: "RPCs by procedure and status code (public and admin).",
		}, []string{"procedure", "code"}),
		RPCSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "app_api_rpc_seconds",
			Help:    "RPC duration by procedure.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5},
		}, []string{"procedure"}),
		Pairings: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "app_api_pairings_total",
			Help: "Pairing codes issued and redeemed (issued, paired, invalid).",
		}, []string{"outcome"}),
		Refreshes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "app_api_refreshes_total",
			Help: "Session refreshes (rotated, retried, reused, ended). `reused` means a copied refresh token.",
		}, []string{"outcome"}),
		Revoked: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "app_api_sessions_revoked_total",
			Help: "Sessions ended, by reason.",
		}, []string{"reason"}),
		Limited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "app_api_rate_limited_total",
			Help: "Requests refused by the per-address rate limit, by procedure.",
		}, []string{"procedure"}),
		Pushes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "app_api_pushes_total",
			Help: "Push notifications by kind and outcome (sent, no_device, unregistered, failed).",
		}, []string{"kind", "outcome"}),
	}
	m.Registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.RPCs, m.RPCSeconds, m.Pairings, m.Refreshes, m.Revoked, m.Limited, m.Pushes,
	)
	return m
}
