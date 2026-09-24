// Package metrics defines the audit service's Prometheus metrics.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// Metrics are registered on their own registry.
type Metrics struct {
	Registry *prometheus.Registry
	// RPCs by method and status code.
	RPCs *prometheus.CounterVec
	// Events recorded, by source and outcome of the audited action.
	Recorded *prometheus.CounterVec
	// Events skipped because they were recorded before (retries).
	Duplicates *prometheus.CounterVec
	// Chain verifications by result (intact, broken).
	Verifications *prometheus.CounterVec
}

// New registers every metric on a fresh registry.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		RPCs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_rpcs_total", Help: "RPCs by method and status code.",
		}, []string{"method", "code"}),
		Recorded: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_events_recorded_total", Help: "Events recorded, by source service and outcome.",
		}, []string{"source", "outcome"}),
		Duplicates: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_events_duplicate_total", Help: "Events already recorded (retried), by source service.",
		}, []string{"source"}),
		Verifications: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_chain_verifications_total", Help: "Hash chain verifications by result.",
		}, []string{"result"}),
	}
	m.Registry.MustRegister(m.RPCs, m.Recorded, m.Duplicates, m.Verifications)
	return m
}
