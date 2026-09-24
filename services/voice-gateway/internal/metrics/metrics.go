// Package metrics holds the gateway's Prometheus metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics are served on the admin listener at /metrics.
type Metrics struct {
	Registry *prometheus.Registry

	SessionsActive  *prometheus.GaugeVec
	SessionsEnded   *prometheus.CounterVec
	AudioBytes      *prometheus.CounterVec
	ProviderConnect *prometheus.HistogramVec
	ResponseLatency *prometheus.HistogramVec
	ForwardLatency  prometheus.Histogram
	Errors          *prometheus.CounterVec

	ToolCalls          *prometheus.CounterVec
	ToolSeconds        prometheus.Histogram
	Notices            prometheus.Counter
	OrchestratorErrors *prometheus.CounterVec
}

// New registers every metric on a fresh registry.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		SessionsActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "voice_sessions_active",
			Help: "Voice sessions currently open.",
		}, []string{"provider"}),
		SessionsEnded: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "voice_sessions_ended_total",
			Help: "Voice sessions that ended, by provider and reason.",
		}, []string{"provider", "reason"}),
		AudioBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "voice_audio_bytes_total",
			Help: "PCM audio bytes relayed (in: from clients, out: to clients).",
		}, []string{"direction"}),
		ProviderConnect: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "voice_provider_connect_seconds",
			Help:    "Time to open and configure a provider session.",
			Buckets: []float64{.05, .1, .2, .3, .5, .75, 1, 2, 5},
		}, []string{"provider"}),
		ResponseLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "voice_response_latency_seconds",
			Help:    "From the end of the user's speech to the first audio sent back.",
			Buckets: []float64{.1, .2, .3, .4, .5, .75, 1, 1.5, 2, 3},
		}, []string{"provider"}),
		ForwardLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "voice_gateway_forward_seconds",
			Help:    "Gateway overhead: provider audio received to written to the client.",
			Buckets: []float64{.0005, .001, .002, .005, .01, .02, .05, .1},
		}),
		Errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "voice_errors_total",
			Help: "Errors reported to clients, by code.",
		}, []string{"code"}),
		ToolCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "voice_tool_calls_total",
			Help: "Function calls of the realtime model (ok, tool_error: the tool reported a failure, " +
				"failed: the orchestrator could not be reached, busy: too many calls at once).",
		}, []string{"outcome"}),
		ToolSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "voice_tool_call_seconds",
			Help:    "From the model's function call to its result.",
			Buckets: []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		}),
		Notices: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "voice_notices_total",
			Help: "Orchestrator events (task results, questions) put into conversations.",
		}),
		OrchestratorErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "voice_orchestrator_errors_total",
			Help: "Failed orchestrator calls, by RPC.",
		}, []string{"rpc"}),
	}
	m.Registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.SessionsActive, m.SessionsEnded, m.AudioBytes, m.ProviderConnect,
		m.ResponseLatency, m.ForwardLatency, m.Errors,
		m.ToolCalls, m.ToolSeconds, m.Notices, m.OrchestratorErrors,
	)
	return m
}
