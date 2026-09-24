// Package metrics holds the orchestrator's Prometheus metrics. Labels never
// carry tenant or user ids, tool arguments or text.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics are served on the admin listener at /metrics.
type Metrics struct {
	Registry *prometheus.Registry

	RPCs          *prometheus.CounterVec
	ToolCalls     *prometheus.CounterVec
	ToolSeconds   *prometheus.HistogramVec
	Confirmations *prometheus.CounterVec
	Tasks         *prometheus.CounterVec
	TaskSteps     prometheus.Histogram
	AgentSeconds  *prometheus.HistogramVec
	MemoryJobs    *prometheus.CounterVec
	Events        prometheus.Counter
}

// New registers every metric on a fresh registry.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		RPCs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orchestrator_rpcs_total", Help: "gRPC calls handled, by method and status code.",
		}, []string{"method", "code"}),
		ToolCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orchestrator_tool_calls_total", Help: "Tool calls by tool kind, caller (voice, task) and outcome.",
		}, []string{"kind", "caller", "outcome"}),
		ToolSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "orchestrator_tool_call_seconds", Help: "Tool call duration by tool kind.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 20},
		}, []string{"kind"}),
		Confirmations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orchestrator_confirmations_total", Help: "Confirmations by outcome (requested, confirmed, cancelled, refused, expired).",
		}, []string{"outcome"}),
		Tasks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orchestrator_tasks_total", Help: "Background tasks by final state.",
		}, []string{"state"}),
		TaskSteps: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "orchestrator_task_steps", Help: "Model steps per finished task.", Buckets: []float64{1, 2, 3, 5, 8, 12, 20},
		}),
		AgentSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "orchestrator_agent_call_seconds", Help: "Sidecar call duration by method.",
			Buckets: []float64{.25, .5, 1, 2, 4, 8, 15, 30, 60},
		}, []string{"method"}),
		MemoryJobs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orchestrator_memory_jobs_total", Help: "Conversation memory extractions by outcome.",
		}, []string{"outcome"}),
		Events: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "orchestrator_events_total", Help: "Events queued for conversations.",
		}),
	}
	m.Registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.RPCs, m.ToolCalls, m.ToolSeconds, m.Confirmations, m.Tasks, m.TaskSteps, m.AgentSeconds, m.MemoryJobs, m.Events)
	return m
}
