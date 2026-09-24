// Package metrics holds the router's Prometheus metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics are served on the admin listener at /metrics. Labels never carry
// tenant, user or tool names (unbounded cardinality, and they are data).
type Metrics struct {
	Registry *prometheus.Registry

	RPCs           *prometheus.CounterVec
	ToolCalls      *prometheus.CounterVec
	ToolCallTime   prometheus.Histogram
	ToolLists      *prometheus.CounterVec
	Authorizations *prometheus.CounterVec
	RateLimited    prometheus.Counter
}

// New registers every metric on a fresh registry.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		RPCs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcp_router_rpcs_total",
			Help: "gRPC calls handled, by method and status code.",
		}, []string{"method", "code"}),
		ToolCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcp_tool_calls_total",
			Help: "Tool calls, by outcome (ok, tool_error, or the failure reason).",
		}, []string{"outcome"}),
		ToolCallTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "mcp_tool_call_seconds",
			Help:    "Tool call duration, including connecting to the server when needed.",
			Buckets: []float64{.05, .1, .25, .5, 1, 2, 5, 10, 30, 60, 120},
		}),
		ToolLists: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcp_tool_lists_total",
			Help: "Per-integration tool list lookups, by source (cache, server, error).",
		}, []string{"source"}),
		Authorizations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcp_authorizations_total",
			Help: "OAuth authorizations, by stage (begin, complete) and result.",
		}, []string{"stage", "result"}),
		RateLimited: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcp_rate_limited_total",
			Help: "Tool calls refused by the rate limiter.",
		}),
	}
	m.Registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.RPCs, m.ToolCalls, m.ToolCallTime, m.ToolLists, m.Authorizations, m.RateLimited,
	)
	return m
}
