"""Prometheus metrics, served on the admin listener at /metrics.

Labels never carry tenant or user ids, entity names or query text.
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram
from prometheus_client.metrics import MetricWrapperBase
from prometheus_client.process_collector import ProcessCollector


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        ProcessCollector(registry=self.registry)
        self.rpcs = Counter(
            "knowledge_rpcs_total",
            "gRPC calls handled, by method and status code.",
            ["method", "code"],
            registry=self.registry,
        )
        self.rpc_seconds = Histogram(
            "knowledge_rpc_seconds",
            "gRPC call duration, by method.",
            ["method"],
            buckets=(0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
            registry=self.registry,
        )
        self.retrieve_stage = Histogram(
            "knowledge_retrieve_stage_seconds",
            "Retrieve duration by stage (embed, vector, graph, pack).",
            ["stage"],
            buckets=(0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25),
            registry=self.registry,
        )
        self.stored = Counter(
            "knowledge_items_stored_total",
            "Items written by UpsertKnowledge, by kind.",
            ["kind"],
            registry=self.registry,
        )
        self.deleted = Counter(
            "knowledge_items_deleted_total",
            "Items deleted, by kind.",
            ["kind"],
            registry=self.registry,
        )

    def all(self) -> list[MetricWrapperBase]:
        return [self.rpcs, self.rpc_seconds, self.retrieve_stage, self.stored, self.deleted]
