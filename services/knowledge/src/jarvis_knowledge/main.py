"""jarvis-knowledge: the knowledge graph and retrieval service."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from collections.abc import Awaitable, Callable

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc
from grpc_health.v1.health import aio as health_aio  # type: ignore[attr-defined]  # typeshed lacks the aio module
from grpc_reflection.v1alpha import reflection
from jarvis.knowledge.v1 import knowledge_pb2_grpc as pb_grpc
from neo4j import AsyncGraphDatabase
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from qdrant_client import AsyncQdrantClient

from jarvis_knowledge import config as config_module
from jarvis_knowledge import logs
from jarvis_knowledge.authz import Policy
from jarvis_knowledge.embedding import AsyncEmbedder, Embedder, ensure_model
from jarvis_knowledge.graph import Graph
from jarvis_knowledge.interceptor import Interceptor
from jarvis_knowledge.metrics import Metrics
from jarvis_knowledge.retrieval import Retriever
from jarvis_knowledge.service import METHODS, SERVICE, KnowledgeService
from jarvis_knowledge.vectors import Vectors

log = logging.getLogger("jarvis_knowledge")

SHUTDOWN_GRACE = 15.0
MAX_MESSAGE_BYTES = 8 << 20  # an upsert of 200 passages of 8000 characters


def main() -> None:
    try:
        cfg = config_module.load()
    except config_module.ConfigError as e:
        print(f"jarvis-knowledge: {e}", file=sys.stderr)
        sys.exit(1)
    logs.configure(cfg.log_format, cfg.log_level)
    try:
        asyncio.run(serve(cfg))
    except Exception:
        log.exception("knowledge service failed")
        sys.exit(1)
    log.info("knowledge service stopped")


async def serve(cfg: config_module.Config) -> None:
    metrics = Metrics()
    policy = Policy.load(cfg.authz_policy, METHODS)

    model_dir = await asyncio.to_thread(ensure_model, cfg.model, cfg.model_dir, download=cfg.model_download)
    embedder = AsyncEmbedder(
        Embedder(cfg.model, model_dir, threads=cfg.embed_threads), concurrency=cfg.embed_concurrency
    )
    await embedder.query("warm up")  # the first inference allocates buffers

    driver = AsyncGraphDatabase.driver(
        cfg.neo4j_uri,
        auth=(cfg.neo4j_user, cfg.neo4j_password),
        connection_timeout=5.0,
        connection_acquisition_timeout=5.0,
        max_transaction_retry_time=5.0,
    )
    qdrant = AsyncQdrantClient(
        url=cfg.qdrant_url, api_key=cfg.qdrant_api_key, prefer_grpc=True, grpc_port=cfg.qdrant_grpc_port, timeout=10
    )
    try:
        graph = Graph(driver, cfg.neo4j_database)
        await graph.ping()
        await graph.ensure_schema()
        vectors = Vectors(qdrant, cfg.qdrant_collection)
        await vectors.ensure_collection(embedder.dimensions)

        retriever = Retriever(embedder, vectors, graph, metrics, min_score=cfg.min_score, margin=cfg.margin)
        await _run(
            cfg,
            policy=policy,
            metrics=metrics,
            service=KnowledgeService(graph, vectors, embedder, retriever, metrics),
            ready=lambda: asyncio.gather(graph.ping(), vectors.ping()),
            model=embedder.model,
        )
    finally:
        await driver.close()
        await qdrant.close()


async def _run(
    cfg: config_module.Config,
    *,
    policy: Policy,
    metrics: Metrics,
    service: KnowledgeService,
    ready: Callable[[], Awaitable[object]],
    model: str,
) -> None:
    server = grpc.aio.server(
        interceptors=[Interceptor(SERVICE, policy, metrics)],
        options=[
            ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
            ("grpc.keepalive_permit_without_calls", 1),
            ("grpc.http2.min_ping_interval_without_data_ms", 10_000),
        ],
    )
    pb_grpc.add_KnowledgeServiceServicer_to_server(service, server)
    health = health_aio.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health, server)
    await health.set(SERVICE, health_pb2.HealthCheckResponse.SERVING)
    if cfg.reflection:
        reflection.enable_server_reflection(
            [SERVICE, health_pb2.DESCRIPTOR.services_by_name["Health"].full_name, reflection.SERVICE_NAME], server
        )
    credentials = grpc.ssl_server_credentials(
        [(cfg.tls_key.read_bytes(), cfg.tls_cert.read_bytes())],
        root_certificates=cfg.tls_client_ca.read_bytes(),
        require_client_auth=True,
    )
    server.add_secure_port(cfg.listen_addr, credentials)
    await server.start()
    admin = await _start_admin(cfg.admin_addr, metrics, ready)
    log.info(
        "knowledge service listening",
        extra={
            "addr": cfg.listen_addr,
            "admin_addr": cfg.admin_addr,
            "principals": len(policy),
            "model": model,
            "neo4j": cfg.neo4j_uri,
            "qdrant": cfg.qdrant_url,
            "collection": cfg.qdrant_collection,
            "min_score": cfg.min_score,
            "margin": cfg.margin,
            "reflection": cfg.reflection,
        },
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    log.info("shutdown requested")
    await health.enter_graceful_shutdown()
    admin.close()
    await server.stop(SHUTDOWN_GRACE)
    await admin.wait_closed()


async def _start_admin(addr: str, metrics: Metrics, ready: Callable[[], Awaitable[object]]) -> asyncio.Server:
    """A minimal loopback HTTP server: GET /metrics and GET /healthz."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await asyncio.wait_for(reader.readline(), timeout=5)
            while (await asyncio.wait_for(reader.readline(), timeout=5)) not in (b"\r\n", b"\n", b""):
                pass
            method, _, rest = request.decode("latin-1").partition(" ")
            path = rest.partition(" ")[0]
            status, content_type, body = "404 Not Found", "text/plain", b"not found\n"
            if method == "GET" and path == "/metrics":
                status, content_type, body = "200 OK", CONTENT_TYPE_LATEST, generate_latest(metrics.registry)
            elif method == "GET" and path == "/healthz":
                try:
                    await asyncio.wait_for(ready(), timeout=2)
                    status, body = "200 OK", b"ok\n"
                except Exception:  # noqa: BLE001 - any failure means not ready
                    status, body = "503 Service Unavailable", b"stores unavailable\n"
            writer.write(
                f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n".encode()
                + body
            )
            await writer.drain()
        except TimeoutError, ConnectionError:
            pass
        finally:
            writer.close()

    host, _, port = addr.rpartition(":")
    return await asyncio.start_server(handle, host.strip("[]"), int(port))


if __name__ == "__main__":
    main()
