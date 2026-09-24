"""jarvis-agent: the orchestrator's LLM sidecar, on a Unix socket."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import sys
from pathlib import Path

import grpc
import httpx2
from grpc_health.v1 import health_pb2, health_pb2_grpc
from grpc_health.v1.health import aio as health_aio  # type: ignore[attr-defined]  # typeshed lacks the aio module
from jarvis.agent.v1 import agent_pb2
from jarvis.agent.v1 import agent_pb2_grpc as pb_grpc
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from jarvis_agent import config as config_module
from jarvis_agent import logs
from jarvis_agent.providers import Providers
from jarvis_agent.service import AgentWorker, Metrics

log = logging.getLogger("jarvis_agent")

SERVICE = agent_pb2.DESCRIPTOR.services_by_name["AgentWorkerService"].full_name
MAX_MESSAGE_BYTES = 16 << 20  # long histories and transcripts


def main() -> None:
    try:
        cfg = config_module.load()
    except config_module.ConfigError as e:
        print(f"jarvis-agent: {e}", file=sys.stderr)
        sys.exit(1)
    logs.configure(cfg.log_format, cfg.log_level)
    try:
        asyncio.run(serve(cfg))
    except Exception:
        log.exception("agent sidecar failed")
        sys.exit(1)
    log.info("agent sidecar stopped")


async def start(cfg: config_module.Config, http: httpx2.AsyncClient, metrics: Metrics) -> grpc.aio.Server:
    """Binds the socket with mode 0600: only the orchestrator's user can connect."""
    providers = Providers(cfg.openai_base_url, cfg.xai_base_url, cfg.request_timeout, cfg.max_retries, http)
    server = grpc.aio.server(
        options=[
            ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
            ("grpc.max_send_message_length", MAX_MESSAGE_BYTES),
        ],
        maximum_concurrent_rpcs=cfg.max_concurrency,
    )
    pb_grpc.add_AgentWorkerServiceServicer_to_server(AgentWorker(providers, metrics), server)
    health = health_aio.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health, server)
    await health.set(SERVICE, health_pb2.HealthCheckResponse.SERVING)
    cfg.socket.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with contextlib.suppress(FileNotFoundError):
        cfg.socket.unlink()  # a stale socket from a previous run
    previous = os.umask(0o177)
    try:
        server.add_insecure_port(f"unix:{cfg.socket}")
        await server.start()
    finally:
        os.umask(previous)
    cfg.socket.chmod(0o600)
    return server


async def serve(cfg: config_module.Config) -> None:
    metrics = Metrics()
    async with httpx2.AsyncClient(limits=httpx2.Limits(max_connections=100, max_keepalive_connections=20)) as http:
        server = await start(cfg, http, metrics)
        admin = await _start_admin(cfg.admin_addr, metrics)
        log.info(
            "agent sidecar listening",
            extra={
                "socket": str(cfg.socket),
                "admin_addr": cfg.admin_addr,
                "openai": cfg.openai_base_url,
                "xai": cfg.xai_base_url,
            },
        )
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        await stop.wait()
        log.info("shutdown requested")
        admin.close()
        await server.stop(30)
        await admin.wait_closed()
        _remove(cfg.socket)


def _remove(socket: Path) -> None:
    socket.unlink(missing_ok=True)


async def _start_admin(addr: str, metrics: Metrics) -> asyncio.Server:
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
                status, body = "200 OK", b"ok\n"
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
