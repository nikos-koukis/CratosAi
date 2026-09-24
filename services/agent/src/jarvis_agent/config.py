"""The sidecar's AGENT_* environment variables. Every problem is reported at once."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

# sockaddr_un.sun_path is 104 bytes on macOS (108 on Linux), including the NUL.
MAX_SOCKET_PATH = 103


class ConfigError(Exception):
    """The configuration is invalid; the message lists every problem."""


@dataclass(frozen=True, slots=True)
class Config:
    # Unix domain socket shared with the orchestrator (mode 0600).
    socket: Path
    admin_addr: str
    openai_base_url: str
    xai_base_url: str
    request_timeout: float
    max_retries: int
    max_concurrency: int
    log_format: str
    log_level: str


def load(env: Mapping[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    errors: list[str] = []

    def number(name: str, default: float, low: float, high: float) -> float:
        raw = env.get(name, "")
        if not raw:
            return default
        try:
            value = float(raw)
        except ValueError:
            errors.append(f"{name} must be a number")
            return default
        if not low <= value <= high:
            errors.append(f"{name} must be between {low:g} and {high:g}")
        return value

    def choice(name: str, default: str, allowed: set[str]) -> str:
        value = env.get(name) or default
        if value not in allowed:
            errors.append(f"{name} must be one of {', '.join(sorted(allowed))}")
        return value

    socket = env.get("AGENT_SOCKET", "")
    if not socket:
        errors.append("AGENT_SOCKET is required (a Unix socket path shared with the orchestrator)")
    elif len(socket.encode()) > MAX_SOCKET_PATH:
        errors.append(f"AGENT_SOCKET must be at most {MAX_SOCKET_PATH} bytes (a Unix socket limit)")
    config = Config(
        socket=Path(socket),
        admin_addr=env.get("AGENT_ADMIN_ADDR") or "127.0.0.1:9095",
        openai_base_url=env.get("AGENT_OPENAI_BASE_URL") or "https://api.openai.com/v1",
        xai_base_url=env.get("AGENT_XAI_BASE_URL") or "https://api.x.ai/v1",
        request_timeout=number("AGENT_REQUEST_TIMEOUT_SECONDS", 90, 1, 600),
        max_retries=int(number("AGENT_MAX_RETRIES", 2, 0, 5)),
        max_concurrency=int(number("AGENT_MAX_CONCURRENCY", 32, 1, 1024)),
        log_format=choice("AGENT_LOG_FORMAT", "json", {"json", "text"}),
        log_level=choice("AGENT_LOG_LEVEL", "info", {"debug", "info", "warning", "error"}),
    )
    host = config.admin_addr.rpartition(":")[0].strip("[]")
    if not _loopback(host):
        errors.append("AGENT_ADMIN_ADDR must be a loopback address (metrics are not public)")
    for name, url in (("AGENT_OPENAI_BASE_URL", config.openai_base_url), ("AGENT_XAI_BASE_URL", config.xai_base_url)):
        parsed = urlsplit(url)
        # Provider keys travel in these requests: https only, except to a
        # local fake provider in development.
        if not parsed.hostname or not (
            parsed.scheme == "https" or (parsed.scheme == "http" and _loopback(parsed.hostname))
        ):
            errors.append(f"{name} must be an https:// URL (http:// only on this machine)")
    if errors:
        raise ConfigError("invalid configuration:\n  " + "\n  ".join(errors))
    return config


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
