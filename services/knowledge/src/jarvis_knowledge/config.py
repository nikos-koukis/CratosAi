"""The service's KNOWLEDGE_* environment variables.

Secrets may instead be given as a file path in <NAME>_FILE. Every problem is
reported at once.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from jarvis_knowledge.embedding import MODELS, ModelSpec

# E5 similarities are compressed into roughly 0.7-0.9: below the floor a
# match is rarely relevant, and relevant matches stand out from the rest of a
# query's results by more than the margin (measured on mixed Greek/English
# notes).
DEFAULT_MIN_SCORES = {"intfloat/multilingual-e5-small": 0.78}
DEFAULT_MARGINS = {"intfloat/multilingual-e5-small": 0.04}


class ConfigError(Exception):
    """The configuration is invalid; the message lists every problem."""


@dataclass(frozen=True, slots=True)
class Config:
    listen_addr: str
    admin_addr: str
    tls_cert: Path
    tls_key: Path
    tls_client_ca: Path
    authz_policy: Path
    reflection: bool

    neo4j_uri: str
    neo4j_user: str
    neo4j_password: str
    neo4j_database: str

    qdrant_url: str
    qdrant_grpc_port: int
    qdrant_api_key: str
    qdrant_collection: str

    model: ModelSpec
    model_dir: Path
    model_download: bool
    embed_threads: int
    embed_concurrency: int
    min_score: float
    margin: float

    log_format: str
    log_level: str


def load(env: Mapping[str, str] | None = None) -> Config:
    r = _Reader(os.environ if env is None else env)
    model_name = r.text("KNOWLEDGE_MODEL", "intfloat/multilingual-e5-small")
    model = MODELS.get(model_name)
    if model is None:
        r.fail(f"KNOWLEDGE_MODEL must be one of {', '.join(sorted(MODELS))}")
    config = Config(
        listen_addr=r.text("KNOWLEDGE_LISTEN_ADDR", "127.0.0.1:50053"),
        admin_addr=r.text("KNOWLEDGE_ADMIN_ADDR", "127.0.0.1:9093"),
        tls_cert=Path(r.required("KNOWLEDGE_TLS_CERT")),
        tls_key=Path(r.required("KNOWLEDGE_TLS_KEY")),
        tls_client_ca=Path(r.required("KNOWLEDGE_TLS_CLIENT_CA")),
        authz_policy=Path(r.required("KNOWLEDGE_AUTHZ_POLICY")),
        reflection=r.boolean("KNOWLEDGE_REFLECTION", default=False),
        neo4j_uri=r.text("KNOWLEDGE_NEO4J_URI", "bolt://127.0.0.1:57687"),
        neo4j_user=r.text("KNOWLEDGE_NEO4J_USER", "neo4j"),
        neo4j_password=r.secret("KNOWLEDGE_NEO4J_PASSWORD", required=True),
        neo4j_database=r.text("KNOWLEDGE_NEO4J_DATABASE", "neo4j"),
        qdrant_url=r.text("KNOWLEDGE_QDRANT_URL", "http://127.0.0.1:56333"),
        qdrant_grpc_port=r.integer("KNOWLEDGE_QDRANT_GRPC_PORT", 56334, low=1, high=65535),
        qdrant_api_key=r.secret("KNOWLEDGE_QDRANT_API_KEY", required=True),
        qdrant_collection=r.text("KNOWLEDGE_QDRANT_COLLECTION", "jarvis_knowledge"),
        model=model or next(iter(MODELS.values())),
        model_dir=Path(r.required("KNOWLEDGE_MODEL_DIR")),
        model_download=r.boolean("KNOWLEDGE_MODEL_DOWNLOAD", default=False),
        embed_threads=r.integer("KNOWLEDGE_EMBED_THREADS", 4, low=1, high=64),
        embed_concurrency=r.integer("KNOWLEDGE_EMBED_CONCURRENCY", 2, low=1, high=64),
        min_score=r.number("KNOWLEDGE_MIN_SCORE", DEFAULT_MIN_SCORES.get(model_name, 0.0), low=0.0, high=1.0),
        margin=r.number("KNOWLEDGE_RELEVANCE_MARGIN", DEFAULT_MARGINS.get(model_name, 1.0), low=0.0, high=1.0),
        log_format=r.choice("KNOWLEDGE_LOG_FORMAT", "json", {"json", "text"}),
        log_level=r.choice("KNOWLEDGE_LOG_LEVEL", "info", {"debug", "info", "warning", "error"}),
    )
    if not _is_loopback(_host(config.admin_addr)):
        r.fail("KNOWLEDGE_ADMIN_ADDR must be a loopback address (metrics are not public)")
    # Credentials must never cross a network in plaintext.
    neo4j = urlsplit(config.neo4j_uri)
    if neo4j.scheme not in {"bolt", "bolt+s", "neo4j", "neo4j+s"} or not neo4j.hostname:
        r.fail("KNOWLEDGE_NEO4J_URI must be a bolt://, bolt+s://, neo4j:// or neo4j+s:// URI")
    elif not neo4j.scheme.endswith("+s") and not _is_loopback(neo4j.hostname):
        r.fail("KNOWLEDGE_NEO4J_URI must use bolt+s:// or neo4j+s:// unless Neo4j is on this machine")
    qdrant = urlsplit(config.qdrant_url)
    if qdrant.scheme not in {"http", "https"} or not qdrant.hostname:
        r.fail("KNOWLEDGE_QDRANT_URL must be an http:// or https:// URL")
    elif qdrant.scheme != "https" and not _is_loopback(qdrant.hostname):
        r.fail("KNOWLEDGE_QDRANT_URL must use https:// unless Qdrant is on this machine")
    r.raise_if_failed()
    return config


def _host(addr: str) -> str:
    host, _, _ = addr.rpartition(":")
    return host.strip("[]")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _Reader:
    def __init__(self, env: Mapping[str, str]) -> None:
        self._env = env
        self._errors: list[str] = []

    def fail(self, message: str) -> None:
        self._errors.append(message)

    def raise_if_failed(self) -> None:
        if self._errors:
            raise ConfigError("invalid configuration:\n  " + "\n  ".join(self._errors))

    def text(self, name: str, default: str) -> str:
        return self._env.get(name) or default

    def required(self, name: str) -> str:
        value = self._env.get(name, "")
        if not value:
            self.fail(f"{name} is required")
        return value

    def secret(self, name: str, *, required: bool) -> str:
        inline, file = self._env.get(name, ""), self._env.get(f"{name}_FILE", "")
        if inline and file:
            self.fail(f"{name} and {name}_FILE are both set; use one")
            return ""
        if file:
            try:
                return Path(file).read_text().rstrip("\r\n")
            except OSError as e:
                self.fail(f"{name}_FILE: {e.strerror}")
                return ""
        if not inline and required:
            self.fail(f"{name} or {name}_FILE is required")
        return inline

    def boolean(self, name: str, *, default: bool) -> bool:
        value = self._env.get(name, "").lower()
        if not value:
            return default
        if value in {"1", "true", "yes"}:
            return True
        if value in {"0", "false", "no"}:
            return False
        self.fail(f"{name} must be true or false")
        return default

    def _parsed[T: (int, float)](
        self, name: str, default: T, parse: Callable[[str], T], *, low: T, high: T, kind: str
    ) -> T:
        value = self._env.get(name, "")
        if not value:
            return default
        try:
            parsed = parse(value)
        except ValueError:
            self.fail(f"{name} must be {kind}")
            return default
        if not (low <= parsed <= high):
            self.fail(f"{name} must be between {low} and {high}")
        return parsed

    def integer(self, name: str, default: int, *, low: int, high: int) -> int:
        return self._parsed(name, default, int, low=low, high=high, kind="an integer")

    def number(self, name: str, default: float, *, low: float, high: float) -> float:
        return self._parsed(name, default, float, low=low, high=high, kind="a number")

    def choice(self, name: str, default: str, allowed: set[str]) -> str:
        value = self._env.get(name) or default
        if value not in allowed:
            self.fail(f"{name} must be one of {', '.join(sorted(allowed))}")
        return value
