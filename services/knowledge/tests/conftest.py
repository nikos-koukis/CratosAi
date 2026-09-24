"""Test fixtures: real Neo4j and Qdrant (the images Docker Compose runs), a
throwaway PKI, and the service behind a real mTLS gRPC server."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import uuid
from collections.abc import AsyncIterator, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

import grpc
import numpy as np
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from jarvis.knowledge.v1 import knowledge_pb2_grpc as pb_grpc
from neo4j import AsyncDriver, AsyncGraphDatabase
from qdrant_client import AsyncQdrantClient
from testcontainers.community.neo4j import Neo4jContainer
from testcontainers.community.qdrant import QdrantContainer

from jarvis_knowledge.authz import Policy
from jarvis_knowledge.embedding import Vector
from jarvis_knowledge.graph import Graph
from jarvis_knowledge.interceptor import Interceptor
from jarvis_knowledge.metrics import Metrics
from jarvis_knowledge.model import normalize
from jarvis_knowledge.retrieval import Retriever
from jarvis_knowledge.service import METHODS, SERVICE, KnowledgeService
from jarvis_knowledge.vectors import Vectors

# gRPC's C core logs connection teardown at INFO; keep test output readable.
os.environ.setdefault("GRPC_VERBOSITY", "ERROR")

NEO4J_IMAGE = "neo4j:2026.09.0-community"
QDRANT_IMAGE = "qdrant/qdrant:v1.19.1"
ORCHESTRATOR = "spiffe://jarvis.local/orchestrator"
DASHBOARD = "spiffe://jarvis.local/dashboard-api"
STRANGER = "spiffe://jarvis.local/stranger"
POLICY = f"""
[[principal]]
id = "{ORCHESTRATOR}"
allow = ["UpsertKnowledge", "Retrieve", "GetEntity", "DeleteSource", "DeleteEntity"]

[[principal]]
id = "{DASHBOARD}"
allow = ["GetEntity", "DeleteSource", "DeleteEntity", "DeleteUserKnowledge"]
"""
# The fake embedder's similarities are lower than a real model's; the
# relevance margin is tested separately (test_units).
TEST_MIN_SCORE = 0.25


class FakeEmbedder:
    """Deterministic bag-of-words vectors: texts sharing words are similar."""

    dimensions = 384
    model = "fake"

    def _vector(self, text: str) -> Vector:
        v = np.zeros(self.dimensions, dtype=np.float32)
        for word in normalize(text).split():
            if len(word) > 2:
                v[int(hashlib.sha256(word.encode()).hexdigest(), 16) % self.dimensions] += 1.0
        norm = float(np.linalg.norm(v))
        return v / norm if norm else v + (1.0 / np.sqrt(self.dimensions))

    async def query(self, text: str) -> Vector:
        return self._vector(text)

    async def passages(self, texts: Sequence[str]) -> list[Vector]:
        return [self._vector(t) for t in texts]


# --- containers ------------------------------------------------------------------


@pytest.fixture(scope="session")
def neo4j_uri() -> Iterator[tuple[str, str, str]]:
    with Neo4jContainer(NEO4J_IMAGE, password="test-password") as container:
        yield container.get_connection_url(), "neo4j", "test-password"


@pytest.fixture(scope="session")
def qdrant_url() -> Iterator[tuple[str, int]]:
    with QdrantContainer(QDRANT_IMAGE) as container:
        host = container.get_container_host_ip()
        yield f"http://{host}:{container.get_exposed_port(6333)}", int(container.get_exposed_port(6334))


@pytest_asyncio.fixture(scope="session")
async def driver(neo4j_uri: tuple[str, str, str]) -> AsyncIterator[AsyncDriver]:
    uri, user, password = neo4j_uri
    driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
    yield driver
    await driver.close()


@pytest_asyncio.fixture(scope="session")
async def graph(driver: AsyncDriver) -> Graph:
    g = Graph(driver, "neo4j")
    await g.ensure_schema()
    await g.ensure_schema()  # idempotent
    return g


@pytest_asyncio.fixture(scope="session")
async def qdrant(qdrant_url: tuple[str, int]) -> AsyncIterator[AsyncQdrantClient]:
    url, grpc_port = qdrant_url
    client = AsyncQdrantClient(url=url, grpc_port=grpc_port, prefer_grpc=True, timeout=10)
    yield client
    await client.close()


@pytest_asyncio.fixture(scope="session")
async def vectors(qdrant: AsyncQdrantClient) -> Vectors:
    v = Vectors(qdrant, "test_knowledge")
    await v.ensure_collection(FakeEmbedder.dimensions)
    await v.ensure_collection(FakeEmbedder.dimensions)  # idempotent
    return v


# --- PKI -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Identity:
    cert: bytes
    key: bytes


@dataclass(frozen=True)
class Pki:
    ca: bytes
    server: Identity
    clients: dict[str, Identity]


def _pem_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _issue(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_name: x509.Name,
    cn: str,
    san: Sequence[x509.GeneralName] | None,
    usage: x509.ObjectIdentifier,
) -> Identity:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    return Identity(cert.public_bytes(serialization.Encoding.PEM), _pem_key(key))


@pytest.fixture(scope="session")
def pki() -> Pki:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Jarvis Test CA")])
    now = dt.datetime.now(dt.UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server = _issue(
        ca_key,
        ca_name,
        "knowledge",
        [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
        ExtendedKeyUsageOID.SERVER_AUTH,
    )
    clients = {
        uri: _issue(
            ca_key,
            ca_name,
            uri.rsplit("/", 1)[-1],
            [x509.UniformResourceIdentifier(uri)],
            ExtendedKeyUsageOID.CLIENT_AUTH,
        )
        for uri in (ORCHESTRATOR, DASHBOARD, STRANGER)
    }
    clients["no-uri"] = _issue(ca_key, ca_name, "anonymous", None, ExtendedKeyUsageOID.CLIENT_AUTH)
    return Pki(ca.public_bytes(serialization.Encoding.PEM), server, clients)


# --- the service ------------------------------------------------------------------------


@dataclass
class Running:
    port: int
    pki: Pki
    metrics: Metrics

    def stub(self, principal: str) -> pb_grpc.KnowledgeServiceAsyncStub:
        identity = self.pki.clients[principal]
        credentials = grpc.ssl_channel_credentials(self.pki.ca, identity.key, identity.cert)
        channel = grpc.aio.secure_channel(f"localhost:{self.port}", credentials)
        return pb_grpc.KnowledgeServiceStub(channel)


async def start_service(graph: Graph, vectors: Vectors, pki: Pki) -> tuple[grpc.aio.Server, Running]:
    metrics = Metrics()
    embedder = FakeEmbedder()
    retriever = Retriever(embedder, vectors, graph, metrics, min_score=TEST_MIN_SCORE, margin=1.0)
    server = grpc.aio.server(interceptors=[Interceptor(SERVICE, Policy.parse(POLICY, METHODS), metrics)])
    pb_grpc.add_KnowledgeServiceServicer_to_server(
        KnowledgeService(graph, vectors, embedder, retriever, metrics), server
    )
    credentials = grpc.ssl_server_credentials(
        [(pki.server.key, pki.server.cert)], root_certificates=pki.ca, require_client_auth=True
    )
    port = server.add_secure_port("127.0.0.1:0", credentials)
    await server.start()
    return server, Running(port, pki, metrics)


@pytest_asyncio.fixture(scope="session")
async def service(graph: Graph, vectors: Vectors, pki: Pki) -> AsyncIterator[Running]:
    server, running = await start_service(graph, vectors, pki)
    yield running
    await server.stop(None)


@pytest.fixture
def orchestrator(service: Running) -> pb_grpc.KnowledgeServiceAsyncStub:
    return service.stub(ORCHESTRATOR)


@pytest.fixture
def dashboard(service: Running) -> pb_grpc.KnowledgeServiceAsyncStub:
    return service.stub(DASHBOARD)


@pytest.fixture
def tenant() -> str:
    """A fresh tenant per test keeps tests independent on shared stores."""
    return str(uuid.uuid4())


@pytest.fixture
def model_dir() -> Path | None:
    """The real embedding model, if downloaded (services/knowledge/.dev/models)."""
    path = Path(__file__).resolve().parent.parent / ".dev" / "models"
    return path if path.is_dir() else None
