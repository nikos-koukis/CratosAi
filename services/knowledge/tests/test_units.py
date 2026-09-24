"""Unit tests that need no containers."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from jarvis.knowledge.v1 import knowledge_pb2 as pb

from jarvis_knowledge import config
from jarvis_knowledge.authz import Policy, PolicyError, peer_principal
from jarvis_knowledge.graph import StoredEntity, StoredRelation
from jarvis_knowledge.logs import JsonFormatter
from jarvis_knowledge.model import (
    InvalidArgument,
    entity_key,
    estimate_tokens,
    name_candidates,
    normalize,
    parse_key,
    parse_upsert,
)
from jarvis_knowledge.retrieval import Retrieval, pack, passage_line, relation_line, select
from jarvis_knowledge.service import METHODS
from jarvis_knowledge.vectors import EntityHit, PassageHit

from .conftest import DASHBOARD, ORCHESTRATOR, POLICY, Pki

NOW = datetime(2026, 9, 20, 10, 0, tzinfo=UTC)


def test_normalize_ignores_case_accents_and_spacing() -> None:
    assert normalize("  Μαρία   ΠΑΠΑΔΟΠΟΎΛΟΥ ") == "μαρια παπαδοπουλου"
    assert normalize("José-Luis O'Neil") == "jose luis o neil"
    assert entity_key("Person", "Μαρία") == entity_key("Person", "ΜΑΡΙΑ") == "Person:μαρια"
    with pytest.raises(InvalidArgument):
        entity_key("Person", "!!!")


def test_name_candidates_are_normalized_ngrams() -> None:
    grams = name_candidates("Τι έγινε με τη Μαρία Παπαδοπούλου;")
    assert "μαρια παπαδοπουλου" in grams and "μαρια" in grams
    assert all(len(g) >= 2 for g in grams)


def test_parse_key_requires_normalized_keys() -> None:
    assert parse_key("Person:maria papadopoulou") == "Person:maria papadopoulou"
    for bad in ["maria", "person:maria", "Person:Maria", "Person:", "Person: maria"]:
        with pytest.raises(InvalidArgument):
            parse_key(bad)


def test_estimate_tokens_is_conservative_for_greek() -> None:
    assert estimate_tokens("hello world, this is text") == 7
    # 2 bytes per Greek letter: counts more than English of the same length.
    assert estimate_tokens("γεια σου κόσμε") > estimate_tokens("hello world!!!")


def test_parse_upsert_merges_duplicates_and_resolves_references() -> None:
    req = pb.UpsertKnowledgeRequest(
        tenant_id="6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f",
        user_id="u",
        source=pb.Source(id="s", kind="note"),
        entities=[
            pb.EntityInput(type="Person", name="Maria", aliases=["M"]),
            pb.EntityInput(type="Person", name="MARIA", aliases=["m", "Mary"], description="PM"),
        ],
        relations=[
            pb.RelationInput(
                source=pb.EntityRef(type="Person", name="maria"),
                type="LEADS",
                target=pb.EntityRef(type="Project", name="Atlas"),
            )
        ]
        * 2,
        passages=[pb.PassageInput(text="t", mentions=[pb.EntityRef(type="Project", name="Atlas")] * 2)],
    )
    up = parse_upsert(req)
    maria = up.entities["Person:maria"]
    assert maria.explicit and maria.aliases == ["M", "Mary"] and maria.description == "PM"
    assert not up.entities["Project:atlas"].explicit
    assert len(up.relations) == 1 and up.relations[0].weight == 0.5
    assert up.passages[0].mentions == ["Project:atlas"] and len(up.passages[0].id) == 32
    assert up.owner.value == "u:u"


def _entity(name: str, description: str = "") -> StoredEntity:
    return StoredEntity("u:u", f"Person:{normalize(name)}", "Person", name, [], description, NOW)


def _relation(fact: str, type_: str = "KNOWS") -> StoredRelation:
    return StoredRelation("u:u", "Person:a", "A", type_, "Person:b", "B", fact, 0.5, NOW)


def _passage(text: str, score: float) -> PassageHit:
    from jarvis_knowledge.model import SourceInfo  # noqa: PLC0415

    return PassageHit("u:u", text[:8], text, SourceInfo("s", "conversation", "Sync", "", NOW), [], score)


def test_pack_orders_dedupes_and_respects_the_budget() -> None:
    result = Retrieval(
        entities=[(_entity("Maria", "PM"), 0.9)],
        relations=[
            (_relation("Maria leads Atlas"), 0.95, 1),
            (_relation("Maria leads Atlas"), 0.5, 1),
            (_relation("", "WORKS_AT"), 0.4, 2),
        ],
        passages=[_passage("Demo moved to Friday", 0.85), _passage("Unrelated long text " * 30, 0.3)],
    )
    pack(result, budget=60)
    lines = result.context.splitlines()
    assert lines == [
        "Entities:",
        "- Maria (Person): PM",
        "Facts:",
        "- Maria leads Atlas",
        "- A works at B",
        "Notes:",
        '- (2026-09-20, conversation, "Sync") Demo moved to Friday',
    ]
    assert result.truncated and result.tokens <= 60
    assert [p.text for p in result.passages] == ["Demo moved to Friday"]
    assert len(result.relations) == 2  # the duplicate sentence is gone


def test_pack_with_nothing() -> None:
    result = Retrieval()
    pack(result, budget=100)
    assert (result.context, result.tokens, result.truncated) == ("", 0, False)


def test_lines() -> None:
    assert relation_line(_relation("", "LIVES_IN")) == "- A lives in B"
    assert passage_line(_passage("a\n\nb  c", 1.0)) == '- (2026-09-20, conversation, "Sync") a b c'


def _env(**overrides: str) -> dict[str, str]:
    env = {
        "KNOWLEDGE_TLS_CERT": "/c.pem",
        "KNOWLEDGE_TLS_KEY": "/k.pem",
        "KNOWLEDGE_TLS_CLIENT_CA": "/ca.pem",
        "KNOWLEDGE_AUTHZ_POLICY": "/authz.toml",
        "KNOWLEDGE_NEO4J_PASSWORD": "pw",
        "KNOWLEDGE_QDRANT_API_KEY": "key",
        "KNOWLEDGE_MODEL_DIR": "/models",
    }
    env.update(overrides)
    return env


def test_config_defaults() -> None:
    cfg = config.load(_env())
    assert cfg.listen_addr == "127.0.0.1:50053" and cfg.admin_addr == "127.0.0.1:9093"
    assert cfg.model.repo == "intfloat/multilingual-e5-small"
    assert (cfg.min_score, cfg.margin) == (0.78, 0.04)
    assert not cfg.model_download and not cfg.reflection


def test_config_secret_files(tmp_path: Path) -> None:
    secret = tmp_path / "pw"
    secret.write_text("from-file\n")
    env = _env(KNOWLEDGE_NEO4J_PASSWORD_FILE=str(secret))
    del env["KNOWLEDGE_NEO4J_PASSWORD"]
    assert config.load(env).neo4j_password == "from-file"


@pytest.mark.parametrize(
    "overrides",
    [
        {"KNOWLEDGE_ADMIN_ADDR": "0.0.0.0:9093"},
        {"KNOWLEDGE_NEO4J_URI": "bolt://neo4j.internal:7687"},  # plaintext across a network
        {"KNOWLEDGE_QDRANT_URL": "http://qdrant.internal:6333"},
        {"KNOWLEDGE_NEO4J_URI": "http://127.0.0.1:7474"},
        {"KNOWLEDGE_MODEL": "some/other-model"},
        {"KNOWLEDGE_MIN_SCORE": "1.5"},
        {"KNOWLEDGE_EMBED_THREADS": "many"},
        {"KNOWLEDGE_LOG_FORMAT": "xml"},
        {"KNOWLEDGE_REFLECTION": "maybe"},
        {"KNOWLEDGE_QDRANT_API_KEY_FILE": "/nonexistent"},
    ],
)
def test_config_refuses_unsafe_or_invalid_settings(overrides: dict[str, str]) -> None:
    with pytest.raises(config.ConfigError):
        config.load(_env(**overrides))


def test_config_reports_every_problem() -> None:
    with pytest.raises(config.ConfigError) as e:
        config.load({})
    for name in ["KNOWLEDGE_TLS_CERT", "KNOWLEDGE_AUTHZ_POLICY", "KNOWLEDGE_NEO4J_PASSWORD", "KNOWLEDGE_MODEL_DIR"]:
        assert name in str(e.value)


def test_policy() -> None:
    policy = Policy.parse(POLICY, METHODS)
    assert len(policy) == 2
    assert policy.allowed(ORCHESTRATOR, "Retrieve") and not policy.allowed(ORCHESTRATOR, "DeleteUserKnowledge")
    assert policy.allowed(DASHBOARD, "DeleteUserKnowledge") and not policy.allowed(DASHBOARD, "Retrieve")
    assert not policy.allowed("spiffe://jarvis.local/unknown", "Retrieve")


@pytest.mark.parametrize(
    "text",
    [
        "bogus = 1",
        '[[principal]]\nid = "not a uri"\nallow = ["Retrieve"]',
        '[[principal]]\nid = "spiffe://x/y"\nallow = []',
        '[[principal]]\nid = "spiffe://x/y"\nallow = ["Nope"]',
        '[[principal]]\nid = "spiffe://x/y"\nallow = ["Retrieve"]\nextra = 1',
        '[[principal]]\nid = "spiffe://x/y"\nallow = ["Retrieve"]\n'
        '[[principal]]\nid = "spiffe://x/y"\nallow = ["Retrieve"]',
        "[[principal]",
    ],
)
def test_policy_rejects_invalid_files(text: str) -> None:
    with pytest.raises(PolicyError):
        Policy.parse(text, METHODS)


def test_peer_principal(pki: Pki) -> None:
    assert peer_principal({"x509_pem_cert": [pki.clients[ORCHESTRATOR].cert]}) == ORCHESTRATOR
    assert peer_principal({"x509_pem_cert": [pki.clients["no-uri"].cert]}) is None
    assert peer_principal({"x509_pem_cert": [b"garbage"]}) is None
    assert peer_principal({}) is None
    # The server certificate has DNS and IP names but no URI.
    assert (
        x509.load_pem_x509_certificate(pki.server.cert) and peer_principal({"x509_pem_cert": [pki.server.cert]}) is None
    )


def test_json_logs_carry_extras() -> None:
    record = logging.LogRecord("jarvis", logging.INFO, __file__, 1, "rpc", None, None)
    record.method = "Retrieve"
    entry = json.loads(JsonFormatter().format(record))
    assert entry["msg"] == "rpc" and entry["method"] == "Retrieve" and entry["level"] == "INFO"


def _hit(key: str, score: float) -> EntityHit:
    return EntityHit("u:u", key, score)


def test_select_keeps_only_matches_near_the_best() -> None:
    # Scores measured with multilingual-e5-small for "Πότε έχω τον λογιστή;".
    accountant = _passage("Κλείσαμε ραντεβού με τον λογιστή", 0.847)
    demo, api = _passage("Η Μαρία ζήτησε να μετακινηθεί το demo", 0.805), _passage("Ο Νίκος είπε ότι το API", 0.799)
    similar = [_hit("Organization:acme", 0.824), _hit("Person:νικος γεωργιου", 0.794)]
    passages, seeds = select([accountant, demo, api], similar, [], min_score=0.78, margin=0.04)
    assert passages == [accountant]
    assert seeds == [(("u:u", "Organization:acme"), 0.824)]


def test_select_seeds_from_names_and_mentions() -> None:
    passage = PassageHit("u:u", "p", "text", _passage("x", 0).source, ["Project:atlas"], 0.85)
    _, seeds = select([passage], [_hit("Topic:other", 0.70)], [_hit("Person:maria", 0.80)], min_score=0.78, margin=0.04)
    assert seeds == [(("u:u", "Person:maria"), 0.97), (("u:u", "Project:atlas"), pytest.approx(0.85 * 0.92))]


def test_select_with_nothing_relevant() -> None:
    passages, seeds = select([_passage("weather", 0.71)], [_hit("Topic:x", 0.72)], [], min_score=0.78, margin=0.04)
    assert passages == []
    assert seeds == []
