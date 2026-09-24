"""The service end to end: mTLS gRPC, Neo4j and Qdrant (fake embedder)."""

from __future__ import annotations

import uuid
from typing import Any

import grpc
import pytest
from google.protobuf import wrappers_pb2  # noqa: F401 - keeps protobuf well-known types loaded
from google.rpc import error_details_pb2
from grpc_status import rpc_status
from jarvis.knowledge.v1 import knowledge_pb2 as pb
from jarvis.knowledge.v1 import knowledge_pb2_grpc as pb_grpc
from neo4j import AsyncDriver

from jarvis_knowledge.graph import Graph
from jarvis_knowledge.vectors import Vectors

from .conftest import ORCHESTRATOR, STRANGER, Pki, Running, start_service

USER = "user-1"


def ref(type_: str, name: str) -> pb.EntityRef:
    return pb.EntityRef(type=type_, name=name)


def upsert(
    tenant: str,
    source: str,
    *,
    user: str = USER,
    scope: pb.Scope.ValueType = pb.SCOPE_USER,
    entities: list[pb.EntityInput] | None = None,
    relations: list[pb.RelationInput] | None = None,
    passages: list[pb.PassageInput] | None = None,
    kind: str = "conversation",
) -> pb.UpsertKnowledgeRequest:
    return pb.UpsertKnowledgeRequest(
        tenant_id=tenant,
        user_id=user,
        scope=scope,
        source=pb.Source(id=source, kind=kind, title="Weekly sync"),
        entities=entities or [],
        relations=relations or [],
        passages=passages or [],
    )


def relation(
    source: pb.EntityRef, type_: str, target: pb.EntityRef, fact: str = "", weight: float | None = None
) -> pb.RelationInput:
    r = pb.RelationInput(source=source, type=type_, target=target, fact=fact)
    if weight is not None:
        r.weight = weight
    return r


def reason(error: grpc.aio.AioRpcError) -> str:
    status = rpc_status.from_call(error)  # type: ignore[arg-type]
    for detail in status.details if status else []:
        info = error_details_pb2.ErrorInfo()
        if detail.Unpack(info):
            assert info.domain == "knowledge.jarvis"
            return info.reason
    return ""


MARIA, ATLAS, ACME, ATHENS = (
    ref("Person", "Maria Papadopoulou"),
    ref("Project", "Atlas"),
    ref("Organization", "Acme"),
    ref("Place", "Athens"),
)


async def seed_atlas(stub: pb_grpc.KnowledgeServiceAsyncStub, tenant: str, **kwargs: object) -> None:
    await stub.UpsertKnowledge(
        upsert(
            tenant,
            "conversation:1",
            entities=[
                pb.EntityInput(
                    type="Person", name="Maria Papadopoulou", aliases=["Μαρία"], description="product manager at Acme"
                )
            ],
            relations=[
                relation(MARIA, "LEADS", ATLAS, "Maria leads the Atlas project since May 2026", 0.9),
                relation(MARIA, "WORKS_AT", ACME),
                relation(ACME, "LOCATED_IN", ATHENS, "Acme is based in Athens"),
            ],
            passages=[
                pb.PassageInput(id="p1", text="Maria asked to move the Atlas demo to Friday.", mentions=[MARIA, ATLAS])
            ],
            **kwargs,  # type: ignore[arg-type]
        )
    )


async def test_upsert_then_retrieve(orchestrator: pb_grpc.KnowledgeServiceAsyncStub, tenant: str) -> None:
    await seed_atlas(orchestrator, tenant)
    resp = await orchestrator.Retrieve(
        pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="When is the Atlas demo with Maria?")
    )
    assert "Maria leads the Atlas project since May 2026" in resp.context
    assert "move the Atlas demo to Friday" in resp.context
    assert resp.context.startswith("Entities:\n")
    assert "\n- Maria Papadopoulou (Person): product manager at Acme\n" in resp.context
    assert 0 < resp.estimated_tokens <= 800
    assert resp.passages[0].id == "p1" and resp.passages[0].source.kind == "conversation"
    assert set(resp.passages[0].mention_keys) == {"Person:maria papadopoulou", "Project:atlas"}
    leads = next(r for r in resp.relations if r.type == "LEADS")
    assert leads.hops == 1 and leads.weight == pytest.approx(0.9) and leads.scope == pb.SCOPE_USER
    assert resp.took.ToTimedelta().total_seconds() > 0


async def test_upsert_counts_and_references(orchestrator: pb_grpc.KnowledgeServiceAsyncStub, tenant: str) -> None:
    resp = await orchestrator.UpsertKnowledge(
        upsert(
            tenant,
            "doc:1",
            kind="document",
            relations=[relation(MARIA, "LEADS", ATLAS)],
            passages=[pb.PassageInput(text="Atlas kickoff notes", mentions=[ATLAS, ref("Topic", "Kickoff")])],
        )
    )
    # Entities referenced by relations and passages are created by name.
    assert (resp.entities, resp.relations, resp.passages) == (3, 1, 1)
    got = await orchestrator.GetEntity(pb.GetEntityRequest(tenant_id=tenant, user_id=USER, key="Topic:kickoff"))
    assert got.entity.name == "Kickoff" and not got.relations


async def test_hops(orchestrator: pb_grpc.KnowledgeServiceAsyncStub, tenant: str) -> None:
    await seed_atlas(orchestrator, tenant)

    async def facts(hops: int) -> set[str]:
        resp = await orchestrator.Retrieve(
            pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="Maria Papadopoulou", max_hops=hops)
        )
        return {r.type for r in resp.relations}

    # A weak relation two hops away is not worth its tokens.
    await orchestrator.UpsertKnowledge(
        upsert(
            tenant, "conversation:2", relations=[relation(ACME, "SPONSORS", ref("Topic", "Chess club"), weight=0.05)]
        )
    )
    assert await facts(0) == set()
    assert await facts(1) == {"LEADS", "WORKS_AT"}
    assert await facts(2) == {"LEADS", "WORKS_AT", "LOCATED_IN"}


async def test_names_in_the_query_find_entities(orchestrator: pb_grpc.KnowledgeServiceAsyncStub, tenant: str) -> None:
    await seed_atlas(orchestrator, tenant)
    # "Μαρία" is only an alias, with no word in common with anything embedded.
    resp = await orchestrator.Retrieve(pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="τι κάνει η μαρια;"))
    assert [e.key for e in resp.entities][:1] == ["Person:maria papadopoulou"]
    assert any(r.type == "LEADS" for r in resp.relations)


async def test_scopes_and_tenants_are_isolated(orchestrator: pb_grpc.KnowledgeServiceAsyncStub, tenant: str) -> None:
    other_tenant = str(uuid.uuid4())
    await orchestrator.UpsertKnowledge(upsert(tenant, "s1", passages=[pb.PassageInput(text="budget review mine")]))
    await orchestrator.UpsertKnowledge(
        upsert(tenant, "s2", scope=pb.SCOPE_TENANT, passages=[pb.PassageInput(text="budget review shared")])
    )
    await orchestrator.UpsertKnowledge(
        upsert(tenant, "s3", user="user-2", passages=[pb.PassageInput(text="budget review colleague")])
    )
    await orchestrator.UpsertKnowledge(
        upsert(other_tenant, "s4", passages=[pb.PassageInput(text="budget review other tenant")])
    )

    resp = await orchestrator.Retrieve(pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="budget review"))
    texts = {p.text: p.scope for p in resp.passages}
    assert texts == {"budget review mine": pb.SCOPE_USER, "budget review shared": pb.SCOPE_TENANT}

    await orchestrator.UpsertKnowledge(
        upsert(tenant, "s5", user="user-2", entities=[pb.EntityInput(type="Person", name="Secret Contact")])
    )
    with pytest.raises(grpc.aio.AioRpcError) as e:
        await orchestrator.GetEntity(pb.GetEntityRequest(tenant_id=tenant, user_id=USER, key="Person:secret contact"))
    assert e.value.code() == grpc.StatusCode.NOT_FOUND and reason(e.value) == "ERROR_REASON_ENTITY_NOT_FOUND"


async def test_upsert_is_idempotent_and_accumulates_evidence(
    orchestrator: pb_grpc.KnowledgeServiceAsyncStub, tenant: str
) -> None:
    request = upsert(
        tenant,
        "conversation:1",
        entities=[pb.EntityInput(type="Person", name="Maria Papadopoulou")],
        relations=[relation(MARIA, "LEADS", ATLAS)],
    )
    await orchestrator.UpsertKnowledge(request)
    await orchestrator.UpsertKnowledge(request)  # a retry changes nothing
    key = pb.GetEntityRequest(tenant_id=tenant, user_id=USER, key="Person:maria papadopoulou")
    assert (await orchestrator.GetEntity(key)).relations[0].weight == pytest.approx(0.5)

    # Another source saying the same thing strengthens it (noisy-OR), and
    # merges what it adds.
    await orchestrator.UpsertKnowledge(
        upsert(
            tenant,
            "conversation:2",
            entities=[
                pb.EntityInput(type="Person", name="MARÍA  papadopoulou", aliases=["Mary"], description="leads Atlas")
            ],
            relations=[relation(MARIA, "LEADS", ATLAS)],
        )
    )
    got = await orchestrator.GetEntity(key)
    assert got.relations[0].weight == pytest.approx(0.75)
    # A mere reference with another spelling does not rename the entity.
    await orchestrator.UpsertKnowledge(
        upsert(
            tenant,
            "conversation:3",
            relations=[relation(ref("Person", "maria PAPADOPOULOU"), "KNOWS", ref("Person", "Nikos"))],
        )
    )
    assert (await orchestrator.GetEntity(key)).entity.name == "MARÍA  papadopoulou"
    assert got.entity.name == "MARÍA  papadopoulou" and list(got.entity.aliases) == ["Mary"]
    assert got.entity.description == "leads Atlas"


async def test_delete_source_keeps_what_others_support(
    orchestrator: pb_grpc.KnowledgeServiceAsyncStub, dashboard: pb_grpc.KnowledgeServiceAsyncStub, tenant: str
) -> None:
    await orchestrator.UpsertKnowledge(
        upsert(
            tenant,
            "a",
            relations=[relation(MARIA, "LEADS", ATLAS), relation(MARIA, "LIKES", ref("Topic", "Chess"))],
            passages=[pb.PassageInput(text="Maria leads Atlas and likes chess")],
        )
    )
    await orchestrator.UpsertKnowledge(upsert(tenant, "b", relations=[relation(MARIA, "LEADS", ATLAS)]))

    first = await dashboard.DeleteSource(pb.DeleteSourceRequest(tenant_id=tenant, user_id=USER, source_id="a"))
    assert (first.passages, first.relations, first.entities) == (1, 1, 1)  # LIKES and Chess go; LEADS stays
    maria = await dashboard.GetEntity(
        pb.GetEntityRequest(tenant_id=tenant, user_id=USER, key="Person:maria papadopoulou")
    )
    assert [r.type for r in maria.relations] == ["LEADS"]

    second = await dashboard.DeleteSource(pb.DeleteSourceRequest(tenant_id=tenant, user_id=USER, source_id="b"))
    assert (second.passages, second.relations, second.entities) == (0, 1, 2)
    again = await dashboard.DeleteSource(pb.DeleteSourceRequest(tenant_id=tenant, user_id=USER, source_id="b"))
    assert (again.passages, again.relations, again.entities) == (0, 0, 0)
    resp = await orchestrator.Retrieve(pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="Maria Atlas chess"))
    assert resp.context == "" and not resp.entities and resp.estimated_tokens == 0


async def test_delete_entity(
    orchestrator: pb_grpc.KnowledgeServiceAsyncStub, dashboard: pb_grpc.KnowledgeServiceAsyncStub, tenant: str
) -> None:
    await seed_atlas(orchestrator, tenant)
    resp = await dashboard.DeleteEntity(
        pb.DeleteEntityRequest(tenant_id=tenant, user_id=USER, key="Person:maria papadopoulou")
    )
    assert resp.relations == 2
    again = await dashboard.DeleteEntity(
        pb.DeleteEntityRequest(tenant_id=tenant, user_id=USER, key="Person:maria papadopoulou")
    )
    assert again.relations == 0
    # The passage stays; its stale mention is harmless.
    found = await orchestrator.Retrieve(pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="Atlas demo Friday"))
    assert [p.id for p in found.passages] == ["p1"]
    assert all("maria" not in e.key for e in found.entities)


async def test_delete_user_knowledge_keeps_shared(
    orchestrator: pb_grpc.KnowledgeServiceAsyncStub, dashboard: pb_grpc.KnowledgeServiceAsyncStub, tenant: str
) -> None:
    await seed_atlas(orchestrator, tenant)
    await seed_atlas(orchestrator, tenant, user="user-2")
    await orchestrator.UpsertKnowledge(
        upsert(
            tenant, "handbook", scope=pb.SCOPE_TENANT, passages=[pb.PassageInput(text="Atlas demo rules for everyone")]
        )
    )
    resp = await dashboard.DeleteUserKnowledge(pb.DeleteUserKnowledgeRequest(tenant_id=tenant, user_id=USER))
    assert (resp.passages, resp.entities, resp.relations) == (1, 4, 3)

    mine = await orchestrator.Retrieve(pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="Atlas demo"))
    assert [p.text for p in mine.passages] == ["Atlas demo rules for everyone"]
    theirs = await orchestrator.Retrieve(pb.RetrieveRequest(tenant_id=tenant, user_id="user-2", query="Atlas demo"))
    assert len(theirs.passages) == 2  # user-2's own passage and the shared one


async def test_context_respects_the_token_budget(orchestrator: pb_grpc.KnowledgeServiceAsyncStub, tenant: str) -> None:
    passages = [
        pb.PassageInput(id=f"n{i}", text=f"release notes item {i}: fixed the login bug on page {i}") for i in range(20)
    ]
    await orchestrator.UpsertKnowledge(upsert(tenant, "notes", passages=passages))
    small = await orchestrator.Retrieve(
        pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="release notes", token_budget=100)
    )
    assert small.truncated and 0 < small.estimated_tokens <= 100 and len(small.passages) >= 1
    large = await orchestrator.Retrieve(
        pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="release notes", token_budget=8000)
    )
    assert not large.truncated and len(large.passages) == 20
    assert small.context.splitlines()[1] in large.context


async def test_source_kind_filter(orchestrator: pb_grpc.KnowledgeServiceAsyncStub, tenant: str) -> None:
    await orchestrator.UpsertKnowledge(upsert(tenant, "c", passages=[pb.PassageInput(text="travel plans Crete")]))
    await orchestrator.UpsertKnowledge(
        upsert(tenant, "e", kind="email", passages=[pb.PassageInput(text="travel plans Crete email")])
    )
    resp = await orchestrator.Retrieve(
        pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="travel plans", source_kinds=["email"])
    )
    assert [p.source.kind for p in resp.passages] == ["email"]


@pytest.mark.parametrize(
    "request_",
    [
        upsert("not-a-uuid", "s", passages=[pb.PassageInput(text="x")]),
        upsert(str(uuid.UUID(int=0)), "s", passages=[pb.PassageInput(text="x")]),
        upsert("6F1C2D3E-4A5B-4C6D-8E7F-9A0B1C2D3E4F", "s", passages=[pb.PassageInput(text="x")]),
        upsert("6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f", "s"),  # nothing to store
        upsert("6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f", "s", user="bad\nuser", passages=[pb.PassageInput(text="x")]),
        upsert("6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f", "s", kind="Bad Kind", passages=[pb.PassageInput(text="x")]),
        upsert("6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f", "s", entities=[pb.EntityInput(type="person", name="x")]),
        upsert("6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f", "s", entities=[pb.EntityInput(type="Person", name="!!!")]),
        upsert("6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f", "s", relations=[relation(MARIA, "leads", ATLAS)]),
        upsert("6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f", "s", relations=[relation(MARIA, "KNOWS", MARIA)]),
        upsert("6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f", "s", relations=[relation(MARIA, "KNOWS", ATLAS, weight=1.5)]),
        upsert("6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f", "s", passages=[pb.PassageInput(text="x" * 8001)]),
        upsert("6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f", "s", passages=[pb.PassageInput(text="a\x00b")]),
        upsert(
            "6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f",
            "s",
            entities=[pb.EntityInput(type="Topic", name=f"t{i}") for i in range(201)],
        ),
    ],
)
async def test_invalid_upserts(
    orchestrator: pb_grpc.KnowledgeServiceAsyncStub, request_: pb.UpsertKnowledgeRequest
) -> None:
    with pytest.raises(grpc.aio.AioRpcError) as e:
        await orchestrator.UpsertKnowledge(request_)
    assert e.value.code() == grpc.StatusCode.INVALID_ARGUMENT


async def test_invalid_reads(orchestrator: pb_grpc.KnowledgeServiceAsyncStub, tenant: str) -> None:
    bad: list[grpc.aio.UnaryUnaryCall[Any, Any]] = [
        orchestrator.Retrieve(pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="")),
        orchestrator.Retrieve(pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="x", token_budget=10)),
        orchestrator.Retrieve(pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="x", max_hops=3)),
        orchestrator.Retrieve(pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="x", source_kinds=["A"])),
        orchestrator.GetEntity(pb.GetEntityRequest(tenant_id=tenant, user_id=USER, key="maria")),
        orchestrator.GetEntity(pb.GetEntityRequest(tenant_id=tenant, user_id=USER, key="Person:Maria")),
        orchestrator.DeleteSource(pb.DeleteSourceRequest(tenant_id=tenant, user_id=USER, source_id="")),
    ]
    for call in bad:
        with pytest.raises(grpc.aio.AioRpcError) as e:
            await call
        assert e.value.code() == grpc.StatusCode.INVALID_ARGUMENT


async def test_authorization(service: Running, dashboard: pb_grpc.KnowledgeServiceAsyncStub, tenant: str) -> None:
    retrieve = pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="x")
    refused: list[grpc.aio.UnaryUnaryCall[Any, Any]] = [
        dashboard.Retrieve(retrieve),
        service.stub(ORCHESTRATOR).DeleteUserKnowledge(pb.DeleteUserKnowledgeRequest(tenant_id=tenant, user_id=USER)),
        service.stub(STRANGER).Retrieve(retrieve),
    ]
    for call in refused:
        with pytest.raises(grpc.aio.AioRpcError) as e:
            await call
        assert e.value.code() == grpc.StatusCode.PERMISSION_DENIED
    with pytest.raises(grpc.aio.AioRpcError) as e:
        await service.stub("no-uri").Retrieve(retrieve)
    assert e.value.code() == grpc.StatusCode.UNAUTHENTICATED


async def test_request_id_is_echoed(service: Running, tenant: str) -> None:
    call = service.stub(ORCHESTRATOR).Retrieve(
        pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="x"), metadata=(("x-request-id", "req-42"),)
    )
    await call
    assert ("x-request-id", "req-42") in list(await call.initial_metadata() or ())
    metric = service.metrics.rpcs.labels("Retrieve", "OK")._value.get()
    assert metric >= 1


async def test_unavailable_store(graph: Graph, vectors: Vectors, pki: Pki, tenant: str) -> None:
    from neo4j import AsyncGraphDatabase  # noqa: PLC0415

    broken = Graph(
        AsyncGraphDatabase.driver(
            "bolt://127.0.0.1:1", auth=("neo4j", "x"), connection_timeout=0.5, max_transaction_retry_time=0.5
        ),
        "neo4j",
    )
    server, running = await start_service(broken, vectors, pki)
    try:
        with pytest.raises(grpc.aio.AioRpcError) as e:
            await running.stub(ORCHESTRATOR).UpsertKnowledge(upsert(tenant, "s", passages=[pb.PassageInput(text="x")]))
        assert e.value.code() == grpc.StatusCode.UNAVAILABLE
        assert reason(e.value) == "ERROR_REASON_STORE_UNAVAILABLE"
    finally:
        await server.stop(None)


async def test_expansion_never_crosses_owners(
    orchestrator: pb_grpc.KnowledgeServiceAsyncStub, driver: AsyncDriver, tenant: str
) -> None:
    """Defense in depth: even a relation that should never exist (between two
    users' entities) is not followed."""
    await orchestrator.UpsertKnowledge(upsert(tenant, "a", entities=[pb.EntityInput(type="Person", name="Maria")]))
    await orchestrator.UpsertKnowledge(
        upsert(
            tenant, "b", user="user-2", relations=[relation(ref("Person", "Private"), "KNOWS", ref("Topic", "Secret"))]
        )
    )
    await driver.execute_query(
        """MATCH (a:Entity {tenant: $t, owner: 'u:user-1', key: 'Person:maria'}),
                 (b:Entity {tenant: $t, owner: 'u:user-2', key: 'Person:private'})
           CREATE (a)-[:RELATES_TO {type: 'LEAKS_TO', fact: 'leak', weight: 1.0, tenant: $t, owner: 'u:user-2',
                                    sources: ['x'], updated: datetime()}]->(b)""",
        {"t": tenant},
    )
    resp = await orchestrator.Retrieve(pb.RetrieveRequest(tenant_id=tenant, user_id=USER, query="Maria", max_hops=2))
    assert [e.key for e in resp.entities] == ["Person:maria"]
    assert not resp.relations
    assert "leak" not in resp.context
