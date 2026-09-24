"""jarvis.knowledge.v1.KnowledgeService."""

from __future__ import annotations

import functools
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from typing import Any, NoReturn

import grpc
import httpx
import neo4j.exceptions
from google.protobuf import duration_pb2, timestamp_pb2
from jarvis.knowledge.v1 import knowledge_pb2 as pb
from jarvis.knowledge.v1 import knowledge_pb2_grpc as pb_grpc
from qdrant_client.http.exceptions import ResponseHandlingException, UnexpectedResponse

from jarvis_knowledge.embedding import TextEmbedder
from jarvis_knowledge.graph import Graph, StoredEntity, StoredRelation
from jarvis_knowledge.interceptor import abort, request_id
from jarvis_knowledge.metrics import Metrics
from jarvis_knowledge.model import (
    DEFAULT_TOKEN_BUDGET,
    MAX_QUERY,
    InvalidArgument,
    Owner,
    SourceInfo,
    clean_text,
    parse_key,
    parse_owner,
    parse_reader,
    parse_source,
    parse_tenant,
    parse_upsert,
    parse_user,
    printable_ascii,
    scope_of,
)
from jarvis_knowledge.retrieval import Retriever
from jarvis_knowledge.vectors import PassageHit, Vectors, entity_text

log = logging.getLogger(__name__)

SERVICE = pb.DESCRIPTOR.services_by_name["KnowledgeService"].full_name
METHODS = [m.name for m in pb.DESCRIPTOR.services_by_name["KnowledgeService"].methods]

# Neo4j or Qdrant unreachable or failing: UNAVAILABLE, the caller may retry.
STORE_ERRORS: tuple[type[BaseException], ...] = (
    neo4j.exceptions.ServiceUnavailable,
    neo4j.exceptions.SessionExpired,
    neo4j.exceptions.TransientError,
    ResponseHandlingException,
    UnexpectedResponse,
    grpc.aio.AioRpcError,
    httpx.TransportError,
    ConnectionError,
    TimeoutError,
)

type Context = grpc.aio.ServicerContext[Any, Any]


async def _invalid(context: Context, error: InvalidArgument) -> NoReturn:
    await abort(context, grpc.StatusCode.INVALID_ARGUMENT, str(error))
    raise AssertionError("unreachable")


def rpc[S, Req, Resp](fn: Callable[[S, Req, Context], Awaitable[Resp]]) -> Callable[[S, Req, Context], Awaitable[Resp]]:
    """Maps validation and store failures to gRPC statuses."""

    @functools.wraps(fn)
    async def wrapper(self: S, request: Req, context: Context) -> Resp:
        try:
            return await fn(self, request, context)
        except InvalidArgument as e:
            await _invalid(context, e)
        except STORE_ERRORS as e:
            log.warning("knowledge store unavailable", extra={"error": repr(e)[:500], "request_id": request_id.get()})
            await abort(
                context,
                grpc.StatusCode.UNAVAILABLE,
                "the knowledge store is unavailable; retry later",
                pb.ErrorReason.Name(pb.ERROR_REASON_STORE_UNAVAILABLE),
            )
        raise AssertionError("unreachable")

    return wrapper


def _timestamp(value: datetime) -> timestamp_pb2.Timestamp:
    ts = timestamp_pb2.Timestamp()
    ts.FromDatetime(value)
    return ts


def _entity(e: StoredEntity, score: float = 0.0) -> pb.Entity:
    return pb.Entity(
        key=e.key,
        type=e.type,
        name=e.name,
        aliases=e.aliases,
        description=e.description,
        scope=scope_of(e.owner),
        score=score,
        update_time=_timestamp(e.updated),
    )


def _relation(r: StoredRelation, score: float = 0.0, hops: int = 0) -> pb.Relation:
    return pb.Relation(
        source_key=r.source_key,
        source_name=r.source_name,
        type=r.type,
        target_key=r.target_key,
        target_name=r.target_name,
        fact=r.fact,
        weight=r.weight,
        scope=scope_of(r.owner),
        score=score,
        hops=hops,
        update_time=_timestamp(r.updated),
    )


def _source(s: SourceInfo) -> pb.Source:
    source = pb.Source(id=s.id, kind=s.kind, title=s.title, uri=s.uri)
    if s.occurred:
        source.occurred_time.FromDatetime(s.occurred)
    return source


def _passage(p: PassageHit) -> pb.Passage:
    return pb.Passage(
        id=p.passage_id,
        text=p.text,
        source=_source(p.source),
        mention_keys=p.mentions,
        scope=scope_of(p.owner),
        score=p.score,
    )


def _source_id(value: str) -> str:
    if not printable_ascii(value, 1, 128):
        raise InvalidArgument("source_id must be 1 to 128 printable ASCII characters")
    return value


class KnowledgeService(pb_grpc.KnowledgeServiceServicer):
    def __init__(
        self, graph: Graph, vectors: Vectors, embedder: TextEmbedder, retriever: Retriever, metrics: Metrics
    ) -> None:
        self._graph = graph
        self._vectors = vectors
        self._embedder = embedder
        self._retriever = retriever
        self._metrics = metrics

    @rpc
    async def UpsertKnowledge(self, request: pb.UpsertKnowledgeRequest, context: Context) -> pb.UpsertKnowledgeResponse:
        upsert = parse_upsert(request)
        # The graph first: it returns each entity's merged name, aliases and
        # description, which is what gets embedded.
        stored, relations = await self._graph.upsert(
            upsert.owner, upsert.source.id, list(upsert.entities.values()), upsert.relations
        )
        vectors = await self._embedder.passages([entity_text(e) for e in stored] + [p.text for p in upsert.passages])
        await self._vectors.upsert_entities(upsert.owner, stored, vectors[: len(stored)])
        await self._vectors.upsert_passages(upsert.owner, upsert.source, upsert.passages, vectors[len(stored) :])

        self._metrics.stored.labels("entity").inc(len(stored))
        self._metrics.stored.labels("relation").inc(relations)
        self._metrics.stored.labels("passage").inc(len(upsert.passages))
        log.info(
            "knowledge stored",
            extra={
                "request_id": request_id.get(),
                "tenant_id": upsert.owner.tenant,
                "scope": pb.Scope.Name(upsert.owner.scope),
                "source_kind": upsert.source.kind,
                "entities": len(stored),
                "relations": relations,
                "passages": len(upsert.passages),
            },
        )
        return pb.UpsertKnowledgeResponse(entities=len(stored), relations=relations, passages=len(upsert.passages))

    @rpc
    async def Retrieve(self, request: pb.RetrieveRequest, context: Context) -> pb.RetrieveResponse:
        started = time.perf_counter()
        reader = parse_reader(request.tenant_id, request.user_id)
        query = clean_text(request.query, "query", MAX_QUERY, required=True)
        budget = request.token_budget or DEFAULT_TOKEN_BUDGET
        if not 50 <= budget <= 8000:
            raise InvalidArgument("token_budget must be between 50 and 8000")
        hops = request.max_hops if request.HasField("max_hops") else 1
        if not 0 <= hops <= 2:
            raise InvalidArgument("max_hops must be 0, 1 or 2")
        if len(request.source_kinds) > 16:
            raise InvalidArgument("at most 16 source_kinds")
        kinds = [parse_source(pb.Source(id="x", kind=k)).kind for k in request.source_kinds]

        result = await self._retriever.retrieve(reader, query, budget=budget, hops=hops, source_kinds=kinds)
        took = time.perf_counter() - started
        log.info(
            "knowledge retrieved",
            extra={
                "request_id": request_id.get(),
                "tenant_id": reader.tenant,
                "entities": len(result.entities),
                "relations": len(result.relations),
                "passages": len(result.passages),
                "tokens": result.tokens,
                "truncated": result.truncated,
                "took_ms": round(took * 1000, 2),
            },
        )
        duration = duration_pb2.Duration()
        duration.FromTimedelta(timedelta(seconds=took))
        return pb.RetrieveResponse(
            context=result.context,
            estimated_tokens=result.tokens,
            entities=[_entity(e, score) for e, score in result.entities],
            relations=[_relation(r, score, hop) for r, score, hop in result.relations],
            passages=[_passage(p) for p in result.passages],
            truncated=result.truncated,
            took=duration,
        )

    @rpc
    async def GetEntity(self, request: pb.GetEntityRequest, context: Context) -> pb.GetEntityResponse:
        owner = parse_owner(request.tenant_id, request.user_id, request.scope)
        key = parse_key(request.key)
        limit = request.relation_limit or 100
        if not 1 <= limit <= 500:
            raise InvalidArgument("relation_limit must be between 1 and 500")
        entity, relations = await self._graph.get(owner, key, limit)
        if entity is None:
            await abort(
                context,
                grpc.StatusCode.NOT_FOUND,
                "entity not found",
                pb.ErrorReason.Name(pb.ERROR_REASON_ENTITY_NOT_FOUND),
            )
        return pb.GetEntityResponse(entity=_entity(entity), relations=[_relation(r) for r in relations])

    @rpc
    async def DeleteSource(self, request: pb.DeleteSourceRequest, context: Context) -> pb.DeleteSourceResponse:
        owner = parse_owner(request.tenant_id, request.user_id, request.scope)
        source_id = _source_id(request.source_id)
        passages = await self._vectors.delete_source(owner, source_id)
        relations, entity_keys = await self._graph.forget_source(owner, source_id)
        await self._vectors.delete_entities(owner, entity_keys)
        self._deleted(passages, relations, len(entity_keys))
        log.info(
            "source forgotten",
            extra={
                "request_id": request_id.get(),
                "tenant_id": owner.tenant,
                "passages": passages,
                "relations": relations,
                "entities": len(entity_keys),
            },
        )
        return pb.DeleteSourceResponse(passages=passages, relations=relations, entities=len(entity_keys))

    @rpc
    async def DeleteEntity(self, request: pb.DeleteEntityRequest, context: Context) -> pb.DeleteEntityResponse:
        owner = parse_owner(request.tenant_id, request.user_id, request.scope)
        key = parse_key(request.key)
        relations = await self._graph.delete_entity(owner, key)
        await self._vectors.delete_entities(owner, [key])
        if relations is not None:
            self._deleted(0, relations, 1)
        return pb.DeleteEntityResponse(relations=relations or 0)

    @rpc
    async def DeleteUserKnowledge(
        self, request: pb.DeleteUserKnowledgeRequest, context: Context
    ) -> pb.DeleteUserKnowledgeResponse:
        owner = Owner(parse_tenant(request.tenant_id), f"u:{parse_user(request.user_id)}")
        entities, relations = await self._graph.delete_owner(owner)
        passages = await self._vectors.delete_owner(owner)
        self._deleted(passages, relations, entities)
        log.info(
            "user knowledge forgotten",
            extra={
                "request_id": request_id.get(),
                "tenant_id": owner.tenant,
                "passages": passages,
                "relations": relations,
                "entities": entities,
            },
        )
        return pb.DeleteUserKnowledgeResponse(passages=passages, entities=entities, relations=relations)

    def _deleted(self, passages: int, relations: int, entities: int) -> None:
        self._metrics.deleted.labels("passage").inc(passages)
        self._metrics.deleted.labels("relation").inc(relations)
        self._metrics.deleted.labels("entity").inc(entities)
