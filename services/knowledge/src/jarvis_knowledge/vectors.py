"""Passages and entity descriptions in Qdrant.

One collection holds two kinds of points, both filtered by tenant (a tenant
index keeps each tenant's points together) and owner:
  * passages: text to search, with the keys of the entities they mention;
  * entities: "name (type): description" vectors, plus normalized names for
    exact name matching, to find where in the graph to start.
Point ids are derived from tenant, owner and item id, so writes are idempotent.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from qdrant_client import AsyncQdrantClient, models

from jarvis_knowledge.embedding import Vector
from jarvis_knowledge.graph import StoredEntity
from jarvis_knowledge.model import (
    Owner,
    PassageWrite,
    Reader,
    SourceInfo,
    entity_point_id,
    normalize,
    passage_point_id,
)

_KEYWORD_FIELDS = ("owner", "kind", "source_id", "source_kind", "key", "names")


class SchemaMismatch(Exception):
    """The collection exists with vectors of another size (another model)."""


@dataclass(frozen=True, slots=True)
class PassageHit:
    owner: str
    passage_id: str
    text: str
    source: SourceInfo
    mentions: list[str]
    score: float


@dataclass(frozen=True, slots=True)
class EntityHit:
    owner: str
    key: str
    score: float


def entity_text(entity: StoredEntity) -> str:
    """What is embedded for an entity."""
    text = f"{entity.name} ({entity.type})"
    if entity.description:
        text += f": {entity.description}"
    if entity.aliases:
        text += f". Also known as {', '.join(entity.aliases)}."
    return text


class Vectors:
    def __init__(self, client: AsyncQdrantClient, collection: str) -> None:
        self._client = client
        self._collection = collection

    async def ensure_collection(self, dimensions: int) -> None:
        if await self._client.collection_exists(self._collection):
            info = await self._client.get_collection(self._collection)
            params = info.config.params.vectors
            size = params.size if isinstance(params, models.VectorParams) else None
            if size != dimensions:
                raise SchemaMismatch(
                    f"collection {self._collection} has {size}-dimensional vectors; the model makes {dimensions}. "
                    "Use another KNOWLEDGE_QDRANT_COLLECTION and re-ingest."
                )
        else:
            await self._client.create_collection(
                self._collection,
                vectors_config=models.VectorParams(size=dimensions, distance=models.Distance.COSINE),
            )
        await self._client.create_payload_index(
            self._collection,
            "tenant_id",
            field_schema=models.KeywordIndexParams(type=models.KeywordIndexType.KEYWORD, is_tenant=True),
        )
        for field in _KEYWORD_FIELDS:
            await self._client.create_payload_index(
                self._collection, field, field_schema=models.PayloadSchemaType.KEYWORD
            )

    async def ping(self) -> None:
        await self._client.get_collection(self._collection)

    async def upsert_passages(
        self, owner: Owner, source: SourceInfo, passages: Sequence[PassageWrite], vectors: Sequence[Vector]
    ) -> None:
        now = datetime.now(UTC).isoformat()
        points = [
            models.PointStruct(
                id=passage_point_id(owner, source.id, p.id),
                vector=v.tolist(),
                payload={
                    "tenant_id": owner.tenant,
                    "owner": owner.value,
                    "kind": "passage",
                    "passage_id": p.id,
                    "text": p.text,
                    "source_id": source.id,
                    "source_kind": source.kind,
                    "source_title": source.title,
                    "source_uri": source.uri,
                    "occurred_at": source.occurred.isoformat() if source.occurred else None,
                    "mentions": p.mentions,
                    "updated_at": now,
                },
            )
            for p, v in zip(passages, vectors, strict=True)
        ]
        if points:
            await self._client.upsert(self._collection, points=points, wait=True)

    async def upsert_entities(self, owner: Owner, entities: Sequence[StoredEntity], vectors: Sequence[Vector]) -> None:
        points = [
            models.PointStruct(
                id=entity_point_id(owner, e.key),
                vector=v.tolist(),
                payload={
                    "tenant_id": owner.tenant,
                    "owner": owner.value,
                    "kind": "entity",
                    "key": e.key,
                    "names": sorted({normalize(n) for n in [e.name, *e.aliases] if normalize(n)}),
                },
            )
            for e, v in zip(entities, vectors, strict=True)
        ]
        if points:
            await self._client.upsert(self._collection, points=points, wait=True)

    async def search(
        self,
        reader: Reader,
        vector: Vector,
        *,
        passages: int,
        entities: int,
        source_kinds: Sequence[str],
        names: Sequence[str],
    ) -> tuple[list[PassageHit], list[EntityHit], list[EntityHit]]:
        """Similar passages, similar entities and entities named in the query, in one round trip."""
        visible: list[models.Condition] = [
            models.FieldCondition(key="tenant_id", match=models.MatchValue(value=reader.tenant)),
            models.FieldCondition(key="owner", match=models.MatchAny(any=reader.owners)),
        ]
        passage_filter: list[models.Condition] = [
            *visible,
            models.FieldCondition(key="kind", match=models.MatchValue(value="passage")),
        ]
        if source_kinds:
            passage_filter.append(
                models.FieldCondition(key="source_kind", match=models.MatchAny(any=list(source_kinds)))
            )
        entity_filter: list[models.Condition] = [
            *visible,
            models.FieldCondition(key="kind", match=models.MatchValue(value="entity")),
        ]
        query = vector.tolist()
        requests = [
            models.QueryRequest(
                query=query, filter=models.Filter(must=passage_filter), limit=passages, with_payload=True
            ),
            models.QueryRequest(
                query=query, filter=models.Filter(must=entity_filter), limit=entities, with_payload=True
            ),
        ]
        if names:
            # Exact (normalized) name matches, ranked by similarity among themselves.
            named: list[models.Condition] = [
                *entity_filter,
                models.FieldCondition(key="names", match=models.MatchAny(any=list(names))),
            ]
            requests.append(
                models.QueryRequest(query=query, filter=models.Filter(must=named), limit=entities, with_payload=True)
            )
        responses = await self._client.query_batch_points(self._collection, requests=requests)
        passage_hits = [_passage(p) for p in responses[0].points]
        entity_hits = [_entity(p) for p in responses[1].points]
        named_hits = [_entity(p) for p in responses[2].points] if names else []
        return passage_hits, entity_hits, named_hits

    async def delete_source(self, owner: Owner, source_id: str) -> int:
        selector = _owned(
            owner,
            models.FieldCondition(key="source_id", match=models.MatchValue(value=source_id)),
            models.FieldCondition(key="kind", match=models.MatchValue(value="passage")),
        )
        return await self._delete(selector)

    async def delete_entities(self, owner: Owner, keys: Sequence[str]) -> None:
        if keys:
            await self._client.delete(
                self._collection,
                points_selector=models.PointIdsList(points=[entity_point_id(owner, k) for k in keys]),
                wait=True,
            )

    async def delete_owner(self, owner: Owner) -> int:
        """Deletes every point of an owner; returns how many were passages."""
        passages = await self._client.count(
            self._collection,
            count_filter=_owned(owner, models.FieldCondition(key="kind", match=models.MatchValue(value="passage"))),
            exact=True,
        )
        await self._client.delete(
            self._collection, points_selector=models.FilterSelector(filter=_owned(owner)), wait=True
        )
        return passages.count

    async def _delete(self, selector: models.Filter) -> int:
        counted = await self._client.count(self._collection, count_filter=selector, exact=True)
        if counted.count:
            await self._client.delete(
                self._collection, points_selector=models.FilterSelector(filter=selector), wait=True
            )
        return counted.count


def _owned(owner: Owner, *conditions: models.FieldCondition) -> models.Filter:
    return models.Filter(
        must=[
            models.FieldCondition(key="tenant_id", match=models.MatchValue(value=owner.tenant)),
            models.FieldCondition(key="owner", match=models.MatchValue(value=owner.value)),
            *conditions,
        ]
    )


def _payload(point: models.ScoredPoint) -> dict[str, Any]:
    return dict(point.payload or {})


def _passage(point: models.ScoredPoint) -> PassageHit:
    p = _payload(point)
    occurred = datetime.fromisoformat(p["occurred_at"]) if p.get("occurred_at") else None
    source = SourceInfo(
        id=str(p["source_id"]),
        kind=str(p["source_kind"]),
        title=str(p.get("source_title", "")),
        uri=str(p.get("source_uri", "")),
        occurred=occurred,
    )
    return PassageHit(
        owner=str(p["owner"]),
        passage_id=str(p["passage_id"]),
        text=str(p["text"]),
        source=source,
        mentions=[str(m) for m in p.get("mentions", [])],
        score=float(point.score),
    )


def _entity(point: models.ScoredPoint) -> EntityHit:
    p = _payload(point)
    return EntityHit(owner=str(p["owner"]), key=str(p["key"]), score=float(point.score))
