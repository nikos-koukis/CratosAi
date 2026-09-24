"""The knowledge graph in Neo4j.

(:Entity {tenant, owner, key, type, name, aliases, description, sources,
created, updated}) nodes connected by [:RELATES_TO {type, fact, weight,
tenant, owner, sources, created, updated}] relationships. Entity and relation
types are properties, never labels, so no caller input is ever spliced into
Cypher. Every query is bound to a tenant and owner(s).

`sources` records which sources support a node or relationship, so a source
can be forgotten without losing what other sources also said. Relation
weights accumulate evidence (noisy-OR) once per source.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, LiteralString

from neo4j import AsyncDriver, RoutingControl

from jarvis_knowledge.model import (
    MAX_STORED_ALIASES,
    MAX_STORED_SOURCES,
    EntityWrite,
    Owner,
    Reader,
    RelationWrite,
)

SCHEMA: list[LiteralString] = [
    "CREATE CONSTRAINT entity_identity IF NOT EXISTS FOR (e:Entity) REQUIRE (e.tenant, e.owner, e.key) IS UNIQUE",
    "CREATE INDEX entity_owner IF NOT EXISTS FOR (e:Entity) ON (e.tenant, e.owner)",
]

_UPSERT_ENTITIES: LiteralString = """
UNWIND $entities AS e
MERGE (n:Entity {tenant: $tenant, owner: $owner, key: e.key})
ON CREATE SET n.type = e.type, n.name = e.name, n.aliases = [], n.description = '', n.sources = [], n.created = $now
WITH n, e, CASE WHEN e.explicit THEN e.name ELSE n.name END AS name
SET n.name = name,
    n.aliases = reduce(acc = [], a IN n.aliases + e.aliases |
                  CASE WHEN a IN acc OR a = name THEN acc ELSE acc + a END)[..$max_aliases],
    n.description = CASE WHEN e.description <> '' THEN e.description ELSE n.description END,
    n.sources = CASE WHEN $source IN n.sources THEN n.sources ELSE (n.sources + $source)[-$max_sources..] END,
    n.updated = $now
RETURN n.key AS key, n.type AS type, n.name AS name, n.aliases AS aliases, n.description AS description,
       n.updated AS updated
"""

_UPSERT_RELATIONS: LiteralString = """
UNWIND $relations AS r
MATCH (a:Entity {tenant: $tenant, owner: $owner, key: r.source_key})
MATCH (b:Entity {tenant: $tenant, owner: $owner, key: r.target_key})
MERGE (a)-[x:RELATES_TO {type: r.type}]->(b)
ON CREATE SET x.tenant = $tenant, x.owner = $owner, x.fact = '', x.weight = 0.0, x.sources = [], x.created = $now
WITH x, r, $source IN x.sources AS known
SET x.weight = CASE WHEN known THEN x.weight ELSE 1.0 - (1.0 - x.weight) * (1.0 - r.weight) END,
    x.fact = CASE WHEN r.fact <> '' THEN r.fact ELSE x.fact END,
    x.sources = CASE WHEN known THEN x.sources ELSE (x.sources + $source)[-$max_sources..] END,
    x.updated = $now
RETURN count(x) AS relations
"""

# One hop from each seed: its strongest, most recent relations.
_EXPAND: LiteralString = """
UNWIND $seeds AS seed
MATCH (s:Entity {tenant: $tenant, owner: seed.owner, key: seed.key})
CALL (s) {
  MATCH (s)-[x:RELATES_TO]-(o:Entity)
  WHERE x.tenant = $tenant AND x.owner = s.owner
  RETURN x, o
  ORDER BY x.weight DESC, x.updated DESC
  LIMIT $fanout
}
RETURN seed.owner AS owner, seed.key AS seed,
       s.name AS seed_name, s.type AS seed_type, s.description AS seed_description,
       startNode(x).key AS source_key, startNode(x).name AS source_name,
       endNode(x).key AS target_key, endNode(x).name AS target_name,
       x.type AS type, x.fact AS fact, x.weight AS weight, x.updated AS updated,
       o.key AS other_key
"""

_ENTITIES: LiteralString = """
UNWIND $seeds AS seed
MATCH (n:Entity {tenant: $tenant, owner: seed.owner, key: seed.key})
RETURN n.owner AS owner, n.key AS key, n.type AS type, n.name AS name, n.aliases AS aliases,
       n.description AS description, n.updated AS updated
"""

_RELATIONS_OF: LiteralString = """
MATCH (n:Entity {tenant: $tenant, owner: $owner, key: $key})-[x:RELATES_TO]-(:Entity)
WHERE x.tenant = $tenant AND x.owner = $owner
RETURN startNode(x).key AS source_key, startNode(x).name AS source_name,
       endNode(x).key AS target_key, endNode(x).name AS target_name,
       x.type AS type, x.fact AS fact, x.weight AS weight, x.updated AS updated
ORDER BY x.weight DESC, x.updated DESC
LIMIT $limit
"""

_FORGET_SOURCE_RELATIONS: LiteralString = """
MATCH (a:Entity {tenant: $tenant, owner: $owner})-[x:RELATES_TO]->(b:Entity)
WHERE $source IN x.sources
SET x.sources = [s IN x.sources WHERE s <> $source]
WITH a, b, x, size(x.sources) = 0 AS gone
CALL (x, gone) {
  WITH x WHERE gone
  DELETE x
}
RETURN collect(DISTINCT a.key) + collect(DISTINCT b.key) AS touched,
       sum(CASE WHEN gone THEN 1 ELSE 0 END) AS deleted
"""

# Entities the source supported, or that lost relations, and are now kept
# by nothing: no source and no relation.
_FORGET_SOURCE_ENTITIES: LiteralString = """
MATCH (n:Entity {tenant: $tenant, owner: $owner})
WHERE $source IN n.sources OR n.key IN $touched
SET n.sources = [s IN n.sources WHERE s <> $source]
WITH n WHERE size(n.sources) = 0 AND NOT (n)-[:RELATES_TO]-()
WITH n, n.key AS key
DELETE n
RETURN collect(key) AS deleted
"""

_DELETE_ENTITY: LiteralString = """
MATCH (n:Entity {tenant: $tenant, owner: $owner, key: $key})
OPTIONAL MATCH (n)-[x:RELATES_TO]-()
WITH n, count(x) AS relations
DETACH DELETE n
RETURN relations
"""

_COUNT_OWNER: LiteralString = """
MATCH (n:Entity {tenant: $tenant, owner: $owner})
OPTIONAL MATCH (n)-[x:RELATES_TO]->()
RETURN count(DISTINCT n) AS entities, count(x) AS relations
"""

_DELETE_OWNER: LiteralString = """
MATCH (n:Entity {tenant: $tenant, owner: $owner})
CALL (n) { DETACH DELETE n } IN TRANSACTIONS OF 500 ROWS
"""


@dataclass(frozen=True, slots=True)
class StoredEntity:
    owner: str
    key: str
    type: str
    name: str
    aliases: list[str]
    description: str
    updated: datetime


@dataclass(frozen=True, slots=True)
class StoredRelation:
    owner: str
    source_key: str
    source_name: str
    type: str
    target_key: str
    target_name: str
    fact: str
    weight: float
    updated: datetime

    @property
    def identity(self) -> tuple[str, str, str, str]:
        return (self.owner, self.source_key, self.type, self.target_key)


@dataclass(frozen=True, slots=True)
class Hop:
    """A relation reached from a seed entity."""

    seed: tuple[str, str]  # (owner, key)
    other: tuple[str, str]
    relation: StoredRelation


def _time(value: Any) -> datetime:
    native = value.to_native() if hasattr(value, "to_native") else value
    return native if isinstance(native, datetime) else datetime.fromtimestamp(0, UTC)


class Graph:
    def __init__(self, driver: AsyncDriver, database: str) -> None:
        self._driver = driver
        self._database = database

    async def ensure_schema(self) -> None:
        for statement in SCHEMA:
            await self._driver.execute_query(statement, database_=self._database)

    async def ping(self) -> None:
        await self._driver.verify_connectivity()

    async def upsert(
        self, owner: Owner, source_id: str, entities: list[EntityWrite], relations: list[RelationWrite]
    ) -> tuple[list[StoredEntity], int]:
        """Stores entities, then relations between them, in one transaction."""
        now = datetime.now(UTC)
        params: dict[str, Any] = {
            "tenant": owner.tenant,
            "owner": owner.value,
            "source": source_id,
            "now": now,
            "max_aliases": MAX_STORED_ALIASES,
            "max_sources": MAX_STORED_SOURCES,
        }
        entity_rows = [
            {
                "key": e.key,
                "type": e.type,
                "name": e.name,
                "aliases": e.aliases,
                "description": e.description,
                "explicit": e.explicit,
            }
            for e in entities
        ]
        relation_rows = [
            {"source_key": r.source_key, "type": r.type, "target_key": r.target_key, "fact": r.fact, "weight": r.weight}
            for r in relations
        ]

        async def work(tx: Any) -> tuple[list[StoredEntity], int]:
            stored: list[StoredEntity] = []
            if entity_rows:
                result = await tx.run(_UPSERT_ENTITIES, params | {"entities": entity_rows})
                async for row in result:
                    stored.append(
                        StoredEntity(
                            owner.value,
                            row["key"],
                            row["type"],
                            row["name"],
                            list(row["aliases"]),
                            row["description"],
                            _time(row["updated"]),
                        )
                    )
            count = 0
            if relation_rows:
                result = await tx.run(_UPSERT_RELATIONS, params | {"relations": relation_rows})
                record = await result.single()
                count = int(record["relations"]) if record else 0
            return stored, count

        async with self._driver.session(database=self._database) as session:
            result: tuple[list[StoredEntity], int] = await session.execute_write(work)
            return result

    async def entities(self, tenant: str, owners: list[str], seeds: list[tuple[str, str]]) -> list[StoredEntity]:
        """Loads entities by (owner, key); unknown ones and other owners' are skipped."""
        visible = [{"owner": o, "key": k} for o, k in seeds if o in owners]
        if not visible:
            return []
        records, _, _ = await self._driver.execute_query(
            _ENTITIES,
            {"tenant": tenant, "seeds": visible},
            database_=self._database,
            routing_=RoutingControl.READ,
        )
        return [
            StoredEntity(
                r["owner"], r["key"], r["type"], r["name"], list(r["aliases"]), r["description"], _time(r["updated"])
            )
            for r in records
        ]

    async def expand(self, reader: Reader, seeds: list[tuple[str, str]], fanout: int) -> list[Hop]:
        """Relations one hop away from each seed (strongest first, per seed)."""
        visible = [{"owner": o, "key": k} for o, k in seeds if o in reader.owners]
        if not visible:
            return []
        records, _, _ = await self._driver.execute_query(
            _EXPAND,
            {"tenant": reader.tenant, "seeds": visible, "fanout": fanout},
            database_=self._database,
            routing_=RoutingControl.READ,
        )
        hops: list[Hop] = []
        for r in records:
            relation = StoredRelation(
                owner=r["owner"],
                source_key=r["source_key"],
                source_name=r["source_name"],
                type=r["type"],
                target_key=r["target_key"],
                target_name=r["target_name"],
                fact=r["fact"],
                weight=float(r["weight"]),
                updated=_time(r["updated"]),
            )
            hops.append(Hop(seed=(r["owner"], r["seed"]), other=(r["owner"], r["other_key"]), relation=relation))
        return hops

    async def get(self, owner: Owner, key: str, limit: int) -> tuple[StoredEntity | None, list[StoredRelation]]:
        entities = await self.entities(owner.tenant, [owner.value], [(owner.value, key)])
        if not entities:
            return None, []
        records, _, _ = await self._driver.execute_query(
            _RELATIONS_OF,
            {"tenant": owner.tenant, "owner": owner.value, "key": key, "limit": limit},
            database_=self._database,
            routing_=RoutingControl.READ,
        )
        relations = [
            StoredRelation(
                owner.value,
                r["source_key"],
                r["source_name"],
                r["type"],
                r["target_key"],
                r["target_name"],
                r["fact"],
                float(r["weight"]),
                _time(r["updated"]),
            )
            for r in records
        ]
        return entities[0], relations

    async def forget_source(self, owner: Owner, source_id: str) -> tuple[int, list[str]]:
        """Removes a source; returns (relations deleted, keys of entities deleted)."""
        params = {"tenant": owner.tenant, "owner": owner.value, "source": source_id}

        async def work(tx: Any) -> tuple[int, list[str]]:
            result = await tx.run(_FORGET_SOURCE_RELATIONS, params)
            record = await result.single()
            touched = list(record["touched"]) if record else []
            relations = int(record["deleted"]) if record else 0
            result = await tx.run(_FORGET_SOURCE_ENTITIES, params | {"touched": touched})
            record = await result.single()
            return relations, list(record["deleted"]) if record else []

        async with self._driver.session(database=self._database) as session:
            outcome: tuple[int, list[str]] = await session.execute_write(work)
            return outcome

    async def delete_entity(self, owner: Owner, key: str) -> int | None:
        """Deletes an entity; returns its relation count, or None if unknown."""
        records, _, _ = await self._driver.execute_query(
            _DELETE_ENTITY, {"tenant": owner.tenant, "owner": owner.value, "key": key}, database_=self._database
        )
        return int(records[0]["relations"]) if records else None

    async def delete_owner(self, owner: Owner) -> tuple[int, int]:
        """Deletes everything of one owner; returns (entities, relations)."""
        params = {"tenant": owner.tenant, "owner": owner.value}
        records, _, _ = await self._driver.execute_query(
            _COUNT_OWNER, params, database_=self._database, routing_=RoutingControl.READ
        )
        entities, relations = int(records[0]["entities"]), int(records[0]["relations"])
        # CALL … IN TRANSACTIONS needs an implicit (auto-commit) transaction.
        async with self._driver.session(database=self._database) as session:
            result = await session.run(_DELETE_OWNER, params)
            await result.consume()
        return entities, relations
