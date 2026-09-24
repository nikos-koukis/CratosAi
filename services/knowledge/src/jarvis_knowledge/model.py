"""Validated domain values: owners, entity keys, request limits."""

from __future__ import annotations

import hashlib
import re
import unicodedata
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

from jarvis.knowledge.v1 import knowledge_pb2 as pb

# Request limits (see knowledge.proto).
MAX_ENTITIES = 200
MAX_RELATIONS = 500
MAX_PASSAGES = 200
MAX_ALIASES = 20
MAX_MENTIONS = 50
MAX_NAME = 200
MAX_DESCRIPTION = 2000
MAX_FACT = 1000
MAX_PASSAGE = 8000
MAX_QUERY = 2000
MAX_TITLE = 200
MAX_URI = 2048
# Stored per entity; the oldest are dropped beyond these.
MAX_STORED_ALIASES = 50
MAX_STORED_SOURCES = 64

DEFAULT_TOKEN_BUDGET = 800
DEFAULT_WEIGHT = 0.5

_ENTITY_TYPE = re.compile(r"^[A-Z][A-Za-z0-9]{0,31}$")
_RELATION_TYPE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SOURCE_KIND = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_KEY = re.compile(r"^[A-Z][A-Za-z0-9]{0,31}:.{1,400}$", re.DOTALL)
_WORD = re.compile(r"\w+")
# Point ids in Qdrant must be UUIDs; derived deterministically for idempotency.
_POINTS = uuid.UUID("5d2c6c4e-8f0e-4d2f-9b7e-3f1a2c9d4e10")


class InvalidArgument(ValueError):
    """A request field is missing, malformed or over its limit."""


def printable_ascii(value: str, low: int, high: int) -> bool:
    return low <= len(value) <= high and all(0x20 <= ord(c) <= 0x7E for c in value)


def clean_text(value: str, field_name: str, high: int, *, required: bool = False) -> str:
    """Trims text and rejects control characters (newlines and tabs are kept)."""
    value = value.strip()
    if required and not value:
        raise InvalidArgument(f"{field_name} is required")
    if len(value) > high:
        raise InvalidArgument(f"{field_name} is longer than {high} characters")
    if any(unicodedata.category(c) == "Cc" and c not in "\n\t" for c in value):
        raise InvalidArgument(f"{field_name} contains control characters")
    return value


def normalize(text: str) -> str:
    """Case-, accent- and spacing-insensitive form used to match names."""
    decomposed = unicodedata.normalize("NFKD", text.casefold())
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return " ".join(_WORD.findall(unicodedata.normalize("NFKC", stripped)))


def name_candidates(query: str, max_words: int = 4) -> list[str]:
    """Normalized word n-grams of a query, for matching entity names."""
    words = normalize(query).split()
    grams = {" ".join(words[i : i + n]) for n in range(1, max_words + 1) for i in range(len(words) - n + 1)}
    return sorted(g for g in grams if len(g) >= 2)


def estimate_tokens(text: str) -> int:
    """Conservative token estimate: UTF-8 bytes / 4.

    Exact for typical English; overestimates Greek (2 bytes per letter), so
    context stays within budget for any model's tokenizer.
    """
    return (len(text.encode()) + 3) // 4


@dataclass(frozen=True, slots=True)
class Owner:
    """Who a piece of knowledge belongs to within a tenant."""

    tenant: str
    # "u:<user id>" (SCOPE_USER) or "t" (SCOPE_TENANT).
    value: str

    @property
    def scope(self) -> pb.Scope.ValueType:
        return pb.SCOPE_TENANT if self.value == "t" else pb.SCOPE_USER


@dataclass(frozen=True, slots=True)
class Reader:
    """A user reading: sees their own and the tenant's shared knowledge."""

    tenant: str
    user: str

    @property
    def owners(self) -> list[str]:
        return [f"u:{self.user}", "t"]


def parse_tenant(tenant_id: str) -> str:
    try:
        parsed = uuid.UUID(tenant_id)
    except ValueError:
        parsed = None
    if parsed is None or parsed.int == 0 or str(parsed) != tenant_id:
        raise InvalidArgument("tenant_id must be a canonical lowercase UUID")
    return tenant_id


def parse_user(user_id: str) -> str:
    if not printable_ascii(user_id, 1, 128):
        raise InvalidArgument("user_id must be 1 to 128 printable ASCII characters")
    return user_id


def parse_reader(tenant_id: str, user_id: str) -> Reader:
    return Reader(parse_tenant(tenant_id), parse_user(user_id))


def parse_owner(tenant_id: str, user_id: str, scope: pb.Scope.ValueType) -> Owner:
    tenant, user = parse_tenant(tenant_id), parse_user(user_id)
    match scope:
        case pb.SCOPE_UNSPECIFIED | pb.SCOPE_USER:
            return Owner(tenant, f"u:{user}")
        case pb.SCOPE_TENANT:
            return Owner(tenant, "t")
        case _:
            raise InvalidArgument("unknown scope")


def scope_of(owner: str) -> pb.Scope.ValueType:
    return pb.SCOPE_TENANT if owner == "t" else pb.SCOPE_USER


def entity_type(value: str) -> str:
    if not _ENTITY_TYPE.match(value):
        raise InvalidArgument(f"entity type {value[:40]!r} must match [A-Z][A-Za-z0-9]{{0,31}}")
    return value


def relation_type(value: str) -> str:
    if not _RELATION_TYPE.match(value):
        raise InvalidArgument(f"relation type {value[:70]!r} must match [A-Z][A-Z0-9_]{{0,63}}")
    return value


def entity_key(type_: str, name: str) -> str:
    """Identity of an entity within its scope: "<type>:<normalized name>"."""
    normalized = normalize(name)
    if not normalized:
        raise InvalidArgument(f"entity name {name[:40]!r} has no letters or digits")
    return f"{type_}:{normalized}"


def parse_key(key: str) -> str:
    if not _KEY.match(key) or normalize(key.partition(":")[2]) != key.partition(":")[2]:
        raise InvalidArgument("key must be an entity key such as Person:maria papadopoulou")
    return key


def passage_point_id(owner: Owner, source_id: str, passage_id: str) -> str:
    return str(uuid.uuid5(_POINTS, f"passage\x00{owner.tenant}\x00{owner.value}\x00{source_id}\x00{passage_id}"))


def entity_point_id(owner: Owner, key: str) -> str:
    return str(uuid.uuid5(_POINTS, f"entity\x00{owner.tenant}\x00{owner.value}\x00{key}"))


def default_passage_id(source_id: str, text: str) -> str:
    return hashlib.sha256(f"{source_id}\x00{text}".encode()).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class SourceInfo:
    id: str
    kind: str
    title: str
    uri: str
    occurred: datetime | None


@dataclass(slots=True)
class EntityWrite:
    key: str
    type: str
    name: str
    aliases: list[str] = field(default_factory=list)
    description: str = ""
    # Created from a reference only: never overwrites a known name.
    explicit: bool = True


@dataclass(frozen=True, slots=True)
class RelationWrite:
    source_key: str
    type: str
    target_key: str
    fact: str
    weight: float


@dataclass(frozen=True, slots=True)
class PassageWrite:
    id: str
    text: str
    mentions: list[str]


@dataclass(slots=True)
class Upsert:
    owner: Owner
    source: SourceInfo
    entities: dict[str, EntityWrite]
    relations: list[RelationWrite]
    passages: list[PassageWrite]


def parse_source(source: pb.Source) -> SourceInfo:
    if not printable_ascii(source.id, 1, 128):
        raise InvalidArgument("source.id must be 1 to 128 printable ASCII characters")
    if not _SOURCE_KIND.match(source.kind):
        raise InvalidArgument("source.kind must match [a-z][a-z0-9_]{0,31}")
    uri = clean_text(source.uri, "source.uri", MAX_URI)
    if uri and not urlsplit(uri).scheme:
        raise InvalidArgument("source.uri must be an absolute URI")
    occurred = None
    if source.HasField("occurred_time"):
        occurred = source.occurred_time.ToDatetime(tzinfo=UTC)
    return SourceInfo(
        id=source.id,
        kind=source.kind,
        title=clean_text(source.title, "source.title", MAX_TITLE),
        uri=uri,
        occurred=occurred,
    )


def parse_upsert(req: pb.UpsertKnowledgeRequest) -> Upsert:
    owner = parse_owner(req.tenant_id, req.user_id, req.scope)
    if not req.HasField("source"):
        raise InvalidArgument("source is required")
    source = parse_source(req.source)
    if len(req.entities) > MAX_ENTITIES or len(req.relations) > MAX_RELATIONS or len(req.passages) > MAX_PASSAGES:
        raise InvalidArgument(f"at most {MAX_ENTITIES} entities, {MAX_RELATIONS} relations and {MAX_PASSAGES} passages")
    if not (req.entities or req.relations or req.passages):
        raise InvalidArgument("nothing to store: give entities, relations or passages")
    entities = _parse_entities(req.entities)
    relations = _parse_relations(req.relations, entities)
    passages = _parse_passages(req.passages, source.id, entities)
    return Upsert(owner, source, entities, relations, passages)


def _parse_entities(inputs: Iterable[pb.EntityInput]) -> dict[str, EntityWrite]:
    entities: dict[str, EntityWrite] = {}
    for e in inputs:
        type_ = entity_type(e.type)
        name = clean_text(e.name, "entity name", MAX_NAME, required=True)
        key = entity_key(type_, name)
        if len(e.aliases) > MAX_ALIASES:
            raise InvalidArgument(f"at most {MAX_ALIASES} aliases per entity")
        aliases = [a for a in (clean_text(a, "alias", MAX_NAME) for a in e.aliases) if a and normalize(a)]
        description = clean_text(e.description, "entity description", MAX_DESCRIPTION)
        known = entities.get(key)
        if known is not None:  # the same entity twice in one request: merge
            known.aliases = _dedupe([*known.aliases, *aliases])
            known.description = description or known.description
        else:
            entities[key] = EntityWrite(key, type_, name, _dedupe(aliases), description)
    return entities


def _reference(ref: pb.EntityRef, what: str, entities: dict[str, EntityWrite]) -> str:
    """Resolves a reference, adding a name-only entity when it is not in the request."""
    type_ = entity_type(ref.type)
    name = clean_text(ref.name, f"{what} name", MAX_NAME, required=True)
    key = entity_key(type_, name)
    entities.setdefault(key, EntityWrite(key, type_, name, explicit=False))
    return key


def _parse_relations(inputs: Iterable[pb.RelationInput], entities: dict[str, EntityWrite]) -> list[RelationWrite]:
    relations: dict[tuple[str, str, str], RelationWrite] = {}
    for r in inputs:
        if not r.HasField("source") or not r.HasField("target"):
            raise InvalidArgument("relations need a source and a target")
        weight = r.weight if r.HasField("weight") else DEFAULT_WEIGHT
        if not 0.0 <= weight <= 1.0:
            raise InvalidArgument("relation weight must be between 0 and 1")
        relation = RelationWrite(
            source_key=_reference(r.source, "relation source", entities),
            type=relation_type(r.type),
            target_key=_reference(r.target, "relation target", entities),
            fact=clean_text(r.fact, "relation fact", MAX_FACT),
            weight=weight,
        )
        if relation.source_key == relation.target_key:
            raise InvalidArgument("a relation cannot connect an entity to itself")
        relations[(relation.source_key, relation.type, relation.target_key)] = relation
    return list(relations.values())


def _parse_passages(
    inputs: Iterable[pb.PassageInput], source_id: str, entities: dict[str, EntityWrite]
) -> list[PassageWrite]:
    passages: dict[str, PassageWrite] = {}
    for p in inputs:
        text = clean_text(p.text, "passage text", MAX_PASSAGE, required=True)
        passage_id = p.id or default_passage_id(source_id, text)
        if not printable_ascii(passage_id, 1, 128):
            raise InvalidArgument("passage id must be 1 to 128 printable ASCII characters")
        if len(p.mentions) > MAX_MENTIONS:
            raise InvalidArgument(f"at most {MAX_MENTIONS} mentions per passage")
        mentions = list(dict.fromkeys(_reference(m, "mention", entities) for m in p.mentions))
        passages[passage_id] = PassageWrite(passage_id, text, mentions)
    return list(passages.values())


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        n = normalize(v)
        if n not in seen:
            seen.add(n)
            out.append(v)
    return out
