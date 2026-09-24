"""GraphRAG retrieval: from a query to compact context within a token budget.

1. Embed the query (local model, a few ms).
2. One Qdrant round trip: similar passages, similar entities, and entities
   whose names appear in the query.
3. Seed entities: those found directly, plus those the best passages
   mention. Scores decay with indirection.
4. Follow the seeds' strongest relations in Neo4j, up to `max_hops`.
5. Rank everything by relevance and pack it, most relevant first, into as
   few tokens as possible: short lines, no duplicates, nothing below the
   relevance floor.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, field

from jarvis_knowledge.embedding import TextEmbedder
from jarvis_knowledge.graph import Graph, StoredEntity, StoredRelation
from jarvis_knowledge.metrics import Metrics
from jarvis_knowledge.model import Reader, estimate_tokens, name_candidates
from jarvis_knowledge.vectors import EntityHit, PassageHit, Vectors

# Search breadth.
PASSAGE_CANDIDATES = 24
ENTITY_CANDIDATES = 12
MAX_SEEDS = 8
FANOUT = (12, 6)  # relations followed per entity, by hop
# Score adjustments.
NAMED_SCORE = 0.97  # an entity named in the query is almost certainly relevant
MENTION_DECAY = 0.92  # entities mentioned by a relevant passage
HOP_DECAY = 0.85
# Relations must keep this share of the best seed's relevance: a weak
# second-hop relation of a weak seed costs tokens for little.
RELATION_FLOOR = 0.6


@dataclass(slots=True)
class Scored:
    score: float
    tokens: int
    line: str


@dataclass(slots=True)
class Retrieval:
    entities: list[tuple[StoredEntity, float]] = field(default_factory=list)
    relations: list[tuple[StoredRelation, float, int]] = field(default_factory=list)
    passages: list[PassageHit] = field(default_factory=list)
    context: str = ""
    tokens: int = 0
    truncated: bool = False


class Retriever:
    def __init__(
        self,
        embedder: TextEmbedder,
        vectors: Vectors,
        graph: Graph,
        metrics: Metrics,
        *,
        min_score: float,
        margin: float,
    ) -> None:
        self._embedder = embedder
        self._vectors = vectors
        self._graph = graph
        self._metrics = metrics
        self._min_score = min_score
        self._margin = margin

    async def retrieve(
        self, reader: Reader, query: str, *, budget: int, hops: int, source_kinds: Sequence[str]
    ) -> Retrieval:
        started = time.perf_counter()
        vector = await self._embedder.query(query)
        self._stage("embed", started)

        started = time.perf_counter()
        passages, similar, named = await self._vectors.search(
            reader,
            vector,
            passages=PASSAGE_CANDIDATES,
            entities=ENTITY_CANDIDATES,
            source_kinds=source_kinds,
            names=name_candidates(query),
        )
        self._stage("vector", started)
        passages, top = select(passages, similar, named, min_score=self._min_score, margin=self._margin)

        started = time.perf_counter()
        result = Retrieval(passages=passages)
        entity_scores = dict(top)
        relations: dict[tuple[str, str, str, str], tuple[StoredRelation, float, int]] = {}
        frontier = dict(top)
        for hop in range(1, hops + 1):
            if not frontier:
                break
            found = await self._graph.expand(reader, list(frontier), FANOUT[hop - 1])
            reached: dict[tuple[str, str], float] = {}
            for h in found:
                base = frontier.get(h.seed, 0.0)  # already decayed when the entity was reached
                score = base * (0.6 + 0.4 * h.relation.weight)
                known = relations.get(h.relation.identity)
                if known is None or known[1] < score:
                    relations[h.relation.identity] = (h.relation, score, hop)
                if h.other not in entity_scores:
                    reached[h.other] = max(reached.get(h.other, 0.0), base * HOP_DECAY)
            frontier = dict(sorted(reached.items(), key=lambda kv: -kv[1])[: MAX_SEEDS * 2])
        stored = await self._graph.entities(reader.tenant, reader.owners, [k for k, _ in top])
        self._stage("graph", started)

        result.entities = sorted(((e, entity_scores[(e.owner, e.key)]) for e in stored), key=lambda es: -es[1])
        floor = RELATION_FLOOR * (top[0][1] if top else 0.0)
        result.relations = sorted((r for r in relations.values() if r[1] >= floor), key=lambda r: -r[1])
        started = time.perf_counter()
        pack(result, budget)
        self._stage("pack", started)
        return result

    def _stage(self, stage: str, started: float) -> None:
        self._metrics.retrieve_stage.labels(stage).observe(time.perf_counter() - started)


def select(
    passages: Sequence[PassageHit],
    similar: Sequence[EntityHit],
    named: Sequence[EntityHit],
    *,
    min_score: float,
    margin: float,
) -> tuple[list[PassageHit], list[tuple[tuple[str, str], float]]]:
    """Keeps the relevant passages and picks the entities to start from.

    Similarity scores are only meaningful relative to each other (E5 puts
    unrelated text at 0.7-0.8), so besides the absolute floor an item must
    be within `margin` of the best match: passages of the best passage,
    entities of the best passage or entity.
    """
    best_passage = max((p.score for p in passages), default=0.0)
    kept = [p for p in passages if p.score >= max(min_score, best_passage - margin)]
    entity_floor = max(min_score, max([best_passage, *(h.score for h in similar)]) - margin)

    seeds: dict[tuple[str, str], float] = {}

    def seed(owner: str, key: str, score: float) -> None:
        seeds[(owner, key)] = max(score, seeds.get((owner, key), 0.0))

    for hit in similar:
        if hit.score >= entity_floor:
            seed(hit.owner, hit.key, hit.score)
    for hit in named:
        seed(hit.owner, hit.key, max(NAMED_SCORE, hit.score))
    for passage in kept[:MAX_SEEDS]:
        for key in passage.mentions:
            seed(passage.owner, key, passage.score * MENTION_DECAY)
    return kept, sorted(seeds.items(), key=lambda kv: -kv[1])[:MAX_SEEDS]


def humanize(relation_type: str) -> str:
    return relation_type.lower().replace("_", " ")


def entity_line(entity: StoredEntity) -> str:
    line = f"- {entity.name} ({entity.type})"
    return f"{line}: {entity.description}" if entity.description else line


def relation_line(relation: StoredRelation) -> str:
    if relation.fact:
        return f"- {relation.fact}"
    return f"- {relation.source_name} {humanize(relation.type)} {relation.target_name}"


def passage_line(passage: PassageHit) -> str:
    about = [passage.source.occurred.date().isoformat()] if passage.source.occurred else []
    about.append(passage.source.kind)
    if passage.source.title:
        about.append(f'"{passage.source.title}"')
    text = " ".join(passage.text.split())
    return f"- ({', '.join(about)}) {text}"


_HEADERS = {"entities": "Entities:", "relations": "Facts:", "passages": "Notes:"}


def pack(result: Retrieval, budget: int) -> None:
    """Keeps the most relevant items that fit the budget and renders them."""
    candidates: list[tuple[str, int, Scored]] = []
    seen: set[str] = set()

    def add(section: str, index: int, score: float, line: str) -> None:
        if line not in seen:  # the same sentence twice costs tokens for nothing
            seen.add(line)
            candidates.append((section, index, Scored(score, estimate_tokens(line + "\n"), line)))

    for i, (entity, score) in enumerate(result.entities):
        add("entities", i, score, entity_line(entity))
    for i, (relation, score, _) in enumerate(result.relations):
        add("relations", i, score, relation_line(relation))
    for i, passage in enumerate(result.passages):
        add("passages", i, passage.score, passage_line(passage))

    chosen: dict[str, list[tuple[int, Scored]]] = {section: [] for section in _HEADERS}
    used = 0
    for section, index, item in sorted(candidates, key=lambda c: -c[2].score):
        cost = item.tokens + (0 if chosen[section] else estimate_tokens(_HEADERS[section] + "\n"))
        if used + cost > budget:
            result.truncated = True
            continue
        chosen[section].append((index, item))
        used += cost

    keep = {section: {index for index, _ in items} for section, items in chosen.items()}
    result.entities = [e for i, e in enumerate(result.entities) if i in keep["entities"]]
    result.relations = [r for i, r in enumerate(result.relations) if i in keep["relations"]]
    result.passages = [p for i, p in enumerate(result.passages) if i in keep["passages"]]

    blocks = []
    for section, header in _HEADERS.items():
        if chosen[section]:
            lines = [item.line for _, item in sorted(chosen[section], key=lambda c: -c[1].score)]
            blocks.append("\n".join([header, *lines]))
    result.context = "\n".join(blocks)
    result.tokens = estimate_tokens(result.context) if result.context else 0
