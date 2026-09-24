# Knowledge service

Jarvis's long-term memory. It keeps a **knowledge graph** of entities and their relations in Neo4j, and **passages** of text in Qdrant. It searches both together, so the agent gets a few relevant lines instead of whole documents. The gRPC contract is [`proto/jarvis/knowledge/v1/knowledge.proto`](../../proto/jarvis/knowledge/v1/knowledge.proto).

```
orchestrator ──gRPC+mTLS──▶ knowledge ──▶ Neo4j:  (:Entity)-[:RELATES_TO]->(:Entity)
dashboard    ─────────────▶    │     └──▶ Qdrant: passage + entity vectors
                               └── local embedding model (no external API)
```

| Caller | May call |
|---|---|
| orchestrator (`spiffe://jarvis.local/orchestrator`) | `UpsertKnowledge`, `Retrieve`, `GetEntity`, `DeleteSource`, `DeleteEntity` |
| dashboard (`spiffe://jarvis.local/dashboard-api`) | `GetEntity`, `DeleteSource`, `DeleteEntity`, `DeleteUserKnowledge` |

## Writing knowledge

The orchestrator's LLM sidecar extracts entities, relations and passages from a conversation, document or tool result. It stores them with `UpsertKnowledge`, naming the **source** they came from. The service never calls an LLM and never holds API keys.

- **Entities** are identified by type and normalized name: `Person:μαρια παπαδοπουλου`. Case, accents and spacing are ignored.
  - Aliases are merged.
  - A newer non-empty description replaces the old one.
  - An entity that is only referenced (by a relation or a passage mention) is created by name, and never renames an existing one.
- **Relations** (`WORKS_ON`, `LEADS`, …) connect two entities in the same scope.
  - Each source adds its evidence once: weights combine as `1 − (1 − w₁)(1 − w₂)`. Two sources at 0.5 give 0.75.
  - A retry with the same source changes nothing.
- **Passages** are pieces of text, up to 8000 characters. Callers split longer text.
- **Idempotency:** everything is idempotent, so retrying a failed upsert converges.

## Scopes

- **`SCOPE_USER`** (the default): private to one user.
- **`SCOPE_TENANT`**: shared with every user of the tenant, e.g. a company handbook.
- **Reads:** a user reads their own knowledge plus the tenant's shared knowledge. Nothing crosses tenants.

## Retrieval (`Retrieve`)

1. **Embed the query** with the local model: about 2 ms.
2. **One Qdrant round trip** finds three things:
   - similar passages,
   - similar entity descriptions,
   - entities whose names or aliases appear in the query (normalized word n-grams, so «τι κάνει η Μαρία;» finds `Μαρία Παπαδοπούλου`).
3. **Keep only what is relevant.**
   - Similarity must be above the floor (0.78).
   - It must also be within 0.04 of the query's best match. E5 scores unrelated text at 0.7–0.8, so only relative scores separate relevant from irrelevant.
4. **Seed entities** are the relevant entity hits, the entities named in the query, and the entities that the relevant passages mention.
5. **Follow relations in Neo4j** up to `max_hops` (default 1): the strongest and most recent relations of each seed. A relation is kept only if it holds at least 60% of the best seed's relevance.
6. **Pack** the most relevant items into `token_budget` (default 800) as short lines:

```
Entities:
- Νίκος Γεωργίου (Person): Backend developer
Facts:
- Ο Νίκος φτιάχνει το API πληρωμών του Atlas
Notes:
- (2026-09-22, conversation, "Εβδομαδιαία σύσκεψη") Ο Νίκος είπε ότι το API πληρωμών θα είναι έτοιμο την Τετάρτη…
```

Duplicate sentences are dropped, and `truncated` says whether relevant items did not fit. Tokens are estimated as UTF-8 bytes / 4. That is exact for English and overestimates Greek, so the context fits any model's tokenizer.

**Measured** on this machine against the Docker Compose stores, with 300 passages, 150 entities and 200 relations: Retrieve took **p50 15 ms, p95 21 ms**.

| Stage | Share of the time |
|---|---|
| embedding | 2 ms |
| Qdrant | 5 ms |
| Neo4j | most of the rest |

## Forgetting

| RPC | Forgets |
|---|---|
| `DeleteSource` | a source's passages, and the relations and entities that no other source supports |
| `DeleteEntity` | an entity and its relations (passages that mention it stay) |
| `DeleteUserKnowledge` | everything private to a user (the right to be forgotten); shared knowledge stays |

## The embedding model

- **Model:** [`intfloat/multilingual-e5-small`](https://huggingface.co/intfloat/multilingual-e5-small). MIT licensed, 384 dimensions, about 100 languages including Greek. Greek queries find English text and the other way round.
- **Pinning:** the model is pinned to an exact revision, and every file is checked against its SHA-256. A corrupt or substituted file is refused.
- **Development:** it is downloaded once into `.dev/models` (470 MB, `KNOWLEDGE_MODEL_DOWNLOAD=true` in `scripts/dev-run.sh`).
- **Production:** production images include the files (`knowledgectl download-model --dir …`) and run with downloads disabled.
- **Runtime:** inference runs on CPU in a thread pool (ONNX Runtime), off the event loop.
- **Memory:** the process uses about 0.9 GB of RAM, most of it the fp32 model. An int8 model would roughly halve that at some cost in quality.

## Run it locally

```bash
pnpm infra:up                              # Neo4j, Qdrant (and the other stores)
pnpm nx run vault:serve                    # once: creates the development CA the certificates come from
pnpm nx run knowledge:serve                # downloads the model on first run
```

Then, from `services/knowledge`:

```bash
T=6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f
uv run knowledgectl upsert --tenant $T --user me --file notes.json
uv run knowledgectl retrieve --tenant $T --user me --query "Τι κάνει ο Νίκος;"
uv run knowledgectl entity --tenant $T --user me --key "Person:νικος γεωργιου"
uv run knowledgectl delete-source --tenant $T --user me --source conversation:1
uv run knowledgectl forget-user --tenant $T --user me
```

`notes.json` is an `UpsertKnowledgeRequest` in protobuf JSON, without tenant and user:

```json
{"source": {"id": "conversation:1", "kind": "conversation", "title": "Weekly sync"},
 "entities": [{"type": "Person", "name": "Νίκος Γεωργίου", "aliases": ["Νίκος"], "description": "Backend developer"}],
 "relations": [{"source": {"type": "Person", "name": "Νίκος Γεωργίου"}, "type": "WORKS_ON",
                "target": {"type": "Project", "name": "Atlas"}, "fact": "Ο Νίκος φτιάχνει το API πληρωμών του Atlas"}],
 "passages": [{"text": "Ο Νίκος είπε ότι το API πληρωμών θα είναι έτοιμο την Τετάρτη."}]}
```

- **Metrics:** `http://127.0.0.1:9093/metrics`, including `knowledge_retrieve_stage_seconds` by stage.
- **Health:** `/healthz` checks both stores.

## Development

```bash
pnpm nx run knowledge:test     # pytest: real Neo4j and Qdrant (testcontainers), mTLS gRPC
pnpm nx run knowledge:lint     # ruff, mypy --strict, uv.lock up to date
```

The Python toolchain is one [uv](https://docs.astral.sh/uv/) workspace at the repository root (`pyproject.toml`, `uv.lock`, Python pinned in `.python-version`). The gRPC code comes from `/proto` into [`gen/python`](../../gen/python), is committed, and is checked by `proto:lint`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `KNOWLEDGE_LISTEN_ADDR` | `127.0.0.1:50053` | gRPC listener (mTLS) |
| `KNOWLEDGE_ADMIN_ADDR` | `127.0.0.1:9093` | metrics and health; must be loopback |
| `KNOWLEDGE_TLS_CERT`, `KNOWLEDGE_TLS_KEY`, `KNOWLEDGE_TLS_CLIENT_CA` | required | server certificate and the CA of callers |
| `KNOWLEDGE_AUTHZ_POLICY` | required | `[[principal]] id / allow` TOML |
| `KNOWLEDGE_REFLECTION` | `false` | gRPC reflection |
| `KNOWLEDGE_NEO4J_URI`, `…_USER`, `…_PASSWORD` (or `_FILE`), `…_DATABASE` | `bolt://127.0.0.1:57687`, `neo4j`, required, `neo4j` | Neo4j; `bolt+s://` or `neo4j+s://` unless on this machine |
| `KNOWLEDGE_QDRANT_URL`, `…_GRPC_PORT`, `…_API_KEY` (or `_FILE`), `…_COLLECTION` | `http://127.0.0.1:56333`, `56334`, required, `jarvis_knowledge` | Qdrant; `https://` unless on this machine |
| `KNOWLEDGE_MODEL`, `KNOWLEDGE_MODEL_DIR`, `KNOWLEDGE_MODEL_DOWNLOAD` | e5-small, required, `false` | embedding model |
| `KNOWLEDGE_EMBED_THREADS`, `KNOWLEDGE_EMBED_CONCURRENCY` | `4`, `2` | ONNX threads per inference, concurrent inferences |
| `KNOWLEDGE_MIN_SCORE`, `KNOWLEDGE_RELEVANCE_MARGIN` | `0.78`, `0.04` | relevance floor and margin below the best match |
| `KNOWLEDGE_LOG_FORMAT`, `KNOWLEDGE_LOG_LEVEL` | `json`, `info` | logging (never query or knowledge text) |

## Known limitations

- **Encryption at rest:** knowledge text and vectors are stored in plaintext in Neo4j and Qdrant. Run them on encrypted volumes. Text is not Vault-sealed, because searching needs it.
- **Neo4j Community Edition:** one database and one user for all tenants. Isolation is enforced by every query, not by the database.
- **Entity resolution** is by type and normalized name, plus the aliases the extractor supplies. Inflected forms («της Μαρίας») match only if listed as aliases, or through the embeddings.
- **Deleting a source** does not recompute the weights that source had strengthened. Each entity or relation remembers its latest 64 sources.
- **Changing the model** needs a new collection (`KNOWLEDGE_QDRANT_COLLECTION`) and re-ingestion. The service refuses to start on a vector-size mismatch.
