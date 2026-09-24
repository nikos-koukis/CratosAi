# Project Jarvis

A voice-first, multi-tenant AI agent platform where tenants bring their own LLM keys (BYOK). This is a polyglot monorepo orchestrated with [Nx](https://nx.dev). Services talk to each other over gRPC.

## Layout

| Path | What |
|---|---|
| [`proto/`](proto/) | gRPC contracts, the single source of truth (linted with `buf`) |
| [`services/vault/`](services/vault/) | BYOK Vault (Rust): envelope-encrypted provider keys over mTLS |
| [`services/voice-gateway/`](services/voice-gateway/) | Voice gateway (Go): real-time audio between apps and OpenAI / xAI |
| [`services/mcp-router/`](services/mcp-router/) | MCP router (Go): users' external tools (Jira, Linear, Notion, GitHub, …) over MCP and OAuth 2.1 |
| [`services/knowledge/`](services/knowledge/) | Knowledge service (Python): long-term memory, GraphRAG over Neo4j + Qdrant with local embeddings |
| [`services/orchestrator/`](services/orchestrator/) | Orchestrator (Go): the voice model's tools, spoken confirmations, durable background tasks, memory |
| [`services/agent/`](services/agent/) | Agent sidecar (Python, LangGraph): the orchestrator's LLM decisions and memory extraction, over a Unix socket |
| [`daemons/mac-daemon/`](daemons/mac-daemon/) | Local daemon (Rust): sandboxed, approval-gated commands on the user's Mac |
| [`libs/rust/jarvis-common/`](libs/rust/jarvis-common/) | Shared Rust code: mTLS identity, RPC authorization, logging |
| [`libs/go/`](libs/go/) | Shared Go code: mTLS identity and RPC authorization, Vault client |
| [`gen/go/`](gen/go/), [`gen/python/`](gen/python/) | Go and Python code generated from `proto/` (`pnpm nx run proto:generate`) |
| [`deploy/compose/`](deploy/compose/) | Local infrastructure: PostgreSQL, DragonflyDB, Neo4j, Qdrant |

## Prerequisites

- Node ≥ 22 with pnpm 10
- Docker Desktop
- Rust via rustup. [`rust-toolchain.toml`](rust-toolchain.toml) pins the version, and rustup installs it automatically.
- Go 1.24 or newer. [`go.work`](go.work) pins 1.27.1, and Go downloads it automatically.
- [uv](https://docs.astral.sh/uv/). [`.python-version`](.python-version) pins Python 3.14, and uv downloads it when missing. Run `uv sync --all-packages --all-groups` once.

## Everyday commands

```bash
pnpm install
pnpm infra:up                 # start local databases (first run generates secrets)
pnpm check                    # lint + format-check + build, every project
pnpm test                     # unit + integration tests (needs Docker)
pnpm infra:test               # smoke-test the local infrastructure
pnpm nx run vault:serve       # run the Vault against the local infrastructure
pnpm nx run mcp-router:serve  # run the MCP router (needs the Vault)
pnpm nx run knowledge:serve   # run the knowledge service (needs the Vault's dev CA once)
pnpm nx run agent:serve       # run the agent sidecar (Unix socket)
pnpm nx run orchestrator:serve  # run the orchestrator (needs the four above)
pnpm nx run voice-gateway:serve # run the voice gateway (tools come from the orchestrator)
pnpm infra:down               # stop local databases (data is kept)
```

To run the whole stack without spending API credits, use the fake providers: `voicectl echo-provider` for realtime voice and `jarvis-fake-llm` for the Responses API. See the [orchestrator README](services/orchestrator/README.md#development).
