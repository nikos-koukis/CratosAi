# Agent sidecar

The [orchestrator](../orchestrator/)'s LLM worker, in Python. It makes one decision per call:
- the next step of a background task,
- or the knowledge in a finished conversation.

It keeps no state and holds no keys: every call brings the model, the tenant's key and the history. The gRPC contract is [`proto/jarvis/agent/v1/agent.proto`](../../proto/jarvis/agent/v1/agent.proto).

```
orchestrator ──gRPC over a Unix socket (0600)──▶ sidecar ──HTTPS──▶ OpenAI / xAI Responses API
```

## RPCs

| RPC | What it does |
|---|---|
| `Decide` | One step of a task. It sends the instructions, the history and the tools to the Responses API, and returns the model's text or tool calls. It also returns the model's output items, which the orchestrator stores and replays as history. |
| `ExtractKnowledge` | Turns a transcript into entities, relations and passages for the [knowledge service](../knowledge/). |

- **Providers:** OpenAI and xAI, both through the Responses API with the `openai` SDK. xAI uses its own base URL. Requests use `store=false`, so providers keep no conversation state.
- **Extraction** is a small LangGraph graph: extract → validate → repair once → done.
  - The model answers in a strict JSON schema.
  - The output is checked against the knowledge service's rules: PascalCase types, non-empty names, no self-relations, weights between 0 and 1, bounded sizes.
  - Anything still invalid after one repair is dropped.
  - The prompt treats the transcript as data, never as instructions.

## Security

- **Local only.** It listens only on a Unix socket with mode 0600, so only the orchestrator's user can connect. There is no network listener except the loopback admin port.
- **Keys** arrive per call. They are never logged or stored, and neither are prompts or transcripts. LangSmith tracing is forced off.
- **Provider errors** are mapped to gRPC codes, but their messages are never passed on, because they can echo the prompt. The mapping:
  - 401/403 → `UNAUTHENTICATED`
  - 429 → `RESOURCE_EXHAUSTED`
  - 400/404/422 → `FAILED_PRECONDITION`
  - anything else → `UNAVAILABLE`
- **Provider URLs** must be HTTPS, except loopback URLs for local fakes.

## Configuration

| Variable | Default | |
|---|---|---|
| `AGENT_SOCKET` | required | Unix socket path (at most 103 bytes) |
| `AGENT_ADMIN_ADDR` | `127.0.0.1:9095` | `/healthz`, `/metrics` (loopback only) |
| `AGENT_OPENAI_BASE_URL` / `AGENT_XAI_BASE_URL` | `https://api.openai.com/v1` / `https://api.x.ai/v1` | |
| `AGENT_REQUEST_TIMEOUT_SECONDS`, `AGENT_MAX_RETRIES` | `90`, `2` | Per provider request |
| `AGENT_MAX_CONCURRENCY` | `32` | Concurrent provider calls |
| `AGENT_LOG_FORMAT`, `AGENT_LOG_LEVEL` | `json`, `info` | |

The metrics are:
- `agent_calls_total{method,provider,outcome}`
- `agent_call_seconds`
- `agent_tokens_total{provider,direction}`

## Development

```bash
pnpm nx run agent:serve     # socket services/agent/.dev/agent.sock, the orchestrator's default
```

**Without API costs:** `jarvis-fake-llm` is a local stand-in for the Responses API.
- **Tasks:** it calls `--tool` once, then summarizes the result.
- **Extraction:** it turns each user line into a passage.
- **Keys:** it accepts only `--key`, which proves the tenant's key from the Vault reaches the provider. Use a made-up key, never a real one.

```bash
uv run jarvis-fake-llm --key sk-dev-fake-0001 --tool work_tracker__echo --tool-args '{"text":"hi"}'
AGENT_OPENAI_BASE_URL=http://127.0.0.1:9910/v1 AGENT_XAI_BASE_URL=http://127.0.0.1:9910/v1 pnpm nx run agent:serve
```

## Tests

```bash
pnpm nx run agent:test   # pytest: the sidecar on a real Unix socket
```

They cover:
- decisions and tool calls, with history replay
- the xAI endpoint
- mapping of provider errors
- invalid requests
- extraction with repair and dropping
- that keys and content are never logged
- the socket's permissions
- the configuration
- the whole path against `jarvis-fake-llm` over real HTTP
