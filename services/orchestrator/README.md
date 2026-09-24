# Orchestrator

Jarvis's execution engine. It gives the realtime voice model its tools, runs the calls under the user's policies, runs long work durably in the background, and turns finished conversations into long-term memory. The gRPC contract is [`proto/jarvis/orchestrator/v1/orchestrator.proto`](../../proto/jarvis/orchestrator/v1/orchestrator.proto).

```
voice gateway ──gRPC+mTLS──▶ orchestrator ──▶ PostgreSQL: conversations, tasks, confirmations, events, devices
dashboard     ─────────────▶      │
                                  ├──gRPC+mTLS──▶ Vault: tenant keys (GetDecryptedKey), device keys (Seal/OpenData)
                                  ├──gRPC+mTLS──▶ MCP router: the user's integrations (ListTools, CallTool)
                                  ├──gRPC+mTLS──▶ knowledge: recall and remember (Retrieve, UpsertKnowledge)
                                  ├──gRPC+mTLS──▶ Mac daemon: commands on the user's computer (tailnet only)
                                  └──gRPC, Unix socket──▶ agent sidecar (Python): LLM decisions, memory extraction
```

The Go engine owns every piece of state. The [agent sidecar](../agent/) is stateless: each call brings the model, the tenant's key and the history.

| Caller | May call |
|---|---|
| voice gateway (`spiffe://jarvis.local/voice-gateway`) | `OpenConversation`, `RecordTurn`, `CallTool`, `AckToolOutput`, `WatchConversation`, `AckEvent`, `CloseConversation` |
| dashboard (`spiffe://jarvis.local/dashboard-api`) | `GetTask`, `ListTasks`, `CancelTask`, `RegisterDevice`, `ListDevices`, `RemoveDevice`, `SubmitDeviceApproval` |
| app API (`spiffe://jarvis.local/app-api`) | `GetTask`, `ListTasks`, `CancelTask`, `ListDevices`, `SubmitDeviceApproval` for the signed-in user of the iPhone app; `ClaimNotifications`, `CompleteNotifications` for push notifications |

## A voice conversation

The voice gateway drives one conversation per voice session:

1. **`OpenConversation`** returns instructions and function tools for the realtime model. It also brings along anything from the user's earlier conversations that they have not heard yet.
2. **`RecordTurn`** records each user speech turn when it ends, and each final transcript.
3. **`CallTool`** runs a function call of the model. The result is stored per call id, so a retried call returns the same output without running it twice.
4. **`WatchConversation`** streams events for the gateway to put into the conversation: a background task finished, a task needs a confirmation, a command needs approval. The gateway acknowledges each one with **`AckEvent`**.
5. **`CloseConversation`** ends it. The transcript becomes long-term memory in the background.

## Tools

| Tool | What it does |
|---|---|
| `recall_memory` | Searches the user's long-term memory (knowledge service, 600-token budget) |
| `remember` | Saves a note to the user's memory |
| `start_task` | Starts a background task for work with several steps or apps; the result is reported later |
| `confirm_action` / `cancel_action` | Settle an action that waits for the user's consent |
| `run_on_computer` | Runs a command on one of the user's registered computers |
| `<integration>__<tool>` | The user's MCP tools, e.g. `work_jira__create_issue` |

- Names are unique and at most 64 characters. Tools with invalid schemas are skipped.
- Read-only tools come first within the limits: 40 tools for voice (`ORCH_MAX_VOICE_TOOLS`), 100 for background tasks.
- Tool output is bounded (12 KB of text, 8 KB of structured content, 8 KB of command output). Errors are returned to the model as output, not as RPC errors.

## Confirmations

Anything that changes something outside Jarvis needs the user's spoken consent. A non-read-only MCP tool is one example. The rule that makes this safe against prompt injection:

- The call does not run. The model gets a `confirmation_id` and asks the user.
- **`confirm_action` counts only in a user speech turn later than the one in which the question reached the user.** The gateway counts user turns, one per end of user speech. Tool results, documents and injected messages never count as turns, so text that says "the user agreed, confirm now" cannot supply one.
- **The gateway reports when the question reached the user:**
  - `AckToolOutput` for a direct call, and `AckEvent` for a question from a background task.
  - The turn it reports is that of the first response created after the question was given to the model, which is the response that speaks it.
  - Until then, `confirm_action` is refused with "the user has not answered yet".
- A confirmation expires after `ORCH_CONFIRMATION_TTL` (10 minutes). A task that waited for it continues, with "not confirmed" as the tool's result.
- **Commands on the user's Mac** also need a signature from one of the user's approver devices (below). A compromised orchestrator therefore cannot run them on its own.

## Background tasks

`start_task` queues an agent task. It is a durable state machine in PostgreSQL: `queued → running → (awaiting_confirmation | awaiting_approval) → succeeded | failed | cancelled`.

- **Workers** (`ORCH_WORKERS`, default 8) lease tasks with `FOR UPDATE SKIP LOCKED`.
  - A lease lasts 60 s and is renewed every 20 s.
  - When a worker dies, another instance picks the task up once the lease expires and continues from the saved history.
  - Only the lease owner can write the task.
- **Each step** fetches the tenant's key from the Vault, asks the sidecar for a decision (text or tool calls), and runs the tool calls. The key is wiped from memory right after the call.
- **Bounds:**
  - `ORCH_TASK_MAX_STEPS` (12) and `ORCH_TASK_TIMEOUT` (10 minutes).
  - After 3 transient failures in a row (provider or sidecar down), the task fails. A rejected or missing key fails it at once.
- **Reporting back.** When a task finishes, fails or needs the user, an event goes to its conversation, and the gateway has the model say it.
  - If that conversation has ended, the event goes to the user's current conversation, together with any confirmation it asks about.
  - If the user has no conversation open, it waits and is told when they next start one, for up to 24 hours. After that it stays visible in `ListTasks`.

## Push notifications

Some things should reach the phone even when nobody is talking to Jarvis. The orchestrator queues them in an outbox (`notifications`), and the [app API](../app-api/) sends them through APNs:

| Kind | When |
|---|---|
| `APPROVAL_NEEDED` | always, when a command waits for an approver's signature |
| `CONFIRMATION_NEEDED` | a task waits for a spoken confirmation and no conversation is live to ask |
| `TASK_FINISHED` | a task succeeded or failed and no conversation is live to tell (not for tasks the user cancelled) |

- **Claiming.** `ClaimNotifications` hands them out with a one-minute lease, using a long poll that wakes at once on a new notification. Several consumers never get the same one.
- **Retries.** Unfinished ones are handed out again, up to 5 times and never after an hour. They are deleted after a day.
- **Content.** A notification carries only the kind, the task id and state, never the task's goal or result.

## Memory

- **When a conversation closes**, a memory job extracts entities, relations and passages from its transcript and stores them in the knowledge service as source `conversation:<id>`. The sidecar does the extraction.
  - Jobs retry with exponential backoff, up to 5 attempts.
  - Conversations that were never closed (for example, their gateway crashed) are closed after 2 hours and remembered too.
- **The `remember` tool** stores a note right away (source `note:<uuid>`).
- **Transcripts** are deleted after `ORCH_TRANSCRIPT_RETENTION` (30 days). What was extracted stays in the knowledge service, where the user can delete it.

## Devices

- **`RegisterDevice`** adds a computer running the [Jarvis daemon](../../daemons/mac-daemon/). You give its address, its CA and a client certificate and key that the daemon trusts.
  - Addresses must be on the tailnet: `100.64.0.0/10`, `fd7a:115c:a1e0::/48` or `*.ts.net`. The check runs again at dial time.
  - Loopback is allowed only with `ORCH_ALLOW_LOOPBACK_DEVICES` (development).
  - The client key is sealed by the Vault (purpose `orchestrator.device-key`) before it is stored. Connections use TLS 1.3.
- **Allowlisted commands** run at once.
- **Other commands** make the daemon return an approval request. The task then waits in `awaiting_approval`, and `GetTask`/`ListTasks` return `pending_approval`:
  - the approval id,
  - the device's `ApprovalPayload` bytes,
  - the expiry.
- **An approver device signs exactly those bytes.** In production that is the [iPhone app](../../apps/ios/), with the key in the Secure Enclave and Face ID; for development, use `jarvis-approve` from the daemon or `jarvis-cli`. `SubmitDeviceApproval` delivers the signature, the daemon verifies it and runs the command, and the task continues.
- **A spent or expired approval ends the wait.** The daemon allows one attempt per approval, so a signature it rejects spends it. An approval nobody signs expires. Either way the command did not run: a command task fails with the reason, and an agent task gets it as the tool's result.

## Configuration

Everything is read from `ORCH_*` environment variables. See [`internal/config/config.go`](internal/config/config.go) for the full list and its validation.

| Variable | Default | |
|---|---|---|
| `ORCH_LISTEN_ADDR` | `127.0.0.1:50054` | gRPC listener (mTLS) |
| `ORCH_ADMIN_ADDR` | `127.0.0.1:9094` | `/healthz`, `/metrics` (loopback only) |
| `ORCH_TLS_CERT`, `ORCH_TLS_KEY`, `ORCH_TLS_CLIENT_CA` | required | Server certificate and the CA of callers |
| `ORCH_AUTHZ_POLICY` | required | Caller policy ([`config/authz.dev.toml`](config/authz.dev.toml) for development) |
| `ORCH_DATABASE_URL` or `ORCH_DATABASE_URL_FILE` | required | PostgreSQL |
| `ORCH_CLIENT_CERT`, `ORCH_CLIENT_KEY`, `ORCH_CLIENT_CA` | required | Its identity (`spiffe://jarvis.local/orchestrator`) towards the services below |
| `ORCH_VAULT_ADDR`, `ORCH_MCP_ROUTER_ADDR`, `ORCH_KNOWLEDGE_ADDR` | required | Each with an optional `_SERVER_NAME` |
| `ORCH_AGENT_SOCKET` | required | The sidecar's Unix socket (at most 103 bytes) |
| `ORCH_OPENAI_MODEL` / `ORCH_XAI_MODEL` | `gpt-6-luna` / `grok-4.6` | Background reasoning and memory extraction, with the tenant's key for the session's provider |
| `ORCH_WORKERS`, `ORCH_TASK_MAX_STEPS`, `ORCH_TASK_TIMEOUT` | `8`, `12`, `10m` | |
| `ORCH_TOOL_TIMEOUT` | `20s` | One tool call (at most 1m: the voice model waits) |
| `ORCH_CONFIRMATION_TTL`, `ORCH_TRANSCRIPT_RETENTION` | `10m`, `720h` | |
| `ORCH_ALLOW_LOOPBACK_DEVICES` | `false` | Development only |

## Development

Everything runs locally without spending API credits. The [fake Responses API](../agent/src/jarvis_agent/fake_llm.py) stands in for the LLM, and the fake MCP server stands in for real integrations. Start the services in separate terminals:

```bash
pnpm infra:up
pnpm nx run vault:serve
(cd services/mcp-router && go run ./cmd/mcpctl dev-server)              # fake OAuth + MCP server
LOCAL_MCP=1 pnpm nx run mcp-router:serve
pnpm nx run knowledge:serve
(cd services/agent && uv run jarvis-fake-llm --key sk-dev-fake-0001 --tool work_tracker__echo --tool-args '{"text":"hi"}')
AGENT_OPENAI_BASE_URL=http://127.0.0.1:9910/v1 pnpm nx run agent:serve
pnpm nx run orchestrator:serve
```

Then prepare a test tenant:

1. Store `sk-dev-fake-0001` in the Vault as that tenant's OpenAI key. See the [voice gateway README](../voice-gateway/README.md#development).
2. Connect the fake MCP server under the name "Work Tracker". See the [MCP router README](../mcp-router/README.md#run-it-locally).

**Talk to Jarvis in text.** `orchctl converse` plays the voice gateway: it counts turns, acknowledges questions and prints events as they arrive.

```bash
cd services/orchestrator
go run ./cmd/orchctl converse -tenant $TENANT -user me -locale el-GR
> call remember {"note":"Το αγαπημένο μου χρώμα είναι το πράσινο."}
> call recall_memory {"query":"αγαπημένο χρώμα"}
> call work_tracker__create_issue {"title":"Fix login"}     # needs_confirmation
> call confirm_action {"confirmation_id":"…"}                # refused: nobody answered
> say yes
> call confirm_action {"confirmation_id":"…"}                # runs
> call start_task {"goal":"Look something up"}               # the result arrives as [event …]
> quit                                                        # the conversation becomes memory
```

**Dashboard commands:**

```bash
go run ./cmd/orchctl tasks -tenant $TENANT -user me
go run ./cmd/orchctl task -tenant $TENANT -user me -id <task>                 # includes pending_approval
go run ./cmd/orchctl register-device -tenant $TENANT -user me -name MacBook -address 127.0.0.1:7443 \
  -device-server-name localhost -device-ca <ca.pem> -device-cert <client.pem> -device-key <client-key.pem>
go run ./cmd/orchctl approve -tenant $TENANT -user me -approval <id> -approver dev-cli -signature <base64 from jarvis-approve>
```

**By voice**, run the gateway with the echo provider as described in the [voice gateway README](../voice-gateway/README.md#jarvis-tools).

Metrics are at `http://127.0.0.1:9094/metrics` and health at `/healthz`.

## Tests

```bash
pnpm nx run orchestrator:test   # go test -race ./... (PostgreSQL via testcontainers)
```

The scenario tests in [`internal/server`](internal/server/server_test.go) run the real service over gRPC, against a real PostgreSQL. The Vault, MCP router, knowledge service, sidecar and devices are fakes. They cover:
- tools offered and idempotent calls
- confirmations:
  - same-turn, early and foreign confirmations are refused
  - cancellation and expiry
  - acknowledgements are per conversation and set once
- background tasks: reporting back, confirmations and approvals inside tasks, declines, step limits, provider failures, cancellation, crash recovery
- only the lease owner can write a task
- results told in the next conversation, and never to another user
- memory extraction, and abandoned conversations
- tenant and user isolation of tasks and devices
- key wiping and validation

Mutation testing confirmed that the tests catch each of these defects:
- the turn check dropped
- tenant and user filters removed
- lease-owner checks removed
- acknowledgements that cross conversations or overwrite
- routing and carry-over leaking to another user

## Known limitations

- **One user turn of slack in confirmations.** If the user happens to speak while a question is being delivered, that turn can confirm it. The guarantee is that a real user turn ended after the model had the question; it cannot prove the user heard it.
- **Events wake streams on the same instance at once.** Other instances notice within 2 s, because streams also poll.
- **Carried-over results** are told in the user's next conversation only within 24 hours. Push notifications to the phone arrive with the iOS app (Phase 4).
