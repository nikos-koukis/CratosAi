# Voice gateway

Relays real-time voice between Jarvis client apps (iOS/macOS) and LLM realtime APIs: OpenAI (`gpt-realtime-2.1`) and xAI (`grok-voice-think-fast-2.0`).
- Each tenant's own provider key comes from the [BYOK Vault](../vault/).
- The [orchestrator](../orchestrator/) gives the model Jarvis's tools: memory, the user's integrations, their computer and background tasks.

The client protocol is [`proto/jarvis/voice/v1/voice.proto`](../../proto/jarvis/voice/v1/voice.proto).

```
app ──wss (protobuf frames, PCM16 24 kHz)──▶ gateway ──wss (realtime JSON)──▶ OpenAI / xAI
                                               │
                                               ├─gRPC + mTLS──▶ Vault: GetDecryptedKey(tenant, provider)
                                               └─gRPC + mTLS──▶ orchestrator: tools, turns, events
```

## How a session works

1. The app connects to `wss://…/v1/voice` with `Authorization: Bearer <token>` and subprotocol `jarvis.voice.v1`.
   - The token is a short-lived EdDSA JWT carrying `sub` (the user) and `tenant_id`.
   - It is checked **before** the WebSocket upgrade. A bad token gets HTTP 401 and triggers no Vault call.
2. The app sends `StartSession`, naming the provider. It may also give a voice and the user's locale (e.g. `el-GR`).
3. The gateway fetches that tenant's key from the Vault, opens the provider session and clears the key from its memory.
   - The request id sent to the Vault equals the session id, so the Vault's audit log lines up with the gateway's.
4. The app streams microphone audio as raw PCM16 in binary protobuf frames, with no base64.
   - The provider's server-side VAD decides when the user has finished and answers.
   - Reply audio, transcripts and turn events stream back.
5. **Barge-in.** When the user talks over the assistant, the gateway:
   - drops all assistant audio still queued for that client
   - drops any audio of the interrupted response that is still in flight
   - sends `SpeechStarted` so the app stops playback
   - sends `conversation.item.truncate` telling the provider how much of the answer the user actually heard, so the conversation history stays truthful

The OpenAI and xAI protocols are the same except for a few `session.update` fields; [`internal/realtime`](internal/realtime/realtime.go) handles both.

## Jarvis tools

With `GATEWAY_ORCHESTRATOR_ADDR` set, each session is also an orchestrator conversation ([`internal/session/jarvis.go`](internal/session/jarvis.go)):

- **Before connecting** to the provider, the gateway opens the conversation. The orchestrator's instructions are appended to the base instructions, and its tools are declared in `session.update`.
  - If the orchestrator is unreachable, the session still works, without tools.
- **Function calls** of the model go to the orchestrator as they arrive.
  - All the outputs of a response are sent together once the response is done.
  - Then one `response.create` lets the model speak about them. It is never sent while the user is talking or while another response is running.
  - Tool failures reach the model as error outputs, never as provider errors. At most 8 calls run at once per session.
- **Events** from the orchestrator (a background task finished, a question from a task) are added to the conversation, and the model is asked to speak them.
  - OpenAI takes them as system messages. xAI accepts only user messages; there the `[Jarvis]` prefix the orchestrator adds marks them. Either way they never count as a user turn.
- **Transcripts** are recorded in order in the background, without blocking audio. When the session ends, the conversation is closed and becomes memory, after the client has already been disconnected.

**Confirmations.** The orchestrator runs a state-changing action only when the model confirms it in a user turn later than the one in which the question reached the user. The gateway supplies the facts it needs:

- **The turn count.** It increases once per end of user speech. Injected text, tool results and the model's own output never count.
- **Each function call is stamped** with the turn at which its response was created. A response started before the user spoke cannot confirm.
- **Each question is reported** (`AckToolOutput`, `AckEvent`) with the turn of the first response created after it was added to the conversation.
  - A response the gateway had already requested does not count, because the provider built it before the question was added.
  - Calls wait until those reports are stored.

## Latency

- Audio is forwarded as soon as it arrives. Frames that are already waiting are merged, but nothing waits to be batched.
- Measured gateway overhead is about **0.05 ms per audio chunk** (`voice_gateway_forward_seconds`).
- End-to-end latency is dominated by the provider and its end-of-speech silence window (`GATEWAY_VAD_SILENCE_MS`, default 500 ms).
- Per session, `voice_response_latency_seconds` records the time from the end of the user's speech to the first reply audio.

## Protections

- **Tokens:** signature (EdDSA only, keys from JWKS), `iss`, `aud`, `exp`/`iat` and a maximum lifetime (`GATEWAY_TOKEN_MAX_LIFETIME`) are all checked.
- **Provider protocol:** the client never speaks it. It cannot change instructions, tools or models, or use the tenant's key for anything but its own voice session.
- **Limits:**
  - audio frames must be even-length PCM16 of at most 100 ms
  - audio may arrive at up to 1.5× real time, with a 2 s burst; beyond that the session ends with `RATE_LIMITED`
  - bounded queues in both directions
  - concurrent sessions per gateway and per tenant
  - idle timeout and maximum session duration (30 min by default; providers cap sessions at 60 min)
- **Transport:**
  - Provider URLs must be `wss://` (plain `ws://` is accepted only for loopback fakes), because the tenant's key travels in the handshake.
  - The public listener refuses to serve plaintext on a non-loopback address unless TLS is configured, or `GATEWAY_ALLOW_PLAINTEXT=true` explicitly declares a TLS-terminating proxy in front.
  - Metrics and health endpoints only listen on loopback.
- **Pseudonymous user id for OpenAI:** it receives `OpenAI-Safety-Identifier`, a hash of tenant and user, never the ids themselves.
- **Shutdown:** on SIGTERM the gateway stops accepting sessions, sends `SHUTTING_DOWN` (reconnect) to open ones and drains them for up to 15 s.

## Configuration

Everything is read from `GATEWAY_*` environment variables. See [`internal/config/config.go`](internal/config/config.go) for the full list and its validation.

| Variable | Default | |
|---|---|---|
| `GATEWAY_LISTEN_ADDR` | `127.0.0.1:8080` | Public WebSocket listener |
| `GATEWAY_TLS_CERT`, `GATEWAY_TLS_KEY` | | Serve `wss://` directly |
| `GATEWAY_ADMIN_ADDR` | `127.0.0.1:9091` | `/healthz`, `/readyz`, `/metrics` (loopback only) |
| `GATEWAY_TOKEN_JWKS` | required | Trusted token-signing public keys |
| `GATEWAY_TOKEN_ISSUER` | required | Expected `iss` |
| `GATEWAY_TOKEN_AUDIENCE` | `jarvis-voice-gateway` | Expected `aud` |
| `GATEWAY_VAULT_ADDR`, `GATEWAY_VAULT_CA/CERT/KEY` | required | Vault endpoint and the gateway's mTLS identity |
| `GATEWAY_PROVIDERS` | `openai,xai` | Enabled providers; the first is the default |
| `GATEWAY_OPENAI_MODEL` / `GATEWAY_XAI_MODEL` | `gpt-realtime-2.1` / `grok-voice-think-fast-2.0` | |
| `GATEWAY_OPENAI_VOICE` / `GATEWAY_XAI_VOICE` | `marin` / `eve` | Default voices |
| `GATEWAY_INSTRUCTIONS` | a short Jarvis persona | Base instructions; the orchestrator's are appended |
| `GATEWAY_ORCHESTRATOR_ADDR` | empty: no tools | Orchestrator endpoint, e.g. `orchestrator.internal:50054` |
| `GATEWAY_ORCHESTRATOR_SERVER_NAME`, `GATEWAY_ORCHESTRATOR_CA/CERT/KEY` | host of the address; the Vault client's files | The same mTLS identity (`spiffe://jarvis.local/voice-gateway`) is used for both |
| `GATEWAY_TOOL_TIMEOUT` | `30s` | One function call (at most 2m) |
| `GATEWAY_MAX_SESSIONS`, `GATEWAY_MAX_SESSIONS_PER_TENANT` | `1000`, `3` | |
| `GATEWAY_IDLE_TIMEOUT`, `GATEWAY_MAX_SESSION_DURATION` | `5m`, `30m` | |

## Development

Prerequisites: `pnpm nx run vault:serve`, which starts the infrastructure too and creates the Vault's dev certificates, including the gateway's client certificate.

**Without any API key, using the local echo provider:**
```bash
cd services/voice-gateway
go run ./cmd/voicectl echo-provider -key sk-dev-echo-key-0000000        # terminal 1
ECHO=1 scripts/dev-run.sh                                                # terminal 2
```
In terminal 3, store that key for a tenant. The Vault's dev certificates act as the dashboard:
```bash
C=../vault/.dev/certs; TENANT=0199e2e0-0000-7000-8000-000000000001
grpcurl -cacert $C/ca.pem -cert $C/dashboard-api.pem -key $C/dashboard-api-key.pem \
  -d "{\"tenant_id\":\"$TENANT\",\"provider\":\"PROVIDER_OPENAI\",\"label\":\"dev\",\"secret\":\"$(printf sk-dev-echo-key-0000000 | base64)\",\"replace_active\":true}" \
  localhost:50051 jarvis.vault.v1.VaultService/CreateKey
```
Then say something and send it:
```bash
say -o /tmp/q.aiff "Hello Jarvis" && afconvert -f WAVE -d LEI16@24000 -c 1 /tmp/q.aiff /tmp/q.wav
go run ./cmd/voicectl talk -token "$(go run ./cmd/voicectl token -tenant $TENANT)" -in /tmp/q.wav -out /tmp/reply.wav
afplay /tmp/reply.wav
```

**With a real provider:** store your real OpenAI or xAI key the same way, then run `scripts/dev-run.sh` without `ECHO=1`. Use `-provider openai` or `-provider xai` with `voicectl talk`.

`scripts/dev-run.sh` connects to the local orchestrator (`127.0.0.1:50054`) for Jarvis tools. Start it first (see the [orchestrator README](../orchestrator/README.md#development)), or set `GATEWAY_ORCHESTRATOR_ADDR=` (empty) for plain voice.

### Jarvis tools

The echo provider can play the model's side of tool use:
- **`-tool`:** after each utterance it calls that tool, then speaks the result as its transcript.
- **Confirmations:** when a result asks for one, your next utterance confirms it.
- **`-confirm-early`:** it also tries to confirm at once, before you answer, the way a prompt injection would. Jarvis must refuse that.

```bash
go run ./cmd/voicectl echo-provider -key sk-dev-echo-key-0000000 -tool recall_memory -tool-args '{"query":"my favourite colour"}'
go run ./cmd/voicectl echo-provider -key sk-dev-echo-key-0000000 -tool work_tracker__create_issue -tool-args '{"title":"Voice"}' -confirm-early
go run ./cmd/voicectl echo-provider -key sk-dev-echo-key-0000000 -tool start_task -tool-args '{"goal":"Check my tracker"}'
```

`voicectl talk` flags for these sessions:
- **`-turns N`** says the input N times, each after the previous spoken reply.
- **`-linger 5s`** keeps listening after the last reply, for background task results.
- **`-locale el-GR`** sets the user's locale.

## Tests

```bash
pnpm nx run voice-gateway:test   # go test -race ./...
```

The end-to-end tests in `internal/server` drive the whole gateway over WebSockets against a fake provider. They cover:
- the conversation round trip
- barge-in with a genuinely backed-up client socket (queued audio is dropped and the item truncated)
- cancelling a response
- authentication before upgrade
- missing and rejected keys
- protocol violations and rate limiting
- session limits, idle expiry, provider failure and graceful shutdown
- Jarvis tools, against an in-process fake orchestrator:
  - tools and instructions are offered, and malformed ones are skipped
  - calls run once
  - outputs wait for the whole response and never interrupt the user
  - calls are stamped with their response's turn
  - questions are acknowledged before the next calls run
  - events are spoken and acknowledged, including events added while a response was already requested
  - failures and overload become tool errors
  - sessions work without the orchestrator

Mutation testing confirmed that the tests catch a broken turn count, missing waits for acknowledgements, and responses sent while the user speaks.

`internal/vaultclient` tests mTLS against an in-process gRPC Vault.

## Known limitations

- **Plain WebSocket transport, not WebRTC.** On poor mobile networks, TCP head-of-line blocking can add jitter.
- **Barge-in truncation is an approximation.** It uses the audio *delivered* to the app, not what the app actually *played*. A future `PlaybackPosition` client message would make it exact.
- **Limits are per instance.** Session limits live in memory, so several gateway instances do not share them yet; a shared limiter via DragonflyDB is the next step.
- **Tool results wait for the response that asked for them to finish.** A model that keeps talking after a call delays the result until it stops.
- **Best-effort key erasure.** Go cannot guarantee erasing the key from memory. The gateway clears its own copy, but the WebSocket library keeps the handshake header until garbage collection.
