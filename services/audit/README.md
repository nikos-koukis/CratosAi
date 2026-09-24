# Audit

The audit trail of Jarvis: who did what, in which workspace, and whether it worked. Every service records here what people, Jarvis and devices did. The [dashboard](../../apps/dashboard/) shows it: owners see everything in their workspace, and members see their own entries.

The contract is [`proto/jarvis/audit/v1/audit.proto`](../../proto/jarvis/audit/v1/audit.proto).

```
vault ─────────┐
app-api ───────┤
mcp-router ────┼──gRPC + mTLS (Record)──▶ audit ──▶ PostgreSQL: append-only events,
orchestrator ──┤                            ▲         one hash chain per workspace
dashboard-api ─┴──(Record, ListEvents, VerifyChain)
```

| RPC | Who may call it ([dev policy](config/authz.dev.toml)) | What it does |
|---|---|---|
| `Record` | every service above | Appends 1–500 events. Idempotent by `event_id`: a retried event is counted as a duplicate, not stored twice. |
| `ListEvents` | `dashboard-api` | A workspace's events, newest first, 50 per page (at most 200). Filters: one person (`user_id` matches the actor or `on_behalf_of`), an action prefix (`key.`), and a time range. |
| `VerifyChain` | `dashboard-api` | Recomputes the workspace's hash chain and says whether it is intact, or where it breaks. |

The services can only write. Only the dashboard backend can read the trail back.

## Events

An event says:
- **who acted:** a person (user id), Jarvis (the assistant), a device (a paired phone, `app-session:<id>`, or a computer by name) or a service;
- **for whom** (`on_behalf_of`), when Jarvis, a device or a service acted for a person;
- **what:** an action (`tool.called`) and its target (`integration` + id);
- **how it went:** success, failure or denied, and a short reason.

It can also carry up to 16 small details (`tool`, `provider`, `role`).

The audit service sets the rest:
- The **source** is the verified mTLS identity of the caller, never a request field. A service cannot record in another service's name.
- The **sequence** (gapless, per workspace), the **record time** and the **hash**.

**Never recorded:** secrets (keys, tokens, codes), message contents, tool arguments, command arguments and task goals. The producers leave them out, and the service caps every field (actions `^[a-z0-9_.]{3,64}$`, detail values 256 characters, no control characters).

| Producer | Actions |
|---|---|
| Vault | `key.created`, `key.revoked`, `key.read`, by the calling service |
| Dashboard | `account.signed_up`, `signed_in`, `sign_in_failed`, `recovery_code_used`, `signed_out`, `signed_out_elsewhere`, `passkey_added`, `passkey_removed`, `recovery_codes_replaced`; `workspace.created`, `access_denied`, `member_invited`, `invitation_revoked`, `member_joined`, `member_role_changed`, `member_removed`, `member_left`; `key.stored`, `key.revoked`; `device.pairing_code_issued`, `device.signed_out` |
| App API | `device.paired`, `device.token_reused`, `device.signed_out`, `task.cancelled`, `command.approval_submitted` |
| MCP router | `integration.created`, `connected`, `authorization_failed`, `deleted`, `needs_reauthorization`; `tool.called` |
| Orchestrator | `action.confirmation_requested`, `confirmed`, `declined`, `confirmation_blocked`; `task.started`, `task.finished`; `command.approval_requested`, `command.ran`, `command.not_run` |

Account events belong to a person rather than a workspace. The dashboard records them in every workspace the person belongs to.

## Tamper evidence

- **Append-only.** Triggers refuse every `UPDATE`, `DELETE` and `TRUNCATE` on `events`. The service itself only inserts.
- **One hash chain per workspace.** Each event's hash covers the previous event's hash and every stored field of the event:

  ```
  SHA-256("jarvis.audit.v1\0" || previous hash || fields)
  ```

  The fields are written in a fixed order, each as an unsigned-varint length followed by its bytes:
  - tenant, sequence, event id;
  - occur time and record time, in Unix microseconds;
  - actor kind, actor id, on behalf of;
  - action, target type, target id;
  - outcome, reason, request id, source;
  - the number of details, then each key and value in key order.

  The encoding does not depend on protobuf, so the stored rows are enough to recompute the chain. [`internal/chain`](internal/chain/chain.go) documents it, and its test pins a hash that was computed independently.
- **Gapless and ordered.** Appending locks the workspace's chain head (`FOR UPDATE`). Concurrent writers therefore get consecutive sequences, and every event links to the one before it.
- **Verification** (`VerifyChain`) reads the whole chain in one `REPEATABLE READ` snapshot. It detects:
  - a changed field;
  - a removed or reordered event;
  - a cut-off tail, because the last event must match the stored chain head.
- **External anchor.** Every hour the service logs each workspace's chain head (`audit chain head`, with the sequence and hash). The log pipeline keeps those lines outside the database. Someone who rewrote a whole chain consistently, including its head, would still disagree with the heads logged earlier.

## Producers never wait

Recording is fail-open: a slow or absent audit service never slows down or fails the action being recorded. Each producer uses a small library:
- Go: [`libs/go/auditlog`](../../libs/go/auditlog/)
- Rust: the Vault's `GrpcAuditSink`
- TypeScript: the dashboard's [`AuditRecorder`](../../apps/dashboard/src/server/audit.ts)

All three work the same way:
- `Record` only queues the event, in a bounded in-memory queue (10,000 events).
- A background task sends batches of up to 200, every 500 ms or as soon as a batch is full.
- A failed batch is retried with exponential backoff, from 1 s up to 30 s. Retries are safe because events are idempotent by id.
- A batch refused as malformed (`INVALID_ARGUMENT`) is sent again one event at a time, so one bad event does not lose the others.
- An event that cannot be delivered is written to the log as `audit event not delivered`, with all its fields. That covers a full queue, a malformed event, and events still queued at shutdown (after a 10 s flush). Nothing is dropped silently.

## Configuration

| Variable | Required | Default | Notes |
|---|---|---|---|
| `AUDIT_DATABASE_URL` / `_FILE` | yes | | PostgreSQL URL of the `audit` database. |
| `AUDIT_TLS_CERT`, `AUDIT_TLS_KEY` | yes | | Server certificate and key (PEM). |
| `AUDIT_TLS_CLIENT_CA` | yes | | CA bundle that client certificates must chain to. |
| `AUDIT_AUTHZ_POLICY` | yes | | Which identity may call which RPC ([dev policy](config/authz.dev.toml)). |
| `AUDIT_LISTEN_ADDR` | no | `127.0.0.1:50056` | |
| `AUDIT_METRICS_ADDR` | no | `127.0.0.1:9097` | Prometheus `/metrics`. Must be loopback. |
| `AUDIT_REFLECTION` | no | `false` | gRPC reflection, for grpcurl. |
| `AUDIT_LOG_FORMAT`, `AUDIT_LOG_LEVEL` | no | `json`, `info` | |

Metrics:
- `audit_rpcs_total{method,code}`
- `audit_events_recorded_total{source,outcome}`
- `audit_events_duplicate_total{source}`
- `audit_chain_verifications_total{result}`

The producers are configured by the following variables. Each is optional; without it, events only go to that service's log.
- Vault: `VAULT_AUDIT_ADDR`
- App API: `APP_AUDIT_ADDR`
- MCP router: `MCP_AUDIT_ADDR`
- Orchestrator: `ORCH_AUDIT_ADDR`
- Dashboard: `DASHBOARD_AUDIT_ADDR`, which defaults to `127.0.0.1:50056`

## Development

```bash
pnpm nx run audit:serve        # needs infra:up (database `audit`) and the Vault's dev CA
tools/dev-stack.sh up          # or the whole stack; the audit service starts right after the Vault
```

- `scripts/dev-run.sh` issues a server certificate from the Vault's development CA into `.dev/certs`.
- It connects to the `audit` database with the password in `deploy/compose/.env`. `pnpm nx run infra:up` creates the database and the password, including on an existing volume.

Read a workspace's trail with grpcurl as the dashboard:

```bash
cd services/vault/.dev/certs   # the development CA and the dashboard's client certificate
grpcurl -cacert ca.pem -cert dashboard-api.pem -key dashboard-api-key.pem \
  -d '{"tenant_id":"<workspace id>","page_size":10}' localhost:50056 jarvis.audit.v1.AuditService/ListEvents
```

## Tests

```bash
pnpm nx run audit:test   # needs Docker (PostgreSQL per run)
pnpm nx run audit:lint
```

The tests serve the real service over mTLS against a real PostgreSQL. They cover:
- the source taken from the certificate, and the access policy;
- idempotency, and refusal of malformed batches;
- filters and pagination;
- 80 concurrent appends yielding a gapless chain;
- six kinds of tampering caught by `VerifyChain`;
- triggers refusing updates and deletes.

## Known limitations

- **The database owner can still rewrite history.** The service's role owns the tables, so it could drop the triggers. The external anchor (logged chain heads) exposes such a rewrite, but does not prevent it. Production should give the service a role that may only `INSERT` and `SELECT`, and run migrations as a separate owner role.
- **No retention.** Events are kept forever, including those of deleted workspaces.
- **Anchoring relies on the logs.** The chain heads are only as safe as the log pipeline that keeps them. Signing the heads, or publishing them elsewhere, would be stronger.
- **Undelivered events are only logged.** A producer that stops while the audit service is down logs its queued events instead of persisting them for later.
