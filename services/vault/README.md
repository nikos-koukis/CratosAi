# BYOK Vault

Stores tenant-owned LLM provider API keys (OpenAI, xAI, Anthropic, Google) and releases plaintext only to authorised internal services. Contract: [`proto/jarvis/vault/v1/vault.proto`](../../proto/jarvis/vault/v1/vault.proto).

| Caller | RPCs |
|---|---|
| Dashboard (`dashboard-api`) | `CreateKey`, `RevokeKey`, `ListKeys` (metadata only: label, provider, last four characters, status) |
| Voice gateway, orchestrator | `GetDecryptedKey` |
| MCP router | `SealData`, `OpenData` (its OAuth tokens) |

## Security model

- **Envelope encryption.** Each key gets its own random 256-bit data key (DEK). The key is encrypted with AES-256-GCM under the DEK, and the DEK is wrapped with AES-256-GCM under the key-encryption key (KEK). Both layers bind the ciphertext to its tenant, key id and provider, so a row copied elsewhere fails to decrypt.
- **KEK** is derived at startup from an operator passphrase with Argon2id (64 MiB, t=3, p=4). It exists only in memory. On first start its id is registered in the database. A later start with a different passphrase or salt is refused.
- **PostgreSQL holds only ciphertext.** Plaintext is never written to disk or logs. Revocation deletes the DEK and ciphertext.
- **mTLS is mandatory.** A caller's identity is the single URI SAN of its client certificate, e.g. `spiffe://jarvis.local/voice-gateway`. A TOML policy grants each identity specific RPCs, and everything else is denied.
- **No existence oracle.** A key that belongs to another tenant is reported as `NOT_FOUND`, identical to a missing one.
- **Every RPC is audited,** success or failure, as a structured log record with `target=audit`: caller, tenant, key id, request id and outcome. Secrets never appear.
- **Key operations reach the [audit trail](../audit/README.md)** when `VAULT_AUDIT_ADDR` is set: `key.created`, `key.revoked` and `key.read`, with the calling service as the actor. A background task sends them in batches and retries while the audit service is down. The Vault keeps serving meanwhile, and anything it cannot deliver is logged (`audit event not delivered`). Listing keys and sealing or opening data stay in the log only.
- **Hardening:**
  - Plaintext buffers are zeroized on drop.
  - Messages that carry secrets have a hand-written `Debug` that redacts them.
  - Core dumps are disabled.
  - Messages are capped at 64 KiB, and requests time out after 10 s.

## Configuration

| Variable | Required | Default | Notes |
|---|---|---|---|
| `VAULT_DATABASE_URL` / `_FILE` | yes | | PostgreSQL URL. Use `sslmode=verify-full` in production. |
| `VAULT_MASTER_PASSPHRASE` / `_FILE` | yes | | At least 32 bytes. **Losing it (or the salt) loses every stored key.** |
| `VAULT_MASTER_SALT` | yes | | Base64, at least 16 bytes. Must never change. |
| `VAULT_TLS_CERT`, `VAULT_TLS_KEY` | yes | | Server certificate chain and key (PEM). |
| `VAULT_TLS_CLIENT_CA` | yes | | CA bundle that client certificates must chain to. |
| `VAULT_AUTHZ_POLICY` | yes | | Path to the policy TOML. See [`config/authz.dev.toml`](config/authz.dev.toml). |
| `VAULT_LISTEN_ADDR` | no | `0.0.0.0:50051` | |
| `VAULT_DATABASE_MAX_CONNECTIONS` | no | `16` | |
| `VAULT_RUN_MIGRATIONS` | no | `true` | Applies `migrations/` at startup. |
| `VAULT_ENABLE_REFLECTION` | no | `false` | gRPC reflection, for grpcurl. |
| `VAULT_LOG_FORMAT` | no | `json` | `json` or `pretty`. The level is set with `RUST_LOG`. |
| `VAULT_AUDIT_ADDR` | no | | The audit service (`host:port`). Without it, audit stays in the log. |
| `VAULT_AUDIT_TLS_CERT`, `VAULT_AUDIT_TLS_KEY` | with `VAULT_AUDIT_ADDR` | | The Vault's client certificate towards the audit service (`spiffe://jarvis.local/vault`). |
| `VAULT_AUDIT_CA` | no | `VAULT_TLS_CLIENT_CA` | CA bundle for the audit service's certificate. |
| `VAULT_AUDIT_SERVER_NAME` | no | host of `VAULT_AUDIT_ADDR` | Name expected in the audit service's certificate. |

A `_FILE` variant reads the secret from a file (Docker or Kubernetes secrets). Setting both variants is an error.

## Local development

```bash
pnpm nx run vault:serve
```

This does the following:
- Starts the [local infrastructure](../../deploy/compose/README.md) (`infra:up`).
- Connects as the `vault` database role, using the credentials in `deploy/compose/.env`.
- Generates dev certificates in `.dev/certs` on first run.
- Uses a fixed development master passphrase.

Setting `VAULT_DATABASE_URL` overrides the database. `services/vault/scripts/dev-run.sh` does the same without starting the infrastructure.

Call it with [grpcurl](https://github.com/fullstorydev/grpcurl), for example as the voice gateway:

```bash
cd services/vault/.dev/certs
grpcurl -cacert ca.pem -cert voice-gateway.pem -key voice-gateway-key.pem localhost:50051 list
```

## Tests

```bash
pnpm nx run vault:test   # unit tests + integration tests (needs Docker)
pnpm nx run vault:lint   # clippy with -D warnings
```

The integration tests (`tests/grpc_api.rs`) start a real PostgreSQL per test with testcontainers. They serve the Vault over mTLS with a throwaway PKI and exercise the API through the generated client. Covered: tenant isolation, authorization, rotation under concurrency, idempotency, crypto-shredding, listing, audit, and the absence of plaintext at rest. `tests/audit_sink.rs` runs the audit sink against a fake audit service: batching, retries during an outage, a refused event not losing the others, and the flush at shutdown.

## Known limitations

- **Tenant scoping.** Principals are services that may act for any tenant. The dashboard checks that the signed-in user belongs to the workspace (tenant) before calling; binding a call to the end user cryptographically would need a propagated user token.
- **Crypto-shredding is logical.** PostgreSQL MVCC, WAL and backups keep old row versions until vacuum or expiry. That ciphertext stays unreadable only while the KEK stays secret.
- **Single KEK.** There is no KEK rotation yet, and no KMS or HSM backend. `MasterKey::from_key_bytes` is the extension point for adding one.
- **Zeroization is best-effort.** The gRPC, HTTP/2 and TLS layers briefly hold plaintext in buffers this code does not control.
- **Undelivered audit events are only logged.** Events still queued when the Vault stops (after a 10 s flush) or when its queue of 10,000 is full are written to the log, not persisted for a later retry.
- **Idempotency records never expire.** No cleanup job exists yet.
