# Local development infrastructure

Docker Compose stack with the stateful services Jarvis depends on. It is for local development only; production runs on managed or hardened deployments.

| Service | Image | Used for | Host address (127.0.0.1 only) |
|---|---|---|---|
| PostgreSQL | `postgres:18.6-alpine` | Relational state: databases `vault`, `mcp` (MCP router), `orchestrator`, `app` (app API) | `127.0.0.1:55432` |
| DragonflyDB | `dragonfly:v1.40.2` | Redis-compatible cache: rate limits, sessions | `127.0.0.1:56379` |
| Neo4j | `neo4j:2026.09.0-community` | Knowledge graph (GraphRAG) | Browser `http://127.0.0.1:57474`, Bolt `127.0.0.1:57687` |
| Qdrant | `qdrant/qdrant:v1.19.1` | Vector search | HTTP `127.0.0.1:56333`, gRPC `127.0.0.1:56334` |

The host ports avoid the defaults so the stack can coexist with locally installed databases. You can override them in `.env` (see [`.env.example`](.env.example)).

## Usage

```bash
pnpm nx run infra:up      # generate .env on first run, start, wait until healthy
pnpm nx run infra:test    # smoke test: auth works, wrong or missing credentials fail
pnpm nx run infra:ps      # status
pnpm nx run infra:logs    # follow logs
pnpm nx run infra:down    # stop; data is kept in Docker volumes
pnpm nx run infra:reset   # stop and DELETE all data
```

## Security defaults

- **Random credentials.** `scripts/init-env.sh` writes `.env` (mode 600, git-ignored) with random credentials. Nothing ships with a default password, and Compose refuses to start without `.env`.
- **Localhost only.** Every port is published on `127.0.0.1`, so nothing is reachable from the network.
- **PostgreSQL:**
  - Every TCP connection needs a password (`scram-sha-256`), including connections from inside the container.
  - Each service gets its own role and database (`vault`, `mcp_router`, `orchestrator`, `app_api`). A role owns only its database and cannot connect to the others or to `postgres`.
  - The superuser is only for administration.
- **Dragonfly** requires a password. **Qdrant** requires an API key. **Neo4j** requires authentication, and its usage reporting is off, as is Qdrant's telemetry.
- **Container hardening:** `no-new-privileges` on every container, rotated logs, and memory caps (Neo4j heap 512 MiB, Dragonfly 512 MiB).

## Connecting

Credentials are in `deploy/compose/.env`. Examples:

```bash
# PostgreSQL as the vault role
psql "postgres://vault:<VAULT_DB_PASSWORD>@127.0.0.1:55432/vault"

# Dragonfly
REDISCLI_AUTH=<DRAGONFLY_PASSWORD> redis-cli -p 56379 ping

# Qdrant
curl -H "api-key: <QDRANT_API_KEY>" http://127.0.0.1:56333/collections
```

For Neo4j, open http://127.0.0.1:57474 and log in as `neo4j` / `<NEO4J_PASSWORD>`.

## Notes

- Deleting `.env` while volumes exist locks you out, because each database keeps the password it was created with. Run `infra:reset` first, then `infra:up` again.
- Scripts in `postgres/init/` run only when the PostgreSQL volume is first created. After changing them, run `infra:reset`.
- There is no TLS between the services and these databases locally. Production connections must use TLS (e.g. `sslmode=verify-full`).
- Dragonfly is pinned to 1.x on purpose; 2.0.0 was only a week old when the stack was set up.
