# MCP router

Connects Jarvis to external tools through the [Model Context Protocol](https://modelcontextprotocol.io): Jira and Confluence (Atlassian), ClickUp, Linear, Notion, GitHub, Slack, Gmail, or any remote MCP server. Each integration belongs to one user of one tenant. The service's gRPC contract is [`proto/jarvis/mcp/v1/mcp.proto`](../../proto/jarvis/mcp/v1/mcp.proto).

```
dashboard ──gRPC+mTLS──▶ router ──HTTPS (MCP streamable HTTP, OAuth 2.1)──▶ Jira / Linear / Notion / …
orchestrator ─────────▶    │
                           ├──gRPC+mTLS──▶ Vault: SealData / OpenData (tokens are never stored in plaintext)
                           ├──PostgreSQL: integrations, OAuth clients, pending authorizations
                           └──DragonflyDB: rate limits, tool-list cache
```

| Caller | May call |
|---|---|
| dashboard (`spiffe://jarvis.local/dashboard-api`) | `ListCatalog`, `CreateIntegration`, `CompleteAuthorization`, `ReauthorizeIntegration`, `ListIntegrations`, `DeleteIntegration`, `ListTools` (to show them; never `CallTool`) |
| orchestrator (`spiffe://jarvis.local/orchestrator`) | `ListTools`, `CallTool` |

## Connecting a server

1. **Choose a server.** The dashboard calls `CreateIntegration` with a catalog slug or, when `MCP_ALLOW_CUSTOM_SERVERS=true`, any `https://` MCP URL.
2. **Bearer-token servers** (e.g. a GitHub fine-grained PAT): the token is sealed by the Vault, and the integration is connected immediately.
3. **OAuth servers:** the router runs the MCP authorization flow.
   - **Discovery:** it sends an unauthenticated request. The server answers `401` with `WWW-Authenticate: resource_metadata=…`, which leads to the protected resource metadata (RFC 9728) and then to the authorization server metadata (RFC 8414).
   - **Client:** it uses the operator's pre-registered app when one is configured. Otherwise it uses dynamic client registration (RFC 7591) once per authorization server; the client secret is Vault-sealed.
   - **Authorization URL:** returned to the dashboard, with PKCE S256, the `resource` indicator (RFC 8707) and a single-use `state`.
     - Only a hash of `state` is stored.
     - The PKCE verifier is Vault-sealed.
     - The URL expires after 10 minutes.
4. **Redirect.** The user consents in the browser. The redirect comes back to the application, and the dashboard relays `state`, `code`, `iss` and `error` to `CompleteAuthorization`.
   - The router rejects any response from an unexpected issuer (RFC 9207, mix-up attacks).
   - It exchanges the code and stores the tokens sealed by the Vault.

## Calling tools

- **`ListTools`** returns the tools of every connected integration of the user.
  - Tools are fetched in parallel.
  - Each list is cached in DragonflyDB for `MCP_TOOLS_CACHE_TTL`.
  - An integration that fails is reported in `unavailable` with a reason (e.g. `NEEDS_REAUTHORIZATION`) instead of failing the call.
  - Tool annotations are the server's claims. Missing hints get the MCP defaults: destructive and open-world.
- **`CallTool`** runs one tool.
  - **Sessions:** kept warm per integration (up to 8 calls in flight each) and closed after 5 idle minutes.
  - **Tool failure:** a tool that runs but fails returns `is_error`.
  - **Protocol errors:** answered with `ABORTED` / `UPSTREAM_ERROR`.
  - **Limits:** results are capped at 1 MiB (`truncated`). Timeouts default to 30 s, with a maximum of 120 s.

## Token lifecycle

- **Expired access tokens** are refreshed automatically, and rotated refresh tokens are re-sealed and stored.
  - All sessions of an integration share one in-memory token, so refreshes are serialized and a rotated refresh token is never used twice.
- **Rejected tokens:** when a server rejects a token early (`401`), the router refreshes once and retries.
  - If the refreshed token is also rejected, or the grant is gone (`invalid_grant`), the integration becomes `NEEDS_REAUTHORIZATION`. The user reconnects with `ReauthorizeIntegration`.
  - A `403` (missing scopes) needs the user as well.
  - Network errors never force a re-consent.
- **Rejected registration:** if a server stops accepting our dynamic registration (`invalid_client`), or the registration is about to expire, the next authorization registers again.

## Protections

- **Outbound traffic (SSRF).** Every request goes to public HTTPS endpoints only: MCP calls, discovery, registration and token requests.
  - The guard checks the actual IP of every connection as it is made. That defeats DNS rebinding and redirects into private networks.
  - Blocked: loopback, private, link-local and cloud metadata addresses (169.254.169.254), CGNAT/Tailscale (100.64/10) and NAT64.
- **Credentials:**
  - Tokens are sealed by the Vault, bound to tenant, purpose and integration. The database holds only Vault blobs.
  - Bearer tokens are cleared from memory after sealing, and nothing secret is ever logged.
- **Tenant isolation:** every lookup is scoped to tenant and user. Other owners' integrations are `NOT_FOUND`.
- **Rate limits:** per tenant and per integration, shared by all router instances (GCRA in DragonflyDB). If DragonflyDB is down, the router allows calls and logs a warning instead of failing.
- **Untrusted servers:** tool names are restricted, and descriptions (8 KiB), schemas (64 KiB), tool counts (500 per integration) and results (1 MiB) are bounded. Error text from servers is sanitized.
- **Callers:** mutual TLS plus a per-principal RPC allowlist ([`config/authz.dev.toml`](config/authz.dev.toml) for development).

## Run it locally

```bash
pnpm infra:up                                   # PostgreSQL + DragonflyDB
pnpm nx run vault:serve                         # terminal 1
go run ./cmd/mcpctl dev-server                  # terminal 2: fake OAuth + MCP server (auto-approves)
LOCAL_MCP=1 pnpm nx run mcp-router:serve        # terminal 3 (LOCAL_MCP allows loopback servers)
```

Then, from `services/mcp-router` (the tenant id is any UUID):

```bash
T=6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f
go run ./cmd/mcpctl connect -tenant $T -user me -url http://127.0.0.1:8931/mcp -open
go run ./cmd/mcpctl tools -tenant $T -user me
go run ./cmd/mcpctl call -tenant $T -user me -integration <id> -tool echo -args '{"text":"hi"}'
go run ./cmd/mcpctl integrations -tenant $T -user me
go run ./cmd/mcpctl delete -tenant $T -user me -integration <id>
```

- **Browser step:** `connect` prints the authorization URL, opens it with `-open`, and waits for the redirect on `http://127.0.0.1:8765/callback`. That address is the development `MCP_OAUTH_REDIRECT_URI` of `scripts/dev-run.sh`.
- **With the dashboard:** `tools/dev-stack.sh up` points `MCP_OAUTH_REDIRECT_URI` at the dashboard (`http://localhost:3000/integrations/callback`), runs `mcpctl dev-server`, and allows loopback servers. Connect `http://127.0.0.1:8931/mcp` from the dashboard's Integrations page. `mcpctl connect` then no longer receives the redirect.
- **Real servers:** use `-slug linear`, `-slug notion`, `-slug atlassian` or `-slug clickup` with your own account, after checking with `mcpctl catalog`.
- **GitHub:** use `-slug github -token-file <file with a fine-grained PAT>`.

Metrics are at `http://127.0.0.1:9092/metrics` and health at `/healthz`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MCP_LISTEN_ADDR` | `127.0.0.1:50052` | gRPC listener (mTLS) |
| `MCP_ADMIN_ADDR` | `127.0.0.1:9092` | metrics and health; must be loopback |
| `MCP_TLS_CERT`, `MCP_TLS_KEY`, `MCP_TLS_CLIENT_CA` | required | server certificate and the CA of callers |
| `MCP_AUTHZ_POLICY` | required | `[[principal]] id / allow` TOML |
| `MCP_REFLECTION` | `false` | gRPC reflection |
| `MCP_DATABASE_URL` (or `_FILE`) | required | PostgreSQL, role `mcp_router`, database `mcp` |
| `MCP_REDIS_ADDR`, `MCP_REDIS_PASSWORD` (or `_FILE`) | `127.0.0.1:56379` | DragonflyDB |
| `MCP_VAULT_ADDR`, `MCP_VAULT_SERVER_NAME`, `MCP_VAULT_CA`, `MCP_VAULT_CERT`, `MCP_VAULT_KEY` | required | the Vault, as `spiffe://jarvis.local/mcp-router` |
| `MCP_OAUTH_REDIRECT_URI` | required | where authorization servers send the user back; `https` (or loopback `http` in development) |
| `MCP_OAUTH_CLIENT_NAME` | `Jarvis` | name shown on consent screens |
| `MCP_OAUTH_<SLUG>_CLIENT_ID`, `…_CLIENT_SECRET` (or `_FILE`) | none | operator-registered OAuth app for a catalog server (required for `slack`, `gmail`) |
| `MCP_ALLOW_CUSTOM_SERVERS` | `false` | allow URLs outside the catalog |
| `MCP_ALLOW_LOOPBACK_SERVERS` | `false` | development only: allow servers on this machine |
| `MCP_RATE_PER_TENANT_PER_MINUTE`, `MCP_RATE_PER_INTEGRATION_PER_MINUTE` | `120`, `60` | tool call limits |
| `MCP_TOOLS_CACHE_TTL` | `5m` | tool-list cache |
| `MCP_DEFAULT_CALL_TIMEOUT`, `MCP_MAX_CALL_TIMEOUT` | `30s`, `120s` | tool call timeouts (max ≤ 10m) |
| `MCP_AUDIT_ADDR`, `MCP_AUDIT_SERVER_NAME` | none: log only | the [audit service](../audit/), with the router's Vault client identity. Records integration changes and every tool call (`tool.called`: Jarvis for the user, the tool, its duration and outcome; never its arguments or result). Recording never delays a call. |
| `MCP_LOG_FORMAT`, `MCP_LOG_LEVEL` | `json`, `info` | logging |

## Known limitations

- **Slack and Gmail** only accept pre-registered apps. Configure `MCP_OAUTH_SLACK_*` / `MCP_OAUTH_GMAIL_*`; until then the catalog lists them as unavailable.
- **Client ID Metadata Documents** (the successor of dynamic registration) need a public HTTPS URL for Jarvis and are not used yet.
- **Several router instances** can race to refresh the same rotating refresh token. Refreshes are serialized only within one instance, so run one instance until a distributed lock is added.
- **Deleting an integration** destroys its tokens locally but does not revoke them at the provider (RFC 7009).
- **Tools that ask for more input** mid-call (elicitation) return `is_error` with an explanation.
