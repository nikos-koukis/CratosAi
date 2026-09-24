# App API

The public API of Jarvis's apps: the [iPhone app](../../apps/ios/) now, the web dashboard later.
- It pairs apps with users and keeps their sessions.
- It issues the tokens the apps use here and at the [voice gateway](../voice-gateway/).
- It acts on the user's [background tasks and command approvals](../orchestrator/).

The contracts are [`proto/jarvis/app/v1/app.proto`](../../proto/jarvis/app/v1/app.proto) (public) and [`admin.proto`](../../proto/jarvis/app/v1/admin.proto) (internal).

```
iPhone app ──HTTPS (Connect / gRPC / gRPC-Web)──▶ app-api ──▶ PostgreSQL: pairing codes, sessions
                                                     │
dashboard backend ──gRPC + mTLS (admin)─────────────▶│
                                                     └──gRPC + mTLS──▶ orchestrator: tasks, approvals
```

| Side | Who | Authentication | RPCs |
|---|---|---|---|
| Public (`APP_PUBLIC_ADDR`) | apps | pairing code, refresh token, or `Authorization: Bearer <access token>` | `RedeemPairingCode`, `RefreshSession`, `SignOut`, `ListTasks`, `CancelTask`, `ListApprovals`, `SubmitApproval`, `RegisterPushToken` |
| Admin (`APP_ADMIN_ADDR`) | dashboard backend (`spiffe://jarvis.local/dashboard-api`) | mTLS + [policy](config/authz.dev.toml) | `CreatePairingCode`, `ListSessions`, `RevokeSession` |

Towards the orchestrator it is `spiffe://jarvis.local/app-api`. The tenant and user of every call come from the verified session, never from the request.

## Pairing and sessions

1. **The dashboard issues a pairing code** (`CreatePairingCode`) for its signed-in user.
   - The code is 12 characters of Crockford base32 (60 bits), shown as `7KQ2-M9XD-4TFA`, and is valid for 10 minutes.
   - It comes with a `jarvis://pair?server=…&code=…` link as a QR code. Scanning it with the iPhone's camera opens the app, which pairs itself.
2. **The app redeems the code** (`RedeemPairingCode`) and gets a session:
   - **An access token** for this API and **a voice token** for the voice gateway. Both are Ed25519 JWTs that expire after 15 minutes and carry the session id (`sid`).
   - **A refresh token**, which the app keeps in the keychain.
   - The voice gateway's address.
3. **Refreshing rotates the refresh token** (`RefreshSession`). Each token works once:
   - Within 60 s of a rotation, the old token still works, so an app that lost the response can retry.
   - After that, presenting the old token means someone copied it, and **the whole session ends**, for the copy and the original alike.
4. **Signing out** (`SignOut`) or **revoking** from the dashboard (`RevokeSession`) ends the session. Its access tokens stop working here at once, and at the voice gateway within 15 minutes.

Pairing codes and refresh tokens are stored only as SHA-256 hashes. Unused refresh tokens expire after 30 days (`APP_REFRESH_IDLE_TTL`). Ended sessions and old pairing codes are deleted after 30 days.

**Tokens and keys.** The app API signs tokens with an Ed25519 key and publishes its JWKS at `GET /.well-known/jwks.json`. The voice gateway trusts that JWKS (`GATEWAY_TOKEN_JWKS`), and each service checks its own audience:
- `jarvis-app-api` for this API,
- `jarvis-voice-gateway` for the gateway.

A voice token therefore does not work here, and an access token does not open a voice session.

## Approvals

`ListApprovals` returns what the user's computers wait for. The payload is the `ApprovalPayload` bytes exactly as the computer sent them. The phone:
1. shows the command from those bytes,
2. signs them with its Secure Enclave key after Face ID,
3. sends the signature with `SubmitApproval`.

The computer's daemon verifies the signature against its `[[approver]]` list and runs the command. **A computer allows one attempt per approval.** A rejected signature (for example, a phone that is not yet one of its approvers) spends the approval, and the task reports that the command did not run.

## Push notifications

The phone gets a notification when:
- **a command waits for its approval** (always; time-sensitive, so it breaks through Focus),
- **a background task waits for a confirmation**, or **a task finished**, while you were not talking to Jarvis. During a conversation Jarvis says it by voice instead.

How it works:
1. **The app registers** its APNs device token for its session (`RegisterPushToken`). A token belongs to one session: when the phone pairs again, it moves to the new session. Revoked or expired sessions get nothing.
2. **The orchestrator queues** each notification in an outbox. The app API's notifier **claims** them with a long poll (`ClaimNotifications`, one-minute lease; several instances never share one), sends them to every phone of the user, and **completes** them.
3. **When APNs rejects a device token** (app removed, other environment), the token is forgotten. A passing failure leaves the notification unfinished, so it is claimed again. The orchestrator gives up after 5 tries or one hour, and approval notifications expire from APNs after 5 minutes.
4. **What a notification says:** only what happened ("A command on one of your computers is waiting for your approval", "Jarvis finished a background task"). It never carries goals, commands or results, because lock screens are public. The app shows the details after you open it.

APNs uses token authentication:
- an ES256 JWT made from your team's `.p8` auth key, renewed every 40 minutes,
- over HTTP/2, to `api.sandbox.push.apple.com` for Xcode builds and `api.push.apple.com` for TestFlight and the App Store.

The phone tells which environment its token is for.

## Protections

- **Rate limits:** the anonymous RPCs (pairing, refresh, sign-out) are limited per client address: 10 at once, then 20 per minute.
  - Guessing would be hopeless anyway: 60-bit codes that expire in 10 minutes, and 256-bit refresh tokens.
  - A wrong code is refused the same way whether it is unknown, used or expired.
- **Transport:**
  - The public listener refuses plaintext on non-loopback addresses unless TLS is configured, or `APP_ALLOW_PLAINTEXT=true` explicitly declares a TLS proxy in front.
  - The voice gateway's address must be `wss://`, except loopback addresses in development.
- **Bounds:** requests are capped at 1 MiB, and orchestrator calls have a 30 s timeout. Errors carry a request id; internals are never exposed.
- **Logs** hold session and tenant ids, never tokens, codes or signatures.

## Configuration

| Variable | Default | |
|---|---|---|
| `APP_PUBLIC_ADDR` | `127.0.0.1:8081` | Public listener (Connect, gRPC, gRPC-Web; HTTP/2 cleartext on loopback) |
| `APP_PUBLIC_URL` | `http://<APP_PUBLIC_ADDR>` | How apps reach it; used in pairing links |
| `APP_TLS_CERT`, `APP_TLS_KEY` | | Serve HTTPS directly |
| `APP_ADMIN_ADDR` | `127.0.0.1:50055` | Admin gRPC listener (mTLS) |
| `APP_ADMIN_TLS_CERT`, `APP_ADMIN_TLS_KEY`, `APP_ADMIN_TLS_CLIENT_CA`, `APP_AUTHZ_POLICY` | required | |
| `APP_METRICS_ADDR` | `127.0.0.1:9096` | `/metrics`, `/healthz` (loopback only) |
| `APP_DATABASE_URL` or `APP_DATABASE_URL_FILE` | required | PostgreSQL |
| `APP_TOKEN_SIGNING_KEY`, `APP_TOKEN_KEY_ID`, `APP_TOKEN_ISSUER` | required | Ed25519 PKCS#8 PEM, its JWKS key id, and the `iss` the gateway expects |
| `APP_ACCESS_TOKEN_TTL`, `APP_REFRESH_IDLE_TTL`, `APP_PAIRING_CODE_TTL` | `15m`, `720h`, `10m` | |
| `APP_VOICE_URL` | required | The voice gateway, e.g. `wss://voice.example.com/v1/voice` |
| `APP_ORCHESTRATOR_ADDR`, `APP_CLIENT_CERT/KEY/CA` | required | The orchestrator and this service's identity towards it |
| `APP_APNS_KEY_FILE`, `APP_APNS_KEY_ID`, `APP_APNS_TEAM_ID`, `APP_APNS_TOPIC` | empty: no push | Your APNs auth key (`AuthKey_<KEY ID>.p8`), its id, your team id and the app's bundle id; all four or none |

## Development

```bash
pnpm infra:up                       # PostgreSQL (database `app`, role `app_api`)
pnpm nx run orchestrator:serve      # and what it needs; see its README
pnpm nx run app-api:serve           # public API on http://127.0.0.1:8081
```

`scripts/dev-run.sh` signs with the voice gateway's development key (`services/voice-gateway/.dev/tokens`), so the gateway accepts its voice tokens.

It turns push notifications on by itself when your APNs key is in `~/.config/jarvis/apns/AuthKey_<KEY ID>.p8` (mode 600):
- the key id comes from the file name,
- the team and bundle id come from the iOS app's `Config/Local.xcconfig`.

**Pair an app:**

```bash
cd services/app-api
go run ./cmd/appctl pair -tenant $TENANT -user me     # prints a QR code, the code and the link
go run ./cmd/appctl sessions -tenant $TENANT -user me
go run ./cmd/appctl revoke -tenant $TENANT -user me -session <id>
```

Scan the QR code with the iPhone (or the simulator's camera). Alternatively, use `jarvis-cli pair '<link>'` from [`apps/ios`](../../apps/ios/README.md#jarvis-cli).

## Tests

```bash
pnpm nx run app-api:test   # go test -race ./... (PostgreSQL via testcontainers)
```

[`internal/api`](internal/api/api_test.go) drives the real Connect handlers over HTTP, with a real PostgreSQL and a fake orchestrator over gRPC. It covers:
- pairing, with loose typing of codes and single use
- expired, unknown and malformed codes, and rate limiting
- token audiences checked against the published JWKS
- refresh rotation, retry within the grace period, and reuse ending the session
- sign-out that ends the session at once
- rejected tokens: voice tokens, tokens without a session, other users'
- tasks and approvals acting only for the signed-in user
- error mapping
- admin listing and revocation
- push tokens following the phone's current session, and none for revoked sessions

[`internal/apns`](internal/apns/apns_test.go) checks the client against a fake APNs over HTTP/2: the provider token (ES256, key and team ids, reuse and renewal), headers, payload, dead tokens and passing failures. [`internal/push`](internal/push/push_test.go) checks the notifier: every phone of the user, generic text only, dead tokens forgotten, and failures retried.

Mutation testing confirmed that the tests catch each of these defects:
- reusable or never-expiring codes
- no reuse detection
- refreshes of revoked sessions
- skipped session or owner checks
- voice tokens accepted here
- expired approvals listed
- a sign-out that does nothing
- push tokens staying with an old session, or revoked sessions still notified
- failed pushes completed, dead tokens kept, task details on the lock screen

## Known limitations

- **One signing key.** There is no rotation yet. The gateway reads the JWKS from a file, not from the endpoint.
- **Rate limits are per instance**, in memory.
- **Pairing is the only way in.** The [dashboard](../../apps/dashboard/) issues the codes (Devices page) to its signed-in users; `appctl` does the same for development.
