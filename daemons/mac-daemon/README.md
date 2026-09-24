# Jarvis local daemon (`jarvisd`)

Runs commands on the user's Mac for the Jarvis orchestrator: allowlisted commands immediately, anything else only after the user signs an approval. Every command runs inside the macOS sandbox. Contract: [`proto/jarvis/device/v1/device.proto`](../../proto/jarvis/device/v1/device.proto).

## Security model

Checks run in this order on every call.

**1. Network.**
- In `tailscale` mode the daemon listens only on the Mac's Tailscale address and serves only tailnet peers. It is never exposed on the LAN or on localhost.
- If Tailscale is down, it waits instead of falling back to another interface.

**2. Caller identity.**
- Mutual TLS is required. The caller is the single URI SAN of its client certificate.
- `[[principal]]` grants decide which RPCs each caller may use.

**3. Policy.**
- **Deny list:** these programs never run, even approved. It covers sudo, security, launchctl and other privilege, persistence and credential tools.
- **Allowlist:** runs immediately when the program matches (canonical path) and the arguments start with `args_prefix`.
- **Everything else**, including allowlisted commands that ask for more grants, returns `ApprovalRequired`.

**4. Approval.**
- The daemon issues a payload describing exactly one command. The approver decodes it, shows it, and signs it with ECDSA P-256.
- The daemon accepts the approval only if all of these hold:
  - The signature verifies against a configured approver key.
  - It is unexpired and unused. Approvals are single use, and a failed attempt burns it too.
  - The retried command is byte-for-byte the approved one.
- A compromised orchestrator cannot forge approvals.

**5. Sandbox (Seatbelt via `sandbox-exec`).** Denies by default. Every command may read non-protected files, and nothing more unless granted:

| Grant | Allows |
|---|---|
| none | read non-protected files, write its private `$TMPDIR` |
| `writable` | create, modify and delete inside the working directory |
| `network` | outbound connections (DNS and TLS trust included) |
| `system_services` | macOS services: launching apps, AppleScript, clipboard. This acts outside the sandbox, so use it sparingly. |

Protected paths can never be read or written, whatever the grants. They are:
- `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.config/gh`
- keychains, cookies, mail, messages, browser profiles
- every `.env` file
- the daemon's own configuration and TLS directories, plus any extra paths you configure

**6. Execution.**
- No shell: `program` and `args` are executed directly.
- Scrubbed environment and a private temp dir that is deleted afterwards.
- Output is capped, and there is a hard timeout.
- Each command gets its own process group. On timeout, or once the command exits, the whole group is killed, so nothing it started survives.

**7. Audit.** Every call is logged with `target=audit`: caller, program, arguments, directory, grants, decision, approver, exit status and duration. Command output is not logged.

**The daemon itself:**
- Runs as the user (a LaunchAgent), never as root.
- Refuses a config other users could modify, or a TLS key other users could read.
- Refuses to start without `sandbox-exec`.
- Disables core dumps.

## Development

```bash
pnpm nx run mac-daemon:setup   # .dev/: certs, approver key, config (loopback, workspace = this repo)
pnpm nx run mac-daemon:serve   # run jarvisd

# In another terminal (needs: brew install grpcurl)
cd daemons/mac-daemon
scripts/grpc.sh GetCapabilities
scripts/grpc.sh ExecuteCommand '{"program":"/usr/bin/git","args":["status","--short"]}'
```

**Approval flow.**
1. Send a command that is not on the allowlist, for example `{"program":"/bin/cat","args":["README.md"]}`. The response is `approvalRequired` with a `payload`.
2. Review and sign it:
   ```bash
   ../../target/debug/jarvis-approve --key .dev/approver/approver-key.pem sign <payload>
   ```
   This prints an `approval` object.
3. Send the same command again with `"approval": <that object>`.

**Tailscale mode.** Turn Tailscale on, set `mode = "tailscale"` in `.dev/config/daemon.toml` and restart. Then call it through the tailnet address:
```bash
ADDRESS=$(tailscale ip -4):7443 scripts/grpc.sh GetCapabilities
```

## Installing as a LaunchAgent

1. Put your configuration at `~/Library/Application Support/Jarvis/daemon/daemon.toml` (mode 600). Start from [`config/daemon.example.toml`](config/daemon.example.toml).
2. Run:
   ```bash
   daemons/mac-daemon/scripts/launchagent.sh install   # build, install, start
   daemons/mac-daemon/scripts/launchagent.sh status
   daemons/mac-daemon/scripts/launchagent.sh uninstall
   ```

Logs go to `~/Library/Logs/Jarvis/jarvisd.log`.

## Tests

```bash
pnpm nx run mac-daemon:test
```

- **Unit tests:** policy, approvals, config validation and the network checks.
- **`tests/sandbox.rs`:** the real macOS sandbox. It checks that the following fail without their grant:
  - reading secrets or `.env` files, including through symlinks
  - writing outside the working directory
  - network and macOS services
  - leaking environment variables
  - leaving processes behind after a timeout or exit
- **`tests/grpc_api.rs`:** the full daemon over mTLS. It covers the allowlist, approvals (single use, bound to the command, forgeries rejected), the deny list, working-directory confinement, authorization and limits.

## Known limitations

- **`sandbox-exec` is deprecated by Apple.** It still works on macOS 26 and is what major developer tools use today. Replacing it would mean an Endpoint Security or App Sandbox helper.
- **Reads are broad.** Commands can read any non-protected file the user can. Add sensitive locations to `protected_paths`.
- **`system_services` escapes the sandbox** through the services it can reach, such as launching apps or AppleScript. Grant it only to specific allowlist entries, ideally with `requires_approval`.
- **A command could escape its process group** by calling `setsid()`, and then survive the timeout kill.
- **The dev approver is a file.** `jarvis-approve` keeps its key in a file. The real approver is the iOS app (Phase 4), with the key in the Secure Enclave behind Face ID.
- **No Tailscale-identity check.** Peers are restricted to tailnet addresses plus mTLS. Checking their Tailscale identity (LocalAPI `whois`) is not implemented yet.
