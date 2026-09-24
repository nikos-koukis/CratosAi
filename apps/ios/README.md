# Jarvis for iPhone

The iPhone app. You talk to Jarvis by voice, follow its background tasks, and approve commands on your computers with Face ID. It talks to the [app API](../../services/app-api/) for pairing, tasks and approvals, and to the [voice gateway](../../services/voice-gateway/) for voice.

```
apps/ios/
  JarvisKit/            Swift package: everything except the app target
    Sources/JarvisKit   app API client (Connect), session, voice session, audio, approver
    Sources/JarvisUI    the SwiftUI screens and their models (iOS; also compiles for macOS)
    Sources/jarvis-cli  the same code from a terminal (development and end-to-end tests)
    Tests/              Swift Testing
  Jarvis/               the app target: entry point, Info.plist, assets
  project.yml           XcodeGen spec for Jarvis.xcodeproj (generated, not committed)
  Config/Base.xcconfig  shared settings; your team goes in Config/Local.xcconfig
```

The generated Swift for the protocol buffers is in [`gen/swift`](../../gen/swift/) (`pnpm nx run proto:generate`). The only dependency is `swift-protobuf`. The app API client is a small Connect implementation over URLSession, so the app does not pull in SwiftNIO.

## What it does

- **Pairing.** Scan the QR code from the [dashboard](../dashboard/) (Devices → Pair an iPhone), or from `appctl pair`, with the Camera app. The `jarvis://pair` link opens Jarvis and pairs it; typing the server and code works too.
  - The refresh token stays in the keychain (`ThisDeviceOnly`), and access tokens stay in memory.
  - Refreshes are serialized, because a refresh token works once.
- **Talk.**
  - Microphone audio streams to the voice gateway as 20 ms PCM16 frames at 24 kHz, and Jarvis's voice plays back.
  - The system's voice processing (echo cancellation) keeps Jarvis's own voice out of the microphone, so you can talk over it: queued speech stops the moment you start.
  - The session keeps running with the screen locked (background audio).
- **Tasks.** Jarvis's background tasks and their results. Swipe to cancel.
- **Approvals.** Commands on your computers that need your OK.
  - Everything shown (program, arguments, folder, time limit, sandbox permissions) comes from the exact bytes the computer sent, and exactly those bytes are signed.
  - Invisible and right-to-left characters are shown as `\u{…}`, so a command cannot pass for another.
  - The key lives in the Secure Enclave and signs only with Face ID of a currently enrolled face. If Face ID changes, the key stops working and the app offers a new one.
- **Settings.** The voice provider, and this phone's `[[approver]]` entry for the computers' `daemon.toml` (share it to your Mac).
- **Notifications.** After pairing, the app asks for permission and registers with APNs.
  - A command waiting for approval is time-sensitive; tapping it opens Approvals.
  - A task that finished or needs your OK while you were not talking to Jarvis opens Tasks.
  - The text is generic (no commands or results on the lock screen).
  - Xcode builds use the APNs sandbox, and TestFlight and App Store builds production. The app reads which from its provisioning profile.

## Build and run

You need:
- **Xcode 26 or newer** with the iOS 18+ SDK. The Command Line Tools alone build and test JarvisKit, but not the app.
- **XcodeGen:** `brew install xcodegen`.
- **Your Apple developer team.**

```bash
cd apps/ios
cat > Config/Local.xcconfig <<'EOF'
DEVELOPMENT_TEAM = ABCDE12345
JARVIS_BUNDLE_ID_PREFIX = com.yourname
EOF
pnpm nx run ios:project        # xcodegen generate
open Jarvis.xcodeproj          # run the Jarvis scheme on a simulator or your iPhone
pnpm nx run ios:build-app      # command-line build for the simulator (skipped without Xcode)
```

### Push notifications

1. **In the Apple Developer portal**, create a key with **Apple Push Notifications service (APNs)**. Keep the `.p8` in `~/.config/jarvis/apns/` with mode 600. The app API's development script finds it there.
2. **In Xcode** (target Jarvis → Signing & Capabilities), check that **Push Notifications** and **Time Sensitive Notifications** are enabled. The entitlements are in [`Jarvis/Jarvis.entitlements`](Jarvis/Jarvis.entitlements), and automatic signing registers them for your App ID.
3. **Run the app** (simulator or iPhone), pair it, and allow notifications. A task that ends while no conversation is open, or any command approval, then reaches the phone.

### Against the local development stack

**Simulator.** It reaches the Mac's `127.0.0.1`, so the development defaults work as they are.

1. Run the services, as in the [orchestrator README](../../services/orchestrator/README.md#development). Add the app API (`pnpm nx run app-api:serve`) and the voice gateway (`ECHO=1 pnpm nx run voice-gateway:serve` for a free fake provider, or real keys).
2. Pair: `(cd services/app-api && go run ./cmd/appctl pair -tenant $TENANT -user me)`, then open the printed link in the simulator with `xcrun simctl openurl booted '<link>'`.

Approvals need the Secure Enclave, which the simulator does not have. Use a real iPhone, or `jarvis-cli` below.

**iPhone.** The phone must reach the app API and the voice gateway over HTTPS/WSS. The simplest way is [Tailscale Serve](https://tailscale.com/kb/1312/serve) on the Mac, with the phone on the same tailnet:

```bash
tailscale serve --bg --https=8443 http://127.0.0.1:8081    # app API
tailscale serve --bg --https=443 http://127.0.0.1:8080     # voice gateway
APP_PUBLIC_URL=https://<mac>.<tailnet>.ts.net:8443 \
APP_VOICE_URL=wss://<mac>.<tailnet>.ts.net/v1/voice pnpm nx run app-api:serve
```

Then add the phone as an approver:
1. On the phone, open **Settings → Approving commands**, and share the entry to your Mac.
2. Add it to the daemon's `daemon.toml`.
3. Restart `jarvisd`.

## jarvis-cli

The app's code in a terminal. It uses the same JarvisKit, but keeps the session in `~/.config/jarvis-cli` (or `$JARVIS_CLI_HOME`) and uses a software approver key instead of the Secure Enclave.

```bash
cd apps/ios/JarvisKit
swift run jarvis-cli pair '<jarvis://pair?... link from appctl>'
swift run jarvis-cli tasks
swift run jarvis-cli talk --in question.wav --turns 1 --linger 5    # PCM16 mono 24 kHz WAV
swift run jarvis-cli keygen --id cli-dev          # prints the [[approver]] entry for daemon.toml
swift run jarvis-cli approvals
swift run jarvis-cli approve <approval-id> --id cli-dev
```

## Tests

```bash
pnpm nx run ios:test     # scripts/swift-test.sh: Swift Testing on macOS, with or without Xcode
pnpm nx run ios:lint     # swift format lint --strict
```

The tests cover:
- **The Connect client:** request format, error decoding, and ErrorInfo bytes produced by connect-go.
- **The session store:**
  - only the refresh token is stored
  - it survives restarts
  - concurrent callers share one refresh
  - an ended session signs the app out
  - network failures keep the session
  - a rejected token is refreshed once
- **Approvals:**
  - the review comes from the signed bytes
  - invisible characters are escaped
  - malformed payloads are refused
  - signatures verify as the daemon checks them
  - high-S signatures are normalized
- **Voice:**
  - 20 ms framing, and resampling from 48 kHz with level kept
  - playback conversion and transcript merging
  - the whole session protocol against a scripted gateway: barge-in, warnings, a fatal end, refusal, timeout, goodbye
  - a refused microphone stops before any connection is opened

End to end, `jarvis-cli` has run against the real app API, voice gateway, orchestrator and Mac daemon:
- pairing from an `appctl` link
- a voice turn with a tool call
- a command approved with a signature the Rust daemon verified
- refresh-token reuse ending the session
- revocation from the admin side

## Known limitations

- **English only.** The strings are ready for a String Catalog.
- **iPhone only.** JarvisUI also compiles for macOS; a Mac app is mostly a new target.
