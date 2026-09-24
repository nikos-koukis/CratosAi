// jarvis-cli: the Jarvis app's code from a terminal, for development and
// end-to-end tests without an iPhone. It uses the same JarvisKit as the app;
// the session lives in ~/.config/jarvis-cli (or $JARVIS_CLI_HOME), and the
// approver key is a software key file instead of the Secure Enclave.
import Foundation
import JarvisKit

let usage = """
    usage: jarvis-cli <command> [options]

      pair <jarvis://pair?...>              pair with a link (or --server URL --code CODE)
      whoami                                show the paired account
      tasks                                 list background tasks
      approvals                             list commands waiting for approval
      keygen [--key FILE] [--id ID]         create a software approver key; prints the daemon.toml entry
      approve <approval-id> [--key FILE] [--id ID] [--yes]
                                            review a command and sign its approval
      talk --in FILE.wav [--turns N] [--linger SECONDS] [--provider openai|xai] [--locale el-GR]
                                            talk to Jarvis with a recording (PCM16 mono 24 kHz)
      signout                               end the session
    """

struct CLIError: Error, CustomStringConvertible {
    let description: String
}

var arguments = Array(CommandLine.arguments.dropFirst())

@MainActor
func option(_ name: String) -> String? {
    guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else { return nil }
    let value = arguments[index + 1]
    arguments.removeSubrange(index...index + 1)
    return value
}

@MainActor
func flag(_ name: String) -> Bool {
    guard let index = arguments.firstIndex(of: name) else { return false }
    arguments.remove(at: index)
    return true
}

let home =
    ProcessInfo.processInfo.environment["JARVIS_CLI_HOME"].map { URL(filePath: $0) }
    ?? FileManager.default.homeDirectoryForCurrentUser.appending(path: ".config/jarvis-cli")
let secrets = FileStore(directory: home)
let store = SessionStore(secrets: secrets)
let defaultKey = home.appending(path: "approver-key.pem").path()

@MainActor
func show(_ task: JarvisTask) {
    let state = String(describing: task.state).replacingOccurrences(of: "TASK_STATE_", with: "").lowercased()
    print("\(task.taskID)  \(state)  \(task.goal)")
    if !task.result.isEmpty {
        print("    → \(task.result.prefix(300))")
    }
    if task.hasPendingApproval {
        print("    waiting for approval \(task.pendingApproval.approvalID) on \(task.pendingApproval.deviceName)")
    }
}

@MainActor
func loadKey(_ path: String) throws -> SoftwareApproverKey {
    guard let pem = try? String(contentsOfFile: path, encoding: .utf8) else {
        throw CLIError(description: "no approver key at \(path); run: jarvis-cli keygen")
    }
    return try SoftwareApproverKey(pem: pem)
}

@MainActor
func run() async throws {
    guard !arguments.isEmpty else {
        print(usage)
        return
    }
    let command = arguments.removeFirst()
    switch command {
    case "pair":
        var server = option("--server").flatMap(URL.init(string:))
        var code = option("--code")
        if let link = arguments.first.flatMap(URL.init(string:)), link.scheme == "jarvis", link.host() == "pair" {
            let items = URLComponents(url: link, resolvingAgainstBaseURL: false)?.queryItems ?? []
            server = items.first { $0.name == "server" }?.value.flatMap(URL.init(string:))
            code = items.first { $0.name == "code" }?.value
        }
        guard let server, let code else {
            throw CLIError(description: "pair needs a jarvis://pair link or --server and --code")
        }
        let host = ProcessInfo.processInfo.hostName
        let account = try await store.pair(
            serverURL: server, code: code, deviceName: "jarvis-cli on \(host)",
            deviceModel: "macOS")
        print("paired: user \(account.userID), tenant \(account.tenantID), session \(account.sessionID)")

    case "whoami":
        guard let account = await store.account else { throw CLIError(description: "not paired; run: jarvis-cli pair") }
        print(
            "user \(account.userID)\ntenant \(account.tenantID)\nsession \(account.sessionID)\nserver \(account.serverURL)"
        )

    case "tasks":
        let tasks = try await store.call { client, token in try await client.listTasks(accessToken: token) }
        if tasks.isEmpty { print("no tasks") }
        tasks.forEach(show)

    case "approvals":
        let approvals = try await store.call { client, token in try await client.listApprovals(accessToken: token) }
        if approvals.isEmpty { print("nothing waits for approval") }
        for approval in approvals {
            let request = try? ApprovalRequest(approval)
            print("\(approval.approvalID)  on \(request?.deviceName ?? "?"): \(request?.commandLine ?? "(malformed)")")
            print("    for: \(approval.taskGoal)")
        }

    case "keygen":
        let path = option("--key") ?? defaultKey
        let id = option("--id") ?? "cli-dev"
        guard !FileManager.default.fileExists(atPath: path) else {
            throw CLIError(description: "\(path) exists; remove it first to make a new key")
        }
        let key = SoftwareApproverKey()
        try FileManager.default.createDirectory(
            at: URL(filePath: path).deletingLastPathComponent(),
            withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        guard
            FileManager.default.createFile(
                atPath: path, contents: Data(key.pem.utf8),
                attributes: [.posixPermissions: 0o600])
        else {
            throw CLIError(description: "cannot write \(path)")
        }
        print("Approver key written to \(path). Add this to the computer's daemon.toml:\n")
        print("[[approver]]\nid = \"\(id)\"\npublic_key = \"\(key.publicKeyBase64)\"")

    case "approve":
        let key = try loadKey(option("--key") ?? defaultKey)
        let approverID = option("--id") ?? "cli-dev"
        let yes = flag("--yes")
        guard let wanted = arguments.first else { throw CLIError(description: "approve needs an approval id") }
        let approvals = try await store.call { client, token in try await client.listApprovals(accessToken: token) }
        guard let approval = approvals.first(where: { $0.approvalID == wanted }) else {
            throw CLIError(description: "no pending approval \(wanted)")
        }
        let request = try ApprovalRequest(approval)
        print("Run on \(request.deviceName):\n  \(request.commandLine)\n  in \(request.workingDirectory)")
        print(
            "  timeout \(Int(request.timeout)) s; sandbox: \(request.grants.isEmpty ? "read-only, no network" : request.grants.joined(separator: "; "))"
        )
        print("  for: \(request.taskGoal)\n  expires \(request.expires.formatted(date: .omitted, time: .standard))")
        if !yes {
            print("Approve? [y/N] ", terminator: "")
            guard readLine()?.lowercased() == "y" else {
                print("not approved")
                return
            }
        }
        let signature = try await request.sign(with: key)
        let output = try await store.call { client, token in
            try await client.submitApproval(
                accessToken: token, approvalID: request.id, approverID: approverID,
                signature: signature)
        }
        print("approved; result: \(output)")

    case "talk":
        guard let input = option("--in") else { throw CLIError(description: "talk needs --in FILE.wav") }
        let turns = Int(option("--turns") ?? "1") ?? 1
        let linger = Double(option("--linger") ?? "0") ?? 0
        let provider: Jarvis_Common_V1_Provider =
            switch option("--provider") {
            case "openai": .openai
            case "xai": .xai
            default: .unspecified
            }
        let locale = option("--locale") ?? ""
        let audio = FileAudio(speech: try WAV.read(URL(filePath: input)))
        let credentials = try await store.voiceCredentials()
        let session = VoiceSession(
            transport: WebSocketTransport(url: credentials.url, token: credentials.token),
            audio: audio)
        let ready = try await session.start(provider: provider, locale: locale)
        print("session \(ready.sessionID): \(ready.provider), voice \(ready.voice)")
        var spoken = 0
        var lingering = false
        var answered = false
        for await event in session.events {
            switch event {
            case .transcript(let line) where line.final:
                print(line.speaker == .user ? "you:       \(line.text)" : "assistant: \(line.text)")
                answered = answered || line.speaker == .assistant
            case .assistantDone:
                guard answered else {
                    print("… the assistant is using a tool")
                    continue
                }
                answered = false
                spoken += 1
                if spoken < turns {
                    audio.speakAgain()
                } else if linger > 0, !lingering {
                    print("… listening for \(Int(linger)) s")
                    lingering = true
                    Task {
                        try? await Task.sleep(for: .seconds(linger))
                        await session.end()
                    }
                } else if !lingering {
                    await session.end()
                }
            case .warning(let message):
                print("warning: \(message)")
            case .ended(let reason):
                if case .byUser = reason {} else { print("ended: \(reason)") }
            default:
                break
            }
        }
        let out = URL(filePath: input).deletingPathExtension().appendingPathExtension("reply.wav")
        try WAV.write(audio.reply, to: out)
        print("saved \(String(format: "%.1f", Double(audio.reply.count) / 48_000)) s of replies to \(out.path())")

    case "signout":
        await store.signOut()
        print("signed out")

    default:
        print(usage)
        throw CLIError(description: "unknown command \(command)")
    }
}

do {
    try await run()
} catch {
    FileHandle.standardError.write(Data("jarvis-cli: \(error)\n".utf8))
    exit(1)
}
