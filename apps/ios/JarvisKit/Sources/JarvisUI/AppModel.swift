import Foundation
import JarvisKit
import Observation
import UserNotifications
import os

#if canImport(UIKit)
    import UIKit
#endif

/// The app's state: the paired account, and the models of each screen.
@MainActor
@Observable
public final class AppModel {
    /// The app's tabs.
    public enum Screen: Hashable {
        case talk, tasks, approvals, settings
    }

    public var screen: Screen = .talk
    public private(set) var account: Account?
    public private(set) var tasks: [JarvisTask] = []
    public private(set) var approvals: [ApprovalRequest] = []
    /// Approvals whose payload did not decode; shown but never signable.
    public private(set) var malformedApprovals = 0
    public var problem: String?
    public var busy = false

    public let voice: VoiceController
    public var provider: Jarvis_Common_V1_Provider {
        didSet { UserDefaults.standard.set(provider.rawValue, forKey: "provider") }
    }

    private let sessions: SessionStore
    private let secrets: SecretStore
    private var watcher: Task<Void, Never>?
    /// The APNs device token of this phone, and the session it was sent for.
    private var deviceToken: Data?
    private var registeredToken: (token: Data, session: String)?
    private let log = Logger(subsystem: "ai.cratos.jarvis", category: "push")

    public init(secrets: SecretStore = KeychainStore()) {
        self.secrets = secrets
        sessions = SessionStore(secrets: secrets)
        voice = VoiceController(sessions: sessions)
        provider =
            Jarvis_Common_V1_Provider(rawValue: UserDefaults.standard.integer(forKey: "provider")) ?? .unspecified
        watcher = Task { [weak self, sessions] in
            if let account = await sessions.account {
                self?.account = account
                await self?.setUpPushNotifications()
            }
            for await change in sessions.accountChanges {
                self?.account = change
                if change == nil {
                    self?.tasks = []
                    self?.approvals = []
                    self?.screen = .talk
                } else {
                    await self?.setUpPushNotifications()
                }
            }
        }
    }

    // MARK: Pairing

    /// Handles a `jarvis://pair?server=…&code=…` link (scanned with the camera).
    public func open(_ url: URL) async {
        guard url.scheme == "jarvis", url.host() == "pair",
            let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems,
            let server = items.first(where: { $0.name == "server" })?.value.flatMap(URL.init(string:)),
            let code = items.first(where: { $0.name == "code" })?.value
        else {
            problem = String(localized: "This link is not a Jarvis pairing link.")
            return
        }
        await pair(server: server, code: code)
    }

    public func pair(server: URL, code: String) async {
        busy = true
        defer { busy = false }
        do {
            account = try await sessions.pair(
                serverURL: server, code: code, deviceName: Self.deviceName,
                deviceModel: Self.deviceModel)
            problem = nil
        } catch let error as ConnectError where error.appReason == .pairingCodeInvalid {
            problem = String(localized: "This code is not valid anymore. Ask for a new one in the dashboard.")
        } catch {
            problem = VoiceController.explain(error)
        }
    }

    public func signOut() async {
        await voice.stop()
        await sessions.signOut()
    }

    // MARK: Tasks and approvals

    public func refresh() async {
        do {
            async let tasks = sessions.call { client, token in
                try await client.listTasks(accessToken: token, limit: 50)
            }
            async let approvals = sessions.call { client, token in
                try await client.listApprovals(accessToken: token)
            }
            self.tasks = try await tasks
            let listed = try await approvals
            self.approvals = listed.compactMap { try? ApprovalRequest($0) }
            malformedApprovals = listed.count - self.approvals.count
            problem = nil
        } catch {
            problem = VoiceController.explain(error)
        }
    }

    public func cancel(_ task: JarvisTask) async {
        do {
            _ = try await sessions.call { client, token in
                try await client.cancelTask(accessToken: token, taskID: task.taskID)
            }
            await refresh()
        } catch {
            problem = VoiceController.explain(error)
        }
    }

    /// Signs and submits an approval; returns the command's result.
    public func approve(_ request: ApprovalRequest) async throws -> String {
        let key = try approverKey()
        let signature = try await request.sign(with: key)
        let approverID = self.approverID
        let output = try await sessions.call { client, token in
            try await client.submitApproval(
                accessToken: token, approvalID: request.id, approverID: approverID,
                signature: signature)
        }
        await refresh()
        return output
    }

    // MARK: Approver key

    /// This phone's approver id on the computers (daemon.toml).
    public var approverID: String {
        if let id = UserDefaults.standard.string(forKey: "approverID") {
            return id
        }
        let id = "iphone-" + UUID().uuidString.prefix(8).lowercased()
        UserDefaults.standard.set(id, forKey: "approverID")
        return id
    }

    public func approverKey() throws -> SecureEnclaveApproverKey {
        try SecureEnclaveApproverKey.loadOrCreate(store: secrets)
    }

    /// The daemon.toml entry that lets this phone approve commands.
    public func approverEntry() throws -> String {
        "[[approver]]\nid = \"\(approverID)\"\npublic_key = \"\(try approverKey().publicKeyBase64)\""
    }

    public func replaceApproverKey() throws -> String {
        _ = try SecureEnclaveApproverKey.create(store: secrets)
        return try approverEntry()
    }

    // MARK: Push notifications

    /// Asks once for permission to notify, then registers with APNs; the
    /// token arrives through `pushTokenReceived`.
    public func setUpPushNotifications() async {
        let center = UNUserNotificationCenter.current()
        do {
            guard try await center.requestAuthorization(options: [.alert, .sound, .badge]) else { return }
        } catch {
            log.warning("notification permission failed: \(String(describing: error), privacy: .public)")
            return
        }
        #if canImport(UIKit)
            UIApplication.shared.registerForRemoteNotifications()
        #endif
        await registerPushToken()
    }

    /// APNs gave this phone a device token.
    public func pushTokenReceived(_ token: Data) async {
        deviceToken = token
        await registerPushToken()
    }

    /// Sends the device token for the current session (again after pairing).
    private func registerPushToken() async {
        guard let token = deviceToken, let session = account?.sessionID else { return }
        if let registeredToken, registeredToken.token == token, registeredToken.session == session { return }
        let sandbox = PushEnvironment.isSandbox
        do {
            try await sessions.call { client, access in
                try await client.registerPushToken(accessToken: access, deviceToken: token, sandbox: sandbox)
            }
            registeredToken = (token, session)
            log.info("push notifications registered (sandbox: \(sandbox, privacy: .public))")
        } catch {
            log.warning("cannot register for push notifications: \(String(describing: error), privacy: .public)")
        }
    }

    /// The user tapped a notification: show what it is about.
    public func openNotification(kind: String) async {
        guard account != nil else { return }
        screen = kind == "approval_needed" ? .approvals : .tasks
        await refresh()
    }

    // MARK: Device

    static var deviceName: String {
        #if canImport(UIKit)
            UIDevice.current.name
        #else
            Host.current().localizedName ?? "Mac"
        #endif
    }

    static var deviceModel: String {
        var info = utsname()
        uname(&info)
        return withUnsafeBytes(of: &info.machine) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
    }
}
