import Foundation
import os

/// The paired account, as the UI shows it.
public struct Account: Sendable, Equatable, Codable {
    public var serverURL: URL
    public var sessionID: String
    public var tenantID: String
    public var userID: String
}

public enum SessionError: Error, Equatable, CustomStringConvertible {
    /// The app is not paired.
    case notSignedIn
    /// The server ended the session (signed out elsewhere, revoked, expired,
    /// or its refresh token was used twice); the app must pair again.
    case ended
    /// The pairing link or server address is not usable.
    case badServer(String)

    public var description: String {
        switch self {
        case .notSignedIn: "not paired"
        case .ended: "the session has ended; pair the app again"
        case .badServer(let why): why
        }
    }
}

/// Keeps the app's session: the refresh token in the keychain, short-lived
/// tokens in memory. Refreshes are serialized (a refresh token works once),
/// and the stored token is replaced before a new one is used.
public actor SessionStore {
    struct Stored: Codable {
        var account: Account
        var voiceURL: URL
        var refreshToken: String
    }

    struct Tokens {
        var access: String
        var voice: String
        var expires: Date
    }

    private static let key = "session"
    /// Tokens are renewed this long before they expire.
    private static let margin: TimeInterval = 60

    private let secrets: SecretStore
    private let makeClient: @Sendable (URL) -> AppClient
    private let now: @Sendable () -> Date
    private let log = Logger(subsystem: "ai.cratos.jarvis", category: "session")

    private var stored: Stored?
    private var tokens: Tokens?
    private var refreshing: Task<Tokens, Error>?
    private let changes: AsyncStream<Account?>.Continuation

    /// The account after every sign-in and sign-out (nil: signed out).
    public nonisolated let accountChanges: AsyncStream<Account?>

    public init(
        secrets: SecretStore,
        makeClient: @escaping @Sendable (URL) -> AppClient = { AppClient(baseURL: $0) },
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.secrets = secrets
        self.makeClient = makeClient
        self.now = now
        (accountChanges, changes) = AsyncStream.makeStream(bufferingPolicy: .bufferingNewest(1))
        if let data = try? secrets.read(Self.key) {
            stored = try? JSONDecoder().decode(Stored.self, from: data)
        }
    }

    /// The paired account, if any.
    public var account: Account? { stored?.account }

    /// Pairs with a code from the dashboard (or `jarvis://pair` link).
    @discardableResult
    public func pair(serverURL: URL, code: String, deviceName: String, deviceModel: String) async throws -> Account {
        guard ["https", "http"].contains(serverURL.scheme ?? ""), serverURL.host() != nil else {
            throw SessionError.badServer("the server address must be an https:// URL")
        }
        let session = try await makeClient(serverURL).redeemPairingCode(
            code, deviceName: deviceName,
            deviceModel: deviceModel)
        guard let voiceURL = URL(string: session.voiceURL) else {
            throw SessionError.badServer("the server sent an unusable voice address")
        }
        if let old = stored {
            // Pairing again replaces the old session; end it quietly.
            let client = makeClient(old.account.serverURL)
            Task { try? await client.signOut(refreshToken: old.refreshToken) }
        }
        let account = Account(
            serverURL: serverURL, sessionID: session.sessionID, tenantID: session.tenantID,
            userID: session.userID)
        try save(Stored(account: account, voiceURL: voiceURL, refreshToken: session.refreshToken))
        tokens = Tokens(
            access: session.accessToken, voice: session.voiceToken,
            expires: session.accessTokenExpireTime.date)
        refreshing = nil
        log.info("paired session \(account.sessionID, privacy: .public)")
        changes.yield(account)
        return account
    }

    /// A valid access token for the app API.
    public func accessToken() async throws -> String {
        try await validTokens().access
    }

    /// The voice gateway's address and a valid token for it.
    public func voiceCredentials() async throws -> (url: URL, token: String) {
        let tokens = try await validTokens()
        guard let stored else { throw SessionError.notSignedIn }
        return (stored.voiceURL, tokens.voice)
    }

    /// Runs an app API call with a valid token. If the server rejects the
    /// token (e.g. it restarted with a new key), it refreshes once and retries.
    public func call<T: Sendable>(_ body: @Sendable (AppClient, String) async throws -> T) async throws -> T {
        guard let current = stored else { throw SessionError.notSignedIn }
        let client = makeClient(current.account.serverURL)
        do {
            return try await body(client, try await accessToken())
        } catch let error as ConnectError where error.code == .unauthenticated {
            if error.appReason == .sessionEnded {
                end(current.account.sessionID)
                throw SessionError.ended
            }
            tokens = nil
            return try await body(client, try await accessToken())
        }
    }

    /// Ends the session here and on the server.
    public func signOut() async {
        guard let old = stored else { return }
        end(old.account.sessionID)
        do {
            try await makeClient(old.account.serverURL).signOut(refreshToken: old.refreshToken)
        } catch {
            log.warning("sign out on the server failed: \(String(describing: error), privacy: .public)")
        }
    }

    private func validTokens() async throws -> Tokens {
        if let tokens, tokens.expires.timeIntervalSince(now()) > Self.margin {
            return tokens
        }
        guard let current = stored else { throw SessionError.notSignedIn }
        let task: Task<Tokens, Error>
        if let refreshing {
            task = refreshing
        } else {
            let client = makeClient(current.account.serverURL)
            task = Task { try await client.refreshSession(refreshToken: current.refreshToken) }
                .asTokens(onRotated: { session in try await self.rotated(session, replacing: current) })
            refreshing = task
        }
        do {
            let fresh = try await task.value
            if refreshing == task {
                refreshing = nil
            }
            return fresh
        } catch let error as ConnectError where error.appReason == .sessionEnded {
            log.notice("the server ended the session")
            end(current.account.sessionID)
            throw SessionError.ended
        } catch {
            if refreshing == task {
                refreshing = nil
            }
            throw error
        }
    }

    /// Stores the rotated refresh token before anything uses the new tokens.
    /// If the app paired again meanwhile, the old session's tokens are dropped.
    private func rotated(_ session: AppSession, replacing current: Stored) throws -> Tokens {
        guard stored?.account.sessionID == current.account.sessionID else { throw CancellationError() }
        var next = current
        next.refreshToken = session.refreshToken
        if let voiceURL = URL(string: session.voiceURL) {
            next.voiceURL = voiceURL
        }
        try save(next)
        let fresh = Tokens(
            access: session.accessToken, voice: session.voiceToken,
            expires: session.accessTokenExpireTime.date)
        tokens = fresh
        return fresh
    }

    private func save(_ value: Stored) throws {
        try secrets.write(Self.key, try JSONEncoder().encode(value))
        stored = value
    }

    /// Forgets the session, unless another one has replaced it meanwhile.
    private func end(_ sessionID: String) {
        guard stored?.account.sessionID == sessionID else { return }
        stored = nil
        tokens = nil
        refreshing = nil
        try? secrets.delete(Self.key)
        changes.yield(nil)
    }
}

extension Task where Success == AppSession, Failure == Error {
    /// Turns a refresh into tokens, storing the rotated refresh token first.
    fileprivate func asTokens(onRotated: @escaping @Sendable (AppSession) async throws -> SessionStore.Tokens)
        -> Task<SessionStore.Tokens, Error>
    {
        Task<SessionStore.Tokens, Error> { try await onRotated(try await self.value) }
    }
}
