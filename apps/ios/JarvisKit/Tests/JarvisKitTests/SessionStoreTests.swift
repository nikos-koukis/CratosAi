import Foundation
import SwiftProtobuf
import Synchronization
import Testing

@testable import JarvisKit

/// A fake app API: rotating refresh tokens, counters, and switches.
final class FakeAppAPI: Sendable {
    struct State {
        var currentRefresh = "jrt_1"
        var refreshes = 0
        var accessCalls: [String] = []
        var signOuts: [String] = []
        var generation = 1
        /// The next refresh fails like this.
        var failRefresh: (status: Int, code: String, reason: String?)?
        /// The next ListTasks fails with a plain unauthenticated error.
        var rejectNextAccess = false
        /// Access tokens expire this long after issue.
        var accessLifetime: TimeInterval = 900
    }

    let state = Mutex(State())
    let host: String

    init(host: String) {
        self.host = host
    }

    var client: @Sendable (URL) -> AppClient {
        let session = StubURLProtocol.session(host: host) { [self] request, body in handle(request, body) }
        return { AppClient(baseURL: $0, session: session) }
    }

    private func session(_ state: inout State) -> AppSession {
        var s = AppSession()
        s.sessionID = "s-1"
        s.tenantID = "t-1"
        s.userID = "u-1"
        s.accessToken = "at-\(state.generation)"
        s.voiceToken = "vt-\(state.generation)"
        s.voiceURL = "wss://voice.test/v1/voice"
        s.accessTokenExpireTime = Google_Protobuf_Timestamp(date: Date().addingTimeInterval(state.accessLifetime))
        s.refreshToken = state.currentRefresh
        return s
    }

    private func ok(_ message: some SwiftProtobuf.Message) -> (Int, [String: String], Data) {
        (200, ["Content-Type": "application/proto"], try! message.serializedData())
    }

    private func handle(_ request: URLRequest, _ body: Data) -> (status: Int, headers: [String: String], body: Data) {
        let method = request.url!.lastPathComponent
        let json = ["Content-Type": "application/json"]
        return state.withLock { state in
            switch method {
            case "RedeemPairingCode":
                let code = try! Jarvis_App_V1_RedeemPairingCodeRequest(serializedBytes: body).code
                guard code == "GOOD-CODE-0001" else {
                    return (
                        401, json,
                        connectErrorBody(
                            code: "unauthenticated", message: "bad code",
                            reason: "ERROR_REASON_PAIRING_CODE_INVALID")
                    )
                }
                var response = Jarvis_App_V1_RedeemPairingCodeResponse()
                response.session = session(&state)
                return ok(response)
            case "RefreshSession":
                state.refreshes += 1
                if let failure = state.failRefresh {
                    state.failRefresh = nil
                    return (
                        failure.status, json,
                        connectErrorBody(code: failure.code, message: "no", reason: failure.reason)
                    )
                }
                let presented = try! Jarvis_App_V1_RefreshSessionRequest(serializedBytes: body).refreshToken
                guard presented == state.currentRefresh else {
                    return (
                        401, json,
                        connectErrorBody(
                            code: "unauthenticated", message: "reused",
                            reason: "ERROR_REASON_SESSION_ENDED")
                    )
                }
                state.generation += 1
                state.currentRefresh = "jrt_\(state.generation)"
                var response = Jarvis_App_V1_RefreshSessionResponse()
                response.session = session(&state)
                return ok(response)
            case "SignOut":
                state.signOuts.append(try! Jarvis_App_V1_SignOutRequest(serializedBytes: body).refreshToken)
                return ok(Jarvis_App_V1_SignOutResponse())
            case "ListTasks":
                let token = request.value(forHTTPHeaderField: "Authorization") ?? ""
                state.accessCalls.append(token)
                if state.rejectNextAccess {
                    state.rejectNextAccess = false
                    return (401, json, connectErrorBody(code: "unauthenticated", message: "bad token"))
                }
                return ok(Jarvis_App_V1_ListTasksResponse())
            default:
                return (404, [:], Data())
            }
        }
    }
}

@Suite struct SessionStoreTests {
    let server = URL(string: "https://api.test")!

    func paired(_ api: FakeAppAPI, secrets: SecretStore = MemoryStore()) async throws -> SessionStore {
        let store = SessionStore(secrets: secrets, makeClient: api.client)
        try await store.pair(
            serverURL: URL(string: "https://\(api.host)")!, code: "GOOD-CODE-0001",
            deviceName: "Test iPhone", deviceModel: "iPhone17,1")
        return store
    }

    @Test func pairingKeepsOnlyTheRefreshTokenOnTheDevice() async throws {
        let api = FakeAppAPI(host: "pair.test")
        let secrets = MemoryStore()
        let store = try await paired(api, secrets: secrets)
        #expect(await store.account?.userID == "u-1")
        let saved = String(decoding: try #require(try secrets.read("session")), as: UTF8.self)
        #expect(saved.contains("jrt_1"))
        #expect(!saved.contains("at-1") && !saved.contains("vt-1"))
        #expect(try await store.accessToken() == "at-1")
        let voice = try await store.voiceCredentials()
        #expect(voice.url.absoluteString == "wss://voice.test/v1/voice" && voice.token == "vt-1")

        // After a restart the session is still there; tokens are refreshed.
        let restarted = SessionStore(secrets: secrets, makeClient: api.client)
        #expect(await restarted.account?.sessionID == "s-1")
        #expect(try await restarted.accessToken() == "at-2")
        #expect(String(decoding: try #require(try secrets.read("session")), as: UTF8.self).contains("jrt_2"))
    }

    @Test func wrongCodesAreReported() async throws {
        let api = FakeAppAPI(host: "badcode.test")
        let store = SessionStore(secrets: MemoryStore(), makeClient: api.client)
        let error = try await #require(throws: ConnectError.self) {
            try await store.pair(
                serverURL: URL(string: "https://badcode.test")!, code: "NOPE",
                deviceName: "p", deviceModel: "m")
        }
        #expect(error.appReason == .pairingCodeInvalid)
        #expect(await store.account == nil)
        await #expect(throws: SessionError.badServer("the server address must be an https:// URL")) {
            try await store.pair(
                serverURL: URL(string: "ftp://x")!, code: "GOOD-CODE-0001", deviceName: "p",
                deviceModel: "m")
        }
    }

    @Test func concurrentCallersShareOneRefresh() async throws {
        let api = FakeAppAPI(host: "concurrent.test")
        api.state.withLock { $0.accessLifetime = 30 }  // inside the renewal margin: every use refreshes
        let store = try await paired(api)
        let tokens = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<8 {
                group.addTask { try await store.accessToken() }
            }
            return try await group.reduce(into: Set<String>()) { $0.insert($1) }
        }
        #expect(tokens == ["at-2"])
        #expect(api.state.withLock { $0.refreshes } == 1)
    }

    @Test func anEndedSessionSignsTheAppOut() async throws {
        let api = FakeAppAPI(host: "ended.test")
        api.state.withLock { $0.accessLifetime = 30 }
        let secrets = MemoryStore()
        let store = try await paired(api, secrets: secrets)
        var changes = store.accountChanges.makeAsyncIterator()
        #expect(await changes.next() != nil)  // paired

        api.state.withLock { $0.failRefresh = (401, "unauthenticated", "ERROR_REASON_SESSION_ENDED") }
        await #expect(throws: SessionError.ended) { _ = try await store.accessToken() }
        #expect(await store.account == nil)
        #expect(try secrets.read("session") == nil)
        #expect(await changes.next() == .some(nil))
    }

    @Test func networkFailuresKeepTheSession() async throws {
        let api = FakeAppAPI(host: "flaky.test")
        api.state.withLock { $0.accessLifetime = 30 }
        let store = try await paired(api)
        api.state.withLock { $0.failRefresh = (503, "unavailable", nil) }
        await #expect(throws: ConnectError.self) { _ = try await store.accessToken() }
        #expect(await store.account != nil)
        #expect(try await store.accessToken() == "at-2")
    }

    @Test func aRejectedAccessTokenIsRefreshedOnce() async throws {
        let api = FakeAppAPI(host: "retry.test")
        let store = try await paired(api)
        api.state.withLock { $0.rejectNextAccess = true }
        _ = try await store.call { client, token in try await client.listTasks(accessToken: token) }
        let calls = api.state.withLock { $0.accessCalls }
        #expect(calls == ["Bearer at-1", "Bearer at-2"])
    }

    @Test func signingOutForgetsTheSessionAndTellsTheServer() async throws {
        let api = FakeAppAPI(host: "signout.test")
        let secrets = MemoryStore()
        let store = try await paired(api, secrets: secrets)
        await store.signOut()
        #expect(await store.account == nil)
        #expect(try secrets.read("session") == nil)
        #expect(api.state.withLock { $0.signOuts } == ["jrt_1"])
        await #expect(throws: SessionError.notSignedIn) { _ = try await store.accessToken() }
    }
}
