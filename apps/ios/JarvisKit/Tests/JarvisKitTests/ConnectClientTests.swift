import Foundation
import Testing

@testable import JarvisKit

@Suite struct ConnectClientTests {
    @Test func unaryCallsSpeakTheConnectProtocol() async throws {
        let session = StubURLProtocol.session(host: "connect.test") { request, body in
            #expect(request.httpMethod == "POST")
            #expect(request.url?.path() == "/jarvis.app.v1.AppService/ListTasks")
            #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/proto")
            #expect(request.value(forHTTPHeaderField: "Connect-Protocol-Version") == "1")
            #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer at-1")
            let sent = try! Jarvis_App_V1_ListTasksRequest(serializedBytes: body)
            #expect(sent.limit == 7)
            var task = Jarvis_App_V1_Task()
            task.taskID = "t1"
            task.state = .succeeded
            var response = Jarvis_App_V1_ListTasksResponse()
            response.tasks = [task]
            return (200, ["Content-Type": "application/proto"], try! response.serializedData())
        }
        let client = AppClient(baseURL: URL(string: "https://connect.test")!, session: session)
        let tasks = try await client.listTasks(accessToken: "at-1", limit: 7)
        #expect(tasks.map(\.taskID) == ["t1"])
        #expect(tasks.first?.state == .succeeded)
    }

    @Test func pushTokensAreSentAsHex() async throws {
        let session = StubURLProtocol.session(host: "push.test") { request, body in
            let sent = try! Jarvis_App_V1_RegisterPushTokenRequest(serializedBytes: body)
            #expect(request.url?.path() == "/jarvis.app.v1.AppService/RegisterPushToken")
            #expect(sent.deviceToken == "00ff10ab" && sent.environment == .sandbox)
            return (
                200, ["Content-Type": "application/proto"],
                try! Jarvis_App_V1_RegisterPushTokenResponse().serializedData()
            )
        }
        let client = AppClient(baseURL: URL(string: "https://push.test")!, session: session)
        try await client.registerPushToken(
            accessToken: "at", deviceToken: Data([0x00, 0xFF, 0x10, 0xAB]), sandbox: true)
    }

    @Test func errorsCarryTheirReason() async throws {
        let session = StubURLProtocol.session(host: "errors.test") { _, _ in
            (
                401, ["Content-Type": "application/json"],
                connectErrorBody(
                    code: "unauthenticated", message: "the session has ended",
                    reason: "ERROR_REASON_SESSION_ENDED")
            )
        }
        let client = AppClient(baseURL: URL(string: "https://errors.test")!, session: session)
        let error = try await #require(throws: ConnectError.self) {
            _ = try await client.refreshSession(refreshToken: "jrt_x")
        }
        #expect(error.code == .unauthenticated)
        #expect(error.message == "the session has ended")
        #expect(error.appReason == .sessionEnded)
    }

    @Test(arguments: [
        (503, ConnectError.Code.unavailable), (401, .unauthenticated), (404, .unimplemented),
        (400, .internal), (500, .unknown),
    ])
    func errorsWithoutABodyFollowTheHTTPStatus(status: Int, code: ConnectError.Code) async throws {
        let host = "status\(status).test"
        let session = StubURLProtocol.session(host: host) { _, _ in
            (status, ["Content-Type": "text/html"], Data("<html>bad gateway</html>".utf8))
        }
        let client = AppClient(baseURL: URL(string: "https://\(host)")!, session: session)
        let error = try await #require(throws: ConnectError.self) {
            _ = try await client.listApprovals(accessToken: "x")
        }
        #expect(error.code == code)
        #expect(error.appReason == nil)
    }

    @Test func errorInfoFromGoDecodes() throws {
        // proto.Marshal(&errdetails.ErrorInfo{Reason: "ERROR_REASON_SESSION_ENDED",
        //   Domain: "app.jarvis", Metadata: {"k": "v"}}) from connect-go's side.
        let bytes = Data(
            hex: "0a1a4552524f525f524541534f4e5f53455353494f4e5f454e444544120a6170702e6a61727669731a060a016b120176")
        let info = try ConnectError.ErrorInfo(protobuf: bytes)
        #expect(info == ConnectError.ErrorInfo(reason: "ERROR_REASON_SESSION_ENDED", domain: "app.jarvis"))
        #expect(Data(base64Unpadded: "ChpFUlJPUl9SRUFTT05fU0VTU0lPTl9FTkRFRBIKYXBwLmphcnZpcxoGCgFrEgF2") == bytes)
        #expect(throws: ProtobufReader.Malformed.self) {
            try ConnectError.ErrorInfo(protobuf: Data([0x0A, 0x7F, 0x41]))
        }
    }
}
