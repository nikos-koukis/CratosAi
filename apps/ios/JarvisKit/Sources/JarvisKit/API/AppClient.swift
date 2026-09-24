import Foundation
@_exported import JarvisProto
import SwiftProtobuf

public typealias AppSession = Jarvis_App_V1_Session
public typealias JarvisTask = Jarvis_App_V1_Task
public typealias TaskState = Jarvis_App_V1_TaskState
public typealias Approval = Jarvis_App_V1_Approval

/// Typed calls to the app API's AppService (jarvis.app.v1).
public struct AppClient: Sendable {
    /// The google.rpc.ErrorInfo domain of the app API's errors.
    public static let errorDomain = "app.jarvis"

    public let baseURL: URL
    private let connect: ConnectClient

    public init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        connect = ConnectClient(baseURL: baseURL, session: session)
    }

    private static let service = "/jarvis.app.v1.AppService/"

    private func call<Request: SwiftProtobuf.Message, Response: SwiftProtobuf.Message>(
        _ method: String, _ request: Request, accessToken: String? = nil
    ) async throws -> Response {
        var headers: [String: String] = [:]
        if let accessToken {
            headers["Authorization"] = "Bearer \(accessToken)"
        }
        return try await connect.unary(Self.service + method, request, headers: headers)
    }

    public func redeemPairingCode(_ code: String, deviceName: String, deviceModel: String) async throws -> AppSession {
        var request = Jarvis_App_V1_RedeemPairingCodeRequest()
        request.code = code
        request.deviceName = deviceName
        request.deviceModel = deviceModel
        let response: Jarvis_App_V1_RedeemPairingCodeResponse = try await call("RedeemPairingCode", request)
        return response.session
    }

    public func refreshSession(refreshToken: String) async throws -> AppSession {
        var request = Jarvis_App_V1_RefreshSessionRequest()
        request.refreshToken = refreshToken
        let response: Jarvis_App_V1_RefreshSessionResponse = try await call("RefreshSession", request)
        return response.session
    }

    public func signOut(refreshToken: String) async throws {
        var request = Jarvis_App_V1_SignOutRequest()
        request.refreshToken = refreshToken
        let _: Jarvis_App_V1_SignOutResponse = try await call("SignOut", request)
    }

    public func listTasks(accessToken: String, limit: Int32 = 20) async throws -> [JarvisTask] {
        var request = Jarvis_App_V1_ListTasksRequest()
        request.limit = limit
        let response: Jarvis_App_V1_ListTasksResponse = try await call("ListTasks", request, accessToken: accessToken)
        return response.tasks
    }

    public func cancelTask(accessToken: String, taskID: String) async throws -> JarvisTask {
        var request = Jarvis_App_V1_CancelTaskRequest()
        request.taskID = taskID
        let response: Jarvis_App_V1_CancelTaskResponse = try await call("CancelTask", request, accessToken: accessToken)
        return response.task
    }

    public func listApprovals(accessToken: String) async throws -> [Approval] {
        let response: Jarvis_App_V1_ListApprovalsResponse =
            try await call("ListApprovals", Jarvis_App_V1_ListApprovalsRequest(), accessToken: accessToken)
        return response.approvals
    }

    /// Sets where this session's push notifications go; nil turns them off.
    public func registerPushToken(accessToken: String, deviceToken: Data?, sandbox: Bool) async throws {
        var request = Jarvis_App_V1_RegisterPushTokenRequest()
        if let deviceToken {
            request.deviceToken = deviceToken.map { String(format: "%02x", $0) }.joined()
            request.environment = sandbox ? .sandbox : .production
        }
        let _: Jarvis_App_V1_RegisterPushTokenResponse =
            try await call("RegisterPushToken", request, accessToken: accessToken)
    }

    /// Returns the command's result (JSON) once the computer has run it.
    public func submitApproval(accessToken: String, approvalID: String, approverID: String, signature: Data)
        async throws -> String
    {
        var request = Jarvis_App_V1_SubmitApprovalRequest()
        request.approvalID = approvalID
        request.approverID = approverID
        request.signature = signature
        let response: Jarvis_App_V1_SubmitApprovalResponse =
            try await call("SubmitApproval", request, accessToken: accessToken)
        return response.output
    }
}

extension ConnectError {
    /// The app API's reason for this error, if any.
    public var appReason: Jarvis_App_V1_ErrorReason? {
        guard let name = reason(domain: AppClient.errorDomain) else { return nil }
        return Jarvis_App_V1_ErrorReason(name: name)
    }
}

extension Jarvis_App_V1_ErrorReason {
    init?(name: String) {
        let cases: [String: Jarvis_App_V1_ErrorReason] = [
            "ERROR_REASON_PAIRING_CODE_INVALID": .pairingCodeInvalid,
            "ERROR_REASON_SESSION_ENDED": .sessionEnded,
            "ERROR_REASON_TASK_NOT_FOUND": .taskNotFound,
            "ERROR_REASON_APPROVAL_NOT_FOUND": .approvalNotFound,
            "ERROR_REASON_APPROVAL_REJECTED": .approvalRejected,
        ]
        guard let value = cases[name] else { return nil }
        self = value
    }
}
