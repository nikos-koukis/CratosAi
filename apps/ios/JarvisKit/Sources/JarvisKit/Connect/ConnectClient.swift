import Foundation
import SwiftProtobuf

/// A unary client for the Connect protocol (https://connectrpc.com/docs/protocol),
/// the protocol the app API speaks, over URLSession with binary protobuf.
///
/// Only unary calls are needed by the apps, which keeps this small and free
/// of dependencies beyond SwiftProtobuf.
public final class ConnectClient: Sendable {
    public let baseURL: URL
    private let session: URLSession
    private let timeout: TimeInterval

    /// - Parameters:
    ///   - baseURL: e.g. `https://api.jarvis.example` (procedures are appended).
    ///   - timeout: per call; sent to the server as `Connect-Timeout-Ms`.
    public init(baseURL: URL, session: URLSession = .shared, timeout: TimeInterval = 30) {
        self.baseURL = baseURL
        self.session = session
        self.timeout = timeout
    }

    /// Calls `procedure` (e.g. `/jarvis.app.v1.AppService/ListTasks`).
    public func unary<Request: SwiftProtobuf.Message, Response: SwiftProtobuf.Message>(
        _ procedure: String,
        _ request: Request,
        headers: [String: String] = [:]
    ) async throws -> Response {
        var urlRequest = URLRequest(url: baseURL.appending(path: procedure), timeoutInterval: timeout)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/proto", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("application/proto", forHTTPHeaderField: "Accept")
        urlRequest.setValue("1", forHTTPHeaderField: "Connect-Protocol-Version")
        urlRequest.setValue(String(Int(timeout * 1000)), forHTTPHeaderField: "Connect-Timeout-Ms")
        for (name, value) in headers {
            urlRequest.setValue(value, forHTTPHeaderField: name)
        }
        urlRequest.httpBody = try request.serializedData()

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: urlRequest)
        } catch let error as URLError {
            throw ConnectError(transport: error)
        }
        guard let http = response as? HTTPURLResponse else {
            throw ConnectError(code: .unknown, message: "not an HTTP response")
        }
        guard http.statusCode == 200 else {
            throw ConnectError(status: http.statusCode, body: data)
        }
        do {
            return try Response(serializedBytes: data)
        } catch {
            throw ConnectError(code: .internal, message: "malformed response: \(error)")
        }
    }
}

/// A Connect error: a code, a message and typed details.
public struct ConnectError: Error, Sendable, Equatable, CustomStringConvertible {
    public var code: Code
    public var message: String
    /// `google.rpc.ErrorInfo` details, if the server sent any.
    public var errorInfos: [ErrorInfo]

    public init(code: Code, message: String, errorInfos: [ErrorInfo] = []) {
        self.code = code
        self.message = message
        self.errorInfos = errorInfos
    }

    /// The ErrorInfo reason in `domain`, e.g. "ERROR_REASON_SESSION_ENDED".
    public func reason(domain: String) -> String? {
        errorInfos.first { $0.domain == domain }?.reason
    }

    public var description: String { "\(code.rawValue): \(message)" }

    /// Connect's error codes.
    public enum Code: String, Sendable {
        case canceled, unknown
        case invalidArgument = "invalid_argument"
        case deadlineExceeded = "deadline_exceeded"
        case notFound = "not_found"
        case alreadyExists = "already_exists"
        case permissionDenied = "permission_denied"
        case resourceExhausted = "resource_exhausted"
        case failedPrecondition = "failed_precondition"
        case aborted
        case outOfRange = "out_of_range"
        case unimplemented
        case `internal`
        case unavailable
        case dataLoss = "data_loss"
        case unauthenticated
    }

    /// `google.rpc.ErrorInfo`.
    public struct ErrorInfo: Sendable, Equatable {
        public var reason: String
        public var domain: String
    }

    init(transport error: URLError) {
        switch error.code {
        case .timedOut:
            self.init(code: .deadlineExceeded, message: "the request timed out")
        case .cancelled:
            self.init(code: .canceled, message: "cancelled")
        default:
            self.init(code: .unavailable, message: error.localizedDescription)
        }
    }

    /// Decodes a Connect error body; without one, the HTTP status decides
    /// (the protocol's mapping for errors from proxies and load balancers).
    init(status: Int, body: Data) {
        struct Wire: Decodable {
            struct Detail: Decodable {
                var type: String
                var value: String
            }
            var code: String
            var message: String?
            var details: [Detail]?
        }
        if let wire = try? JSONDecoder().decode(Wire.self, from: body), let code = Code(rawValue: wire.code) {
            let infos = (wire.details ?? []).compactMap { detail -> ErrorInfo? in
                guard detail.type == "google.rpc.ErrorInfo", let bytes = Data(base64Unpadded: detail.value) else {
                    return nil
                }
                return try? ErrorInfo(protobuf: bytes)
            }
            self.init(code: code, message: wire.message ?? "", errorInfos: infos)
            return
        }
        let code: Code =
            switch status {
            case 400: .internal
            case 401: .unauthenticated
            case 403: .permissionDenied
            case 404: .unimplemented
            case 429, 502, 503, 504: .unavailable
            default: .unknown
            }
        self.init(code: code, message: "HTTP \(status)")
    }
}

extension ConnectError.ErrorInfo {
    /// Decodes the protobuf encoding of google.rpc.ErrorInfo (reason = 1,
    /// domain = 2, metadata = 3, which is skipped).
    init(protobuf data: Data) throws {
        var reader = ProtobufReader(data)
        var reason = ""
        var domain = ""
        while let (field, wireType) = try reader.nextTag() {
            switch (field, wireType) {
            case (1, .lengthDelimited): reason = try reader.string()
            case (2, .lengthDelimited): domain = try reader.string()
            default: try reader.skip(wireType)
            }
        }
        self.init(reason: reason, domain: domain)
    }
}

extension Data {
    /// Base64 with or without padding (Connect allows both).
    init?(base64Unpadded string: String) {
        var padded = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        padded += String(repeating: "=", count: (4 - padded.count % 4) % 4)
        self.init(base64Encoded: padded)
    }
}
