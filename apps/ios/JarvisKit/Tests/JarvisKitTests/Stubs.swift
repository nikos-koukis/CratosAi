import Foundation
import Synchronization

@testable import JarvisKit

/// Answers URLSession requests from a handler, per test (keyed by host).
final class StubURLProtocol: URLProtocol, @unchecked Sendable {
    typealias Handler = @Sendable (URLRequest, Data) -> (status: Int, headers: [String: String], body: Data)

    private static let handlers = Mutex<[String: Handler]>([:])

    /// A session whose requests to `host` go to `handler`.
    static func session(host: String, handler: @escaping Handler) -> URLSession {
        handlers.withLock { $0[host] = handler }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let host = request.url?.host() ?? ""
        guard let handler = Self.handlers.withLock({ $0[host] }) else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotFindHost))
            return
        }
        let body = request.httpBody ?? request.httpBodyStream.map(Self.read) ?? Data()
        let (status, headers, responseBody) = handler(request, body)
        let response = HTTPURLResponse(
            url: request.url!, statusCode: status, httpVersion: "HTTP/1.1",
            headerFields: headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: responseBody)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func read(_ stream: InputStream) -> Data {
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let n = stream.read(&buffer, maxLength: buffer.count)
            guard n > 0 else { break }
            data.append(buffer, count: n)
        }
        return data
    }
}

/// A Connect error body, as connect-go writes it.
func connectErrorBody(code: String, message: String, reason: String? = nil) -> Data {
    var details: [[String: String]] = []
    if let reason {
        // google.rpc.ErrorInfo{reason, domain: "app.jarvis"}, unpadded base64.
        var info = Data([0x0A, UInt8(reason.utf8.count)]) + Data(reason.utf8)
        info += Data([0x12, 10]) + Data("app.jarvis".utf8)
        let value = info.base64EncodedString().replacingOccurrences(of: "=", with: "")
        details.append(["type": "google.rpc.ErrorInfo", "value": value])
    }
    let body: [String: Any] = ["code": code, "message": message, "details": details]
    return try! JSONSerialization.data(withJSONObject: body)
}

extension Data {
    init(hex: String) {
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        self.init(bytes)
    }
}
