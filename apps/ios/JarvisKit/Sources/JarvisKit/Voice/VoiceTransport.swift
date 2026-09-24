import Foundation

/// A binary message channel to the voice gateway (a WebSocket in the app).
public protocol VoiceTransport: Sendable {
    func send(_ data: Data) async throws
    /// The next binary frame; throws when the connection ends.
    func receive() async throws -> Data
    func close()
}

public enum VoiceTransportError: Error, Equatable {
    /// The gateway sent a text frame; the protocol is binary only.
    case unexpectedTextFrame
}

/// The voice gateway's WebSocket (`jarvis.voice.v1`), authenticated with the
/// session's voice token.
public final class WebSocketTransport: VoiceTransport {
    public static let subprotocol = "jarvis.voice.v1"
    private let task: URLSessionWebSocketTask

    public init(url: URL, token: String, session: URLSession = .shared) {
        var request = URLRequest(url: url)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue(Self.subprotocol, forHTTPHeaderField: "Sec-WebSocket-Protocol")
        task = session.webSocketTask(with: request)
        task.maximumMessageSize = 1 << 20
        task.resume()
    }

    public func send(_ data: Data) async throws {
        try await task.send(.data(data))
    }

    public func receive() async throws -> Data {
        switch try await task.receive() {
        case .data(let data):
            return data
        case .string:
            throw VoiceTransportError.unexpectedTextFrame
        @unknown default:
            throw VoiceTransportError.unexpectedTextFrame
        }
    }

    public func close() {
        task.cancel(with: .normalClosure, reason: nil)
    }
}
