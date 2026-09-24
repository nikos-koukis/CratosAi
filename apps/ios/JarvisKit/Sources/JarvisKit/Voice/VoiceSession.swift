import Foundation
import SwiftProtobuf
import os

/// A line of the live transcript.
public struct TranscriptLine: Sendable, Equatable, Identifiable {
    public enum Speaker: Sendable { case user, assistant }
    public var speaker: Speaker
    public var itemID: String
    public var text: String
    public var final: Bool
    public var id: String { itemID }
}

/// Why a voice session ended.
public enum VoiceEnd: Sendable, Equatable {
    case byUser
    /// The gateway ended it (e.g. the key was rejected, time limit, restart).
    case byServer(code: Jarvis_Voice_V1_ErrorCode, message: String)
    case connectionLost(String)
}

/// What happens in a voice session, for the UI.
public enum VoiceEvent: Sendable, Equatable {
    case ready(sessionID: String, voice: String)
    case userSpeaking(Bool)
    case assistantSpeaking(responseID: String)
    case assistantDone(responseID: String)
    case transcript(TranscriptLine)
    /// A problem the session survives, e.g. a provider hiccup.
    case warning(String)
    case ended(VoiceEnd)
}

public enum VoiceError: Error, Equatable, CustomStringConvertible {
    /// The gateway refused to start (e.g. no API key for the provider).
    case refused(code: Jarvis_Voice_V1_ErrorCode, message: String)
    case timedOut
    case protocolViolation(String)
    /// The user did not allow the microphone.
    case microphoneDenied

    public var description: String {
        switch self {
        case .refused(_, let message): message
        case .timedOut: "the voice service did not answer in time"
        case .microphoneDenied: "Jarvis needs the microphone. Allow it in Settings → Apps → Jarvis."
        case .protocolViolation(let what): "unexpected answer from the voice service: \(what)"
        }
    }
}

/// One voice session with the gateway (jarvis.voice.v1): microphone frames
/// go up as they are captured, speech comes back and plays, and when the user
/// starts talking over Jarvis the queued speech is dropped at once.
public actor VoiceSession {
    public nonisolated let events: AsyncStream<VoiceEvent>
    private let emit: AsyncStream<VoiceEvent>.Continuation
    private let transport: VoiceTransport
    private let audio: AudioIO
    private let log = Logger(subsystem: "ai.cratos.jarvis", category: "voice")

    private var frames: AsyncStream<Data>.Continuation?
    private var sender: Task<Void, Never>?
    private var receiver: Task<Void, Never>?
    private var speaking: String?
    private var finished = false

    public init(transport: VoiceTransport, audio: AudioIO) {
        self.transport = transport
        self.audio = audio
        (events, emit) = AsyncStream.makeStream(bufferingPolicy: .bufferingNewest(512))
    }

    /// Opens the session and starts the microphone once the gateway is ready.
    @discardableResult
    public func start(
        provider: Jarvis_Common_V1_Provider = .unspecified, voice: String = "", locale: String = "",
        timeout: Duration = .seconds(15)
    ) async throws -> Jarvis_Voice_V1_SessionReady {
        var start = Jarvis_Voice_V1_StartSession()
        start.provider = provider
        start.voice = voice
        start.locale = locale
        var hello = Jarvis_Voice_V1_ClientMessage()
        hello.startSession = start
        do {
            try await transport.send(try hello.serializedData())
            let first = try await firstMessage(within: timeout)
            switch first.message {
            case .sessionReady(let ready):
                emit.yield(.ready(sessionID: ready.sessionID, voice: ready.voice))
                try startAudio()
                receiver = Task { await self.receiveLoop() }
                log.info("voice session \(ready.sessionID, privacy: .public) ready")
                return ready
            case .error(let error):
                throw VoiceError.refused(code: error.code, message: error.message)
            default:
                throw VoiceError.protocolViolation("expected SessionReady")
            }
        } catch {
            finish(.connectionLost(String(describing: error)), quietly: true)
            throw error
        }
    }

    /// Stops Jarvis's current answer (a tap on the stop button).
    public func interrupt() async {
        audio.flushPlayback()
        var message = Jarvis_Voice_V1_ClientMessage()
        message.cancelResponse = Jarvis_Voice_V1_CancelResponse()
        try? await transport.send(try message.serializedData())
    }

    /// Ends the session.
    public func end() async {
        guard !finished else { return }
        var message = Jarvis_Voice_V1_ClientMessage()
        message.endSession = Jarvis_Voice_V1_EndSession()
        try? await transport.send(try message.serializedData())
        finish(.byUser)
    }

    private func firstMessage(within timeout: Duration) async throws -> Jarvis_Voice_V1_ServerMessage {
        let transport = self.transport
        return try await withThrowingTaskGroup(of: Jarvis_Voice_V1_ServerMessage.self) { group in
            group.addTask { try Jarvis_Voice_V1_ServerMessage(serializedBytes: try await transport.receive()) }
            group.addTask {
                try await Task.sleep(for: timeout)
                throw VoiceError.timedOut
            }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }

    private func startAudio() throws {
        // Frames queue here while the network catches up (5 s at most).
        let (stream, continuation) = AsyncStream<Data>.makeStream(bufferingPolicy: .bufferingNewest(250))
        frames = continuation
        let transport = self.transport
        sender = Task {
            for await frame in stream {
                var message = Jarvis_Voice_V1_ClientMessage()
                message.inputAudio.pcm16 = frame
                do {
                    try await transport.send(try message.serializedData())
                } catch {
                    self.finish(.connectionLost(String(describing: error)))
                    return
                }
            }
        }
        try audio.start { frame in continuation.yield(frame) }
    }

    private func receiveLoop() async {
        while !finished {
            let data: Data
            do {
                data = try await transport.receive()
            } catch {
                finish(.connectionLost(String(describing: error)))
                return
            }
            guard let message = try? Jarvis_Voice_V1_ServerMessage(serializedBytes: data) else {
                log.error("dropping a malformed message from the gateway")
                continue
            }
            handle(message)
        }
    }

    private func handle(_ message: Jarvis_Voice_V1_ServerMessage) {
        switch message.message {
        case .outputAudio(let audioChunk):
            audio.play(audioChunk.pcm16)
            if speaking != audioChunk.responseID {
                speaking = audioChunk.responseID
                emit.yield(.assistantSpeaking(responseID: audioChunk.responseID))
            }
        case .transcript(let t):
            emit.yield(
                .transcript(
                    TranscriptLine(
                        speaker: t.role == .assistant ? .assistant : .user, itemID: t.itemID,
                        text: t.text, final: t.final)))
        case .speechStarted:
            // Barge-in: the gateway already dropped the rest of the answer.
            audio.flushPlayback()
            speaking = nil
            emit.yield(.userSpeaking(true))
        case .speechStopped:
            emit.yield(.userSpeaking(false))
        case .responseDone(let done):
            if speaking == done.responseID {
                speaking = nil
            }
            emit.yield(.assistantDone(responseID: done.responseID))
        case .error(let error):
            if error.fatal {
                finish(.byServer(code: error.code, message: error.message))
            } else {
                emit.yield(.warning(error.message))
            }
        case .sessionReady, .none:
            break
        }
    }

    private func finish(_ reason: VoiceEnd, quietly: Bool = false) {
        guard !finished else { return }
        finished = true
        audio.stop()
        frames?.finish()
        transport.close()
        receiver?.cancel()
        if !quietly {
            emit.yield(.ended(reason))
        }
        emit.finish()
        log.info("voice session ended: \(String(describing: reason), privacy: .public)")
    }
}

/// The live transcript, merging streamed deltas into lines.
public struct TranscriptLog: Sendable, Equatable {
    public private(set) var lines: [TranscriptLine] = []
    public let limit: Int

    public init(limit: Int = 200) {
        self.limit = limit
    }

    public mutating func apply(_ line: TranscriptLine) {
        if let index = lines.lastIndex(where: { $0.itemID == line.itemID && $0.speaker == line.speaker }) {
            if line.final {
                lines[index].text = line.text
                lines[index].final = true
            } else if !lines[index].final {
                lines[index].text += line.text
            }
            return
        }
        lines.append(line)
        if lines.count > limit {
            lines.removeFirst(lines.count - limit)
        }
    }
}
