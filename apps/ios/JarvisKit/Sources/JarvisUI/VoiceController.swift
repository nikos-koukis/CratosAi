import Foundation
import JarvisKit
import Observation

/// Drives a voice session for the conversation screen.
@MainActor
@Observable
public final class VoiceController {
    public enum Phase: Equatable {
        case idle
        case connecting
        case listening
        case userSpeaking
        case assistantSpeaking
    }

    public private(set) var phase: Phase = .idle
    public private(set) var transcript = TranscriptLog()
    /// The last problem, for a banner.
    public var problem: String?

    private let sessions: SessionStore
    private let makeAudio: @Sendable () -> AudioIO
    private var session: VoiceSession?
    private var listener: Task<Void, Never>?

    public init(sessions: SessionStore, makeAudio: @escaping @Sendable () -> AudioIO = { AudioEngineIO() }) {
        self.sessions = sessions
        self.makeAudio = makeAudio
    }

    public var isActive: Bool { phase != .idle }

    /// Starts talking to Jarvis.
    public func start(provider: Jarvis_Common_V1_Provider, locale: String) async {
        guard phase == .idle else { return }
        phase = .connecting
        problem = nil
        do {
            // Before connecting: the first time, the user reads the system's
            // question for as long as they like, and the gateway would not wait.
            let audio = makeAudio()
            guard await audio.requestAccess() else { throw VoiceError.microphoneDenied }
            let credentials = try await sessions.voiceCredentials()
            let session = VoiceSession(
                transport: WebSocketTransport(url: credentials.url, token: credentials.token),
                audio: audio)
            self.session = session
            listener = Task { [weak self] in
                for await event in session.events {
                    self?.handle(event)
                }
            }
            try await session.start(provider: provider, locale: locale)
            if phase == .connecting {
                phase = .listening
            }
        } catch {
            problem = Self.explain(error)
            finish()
        }
    }

    /// Stops Jarvis mid-answer.
    public func interrupt() async {
        await session?.interrupt()
    }

    public func stop() async {
        await session?.end()
        finish()
    }

    private func handle(_ event: VoiceEvent) {
        switch event {
        case .ready:
            phase = .listening
        case .userSpeaking(let speaking):
            phase = speaking ? .userSpeaking : .listening
        case .assistantSpeaking:
            phase = .assistantSpeaking
        case .assistantDone:
            if phase == .assistantSpeaking {
                phase = .listening
            }
        case .transcript(let line):
            transcript.apply(line)
        case .warning(let message):
            problem = message
        case .ended(let reason):
            switch reason {
            case .byUser: break
            case .byServer(_, let message): problem = message
            case .connectionLost: problem = String(localized: "The connection to Jarvis was lost.")
            }
            finish()
        }
    }

    private func finish() {
        session = nil
        listener?.cancel()
        listener = nil
        phase = .idle
    }

    static func explain(_ error: Error) -> String {
        switch error {
        case let error as VoiceError: error.description
        case let error as SessionError: error.description
        case let error as ConnectError: error.message.isEmpty ? error.description : error.message
        case let error as URLError where error.code == .notConnectedToInternet:
            String(localized: "You are offline.")
        default: error.localizedDescription
        }
    }
}
