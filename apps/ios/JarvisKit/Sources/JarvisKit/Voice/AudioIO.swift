import AVFoundation
import Foundation
import os

/// Microphone in, speaker out, in the voice protocol's format.
public protocol AudioIO: AnyObject, Sendable {
    /// Asks for the microphone the first time; false if the user refused it.
    func requestAccess() async -> Bool
    /// Starts capture; `onFrame` receives 20 ms PCM16 frames from an audio thread.
    func start(onFrame: @escaping @Sendable (Data) -> Void) throws
    func stop()
    /// Queues assistant speech (PCM16) for playback.
    func play(_ pcm16: Data)
    /// Drops queued speech at once (the user started talking).
    func flushPlayback()
}

public struct NoMicrophoneError: Error, CustomStringConvertible {
    public var description: String { "no microphone is available" }
}

/// AVAudioEngine with the system's voice processing: echo cancellation keeps
/// the assistant's own voice out of the microphone, so the user can talk
/// over it (barge-in) and the provider does not answer itself.
///
/// The microphone is read with a tap on the input node only, never by wiring
/// the input into the graph: the output's render cycle would then pull it,
/// and whenever the input's hardware cycle lags, that cycle gets silence
/// (measured: a 23 ms gap every 70–90 ms, 30% of the speech lost).
///
/// When the audio configuration changes (voice processing starting up right
/// after the first start, a route change such as headphones), the engine
/// stops itself; it is wired again and restarted.
public final class AudioEngineIO: AudioIO, @unchecked Sendable {
    // AVAudioEngine is not thread-safe; everything that touches the graph
    // runs under `lock`. The microphone tap runs on an audio thread and takes
    // only `captureLock`, so stopping the engine (which waits for the tap)
    // cannot deadlock with it.
    private let lock = NSLock()
    private let engine = AVAudioEngine()
    private let player = AVAudioPlayerNode()
    private var running = false
    private var restarts = 0
    private var observer: (any NSObjectProtocol)?
    // Configuration changes are handled here, never on the thread that posts
    // them: that may be one holding `lock` inside engine.start().
    private let changes: OperationQueue = {
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        return queue
    }()

    private let captureLock = NSLock()
    private var capturing = false
    private var onFrame: (@Sendable (Data) -> Void)?
    private var converter = PCMConverter()
    private var chunker = FrameChunker()
    // What the microphone gave, for the log when the session ends.
    private var dropouts = DropoutCounter()
    private var buffers = 0
    private var framesOut = 0
    private var failures = 0

    private static let maxRestarts = 5
    private let log = Logger(subsystem: "ai.cratos.jarvis", category: "audio")

    public init() {}

    public func requestAccess() async -> Bool {
        await AVAudioApplication.requestRecordPermission()
    }

    public func start(onFrame: @escaping @Sendable (Data) -> Void) throws {
        try lock.withLock {
            guard !running else { return }
            #if os(iOS)
                let session = AVAudioSession.sharedInstance()
                try session.setCategory(
                    .playAndRecord, mode: .voiceChat, options: [.defaultToSpeaker, .allowBluetoothHFP])
                try session.setActive(true)
            #endif
            try engine.inputNode.setVoiceProcessingEnabled(true)
            engine.attach(player)
            captureLock.withLock {
                self.onFrame = onFrame
                converter = PCMConverter()
                chunker = FrameChunker()
                dropouts = DropoutCounter()
                (buffers, framesOut, failures) = (0, 0, 0)
                capturing = true
            }
            do {
                try wireAndStart()
            } catch {
                captureLock.withLock { capturing = false }
                throw error
            }
            running = true
            observer = NotificationCenter.default.addObserver(
                forName: .AVAudioEngineConfigurationChange, object: engine, queue: changes
            ) { [weak self] _ in
                self?.configurationChanged()
            }
        }
    }

    /// Connects the graph for the current hardware format and starts the
    /// engine. Called under `lock`.
    private func wireAndStart() throws {
        let input = engine.inputNode
        let format = input.outputFormat(forBus: 0)
        guard format.sampleRate > 0, format.channelCount > 0 else { throw NoMicrophoneError() }
        engine.connect(player, to: engine.mainMixerNode, format: VoiceAudio.floatFormat)
        input.removeTap(onBus: 0)
        input.installTap(onBus: 0, bufferSize: AVAudioFrameCount(format.sampleRate / 50), format: format) {
            [weak self] buffer, _ in
            self?.captured(buffer)
        }
        engine.prepare()
        do {
            try engine.start()
        } catch {
            input.removeTap(onBus: 0)
            throw error
        }
        player.play()
        log.info(
            "audio started: microphone \(format.description, privacy: .public), permission \(Self.permission, privacy: .public)"
        )
    }

    private func configurationChanged() {
        lock.withLock {
            guard running else { return }
            log.info("audio configuration changed (engine running: \(self.engine.isRunning, privacy: .public))")
            guard restarts < Self.maxRestarts else {
                log.error("audio configuration keeps changing; not restarting again")
                return
            }
            restarts += 1
            do {
                try wireAndStart()
            } catch {
                log.error("cannot restart audio: \(String(describing: error), privacy: .public)")
            }
        }
    }

    /// The tap: converts and cuts the microphone's audio into frames.
    private func captured(_ buffer: AVAudioPCMBuffer) {
        let (frames, onFrame): ([Data], (@Sendable (Data) -> Void)?) = captureLock.withLock {
            guard capturing else { return ([], nil) }
            buffers += 1
            dropouts.scan(buffer)
            if buffers == 1 {
                log.info(
                    "first microphone buffer: \(buffer.frameLength) frames, \(buffer.format.description, privacy: .public)"
                )
            }
            do {
                let frames = chunker.push(try converter.convert(buffer))
                framesOut += frames.count
                return (frames, self.onFrame)
            } catch {
                failures += 1
                if failures == 1 {
                    log.error(
                        "cannot convert microphone audio (\(buffer.format.description, privacy: .public)): \(String(describing: error), privacy: .public)"
                    )
                }
                return ([], nil)
            }
        }
        if let onFrame {
            frames.forEach(onFrame)
        }
    }

    public func stop() {
        let (buffers, frames, failures, dropouts) = captureLock.withLock {
            capturing = false
            onFrame = nil
            return (self.buffers, framesOut, self.failures, self.dropouts.count)
        }
        let state: (wasRunning: Bool, restarts: Int)? = lock.withLock {
            guard running else { return nil }
            running = false
            if let observer {
                NotificationCenter.default.removeObserver(observer)
                self.observer = nil
            }
            let wasRunning = engine.isRunning
            engine.inputNode.removeTap(onBus: 0)
            player.stop()
            engine.stop()
            #if os(iOS)
                try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
            #endif
            return (wasRunning, restarts)
        }
        if let state {
            log.info(
                "audio stopped: engine running \(state.wasRunning, privacy: .public), \(state.restarts) restarts, \(buffers) microphone buffers, \(dropouts) dropouts, \(frames) frames sent, \(failures) conversion failures"
            )
        }
    }

    public func play(_ pcm16: Data) {
        guard let buffer = VoiceAudio.floatBuffer(pcm16) else { return }
        lock.withLock {
            guard running else { return }
            player.scheduleBuffer(buffer)
        }
    }

    public func flushPlayback() {
        lock.withLock {
            guard running else { return }
            player.stop()  // drops everything scheduled
            player.play()
        }
    }

    private static var permission: String {
        switch AVAudioApplication.shared.recordPermission {
        case .granted: "granted"
        case .denied: "denied"
        case .undetermined: "undetermined"
        @unknown default: "unknown"
        }
    }
}
