import AVFoundation
import Foundation
import JarvisUI
import Synchronization
import Testing

@testable import JarvisKit

/// A scripted gateway connection.
final class FakeTransport: VoiceTransport {
    private let incoming: AsyncStream<Data>
    private let push: AsyncStream<Data>.Continuation
    let sent = Mutex<[Jarvis_Voice_V1_ClientMessage]>([])
    let closed = Mutex(false)

    init() {
        (incoming, push) = AsyncStream.makeStream()
    }

    func deliver(_ message: Jarvis_Voice_V1_ServerMessage) {
        push.yield(try! message.serializedData())
    }

    func send(_ data: Data) async throws {
        sent.withLock { $0.append(try! Jarvis_Voice_V1_ClientMessage(serializedBytes: data)) }
    }

    func receive() async throws -> Data {
        var iterator = incoming.makeAsyncIterator()
        guard let data = await iterator.next() else { throw URLError(.networkConnectionLost) }
        return data
    }

    func close() {
        closed.withLock { $0 = true }
        push.finish()
    }

    var messages: [Jarvis_Voice_V1_ClientMessage] { sent.withLock { $0 } }
}

/// Microphone and speaker stand-ins.
final class FakeAudio: AudioIO, @unchecked Sendable {
    let state = Mutex<(started: Bool, played: [Data], flushes: Int, stopped: Bool)>((false, [], 0, false))
    private let onFrame = Mutex<(@Sendable (Data) -> Void)?>(nil)
    private let allowed: Bool

    init(allowed: Bool = true) {
        self.allowed = allowed
    }

    func requestAccess() async -> Bool { allowed }
    func start(onFrame: @escaping @Sendable (Data) -> Void) throws {
        self.onFrame.withLock { $0 = onFrame }
        state.withLock { $0.started = true }
    }
    func stop() { state.withLock { $0.stopped = true } }
    func play(_ pcm16: Data) { state.withLock { $0.played.append(pcm16) } }
    func flushPlayback() { state.withLock { $0.flushes += 1 } }
    func speak(_ frame: Data) { onFrame.withLock { $0 }?(frame) }
}

func server(_ build: (inout Jarvis_Voice_V1_ServerMessage) -> Void) -> Jarvis_Voice_V1_ServerMessage {
    var message = Jarvis_Voice_V1_ServerMessage()
    build(&message)
    return message
}

/// Waits for `condition`, up to two seconds.
func eventually(_ condition: () -> Bool) async -> Bool {
    for _ in 0..<200 {
        if condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return condition()
}

@Suite struct VoiceTests {
    @Test func framesAre20Milliseconds() {
        var chunker = FrameChunker()
        #expect(chunker.push(Data(count: 500)).isEmpty)
        let frames = chunker.push(Data(count: 1_500))
        #expect(frames.map(\.count) == [960, 960])
        #expect(chunker.push(Data(count: 40)).isEmpty)  // 80 + 40 bytes left over
    }

    @Test func microphoneAudioIsResampledTo24kHz() throws {
        let format = AVAudioFormat(standardFormatWithSampleRate: 48_000, channels: 1)!
        let converter = PCMConverter()
        var total = 0
        var peak: Int16 = 0
        for chunk in 0..<10 {  // 10 × 100 ms of a 440 Hz tone at half scale
            let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: 4_800)!
            buffer.frameLength = 4_800
            for i in 0..<4_800 {
                let t = Double(chunk * 4_800 + i) / 48_000
                buffer.floatChannelData![0][i] = Float(0.5 * sin(2 * .pi * 440 * t))
            }
            let pcm = try converter.convert(buffer)
            total += pcm.count / 2
            pcm.withUnsafeBytes { raw in
                for s in raw.bindMemory(to: Int16.self) { peak = max(peak, s) }
            }
        }
        // The resampler holds back ~8 ms (its filter's delay); nothing is lost.
        #expect(total <= 24_000 && total > 23_600, "one second of audio should give ~24000 samples, got \(total)")
        #expect(peak > 15_000 && peak < 17_500, "amplitude should be kept, peak \(peak)")
    }

    @Test func dropoutsAreCountedButPausesAreNot() {
        // 48 kHz microphone audio in 100 ms buffers; `silent` samples are exactly zero.
        func buffers(_ silent: (Int) -> Bool, seconds: Double) -> [AVAudioPCMBuffer] {
            let format = AVAudioFormat(standardFormatWithSampleRate: 48_000, channels: 1)!
            let total = Int(seconds * 48_000)
            return stride(from: 0, to: total, by: 4_800).map { start in
                let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: 4_800)!
                buffer.frameLength = AVAudioFrameCount(min(4_800, total - start))
                for i in 0..<Int(buffer.frameLength) {
                    let n = start + i
                    buffer.floatChannelData![0][i] = silent(n) ? 0 : Float(0.3 * sin(Double(n) * 0.05) + 0.01)
                }
                return buffer
            }
        }
        // What the capture did: a 23 ms gap every ~70 ms, one across two buffers.
        var dropouts = DropoutCounter()
        let gaps = [3_000, 6_300, 9_500]  // starts; 9_500 + 1_104 crosses 9_600
        buffers({ n in gaps.contains { n >= $0 && n < $0 + 1_104 } }, seconds: 0.3).forEach { dropouts.scan($0) }
        #expect(dropouts.count == 3)

        // Silence before speaking, a pause between words, silence after: none.
        var pauses = DropoutCounter()
        buffers({ n in n < 9_600 || (n >= 24_000 && n < 43_200) || n >= 57_600 }, seconds: 1.5)
            .forEach { pauses.scan($0) }
        #expect(pauses.count == 0)
    }

    @Test func playbackConversionKeepsTheSignal() {
        var pcm = Data()
        for sample: Int16 in [0, 16_384, -16_384, 32_767, -32_768] {
            withUnsafeBytes(of: sample.littleEndian) { pcm.append(contentsOf: $0) }
        }
        let buffer = VoiceAudio.floatBuffer(pcm)!
        let values = (0..<5).map { buffer.floatChannelData![0][$0] }
        #expect(values == [0, 0.5, -0.5, Float(32_767) / 32_768, -1])
        #expect(VoiceAudio.floatBuffer(Data()) == nil)
    }

    @Test func transcriptDeltasMergeIntoLines() {
        var log = TranscriptLog(limit: 3)
        log.apply(TranscriptLine(speaker: .user, itemID: "u1", text: "Γεια", final: false))
        log.apply(TranscriptLine(speaker: .user, itemID: "u1", text: " σου", final: false))
        log.apply(TranscriptLine(speaker: .assistant, itemID: "a1", text: "Hel", final: false))
        log.apply(TranscriptLine(speaker: .assistant, itemID: "a1", text: "lo", final: false))
        #expect(log.lines.map(\.text) == ["Γεια σου", "Hello"])
        log.apply(TranscriptLine(speaker: .user, itemID: "u1", text: "Γεια σου Jarvis", final: true))
        log.apply(TranscriptLine(speaker: .user, itemID: "u1", text: " late", final: false))  // after final: ignored
        #expect(log.lines.first?.text == "Γεια σου Jarvis" && log.lines.first?.final == true)
        log.apply(TranscriptLine(speaker: .user, itemID: "u2", text: "2", final: true))
        log.apply(TranscriptLine(speaker: .user, itemID: "u3", text: "3", final: true))
        #expect(log.lines.map(\.itemID) == ["a1", "u2", "u3"])
    }

    @Test func aSessionStreamsBothWaysAndHandlesBargeIn() async throws {
        let transport = FakeTransport()
        let audio = FakeAudio()
        let session = VoiceSession(transport: transport, audio: audio)
        transport.deliver(
            server {
                $0.sessionReady.sessionID = "vs-1"
                $0.sessionReady.voice = "marin"
            })
        let ready = try await session.start(provider: .xai, voice: "eve", locale: "el-GR")
        #expect(ready.sessionID == "vs-1")
        let hello = try #require(transport.messages.first)
        #expect(
            hello.startSession.provider == .xai && hello.startSession.voice == "eve"
                && hello.startSession.locale == "el-GR")
        #expect(audio.state.withLock { $0.started })

        // Microphone frames go up in order.
        audio.speak(Data(repeating: 1, count: 960))
        audio.speak(Data(repeating: 2, count: 960))
        #expect(await eventually { transport.messages.count == 3 })
        #expect(transport.messages[1].inputAudio.pcm16.first == 1 && transport.messages[2].inputAudio.pcm16.first == 2)

        var events = session.events.makeAsyncIterator()
        #expect(await events.next() == .ready(sessionID: "vs-1", voice: "marin"))

        transport.deliver(
            server {
                $0.outputAudio.pcm16 = Data(repeating: 9, count: 480)
                $0.outputAudio.responseID = "r1"
            })
        #expect(await events.next() == .assistantSpeaking(responseID: "r1"))
        #expect(audio.state.withLock { $0.played.count } == 1)

        // Barge-in: queued speech is dropped at once.
        transport.deliver(server { $0.speechStarted = Jarvis_Voice_V1_SpeechStarted() })
        #expect(await events.next() == .userSpeaking(true))
        #expect(audio.state.withLock { $0.flushes } == 1)

        transport.deliver(
            server {
                $0.transcript.role = .user
                $0.transcript.itemID = "u1"
                $0.transcript.text = "hi"
                $0.transcript.final = true
            })
        #expect(
            await events.next() == .transcript(TranscriptLine(speaker: .user, itemID: "u1", text: "hi", final: true)))

        transport.deliver(
            server {
                $0.error.code = .providerError
                $0.error.message = "hiccup"
            })
        #expect(await events.next() == .warning("hiccup"))

        transport.deliver(
            server {
                $0.error.code = .sessionExpired
                $0.error.message = "time is up"
                $0.error.fatal = true
            })
        #expect(await events.next() == .ended(.byServer(code: .sessionExpired, message: "time is up")))
        #expect(await events.next() == nil)
        #expect(audio.state.withLock { $0.stopped })
        #expect(transport.closed.withLock { $0 })
    }

    @Test func aRefusedStartIsReported() async throws {
        let transport = FakeTransport()
        let audio = FakeAudio()
        let session = VoiceSession(transport: transport, audio: audio)
        transport.deliver(
            server {
                $0.error.code = .providerKeyMissing
                $0.error.message = "no active openai API key"
                $0.error.fatal = true
            })
        await #expect(throws: VoiceError.refused(code: .providerKeyMissing, message: "no active openai API key")) {
            try await session.start()
        }
        #expect(!audio.state.withLock { $0.started })
        #expect(transport.closed.withLock { $0 })
    }

    @Test func aSilentGatewayTimesOut() async throws {
        let session = VoiceSession(transport: FakeTransport(), audio: FakeAudio())
        await #expect(throws: VoiceError.timedOut) { try await session.start(timeout: .milliseconds(100)) }
    }

    @Test func endingSaysGoodbye() async throws {
        let transport = FakeTransport()
        let session = VoiceSession(transport: transport, audio: FakeAudio())
        transport.deliver(server { $0.sessionReady.sessionID = "vs-2" })
        try await session.start()
        await session.interrupt()
        await session.end()
        let kinds = transport.messages.map { $0.message }
        #expect(kinds.contains { if case .cancelResponse = $0 { true } else { false } })
        #expect(kinds.last.map { if case .endSession = $0 { true } else { false } } == true)
    }
}

@MainActor
@Suite struct VoiceControllerTests {
    @Test func aRefusedMicrophoneStopsBeforeAnyConnection() async {
        // Not signed in: had it asked for voice credentials first, the
        // problem would be the missing session, not the microphone.
        let sessions = SessionStore(secrets: MemoryStore(), makeClient: FakeAppAPI(host: "mic.test").client)
        let audio = FakeAudio(allowed: false)
        let controller = VoiceController(sessions: sessions, makeAudio: { audio })
        await controller.start(provider: .unspecified, locale: "")
        #expect(controller.problem == VoiceError.microphoneDenied.description)
        #expect(controller.phase == .idle)
        #expect(!audio.state.withLock { $0.started })
    }
}
