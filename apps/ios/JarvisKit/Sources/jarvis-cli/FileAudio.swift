import Foundation
import JarvisKit
import Synchronization

/// Plays a WAV file as the microphone (in real time, then silence so the
/// gateway hears the end of speech) and records what Jarvis says.
final class FileAudio: AudioIO {
    private struct State {
        var feeder: Task<Void, Never>?
        var reply = Data()
        var speech: Data
        var pending = Data()
    }

    private let state: Mutex<State>

    init(speech: Data) {
        state = Mutex(State(speech: speech))
    }

    /// Says the recording again (the next turn).
    func speakAgain() {
        state.withLock { $0.pending = $0.speech }
    }

    /// Everything Jarvis said.
    var reply: Data { state.withLock { $0.reply } }

    func requestAccess() async -> Bool { true }  // a file, not the microphone

    func start(onFrame: @escaping @Sendable (Data) -> Void) throws {
        speakAgain()
        let feeder = Task { [weak self] in
            let silence = Data(count: VoiceAudio.frameBytes)
            while !Task.isCancelled, let self {
                let frame: Data = self.state.withLock { state in
                    guard !state.pending.isEmpty else { return silence }
                    let next = state.pending.prefix(VoiceAudio.frameBytes)
                    state.pending.removeFirst(next.count)
                    return Data(next)
                }
                onFrame(frame.count % 2 == 0 ? frame : frame.dropLast())
                try? await Task.sleep(for: .milliseconds(20))
            }
        }
        state.withLock { $0.feeder = feeder }
    }

    func stop() {
        state.withLock { $0.feeder?.cancel() }
    }

    func play(_ pcm16: Data) {
        state.withLock { $0.reply.append(pcm16) }
    }

    func flushPlayback() {}
}

/// Minimal WAV (RIFF) reading and writing for PCM16 mono 24 kHz.
enum WAV {
    struct Unsupported: Error, CustomStringConvertible {
        let description: String
    }

    static func read(_ url: URL) throws -> Data {
        let data = try Data(contentsOf: url)
        guard data.count > 12, data.prefix(4) == Data("RIFF".utf8), data[8..<12] == Data("WAVE".utf8) else {
            throw Unsupported(description: "\(url.lastPathComponent) is not a WAV file")
        }
        var offset = 12
        var format: (channels: UInt16, rate: UInt32, bits: UInt16)?
        while offset + 8 <= data.count {
            let id = String(decoding: data[offset..<offset + 4], as: UTF8.self)
            let size = Int(
                data.subdata(in: offset + 4..<offset + 8).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) })
            let body = offset + 8
            guard body + size <= data.count else { break }
            switch id {
            case "fmt ":
                let chunk = data.subdata(in: body..<body + size)
                format = chunk.withUnsafeBytes {
                    (
                        $0.loadUnaligned(fromByteOffset: 2, as: UInt16.self),
                        $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self),
                        $0.loadUnaligned(fromByteOffset: 14, as: UInt16.self)
                    )
                }
            case "data":
                guard let format, format.channels == 1, format.rate == 24_000, format.bits == 16 else {
                    throw Unsupported(
                        description: "the WAV must be PCM16 mono 24 kHz (afconvert -f WAVE -d LEI16@24000 -c 1)")
                }
                return data.subdata(in: body..<body + size)
            default:
                break
            }
            offset = body + size + size % 2
        }
        throw Unsupported(description: "no audio in \(url.lastPathComponent)")
    }

    static func write(_ pcm: Data, to url: URL) throws {
        func le<T: FixedWidthInteger>(_ value: T) -> Data { withUnsafeBytes(of: value.littleEndian) { Data($0) } }
        var file = Data("RIFF".utf8) + le(UInt32(36 + pcm.count)) + Data("WAVEfmt ".utf8)
        file += le(UInt32(16)) + le(UInt16(1)) + le(UInt16(1)) + le(UInt32(24_000)) + le(UInt32(48_000))
        file += le(UInt16(2)) + le(UInt16(16)) + Data("data".utf8) + le(UInt32(pcm.count)) + pcm
        try file.write(to: url)
    }
}
