import AVFoundation
import Foundation

/// The voice protocol's audio: PCM16 little-endian, mono, 24 kHz.
public enum VoiceAudio {
    public static let sampleRate: Double = 24_000
    /// 20 ms, the recommended frame size.
    public static let frameBytes = 960
    /// 100 ms, the largest frame the gateway accepts.
    public static let maxFrameBytes = 4_800

    public static let pcm16Format = AVAudioFormat(
        commonFormat: .pcmFormatInt16, sampleRate: sampleRate, channels: 1, interleaved: true)!
    public static let floatFormat = AVAudioFormat(standardFormatWithSampleRate: sampleRate, channels: 1)!

    /// PCM16 bytes as a float buffer for playback.
    public static func floatBuffer(_ pcm16: Data) -> AVAudioPCMBuffer? {
        let frames = pcm16.count / 2
        guard frames > 0,
            let buffer = AVAudioPCMBuffer(pcmFormat: floatFormat, frameCapacity: AVAudioFrameCount(frames))
        else { return nil }
        buffer.frameLength = AVAudioFrameCount(frames)
        let out = buffer.floatChannelData![0]
        pcm16.withUnsafeBytes { raw in
            for i in 0..<frames {
                let sample = Int16(littleEndian: raw.loadUnaligned(fromByteOffset: i * 2, as: Int16.self))
                out[i] = Float(sample) / 32_768
            }
        }
        return buffer
    }
}

/// Cuts a stream of PCM16 into 20 ms frames.
public struct FrameChunker: Sendable {
    private var pending = Data()

    public init() {}

    /// Adds audio; returns the complete frames now available, in order.
    public mutating func push(_ pcm16: Data) -> [Data] {
        pending.append(pcm16)
        var frames: [Data] = []
        while pending.count >= VoiceAudio.frameBytes {
            frames.append(Data(pending.prefix(VoiceAudio.frameBytes)))
            pending.removeFirst(VoiceAudio.frameBytes)
        }
        return frames
    }
}

public struct PCMConversionError: Error {}

/// Converts microphone buffers (whatever the hardware gives: 48 kHz float,
/// stereo, …) to the protocol's 24 kHz PCM16 mono, keeping the resampler's
/// state across buffers so the stream has no clicks.
public final class PCMConverter {
    private var converter: AVAudioConverter?
    private var input: AVAudioFormat?

    public init() {}

    public func convert(_ buffer: AVAudioPCMBuffer) throws -> Data {
        if converter == nil || input != buffer.format {
            converter = AVAudioConverter(from: buffer.format, to: VoiceAudio.pcm16Format)
            input = buffer.format
        }
        guard let converter else { throw PCMConversionError() }
        let ratio = VoiceAudio.sampleRate / buffer.format.sampleRate
        let capacity = AVAudioFrameCount((Double(buffer.frameLength) * ratio).rounded(.up)) + 64
        guard let output = AVAudioPCMBuffer(pcmFormat: VoiceAudio.pcm16Format, frameCapacity: capacity) else {
            throw PCMConversionError()
        }
        var given = false
        var error: NSError?
        let status = converter.convert(to: output, error: &error) { _, inputStatus in
            if given {
                inputStatus.pointee = .noDataNow
                return nil
            }
            given = true
            inputStatus.pointee = .haveData
            return buffer
        }
        guard status != .error, let samples = output.int16ChannelData else { throw error ?? PCMConversionError() }
        return Data(bytes: samples[0], count: Int(output.frameLength) * 2)
    }
}

/// Counts dropouts in microphone audio: short stretches of exact digital
/// silence between sounds. A real microphone is never exactly zero for
/// 10 ms, and a pause in speech lasts longer than 60 ms, so each one is audio
/// the capture lost.
public struct DropoutCounter: Sendable {
    public private(set) var count = 0
    private var zeros = 0
    private var heardSound = false

    public init() {}

    public mutating func scan(_ buffer: AVAudioPCMBuffer) {
        guard let samples = buffer.floatChannelData?[0] else { return }
        let shortest = Int(buffer.format.sampleRate / 100)  // 10 ms
        let longest = Int(buffer.format.sampleRate * 0.06)  // 60 ms
        for i in 0..<Int(buffer.frameLength) {
            if samples[i] == 0 {
                zeros += 1
                continue
            }
            if heardSound && zeros >= shortest && zeros < longest {
                count += 1
            }
            zeros = 0
            heardSound = true
        }
    }
}
