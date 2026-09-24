import Foundation

/// A minimal protobuf wire-format reader, for the one message the generated
/// code does not include (google.rpc.ErrorInfo in error details).
struct ProtobufReader {
    enum WireType: UInt64 {
        case varint = 0, fixed64 = 1, lengthDelimited = 2, fixed32 = 5
    }

    struct Malformed: Error {}

    private let bytes: [UInt8]
    private var offset = 0

    init(_ data: Data) {
        bytes = [UInt8](data)
    }

    /// The next field number and wire type, or nil at the end.
    mutating func nextTag() throws -> (UInt64, WireType)? {
        guard offset < bytes.count else { return nil }
        let tag = try varint()
        guard let wireType = WireType(rawValue: tag & 7), tag >> 3 != 0 else { throw Malformed() }
        return (tag >> 3, wireType)
    }

    mutating func varint() throws -> UInt64 {
        var value: UInt64 = 0
        for shift in stride(from: 0, to: 64, by: 7) {
            guard offset < bytes.count else { throw Malformed() }
            let byte = bytes[offset]
            offset += 1
            value |= UInt64(byte & 0x7F) << UInt64(shift)
            if byte & 0x80 == 0 { return value }
        }
        throw Malformed()
    }

    mutating func lengthDelimited() throws -> ArraySlice<UInt8> {
        let length = try varint()
        guard length <= UInt64(bytes.count - offset) else { throw Malformed() }
        let end = offset + Int(length)
        defer { offset = end }
        return bytes[offset..<end]
    }

    mutating func string() throws -> String {
        guard let text = String(bytes: try lengthDelimited(), encoding: .utf8) else { throw Malformed() }
        return text
    }

    mutating func skip(_ wireType: WireType) throws {
        switch wireType {
        case .varint: _ = try varint()
        case .lengthDelimited: _ = try lengthDelimited()
        case .fixed64: try advance(8)
        case .fixed32: try advance(4)
        }
    }

    private mutating func advance(_ count: Int) throws {
        guard count <= bytes.count - offset else { throw Malformed() }
        offset += count
    }
}
