import Foundation
import SwiftProtobuf

public enum ApprovalError: Error, Equatable, CustomStringConvertible {
    /// The payload is not a valid ApprovalPayload, or it is for another
    /// approval than the one listed.
    case malformedPayload
    /// The approval expired.
    case expired

    public var description: String {
        switch self {
        case .malformedPayload: "this approval request is malformed; it was not signed"
        case .expired: "this approval has expired"
        }
    }
}

/// A command waiting for approval, decoded from the exact bytes the computer
/// sent. What the user reviews comes only from those bytes, never from the
/// server's description, and exactly those bytes are signed.
public struct ApprovalRequest: Sendable, Identifiable {
    /// Domain separation, as the daemon's verifier expects it.
    public static let signatureContext = Data("jarvis.device.v1.ApprovalPayload\u{0}".utf8)

    public let approval: Approval
    public let payload: Jarvis_Device_V1_ApprovalPayload

    public var id: String { approval.approvalID }
    /// What the user asked for (from the server; context only).
    public var taskGoal: String { approval.taskGoal }
    public var deviceName: String { Self.visible(payload.deviceName) }
    public var program: String { Self.visible(payload.program) }
    public var arguments: [String] { payload.args.map(Self.visible) }
    public var workingDirectory: String { Self.visible(payload.workingDirectory) }
    public var timeout: TimeInterval {
        TimeInterval(payload.timeout.seconds) + TimeInterval(payload.timeout.nanos) / 1e9
    }
    public var expires: Date { payload.expireTime.date }

    /// Sandbox grants in plain words; empty when the command runs fully
    /// sandboxed (read-only, no network).
    public var grants: [String] {
        var out: [String] = []
        if payload.sandbox.writable {
            out.append("may change files in its working directory")
        }
        if payload.sandbox.network {
            out.append("may use the network")
        }
        if payload.sandbox.systemServices {
            out.append("may use macOS services (launch apps, AppleScript, clipboard), which reach outside the sandbox")
        }
        return out
    }

    /// The command as a shell would show it, with quoting where needed.
    /// Invisible and direction-changing characters are shown as escapes, so
    /// a command cannot disguise itself as another on screen.
    public var commandLine: String {
        ([payload.program] + payload.args).map(Self.quoted).joined(separator: " ")
    }

    /// `text` for display, with control, format (e.g. U+202E, zero-width) and
    /// other invisible characters escaped as \u{…}.
    public static func visible(_ text: String) -> String {
        var out = ""
        for scalar in text.unicodeScalars {
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .surrogate, .unassigned:
                out += "\\u{" + String(scalar.value, radix: 16, uppercase: true) + "}"
            case .spaceSeparator where scalar != " ":
                out += "\\u{" + String(scalar.value, radix: 16, uppercase: true) + "}"
            default:
                out.unicodeScalars.append(scalar)
            }
        }
        return out
    }

    public init(_ approval: Approval) throws {
        var options = BinaryDecodingOptions()
        options.discardUnknownFields = false
        guard let payload = try? Jarvis_Device_V1_ApprovalPayload(serializedBytes: approval.payload, options: options),
            payload.approvalID == approval.approvalID, !payload.program.isEmpty
        else {
            throw ApprovalError.malformedPayload
        }
        self.approval = approval
        self.payload = payload
    }

    /// What the approver signs.
    public var message: Data { Self.signatureContext + approval.payload }

    /// Signs the request with `key` (Face ID for the Secure Enclave key).
    /// The signature is normalized to low-S, which every ECDSA verifier accepts.
    public func sign(with key: ApproverKey, now: Date = Date()) async throws -> Data {
        guard now < expires else { throw ApprovalError.expired }
        let reason = "Approve on \(deviceName): \(commandLine)"
        return try P256Signature.lowS(try await key.sign(message, reason: String(reason.prefix(200))))
    }

    static func quoted(_ word: String) -> String {
        let shown = visible(word)
        let plain = CharacterSet(
            charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./=:,+@%")
        if !shown.isEmpty && shown == word && word.unicodeScalars.allSatisfy(plain.contains) {
            return word
        }
        return "'" + shown.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

/// ECDSA P-256 signature helpers.
enum P256Signature {
    /// The group order n of P-256.
    static let order: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    ]
    /// n / 2, rounded down.
    static let halfOrder: [UInt8] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
    ]

    /// Replaces s by n − s when s > n/2: (r, s) and (r, n − s) are both valid,
    /// and strict verifiers accept only the low one.
    static func lowS(_ raw: Data) throws -> Data {
        guard raw.count == 64 else { throw ApprovalError.malformedPayload }
        let r = [UInt8](raw.prefix(32))
        let s = [UInt8](raw.suffix(32))
        guard s.lexicographicallyPrecedes(halfOrder) || s == halfOrder else {
            return Data(r + subtract(order, s))
        }
        return raw
    }

    /// a − b for 256-bit big-endian numbers with a ≥ b.
    static func subtract(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            var digit = Int(a[i]) - Int(b[i]) - borrow
            borrow = digit < 0 ? 1 : 0
            if digit < 0 { digit += 256 }
            result[i] = UInt8(digit)
        }
        return result
    }
}
