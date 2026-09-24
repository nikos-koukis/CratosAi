import CryptoKit
import Foundation
import SwiftProtobuf
import Testing

@testable import JarvisKit

func approval(
    id: String = "appr-1", program: String = "/bin/rm", args: [String] = ["-rf", "build"],
    expires: Date = Date().addingTimeInterval(120),
    sandbox: Jarvis_Device_V1_SandboxGrants = Jarvis_Device_V1_SandboxGrants()
) throws -> Approval {
    var payload = Jarvis_Device_V1_ApprovalPayload()
    payload.approvalID = id
    payload.deviceName = "MacBook"
    payload.program = program
    payload.args = args
    payload.workingDirectory = "/Users/me/project"
    payload.timeout = Google_Protobuf_Duration(seconds: 60)
    payload.sandbox = sandbox
    payload.expireTime = Google_Protobuf_Timestamp(date: expires)
    var a = Approval()
    a.approvalID = id
    a.taskID = "task-1"
    a.taskGoal = "Clean the build"
    a.deviceName = "server says something else"
    a.payload = try payload.serializedData()
    a.expireTime = Google_Protobuf_Timestamp(date: expires)
    return a
}

@Suite struct ApprovalTests {
    @Test func theReviewComesFromTheSignedBytes() throws {
        var grants = Jarvis_Device_V1_SandboxGrants()
        grants.network = true
        let raw = try approval(args: ["-rf", "my build", "it's"], sandbox: grants)
        let request = try ApprovalRequest(raw)
        #expect(request.deviceName == "MacBook")  // from the payload, not the server's field
        #expect(request.commandLine == "/bin/rm -rf 'my build' 'it'\\''s'")
        #expect(request.workingDirectory == "/Users/me/project")
        #expect(request.timeout == 60)
        #expect(request.grants == ["may use the network"])
        #expect(request.message == Data("jarvis.device.v1.ApprovalPayload\u{0}".utf8) + raw.payload)
    }

    @Test func invisibleCharactersCannotDisguiseACommand() throws {
        // U+202E reverses what follows on screen; U+200B is invisible.
        let request = try ApprovalRequest(
            try approval(program: "/bin/echo", args: ["safe\u{202E}txt.sh", "a\u{200B}b"]))
        #expect(request.commandLine == "/bin/echo 'safe\\u{202E}txt.sh' 'a\\u{200B}b'")
        #expect(request.arguments == ["safe\\u{202E}txt.sh", "a\\u{200B}b"])
        #expect(ApprovalRequest.visible("ok \u{00A0}nbsp\n") == "ok \\u{A0}nbsp\\u{A}")
    }

    @Test func mismatchedOrBrokenPayloadsAreRefused() throws {
        var wrongID = try approval()
        wrongID.approvalID = "appr-2"
        #expect(throws: ApprovalError.malformedPayload) { try ApprovalRequest(wrongID) }
        var garbage = try approval()
        garbage.payload = Data([0xFF, 0xFF, 0xFF])
        #expect(throws: ApprovalError.malformedPayload) { try ApprovalRequest(garbage) }
    }

    @Test func signaturesVerifyAsTheDaemonChecksThem() async throws {
        let key = SoftwareApproverKey()
        let raw = try approval()
        let request = try ApprovalRequest(raw)
        for _ in 0..<20 {
            let signature = try await request.sign(with: key)
            #expect(signature.count == 64)
            // The daemon: ECDSA P-256/SHA-256 over context + payload, raw r||s,
            // with the public key from base64 SEC1.
            let publicKey = try P256.Signing.PublicKey(x963Representation: Data(base64Encoded: key.publicKeyBase64)!)
            let parsed = try P256.Signing.ECDSASignature(rawRepresentation: signature)
            #expect(publicKey.isValidSignature(parsed, for: ApprovalRequest.signatureContext + raw.payload))
            #expect(!publicKey.isValidSignature(parsed, for: raw.payload))  // the context is required
            let s = [UInt8](signature.suffix(32))
            #expect(s.lexicographicallyPrecedes(P256Signature.halfOrder) || s == P256Signature.halfOrder)
        }
        await #expect(throws: ApprovalError.expired) {
            _ = try await request.sign(with: key, now: Date().addingTimeInterval(3600))
        }
    }

    @Test func highSSignaturesAreNormalized() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("m".utf8)
        let low = try P256Signature.lowS(try key.signature(for: message).rawRepresentation)
        let r = [UInt8](low.prefix(32))
        let high = Data(r + P256Signature.subtract(P256Signature.order, [UInt8](low.suffix(32))))
        #expect(high != low)
        // Both are valid ECDSA signatures; normalization maps high to low.
        #expect(key.publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: high), for: message))
        #expect(try P256Signature.lowS(high) == low)
        #expect(try P256Signature.lowS(low) == low)
    }
}
