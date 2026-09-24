import CryptoKit
import Foundation
import LocalAuthentication

/// A key that approves commands on the user's computers: ECDSA P-256, as the
/// Jarvis daemon verifies it. Its public key goes into the computer's
/// daemon.toml as an `[[approver]]`; the private key never leaves the device.
public protocol ApproverKey: Sendable {
    /// The public key as base64 SEC1 (uncompressed), as daemon.toml takes it.
    var publicKeyBase64: String { get }
    /// Signs `message` (SHA-256 is applied inside) and returns raw r||s.
    /// `reason` is shown to the user when the key needs Face ID.
    func sign(_ message: Data, reason: String) async throws -> Data
}

public enum ApproverKeyError: Error, Equatable, CustomStringConvertible {
    /// No Secure Enclave (the simulator, old devices).
    case secureEnclaveUnavailable
    /// The biometric enrollment changed, so the key no longer works; make a
    /// new one and register it on the computer again.
    case keyInvalidated
    /// The user cancelled Face ID.
    case cancelled

    public var description: String {
        switch self {
        case .secureEnclaveUnavailable: "this device has no Secure Enclave"
        case .keyInvalidated: "Face ID changed, so the approver key no longer works; create a new one"
        case .cancelled: "cancelled"
        }
    }
}

/// The approver key in the Secure Enclave. Every signature needs Face ID (or
/// Touch ID) of a currently enrolled face: adding a face invalidates the key,
/// so someone who learns the passcode cannot enroll themselves and approve.
public struct SecureEnclaveApproverKey: ApproverKey {
    private static let handleKey = "approver-key"
    private static let biometryKey = "approver-key-biometry"
    private let key: SecureEnclave.P256.Signing.PrivateKey
    /// The biometric enrollment the key was made under.
    private let biometry: Data?

    /// Loads the key, creating it on first use. Its opaque handle (not the
    /// key itself, which stays in the Secure Enclave) is kept in `store`.
    public static func loadOrCreate(store: SecretStore) throws -> SecureEnclaveApproverKey {
        guard SecureEnclave.isAvailable else { throw ApproverKeyError.secureEnclaveUnavailable }
        if let handle = try store.read(handleKey) {
            return SecureEnclaveApproverKey(
                key: try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: handle),
                biometry: try store.read(biometryKey))
        }
        return try create(store: store)
    }

    /// Replaces the key (e.g. after Face ID changed). The old public key must
    /// then be removed from the computers' daemon.toml.
    public static func create(store: SecretStore) throws -> SecureEnclaveApproverKey {
        guard SecureEnclave.isAvailable else { throw ApproverKeyError.secureEnclaveUnavailable }
        var error: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error)
        else {
            throw error!.takeRetainedValue() as Error
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        let biometry = currentBiometry()
        try store.write(handleKey, key.dataRepresentation)
        if let biometry {
            try store.write(biometryKey, biometry)
        } else {
            try store.delete(biometryKey)
        }
        return SecureEnclaveApproverKey(key: key, biometry: biometry)
    }

    private static func currentBiometry() -> Data? {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return context.domainState.biometry.stateHash
    }

    /// Whether Face ID's enrollment changed since the key was made, which
    /// makes the Secure Enclave refuse it.
    public var isInvalidated: Bool {
        biometry != Self.currentBiometry()
    }

    public var publicKeyBase64: String { key.publicKey.x963Representation.base64EncodedString() }

    public func sign(_ message: Data, reason: String) async throws -> Data {
        if isInvalidated {
            throw ApproverKeyError.keyInvalidated
        }
        let context = LAContext()
        context.localizedReason = reason
        do {
            // Rebuilding the key with the context makes Face ID show `reason`.
            let bound = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: key.dataRepresentation,
                authenticationContext: context)
            return try bound.signature(for: message).rawRepresentation
        } catch let error as LAError where [.userCancel, .appCancel, .systemCancel].contains(error.code) {
            throw ApproverKeyError.cancelled
        }
    }
}

/// An approver key in software, for the command-line tool and tests. It is
/// only as safe as the file it is kept in.
public struct SoftwareApproverKey: ApproverKey {
    public let key: P256.Signing.PrivateKey

    public init(key: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) {
        self.key = key
    }

    public init(pem: String) throws {
        key = try P256.Signing.PrivateKey(pemRepresentation: pem)
    }

    public var pem: String { key.pemRepresentation }

    public var publicKeyBase64: String { key.publicKey.x963Representation.base64EncodedString() }

    public func sign(_ message: Data, reason _: String) async throws -> Data {
        try key.signature(for: message).rawRepresentation
    }
}
