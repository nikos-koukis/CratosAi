import Foundation
import Security
import Synchronization

/// Small secrets kept on the device (the session's refresh token, the
/// approver key's Secure Enclave handle).
public protocol SecretStore: Sendable {
    func read(_ key: String) throws -> Data?
    func write(_ key: String, _ data: Data) throws
    func delete(_ key: String) throws
}

public struct KeychainError: Error, CustomStringConvertible {
    public let status: OSStatus
    public var description: String {
        (SecCopyErrorMessageString(status, nil) as String?) ?? "keychain error \(status)"
    }
}

/// The keychain, as generic passwords of one service. Items are
/// `ThisDeviceOnly` (never in backups or on another device) and readable
/// after the first unlock, so the app can refresh its session in the
/// background.
public struct KeychainStore: SecretStore {
    public let service: String

    public init(service: String = "ai.cratos.jarvis") {
        self.service = service
    }

    private func query(_ key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    public func read(_ key: String) throws -> Data? {
        var q = query(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        switch status {
        case errSecSuccess: return result as? Data
        case errSecItemNotFound: return nil
        default: throw KeychainError(status: status)
        }
    }

    public func write(_ key: String, _ data: Data) throws {
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var status = SecItemUpdate(query(key) as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query(key).merging(attributes) { $1 } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }

    public func delete(_ key: String) throws {
        let status = SecItemDelete(query(key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError(status: status) }
    }
}

/// Secrets in memory (tests, previews).
public final class MemoryStore: SecretStore {
    private let items = Mutex<[String: Data]>([:])

    public init() {}

    public func read(_ key: String) throws -> Data? { items.withLock { $0[key] } }
    public func write(_ key: String, _ data: Data) throws { items.withLock { $0[key] = data } }
    public func delete(_ key: String) throws { _ = items.withLock { $0.removeValue(forKey: key) } }
}

/// Secrets in one file per key, readable only by the user (the macOS
/// command-line tool, which has no keychain entitlements).
public struct FileStore: SecretStore {
    public let directory: URL

    public init(directory: URL) {
        self.directory = directory
    }

    private func url(_ key: String) -> URL { directory.appending(path: key) }

    public func read(_ key: String) throws -> Data? {
        do {
            return try Data(contentsOf: url(key))
        } catch CocoaError.fileReadNoSuchFile {
            return nil
        }
    }

    public func write(_ key: String, _ data: Data) throws {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try data.write(to: url(key), options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url(key).path)
    }

    public func delete(_ key: String) throws {
        do {
            try FileManager.default.removeItem(at: url(key))
        } catch CocoaError.fileNoSuchFile {}
    }
}
