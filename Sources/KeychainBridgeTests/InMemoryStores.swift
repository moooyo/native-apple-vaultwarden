import Foundation
import KeychainBridge

/// In-memory `SecureEnclaveKeyStore` fake. Simulates SE keygen + ECIES wrap/unwrap so the
/// `KeychainBridge` orchestration is fully testable without entitlements.
///
/// `wrap`/`unwrap` use a reversible XOR against a per-key random pad so a wrong/foreign key
/// would not unwrap correctly — enough to validate the round-trip and the key-binding logic.
/// `unwrap` can be made to throw a chosen error to simulate biometric cancellation.
///
/// Thread-safety uses `NSLock.withLock` (the async-safe scoped form), so the fake is safe to
/// reach from the actor's executor.
final class InMemorySecureEnclaveKeyStore: SecureEnclaveKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var pads: [String: Data] = [:]   // tag|group -> 64-byte pad acting as the "SE key"
    private var injectedUnwrapError: KeychainError?

    /// When set, `unwrap` throws this instead of decrypting (simulates a biometric prompt failure).
    var unwrapError: KeychainError? {
        get { lock.withLock { injectedUnwrapError } }
        set { lock.withLock { injectedUnwrapError = newValue } }
    }

    private func id(_ tag: String, _ group: String) -> String { "\(group)::\(tag)" }

    func createBiometricKey(tag: String, accessGroup: String) throws {
        let key = id(tag, accessGroup)
        lock.withLock {
            guard pads[key] == nil else { return }   // idempotent
            pads[key] = Data((0..<64).map { _ in UInt8.random(in: 0...255) })
        }
    }

    func hasKey(tag: String, accessGroup: String) -> Bool {
        lock.withLock { pads[id(tag, accessGroup)] != nil }
    }

    func deleteKey(tag: String, accessGroup: String) {
        lock.withLock { pads[id(tag, accessGroup)] = nil }
    }

    func wrap(_ plaintext: Data, tag: String, accessGroup: String) throws -> Data {
        try lock.withLock {
            guard let pad = pads[id(tag, accessGroup)] else { throw KeychainError.notFound }
            return Self.xor(plaintext, pad: pad)
        }
    }

    func unwrap(_ ciphertext: Data, tag: String, accessGroup: String, reason: String) async throws -> Data {
        try lock.withLock {
            if let injectedUnwrapError { throw injectedUnwrapError }
            guard let pad = pads[id(tag, accessGroup)] else { throw KeychainError.notFound }
            return Self.xor(ciphertext, pad: pad)
        }
    }

    private static func xor(_ data: Data, pad: Data) -> Data {
        var out = Data(count: data.count)
        for i in 0..<data.count {
            out[i] = data[i] ^ pad[i % pad.count]
        }
        return out
    }
}

/// In-memory `KeychainItemStore` fake: a simple dictionary keyed by account|group.
final class InMemoryKeychainItemStore: KeychainItemStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]

    private func id(_ account: String, _ group: String) -> String { "\(group)::\(account)" }

    func set(_ data: Data, account: String, accessGroup: String, biometryGated: Bool) throws {
        lock.withLock { items[id(account, accessGroup)] = data }
    }

    func get(account: String, accessGroup: String) async throws -> Data? {
        lock.withLock { items[id(account, accessGroup)] }
    }

    func delete(account: String, accessGroup: String) {
        lock.withLock { items[id(account, accessGroup)] = nil }
    }
}
