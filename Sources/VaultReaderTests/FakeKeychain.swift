import Foundation
import CryptoCore
import KeychainBridge
import AppShared

/// In-memory `SecureEnclaveKeyStore` fake: reversible XOR wrap/unwrap against a per-key
/// random pad, so a wrong/foreign key wouldn't unwrap correctly. `unwrap` can be made to
/// throw a chosen error to simulate biometric cancellation.
final class InMemorySecureEnclaveKeyStore: SecureEnclaveKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var pads: [String: Data] = [:]
    private var injectedUnwrapError: KeychainError?
    private var unwrapCalls = 0

    var unwrapError: KeychainError? {
        get { lock.withLock { injectedUnwrapError } }
        set { lock.withLock { injectedUnwrapError = newValue } }
    }

    var unwrapCallCount: Int { lock.withLock { unwrapCalls } }

    private func id(_ tag: String, _ group: String) -> String { "\(group)::\(tag)" }

    func createBiometricKey(tag: String, accessGroup: String) throws {
        let key = id(tag, accessGroup)
        lock.withLock {
            guard pads[key] == nil else { return }
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
            unwrapCalls += 1
            if let injectedUnwrapError { throw injectedUnwrapError }
            guard let pad = pads[id(tag, accessGroup)] else { throw KeychainError.notFound }
            return Self.xor(ciphertext, pad: pad)
        }
    }

    private static func xor(_ data: Data, pad: Data) -> Data {
        var out = Data(count: data.count)
        for i in 0..<data.count { out[i] = data[i] ^ pad[i % pad.count] }
        return out
    }
}

/// In-memory `KeychainItemStore` fake: a dictionary keyed by account|group.
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

/// A `KeychainBridge` backed by fresh in-memory seams (no entitlements needed).
func makeFakeKeychain(
    activeAccountID: String? = Fixtures.accountID,
    biometricAccountID: String? = Fixtures.accountID,
    activeSessionID: String? = "test-session",
    secureEnclave: InMemorySecureEnclaveKeyStore = InMemorySecureEnclaveKeyStore(),
    itemStore: InMemoryKeychainItemStore = InMemoryKeychainItemStore()
) -> KeychainBridge {
    if let activeAccountID {
        try! itemStore.set(
            Data(activeAccountID.utf8),
            account: AppShared.KeychainAccount.activeAccountID,
            accessGroup: "test.group",
            biometryGated: false
        )
    }
    if let biometricAccountID {
        try! itemStore.set(
            Data(biometricAccountID.utf8),
            account: AppShared.KeychainAccount.biometricAccountID,
            accessGroup: "test.group",
            biometryGated: false
        )
    }
    if let activeSessionID {
        try! itemStore.set(
            Data(activeSessionID.utf8),
            account: AppShared.KeychainAccount.activeSessionID,
            accessGroup: "test.group",
            biometryGated: false
        )
    }
    return KeychainBridge(accessGroup: "test.group",
                          service: "test.service",
                          secureEnclave: secureEnclave,
                          itemStore: itemStore)
}
