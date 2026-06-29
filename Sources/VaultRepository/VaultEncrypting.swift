import Foundation
import CryptoCore

/// Encryption seam for the write path.
///
/// ## Why this exists (documented adaptation)
/// `KeyVault` (the in-memory key holder) intentionally exposes only **decryption** — it has
/// no `encrypt` and never vends the raw user key. The create/update write paths need to
/// encrypt plaintext fields under the user key, so VaultRepository adds this small,
/// repository-local encryptor rather than modifying `KeyVault`'s source (per the task's
/// "adapt within these two modules" rule). It mirrors `KeyVault`'s lifecycle: the user key
/// is set on a successful unlock and zeroed on lock, so it never outlives an unlocked
/// session and is never persisted.
public protocol VaultEncrypting: Sendable {
    /// Encrypt `plaintext` under the held user key (or a supplied per-cipher key).
    /// Throws `RepositoryError.locked` when no key is held.
    func encrypt(_ plaintext: Data, cipherKey: SymmetricCryptoKey?) async throws -> EncString
    /// Hand the encryptor the user key after a successful unlock.
    func setUserKey(_ key: SymmetricCryptoKey) async
    /// Whether a user key is currently held (mirrors the vault's unlocked state).
    func hasKey() async -> Bool
    /// Zero the held key (called on lock / logout).
    func clear() async
}

extension VaultEncrypting {
    /// Convenience: encrypt a UTF-8 string under the user key.
    public func encryptString(_ s: String, cipherKey: SymmetricCryptoKey? = nil) async throws -> EncString {
        try await encrypt(Data(s.utf8), cipherKey: cipherKey)
    }
}

/// Default `VaultEncrypting`: an actor holding the unlocked user key for AES-256-CBC +
/// HMAC encryption (the type-2 EncString format). Lifecycle is bound to the vault's:
/// `setUserKey` on unlock, `clear` on lock.
public actor UserKeyEncryptor: VaultEncrypting {
    private var userKey: SymmetricCryptoKey?

    public init() {}

    public func encrypt(_ plaintext: Data, cipherKey: SymmetricCryptoKey?) async throws -> EncString {
        let key: SymmetricCryptoKey
        if let cipherKey {
            key = cipherKey
        } else if let userKey {
            key = userKey
        } else {
            throw RepositoryError.locked
        }
        do { return try SymmetricCrypto.encrypt(plaintext, using: key) }
        catch { throw RepositoryError.crypto(error) }
    }

    public func setUserKey(_ key: SymmetricCryptoKey) async { userKey = key }
    public func hasKey() async -> Bool { userKey != nil }
    public func clear() async { userKey = nil }
}
