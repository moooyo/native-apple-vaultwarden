import Foundation
import CryptoCore

/// Owns the in-memory key hierarchy. An `actor` so all key access is serialized;
/// the user key never leaves the actor as raw bytes except through explicit decrypt calls.
public actor KeyVault {
    private var userKey: SymmetricCryptoKey?

    public init() {}

    public var isUnlocked: Bool { userKey != nil }

    /// Direct unlock when the 64-byte user key is already recovered (e.g. via the biometric path later).
    public func unlock(userKey: SymmetricCryptoKey) {
        lock()
        self.userKey = userKey.isolatedCopy()
    }

    public func lock() {
        userKey?.erase()
        userKey = nil
    }

    /// Package-scoped enrollment bridge. The key is exported only to AuthRepository long
    /// enough to wrap it with the Secure Enclave; UI code cannot call this API.
    package func userKeyForBiometricEnrollment() throws -> SymmetricCryptoKey {
        guard let userKey else { throw KeyVaultError.locked }
        return userKey.isolatedCopy()
    }

    /// Decrypt an EncString with the user key (throws `.locked` if not unlocked).
    public func decrypt(_ encString: EncString) throws -> Data {
        guard let userKey else { throw KeyVaultError.locked }
        return try SymmetricCrypto.decrypt(encString, using: userKey)
    }

    public func decryptString(_ encString: EncString) throws -> String {
        let data = try decrypt(encString)
        guard let s = String(data: data, encoding: .utf8) else { throw CryptoError.decryptionFailed }
        return s
    }

    /// Real unlock: PBKDF2(masterpw) -> HKDF-stretch -> decrypt the protected user key
    /// (a type-2 EncString wrapping the 64-byte user key) -> hold the UserKey. PBKDF2 only.
    public func unlock(password: String, email: String, iterations: Int,
                       protectedUserKey: EncString) throws {
        var masterKey = try KDF.deriveMasterKey(password: password, email: email, iterations: iterations)
        defer { masterKey.withUnsafeMutableBytes(SecureBytes.erase) }
        let stretched = KeyStretch.stretchMasterKey(masterKey)
        var raw: Data
        do { raw = try SymmetricCrypto.decrypt(protectedUserKey, using: stretched) }
        catch { throw KeyVaultError.unlockFailed }
        defer { raw.withUnsafeMutableBytes(SecureBytes.erase) }
        guard raw.count == 64 else { throw KeyVaultError.invalidUserKey }
        let recovered = try SymmetricCryptoKey(combined: raw)
        lock()
        self.userKey = recovered
    }

    /// Decrypt the per-cipher key (a type-2 EncString wrapping 64 bytes) into a usable key.
    public func cipherKey(fromProtected protectedKey: EncString) throws -> SymmetricCryptoKey {
        guard let userKey else { throw KeyVaultError.locked }
        var raw = try SymmetricCrypto.decrypt(protectedKey, using: userKey)
        defer { raw.withUnsafeMutableBytes(SecureBytes.erase) }
        guard raw.count == 64 else { throw KeyVaultError.invalidUserKey }
        return try SymmetricCryptoKey(combined: raw)
    }

    package func sealPasskeyHandoff(_ bytes: Data) throws -> EncString {
        guard let userKey else { throw KeyVaultError.locked }
        return try SymmetricCrypto.encrypt(bytes, using: Self.handoffKey(userKey))
    }

    package func openPasskeyHandoff(_ envelope: EncString) throws -> Data {
        guard let userKey else { throw KeyVaultError.locked }
        return try SymmetricCrypto.decrypt(envelope, using: Self.handoffKey(userKey))
    }

    private static func handoffKey(_ userKey: SymmetricCryptoKey) -> SymmetricCryptoKey {
        userKey.deriveScopedKey(info: "OpenVault.PasskeyHandoff.v2")
    }

    /// Decrypt a field using a per-cipher key if provided, else the user key.
    /// The locked invariant is uniform: a locked vault rejects all decryption,
    /// even when an explicit per-cipher key is supplied.
    public func decrypt(_ encString: EncString, cipherKey: SymmetricCryptoKey?) throws -> Data {
        guard isUnlocked else { throw KeyVaultError.locked }
        if let cipherKey { return try SymmetricCrypto.decrypt(encString, using: cipherKey) }
        return try decrypt(encString)
    }
}
