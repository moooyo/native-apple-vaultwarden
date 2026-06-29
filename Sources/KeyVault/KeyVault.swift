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
        self.userKey = userKey
    }

    public func lock() {
        // Value type drops; no long-lived SecureBytes held here.
        userKey = nil
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
    /// (a type-2 EncString wrapping the 64-byte user key) -> hold the UserKey. PBKDF2 only (D6).
    public func unlock(password: String, email: String, iterations: Int,
                       protectedUserKey: EncString) throws {
        let masterKey = try KDF.deriveMasterKey(password: password, email: email, iterations: iterations)
        let stretched = KeyStretch.stretchMasterKey(masterKey)
        let raw: Data
        do { raw = try SymmetricCrypto.decrypt(protectedUserKey, using: stretched) }
        catch { throw KeyVaultError.unlockFailed }
        guard raw.count == 64 else { throw KeyVaultError.invalidUserKey }
        self.userKey = try SymmetricCryptoKey(combined: raw)
    }

    /// Decrypt the per-cipher key (a type-2 EncString wrapping 64 bytes) into a usable key.
    public func cipherKey(fromProtected protectedKey: EncString) throws -> SymmetricCryptoKey {
        guard let userKey else { throw KeyVaultError.locked }
        let raw = try SymmetricCrypto.decrypt(protectedKey, using: userKey)
        guard raw.count == 64 else { throw KeyVaultError.invalidUserKey }
        return try SymmetricCryptoKey(combined: raw)
    }

    /// Decrypt a field using a per-cipher key if provided, else the user key.
    public func decrypt(_ encString: EncString, cipherKey: SymmetricCryptoKey?) throws -> Data {
        if let cipherKey { return try SymmetricCrypto.decrypt(encString, using: cipherKey) }
        return try decrypt(encString)
    }
}
