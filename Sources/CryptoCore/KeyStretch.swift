import Foundation
import CryptoKit

/// A 64-byte symmetric key split into a 32-byte AES key and a 32-byte HMAC key.
public struct SymmetricCryptoKey: Sendable, Equatable {
    private let storage: SecureBytes

    public var encKey: Data { withEncryptionBytes { Data($0) } }
    public var macKey: Data { withAuthenticationBytes { Data($0) } }

    public init(encKey: Data, macKey: Data) throws {
        guard encKey.count == 32, macKey.count == 32 else { throw CryptoError.invalidKeyLength }
        storage = SecureBytes(count: 64)
        storage.withUnsafeMutableBytes { bytes in
            encKey.copyBytes(to: UnsafeMutableRawBufferPointer(rebasing: bytes[..<32]))
            macKey.copyBytes(to: UnsafeMutableRawBufferPointer(rebasing: bytes[32...]))
        }
    }

    /// Split a 64-byte combined key (first 32 = enc, last 32 = mac).
    public init(combined: Data) throws {
        guard combined.count == 64 else { throw CryptoError.invalidKeyLength }
        storage = SecureBytes(count: 64)
        _ = storage.withUnsafeMutableBytes { combined.copyBytes(to: $0) }
    }

    fileprivate init(encryptionKey: SymmetricKey, authenticationKey: SymmetricKey) {
        precondition(encryptionKey.bitCount == 256 && authenticationKey.bitCount == 256)
        storage = SecureBytes(count: 64)
        storage.withUnsafeMutableBytes { bytes in
            encryptionKey.withUnsafeBytes { UnsafeMutableRawBufferPointer(rebasing: bytes[..<32]).copyMemory(from: $0) }
            authenticationKey.withUnsafeBytes { UnsafeMutableRawBufferPointer(rebasing: bytes[32...]).copyMemory(from: $0) }
        }
    }

    private init(storage: SecureBytes) { self.storage = storage }

    package func isolatedCopy() -> Self {
        let copy = SecureBytes(count: 64)
        storage.withUnsafeBytes { source in
            copy.withUnsafeMutableBytes { $0.copyMemory(from: source) }
        }
        return Self(storage: copy)
    }

    // Only erase an actor's isolated copy, never a borrowed key.
    package func erase() { storage.clear() }

    package func deriveScopedKey(info: String) -> Self {
        withCombinedBytes { bytes in
            let derived = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: bytes),
                                                 info: Data(info.utf8), outputByteCount: 64)
            let copy = SecureBytes(count: 64)
            derived.withUnsafeBytes { source in
                copy.withUnsafeMutableBytes { $0.copyMemory(from: source) }
            }
            return Self(storage: copy)
        }
    }

    package func withCombinedBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try storage.withUnsafeBytes(body)
    }

    func withEncryptionBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try withCombinedBytes { try body(UnsafeRawBufferPointer(rebasing: $0[..<32])) }
    }

    func withAuthenticationBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try withCombinedBytes { try body(UnsafeRawBufferPointer(rebasing: $0[32...])) }
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        if lhs.storage === rhs.storage { return true }
        let lhsKey = lhs.withCombinedBytes { SymmetricKey(data: $0) }
        return rhs.withCombinedBytes { lhsKey == SymmetricKey(data: $0) }
    }
}

public enum KeyStretch {
    /// HKDF-Expand (RFC 5869, no extract step) with SHA-256. PRK is used directly.
    public static func hkdfExpand(prk: [UInt8], info: String, length: Int) -> [UInt8] {
        let key = SymmetricKey(data: prk)
        let okm = HKDF<SHA256>.expand(pseudoRandomKey: key,
                                      info: Data(info.utf8),
                                      outputByteCount: length)
        return okm.withUnsafeBytes { Array($0) }
    }

    /// Bitwarden stretched master key: HKDF-Expand("enc") || HKDF-Expand("mac").
    public static func stretchMasterKey(_ masterKey: [UInt8]) -> SymmetricCryptoKey {
        let key = SymmetricKey(data: masterKey)
        let enc = HKDF<SHA256>.expand(pseudoRandomKey: key, info: Data("enc".utf8), outputByteCount: 32)
        let mac = HKDF<SHA256>.expand(pseudoRandomKey: key, info: Data("mac".utf8), outputByteCount: 32)
        return SymmetricCryptoKey(encryptionKey: enc, authenticationKey: mac)
    }
}
