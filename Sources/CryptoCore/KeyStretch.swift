import Foundation
import CryptoKit

/// A 64-byte symmetric key split into a 32-byte AES key and a 32-byte HMAC key.
public struct SymmetricCryptoKey: Sendable, Equatable {
    public let encKey: Data   // 32 bytes
    public let macKey: Data   // 32 bytes

    public init(encKey: Data, macKey: Data) throws {
        guard encKey.count == 32, macKey.count == 32 else { throw CryptoError.invalidKeyLength }
        self.encKey = encKey
        self.macKey = macKey
    }

    /// Split a 64-byte combined key (first 32 = enc, last 32 = mac).
    public init(combined: Data) throws {
        guard combined.count == 64 else { throw CryptoError.invalidKeyLength }
        self.encKey = combined.prefix(32)
        self.macKey = combined.suffix(32)
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
        let enc = hkdfExpand(prk: masterKey, info: "enc", length: 32)
        let mac = hkdfExpand(prk: masterKey, info: "mac", length: 32)
        // 32-byte halves are guaranteed valid, so `try!` is safe here.
        return try! SymmetricCryptoKey(encKey: Data(enc), macKey: Data(mac))
    }
}
