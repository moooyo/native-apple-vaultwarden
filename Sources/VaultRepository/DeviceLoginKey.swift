import CoreFoundation
import CryptoCore
import Foundation
import Networking
import Security
import Synchronization

/// A request-scoped, nonpersistent RSA key. Only its public SPKI is exported.
/// Release the private key after one successful unwrap or when the attempt ends.
package final class DeviceLoginKey: Sendable, CustomStringConvertible, CustomReflectable {
    private let privateKey: Mutex<SecKey?>
    package let publicKey: String

    package init() throws {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2_048,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false],
        ]
        guard let generated = SecKeyCreateRandomKey(attributes as CFDictionary, nil),
              let publicPart = SecKeyCopyPublicKey(generated),
              let pkcs1 = SecKeyCopyExternalRepresentation(publicPart, nil) else {
            throw CryptoError.randomGenerationFailed
        }
        // SubjectPublicKeyInfo wraps Security's PKCS#1 representation in rsaEncryption + NULL.
        let algorithm = Data([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00])
        let bitString = Self.der(tag: 0x03, contents: Data([0]) + (pkcs1 as Data))
        publicKey = Self.der(tag: 0x30, contents: algorithm + bitString).base64EncodedString()
        privateKey = Mutex(generated)
    }

    package func fingerprint(email: String, words: [String]) throws -> String {
        try Self.fingerprint(email: email, publicKey: publicKey, words: words)
    }

    package static func fingerprint(email: String, publicKey: String, words: [String]) throws -> String {
        // Device approval uses the lowercased email as HKDF info, unlike the account sharing
        // fingerprint which uses the server user ID. The input key bytes are the same SPKI format.
        let email = try DeviceLoginWire.normalizedEmail(email)
        guard let spki = DeviceLoginWire.publicKeyBytes(publicKey) else { throw DeviceLoginError.invalidPublicKey }
        do { return try EmergencyAccessCryptography.fingerprint(userID: email, spki: spki, words: words) }
        catch { throw DeviceLoginError.invalidPublicKey }
    }

    package static func wrap(_ key: SymmetricCryptoKey, publicKey: String) throws -> EncString {
        guard let spki = DeviceLoginWire.publicKeyBytes(publicKey) else { throw DeviceLoginError.invalidPublicKey }
        do { return try EmergencyAccessCryptography.wrap(key, spki: spki) }
        catch { throw DeviceLoginError.invalidPublicKey }
    }

    package func unwrap(_ encryptedKey: EncString) throws -> SymmetricCryptoKey {
        guard DeviceLoginWire.isWrappedKey(encryptedKey) else { throw DeviceLoginError.invalidWrappedKey }
        return try privateKey.withLock { privateKey in
            guard let key = privateKey else { throw CryptoError.decryptionFailed }
            // SHA-1 is part of the RSA-OAEP type 4 wire format, not a password hash.
            guard let decrypted = SecKeyCreateDecryptedData(key, .rsaEncryptionOAEPSHA1, encryptedKey.ciphertext as CFData, nil),
                  CFDataGetLength(decrypted) == 64, let pointer = CFDataGetBytePtr(decrypted) else {
                throw DeviceLoginError.invalidWrappedKey
            }
            let userKey = try withExtendedLifetime(decrypted) {
                // Borrow Security's immutable bytes until they are copied to the owned secure key.
                let bytes = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: pointer), count: 64, deallocator: .none)
                return try SymmetricCryptoKey(combined: bytes)
            }
            privateKey = nil
            return userKey
        }
    }

    package func invalidate() { privateKey.withLock { $0 = nil } }

    package var description: String { "DeviceLoginKey(redacted)" }
    package var customMirror: Mirror { Mirror(self, children: [:]) }

    /// Encodes the two locally generated wrappers around the fixed-size RSA-2048 public key.
    private static func der(tag: UInt8, contents: Data) -> Data {
        let length = contents.count
        if length < 0x80 { return Data([tag, UInt8(length)]) + contents }
        if length <= 0xff { return Data([tag, 0x81, UInt8(length)]) + contents }
        return Data([tag, 0x82, UInt8(length >> 8), UInt8(length & 0xff)]) + contents
    }
}
