import Foundation
import CryptoKit
@testable import CryptoCore

private func makeSymCryptoKey() throws -> SymmetricCryptoKey {
    try SymmetricCryptoKey(combined: Data((0..<64).map { UInt8($0) }))
}

func checkSymmetricCrypto(_ r: inout TestRunner) {
    // test_roundTrip
    do {
        let key = try makeSymCryptoKey()
        let plaintext = Data("the quick brown fox jumps over the lazy dog".utf8)
        let enc = try SymmetricCrypto.encrypt(plaintext, using: key)
        r.expect(enc.type, .aesCbc256_HmacSha256_B64, "SymmetricCrypto.encrypt type")
        r.expect(enc.iv?.count, 16, "SymmetricCrypto.encrypt iv length")
        r.expect(enc.mac?.count, 32, "SymmetricCrypto.encrypt mac length")
        let decrypted = try SymmetricCrypto.decrypt(enc, using: key)
        r.expect(decrypted, plaintext, "SymmetricCrypto round-trip")
    } catch {
        r.expectTrue(false, "SymmetricCrypto round-trip threw: \(error)")
    }

    // test_roundTripViaStringSerialization
    do {
        let key = try makeSymCryptoKey()
        let plaintext = Data("secret".utf8)
        let enc = try SymmetricCrypto.encrypt(plaintext, using: key)
        let reparsed = try EncString(parsing: enc.stringValue)
        r.expect(try SymmetricCrypto.decrypt(reparsed, using: key), plaintext,
                 "SymmetricCrypto round-trip via string serialization")
    } catch {
        r.expectTrue(false, "SymmetricCrypto string round-trip threw: \(error)")
    }

    // test_macTamperRejected
    do {
        let key = try makeSymCryptoKey()
        let enc = try SymmetricCrypto.encrypt(Data("secret".utf8), using: key)
        var badMac = Data(enc.mac!)
        badMac[0] ^= 0xFF
        let tampered = EncString(type: .aesCbc256_HmacSha256_B64, iv: enc.iv, ciphertext: enc.ciphertext, mac: badMac)
        r.expectThrowsError(CryptoError.macMismatch, "SymmetricCrypto rejects tampered MAC (first byte)") {
            _ = try SymmetricCrypto.decrypt(tampered, using: key)
        }
    } catch {
        r.expectTrue(false, "SymmetricCrypto MAC-tamper setup threw: \(error)")
    }

    // test_macLastByteTamperRejected — guards that the comparison covers the whole MAC,
    // not just a prefix (a non-constant-time `==` or truncated compare could miss this).
    do {
        let key = try makeSymCryptoKey()
        let enc = try SymmetricCrypto.encrypt(Data("secret".utf8), using: key)
        var badMac = Data(enc.mac!)
        badMac[badMac.count - 1] ^= 0xFF
        let tampered = EncString(type: .aesCbc256_HmacSha256_B64, iv: enc.iv, ciphertext: enc.ciphertext, mac: badMac)
        r.expectThrowsError(CryptoError.macMismatch, "SymmetricCrypto rejects tampered MAC (last byte)") {
            _ = try SymmetricCrypto.decrypt(tampered, using: key)
        }
    } catch {
        r.expectTrue(false, "SymmetricCrypto last-byte MAC-tamper setup threw: \(error)")
    }

    // test_ciphertextTamperRejectedByMAC
    do {
        let key = try makeSymCryptoKey()
        let enc = try SymmetricCrypto.encrypt(Data("secret".utf8), using: key)
        var badCt = Data(enc.ciphertext)
        badCt[0] ^= 0xFF
        let tampered = EncString(type: .aesCbc256_HmacSha256_B64, iv: enc.iv, ciphertext: badCt, mac: enc.mac)
        r.expectThrowsError(CryptoError.macMismatch, "SymmetricCrypto rejects tampered ciphertext via MAC") {
            _ = try SymmetricCrypto.decrypt(tampered, using: key)
        }
    } catch {
        r.expectTrue(false, "SymmetricCrypto ciphertext-tamper setup threw: \(error)")
    }

    // test_decrypt64ByteCipherKey_pkcs7Unpadded
    do {
        let key = try makeSymCryptoKey()
        let cipherKey = Data((0..<64).map { UInt8(($0 * 7) & 0xff) })
        let enc = try SymmetricCrypto.encrypt(cipherKey, using: key)
        let out = try SymmetricCrypto.decrypt(enc, using: key)
        r.expect(out.count, 64, "SymmetricCrypto 64-byte cipher key length after PKCS#7 unpad")
        r.expect(out, cipherKey, "SymmetricCrypto 64-byte cipher key round-trips")
    } catch {
        r.expectTrue(false, "SymmetricCrypto 64-byte cipher key threw: \(error)")
    }

    // test_type0DecryptionBlocked
    do {
        let key = try makeSymCryptoKey()
        let enc = EncString(type: .aesCbc256_B64, iv: Data(count: 16), ciphertext: Data(count: 16), mac: nil)
        r.expectThrowsError(CryptoError.unsupportedEncStringType(0), "SymmetricCrypto blocks type 0 decryption") {
            _ = try SymmetricCrypto.decrypt(enc, using: key)
        }
    } catch {
        r.expectTrue(false, "SymmetricCrypto type-0 setup threw: \(error)")
    }

    // test_type2MissingIVThrows — a type-2 EncString with no IV is structurally invalid.
    do {
        let enc = EncString(type: .aesCbc256_HmacSha256_B64, iv: nil, ciphertext: Data(count: 16), mac: Data(count: 32))
        let key = try makeSymCryptoKey()
        r.expectThrowsError(CryptoError.invalidEncString, "SymmetricCrypto rejects type-2 with nil iv") {
            _ = try SymmetricCrypto.decrypt(enc, using: key)
        }
    } catch {
        r.expectTrue(false, "SymmetricCrypto nil-iv setup threw: \(error)")
    }

    // test_type2MissingMACThrows — a type-2 EncString with no MAC is structurally invalid.
    do {
        let enc = EncString(type: .aesCbc256_HmacSha256_B64, iv: Data(count: 16), ciphertext: Data(count: 16), mac: nil)
        let key = try makeSymCryptoKey()
        r.expectThrowsError(CryptoError.invalidEncString, "SymmetricCrypto rejects type-2 with nil mac") {
            _ = try SymmetricCrypto.decrypt(enc, using: key)
        }
    } catch {
        r.expectTrue(false, "SymmetricCrypto nil-mac setup threw: \(error)")
    }
}
