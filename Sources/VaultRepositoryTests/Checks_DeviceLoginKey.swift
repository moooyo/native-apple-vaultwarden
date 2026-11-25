import CoreFoundation
import CryptoCore
import Foundation
import Security
import VaultRepository

func checkDeviceLoginKey(_ r: inout TestRunner) {
    do {
        let words = (0..<7_776).map(String.init)
        // The published Bitwarden SDK SPKI fixture, with an email as HKDF info for device approval.
        let knownSPKI = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuyYs8W7NWf0Zv35Ueco93730dtRKi4Jhc6Snar+86drE+ruSfaCWMcbgsAoAj2Pm6KAzaJrTIVCqBERQ23OncpzjfcGAeyf+v3w/gSw/EjihMJ4AG5ICY4hLFYcGdgwa+7is+TVO0i6PEWjKQa3l2+mQo2XY7pg2ngHDMssV4gxSqq+qoBX3+FBhewCYdOV+3cebwsAzz7HwoFTxKViwNW8crbHonhZPhZgfIAzEkzo5MvzQg5azhLKW6vuPfaOQFC5HqPykVnh8OPzO0uzUi3+97CguAu4N2CgwVYXltZuw2fGamdVw3kjbxQPbOE1tL0j7gyTwYKkfUl2m8gMh1QIDAQAB"
        r.expect(try DeviceLoginKey.fingerprint(email: " Alice@Example.Test ", publicKey: knownSPKI, words: words),
                 "1226-1244-5444-356-3814", "device login key: fingerprint uses normalized email and full SPKI")

        let attempt = try DeviceLoginKey()
        let unrelatedAttempt = try DeviceLoginKey()
        defer { attempt.invalidate(); unrelatedAttempt.invalidate() }
        r.expectTrue(attempt.publicKey != unrelatedAttempt.publicKey, "device login key: each attempt has a new public key")
        r.expectTrue(!String(reflecting: attempt).contains(attempt.publicKey), "device login key: reflection is redacted")
        r.expect(try attempt.fingerprint(email: "alice@example.test", words: words),
                 try DeviceLoginKey.fingerprint(email: "ALICE@EXAMPLE.TEST", publicKey: attempt.publicKey, words: words),
                 "device login key: both devices compute the same fingerprint")

        let userKey = try SymmetricCryptoKey(combined: Data(0..<64))
        defer { userKey.erase() }
        let wrapped = try DeviceLoginKey.wrap(userKey, publicKey: attempt.publicKey)
        r.expect(wrapped.type, .rsa2048_OaepSha1_B64, "device login key: wraps in RSA-2048 OAEP SHA-1 format")
        r.expect(wrapped.ciphertext.count, 256, "device login key: expected RSA ciphertext size")
        r.expectDeviceLoginKeyFailure("device login key: a different attempt cannot unwrap the approval") {
            _ = try unrelatedAttempt.unwrap(wrapped)
        }
        let wrongType = EncString(type: .rsa2048_OaepSha256_B64, iv: nil, ciphertext: wrapped.ciphertext, mac: nil)
        r.expectDeviceLoginKeyFailure("device login key: non-type-4 ciphertext is rejected") { _ = try attempt.unwrap(wrongType) }
        let malformedSPKI = (Data(base64Encoded: attempt.publicKey)! + Data([0])).base64EncodedString()
        r.expectDeviceLoginKeyFailure("device login key: trailing data in SPKI is rejected before wrapping") {
            _ = try DeviceLoginKey.wrap(userKey, publicKey: malformedSPKI)
        }

        // OpenVault accepts the 64-byte account key only, not the old 32-byte master-key payload.
        let spki = Data(base64Encoded: attempt.publicKey)!
        let pkcs1 = Data(spki.dropFirst(24)) // RSA-2048 SPKI sequence + algorithm identifier + bit string wrapper.
        let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary
        guard let rsa = SecKeyCreateWithData(pkcs1 as CFData, attributes, nil),
              let wrappedMasterKey = SecKeyCreateEncryptedData(rsa, .rsaEncryptionOAEPSHA1,
                                                               Data(repeating: 0x32, count: 32) as CFData, nil) else {
            r.expectTrue(false, "device login key: prepare short plaintext fixture")
            return
        }
        let shortKey = EncString(type: .rsa2048_OaepSha1_B64, iv: nil, ciphertext: wrappedMasterKey as Data, mac: nil)
        r.expectDeviceLoginKeyFailure("device login key: refuses to interpret a legacy master key as a user key") {
            _ = try attempt.unwrap(shortKey)
        }

        let decrypted = try attempt.unwrap(EncString(parsing: wrapped.stringValue))
        defer { decrypted.erase() }
        r.expectTrue(decrypted == userKey, "device login key: recovers the original 64-byte user key")
        r.expectDeviceLoginKeyFailure("device login key: successful unwrap consumes the private key") { _ = try attempt.unwrap(wrapped) }

        let canceledWire = try DeviceLoginKey.wrap(userKey, publicKey: unrelatedAttempt.publicKey)
        unrelatedAttempt.invalidate()
        r.expectDeviceLoginKeyFailure("device login key: cancellation releases the private key") { _ = try unrelatedAttempt.unwrap(canceledWire) }
    } catch {
        r.expectTrue(false, "device login key: RSA generation and wire round trip completed")
    }
}

private extension TestRunner {
    mutating func expectDeviceLoginKeyFailure(_ name: String, _ operation: () throws -> Void) {
        do { try operation(); expectTrue(false, name) }
        catch { expectTrue(true, name) }
    }
}
