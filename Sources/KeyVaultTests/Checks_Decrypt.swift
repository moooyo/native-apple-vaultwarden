import Foundation
import CryptoCore
import KeyVault

/// Build a deterministic 64-byte user key from known bytes.
func makeUserKey() throws -> SymmetricCryptoKey {
    try SymmetricCryptoKey(combined: Data((0..<64).map { UInt8($0) }))
}

func checkDecrypt(_ r: inout TestRunner) async {
    // test_directUnlock_decryptsWithUserKey
    do {
        let key = try makeUserKey()
        let plaintext = Data("the quick brown fox".utf8)
        let enc = try SymmetricCrypto.encrypt(plaintext, using: key)

        let vault = KeyVault()
        await vault.unlock(userKey: key)
        let out = try await vault.decrypt(enc)
        r.expect(out, plaintext, "KeyVault.decrypt round-trips with user key")

        let strEnc = try SymmetricCrypto.encrypt(Data("hello world".utf8), using: key)
        let s = try await vault.decryptString(strEnc)
        r.expect(s, "hello world", "KeyVault.decryptString round-trips")
    } catch {
        r.expectTrue(false, "KeyVault direct-unlock decrypt threw: \(error)")
    }

    // test_decryptWhileLockedThrows
    do {
        let key = try makeUserKey()
        let enc = try SymmetricCrypto.encrypt(Data("secret".utf8), using: key)
        let vault = KeyVault()
        do {
            _ = try await vault.decrypt(enc)
            r.expectTrue(false, "KeyVault.decrypt while locked should throw")
        } catch let e as KeyVaultError {
            r.expect(e, .locked, "KeyVault.decrypt while locked throws .locked")
        }
    } catch {
        r.expectTrue(false, "KeyVault locked-decrypt setup threw: \(error)")
    }

    // test_cipherKeyFromProtected_roundTrips
    do {
        let userKey = try makeUserKey()
        let cipherKeyData = Data((0..<64).map { UInt8(($0 * 5) & 0xff) })
        let protectedKey = try SymmetricCrypto.encrypt(cipherKeyData, using: userKey)

        let vault = KeyVault()
        await vault.unlock(userKey: userKey)
        let recovered = try await vault.cipherKey(fromProtected: protectedKey)
        let expected = try SymmetricCryptoKey(combined: cipherKeyData)
        r.expect(recovered, expected, "KeyVault.cipherKey(fromProtected:) recovers original cipher key")
    } catch {
        r.expectTrue(false, "KeyVault cipherKey round-trip threw: \(error)")
    }

    // test_cipherKeyWhileLockedThrows
    do {
        let userKey = try makeUserKey()
        let cipherKeyData = Data((0..<64).map { UInt8(($0 * 5) & 0xff) })
        let protectedKey = try SymmetricCrypto.encrypt(cipherKeyData, using: userKey)

        let vault = KeyVault()
        do {
            _ = try await vault.cipherKey(fromProtected: protectedKey)
            r.expectTrue(false, "KeyVault.cipherKey while locked should throw")
        } catch let e as KeyVaultError {
            r.expect(e, .locked, "KeyVault.cipherKey while locked throws .locked")
        }
    } catch {
        r.expectTrue(false, "KeyVault locked-cipherKey setup threw: \(error)")
    }

    // test_cipherKeyNot64Bytes_throwsInvalidUserKey
    do {
        let userKey = try makeUserKey()
        let shortData = Data((0..<32).map { UInt8($0) })
        let protectedKey = try SymmetricCrypto.encrypt(shortData, using: userKey)

        let vault = KeyVault()
        await vault.unlock(userKey: userKey)
        do {
            _ = try await vault.cipherKey(fromProtected: protectedKey)
            r.expectTrue(false, "KeyVault.cipherKey with non-64-byte payload should throw")
        } catch let e as KeyVaultError {
            r.expect(e, .invalidUserKey, "KeyVault.cipherKey non-64-byte payload throws .invalidUserKey")
        }
    } catch {
        r.expectTrue(false, "KeyVault cipherKey invalid-length setup threw: \(error)")
    }

    // test_twoLevelDecrypt_perCipherKeyVsUserKey
    do {
        let userKey = try makeUserKey()
        let cipherKeyData = Data((0..<64).map { UInt8(($0 * 5) & 0xff) })
        let cipherKey = try SymmetricCryptoKey(combined: cipherKeyData)
        let protectedKey = try SymmetricCrypto.encrypt(cipherKeyData, using: userKey)

        // Field is encrypted under the PER-CIPHER key, not the user key.
        let field = try SymmetricCrypto.encrypt(Data("field secret".utf8), using: cipherKey)

        let vault = KeyVault()
        await vault.unlock(userKey: userKey)
        let recoveredCipherKey = try await vault.cipherKey(fromProtected: protectedKey)

        // Decrypts when the per-cipher key is supplied.
        let withCipherKey = try await vault.decrypt(field, cipherKey: recoveredCipherKey)
        r.expect(withCipherKey, Data("field secret".utf8), "KeyVault.decrypt(_:cipherKey:) uses per-cipher key")

        // Same field FAILS (macMismatch) under the user key (cipherKey: nil) — proves two-level path.
        do {
            _ = try await vault.decrypt(field, cipherKey: nil)
            r.expectTrue(false, "KeyVault.decrypt under user key should fail for cipher-key field")
        } catch let e as CryptoError {
            r.expect(e, .macMismatch, "KeyVault per-cipher field rejected by user key (macMismatch)")
        }
    } catch {
        r.expectTrue(false, "KeyVault two-level decrypt setup threw: \(error)")
    }
}
