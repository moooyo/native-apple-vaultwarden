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
}
