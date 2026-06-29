import Foundation
import CryptoCore
import KeyVault

func checkUnlock(_ r: inout TestRunner) async {
    // Verified golden vector from the CryptoCore plan.
    let email = "user@example.com"
    let password = "Password123!"
    let iterations = 5000

    // test_masterPasswordUnlock_endToEnd
    do {
        // Derive masterKey -> stretch -> wrap a synthetic 64-byte user key.
        let masterKey = try KDF.deriveMasterKey(password: password, email: email, iterations: iterations)
        let stretched = KeyStretch.stretchMasterKey(masterKey)
        let userKeyData = Data((0..<64).map { UInt8(($0 * 3) & 0xff) })
        let protectedUserKey = try SymmetricCrypto.encrypt(userKeyData, using: stretched)

        let vault = KeyVault()
        try await vault.unlock(password: password, email: email,
                               iterations: iterations, protectedUserKey: protectedUserKey)
        let unlocked = await vault.isUnlocked
        r.expect(unlocked, true, "KeyVault master-password unlock -> isUnlocked")

        // Decrypt a field encrypted under the synthetic user key.
        let userKey = try SymmetricCryptoKey(combined: userKeyData)
        let field = try SymmetricCrypto.encrypt(Data("secret value".utf8), using: userKey)
        let out = try await vault.decrypt(field)
        r.expect(out, Data("secret value".utf8), "KeyVault master-password unlock decrypts field")
    } catch {
        r.expectTrue(false, "KeyVault master-password unlock threw: \(error)")
    }

    // test_wrongPassword_throwsUnlockFailed
    do {
        let masterKey = try KDF.deriveMasterKey(password: password, email: email, iterations: iterations)
        let stretched = KeyStretch.stretchMasterKey(masterKey)
        let userKeyData = Data((0..<64).map { UInt8(($0 * 3) & 0xff) })
        let protectedUserKey = try SymmetricCrypto.encrypt(userKeyData, using: stretched)

        let vault = KeyVault()
        do {
            try await vault.unlock(password: "wrong", email: email,
                                   iterations: iterations, protectedUserKey: protectedUserKey)
            r.expectTrue(false, "KeyVault wrong-password unlock should throw")
        } catch let e as KeyVaultError {
            r.expect(e, .unlockFailed, "KeyVault wrong password throws .unlockFailed")
        }
        let stillLocked = await vault.isUnlocked
        r.expect(stillLocked, false, "KeyVault stays locked after wrong password")
    } catch {
        r.expectTrue(false, "KeyVault wrong-password setup threw: \(error)")
    }

    // test_userKeyNot64Bytes_throwsInvalidUserKey
    do {
        let masterKey = try KDF.deriveMasterKey(password: password, email: email, iterations: iterations)
        let stretched = KeyStretch.stretchMasterKey(masterKey)
        // Wrap a 32-byte payload (decrypts cleanly, but is not a valid 64-byte user key).
        let shortData = Data((0..<32).map { UInt8($0) })
        let protectedUserKey = try SymmetricCrypto.encrypt(shortData, using: stretched)

        let vault = KeyVault()
        do {
            try await vault.unlock(password: password, email: email,
                                   iterations: iterations, protectedUserKey: protectedUserKey)
            r.expectTrue(false, "KeyVault non-64-byte user key should throw")
        } catch let e as KeyVaultError {
            r.expect(e, .invalidUserKey, "KeyVault non-64-byte user key throws .invalidUserKey")
        }
    } catch {
        r.expectTrue(false, "KeyVault invalid-user-key setup threw: \(error)")
    }
}
