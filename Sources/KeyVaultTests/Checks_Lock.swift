import Foundation
import CryptoCore
import KeyVault

func checkLock(_ r: inout TestRunner) async {
    // test_lockClearsUserKey
    do {
        let key = try makeUserKey()
        let enc = try SymmetricCrypto.encrypt(Data("secret".utf8), using: key)

        let vault = KeyVault()
        let lockedBefore = await vault.isUnlocked
        r.expect(lockedBefore, false, "KeyVault starts locked")

        await vault.unlock(userKey: key)
        let unlocked = await vault.isUnlocked
        r.expect(unlocked, true, "KeyVault isUnlocked true after unlock")

        await vault.lock()
        let lockedAfter = await vault.isUnlocked
        r.expect(lockedAfter, false, "KeyVault isUnlocked false after lock")

        do {
            _ = try await vault.decrypt(enc)
            r.expectTrue(false, "KeyVault.decrypt after lock should throw")
        } catch let e as KeyVaultError {
            r.expect(e, .locked, "KeyVault.decrypt after lock throws .locked")
        }
    } catch {
        r.expectTrue(false, "KeyVault lock setup threw: \(error)")
    }
}
