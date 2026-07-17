import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import KeychainBridge
import VaultReader
import AppShared

/// `unlockWithBiometrics` recovers the SE-wrapped UserKey via the Keychain and unlocks the
/// KeyVault — after which a single cipher decrypts. A KeyVault that starts locked rejects
/// decryption until this runs.
func checkBiometricUnlock(_ r: inout TestRunner) async {
    let (store, dir): (VaultStore, URL)
    do { (store, dir) = try await Fixtures.freshStore() }
    catch { r.expectTrue(false, "freshStore threw: \(error)"); return }
    defer { Fixtures.cleanup(dir) }

    do {
        try await store.upsertCiphers([
            Fixtures.loginRow(id: "login-1", name: "GitHub", username: "octocat", password: "s3cr3t!"),
        ])
    } catch {
        r.expectTrue(false, "seed upsert threw: \(error)"); return
    }

    // A keychain that already has biometric unlock enabled for the synthetic user key.
    let keychain = makeFakeKeychain(
        secureEnclave: InMemorySecureEnclaveKeyStore(),
        itemStore: InMemoryKeychainItemStore()
    )
    do {
        try await keychain.enableBiometricUnlock(userKey: Fixtures.userKey())
    } catch {
        r.expectTrue(false, "enableBiometricUnlock threw: \(error)"); return
    }

    let keyVault = KeyVault()   // starts locked
    let reader = VaultReader(store: store, keyVault: keyVault, keychain: keychain)

    // Before unlock: decryption is rejected.
    await r.expectThrowsErrorAsync(VaultReaderError.locked, "pre-unlock decrypt → locked") {
        _ = try await reader.passwordCredential(for: "login-1")
    }

    // Unlock via biometrics → KeyVault holds the recovered key.
    do {
        try await reader.unlockWithBiometrics(reason: "Unlock Tessera")
    } catch {
        r.expectTrue(false, "unlockWithBiometrics threw: \(error)"); return
    }
    let unlocked = await keyVault.isUnlocked
    r.expectTrue(unlocked, "KeyVault unlocked after biometrics")

    // After unlock: the credential decrypts.
    do {
        let (user, password) = try await reader.passwordCredential(for: "login-1")
        r.expect(user, "octocat", "post-unlock user")
        r.expect(password, "s3cr3t!", "post-unlock password")
    } catch {
        r.expectTrue(false, "post-unlock passwordCredential threw: \(error)")
    }

    // Main-app lock/login/restore rotates this nonce. Even when the account id returns
    // to the same value (A -> B -> A), the old extension key lease must fail closed.
    do {
        try await keychain.setSecret(
            Data("rotated-session".utf8),
            account: AppShared.KeychainAccount.activeSessionID,
            biometryGated: false
        )
    } catch {
        r.expectTrue(false, "session rotation fixture threw: \(error)")
    }
    await r.expectThrowsErrorAsync(
        VaultReaderError.notFound,
        "rotated session nonce rejects already-unlocked extension"
    ) {
        _ = try await reader.passwordCredential(for: "login-1")
    }
    r.expectTrue(!(await keyVault.isUnlocked),
                 "session nonce mismatch clears stale extension key")
}

/// When biometric unlock was never enabled, `unlockWithBiometrics` surfaces the keychain
/// error (`.notFound`) and leaves the vault locked.
func checkBiometricUnlockNotEnabled(_ r: inout TestRunner) async {
    let (store, dir): (VaultStore, URL)
    do { (store, dir) = try await Fixtures.freshStore() }
    catch { r.expectTrue(false, "freshStore threw: \(error)"); return }
    defer { Fixtures.cleanup(dir) }

    let keyVault = KeyVault()
    let reader = VaultReader(store: store, keyVault: keyVault, keychain: makeFakeKeychain())

    await r.expectThrowsAsync("unlockWithBiometrics (not enabled) throws") {
        try await reader.unlockWithBiometrics(reason: "Unlock Tessera")
    }
    let stillLocked = await !keyVault.isUnlocked
    r.expectTrue(stillLocked, "KeyVault stays locked when biometrics unavailable")
}
