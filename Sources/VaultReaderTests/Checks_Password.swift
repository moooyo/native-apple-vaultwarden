import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import KeychainBridge
import VaultReader

/// `passwordCredential` happy path + the per-cipher-key path + the error paths.
func checkPasswordCredential(_ r: inout TestRunner) async {
    let (store, dir): (VaultStore, URL)
    do { (store, dir) = try await Fixtures.freshStore() }
    catch { r.expectTrue(false, "freshStore threw: \(error)"); return }
    defer { Fixtures.cleanup(dir) }

    do {
        try await store.upsertCiphers([
            Fixtures.loginRow(id: "login-1", name: "GitHub", username: "octocat",
                              password: "s3cr3t!", uris: ["https://github.com"]),
            Fixtures.loginRowWithCipherKey(id: "login-2", name: "GitLab",
                                           username: "tanuki", password: "p@ss"),
            Fixtures.secureNoteRow(id: "note-1", name: "My note"),
        ])
    } catch {
        r.expectTrue(false, "seed upsert threw: \(error)"); return
    }

    let keyVault = await Fixtures.unlockedVault()
    let reader = VaultReader(store: store,
                             keyVault: keyVault,
                             keychain: makeFakeKeychain())

    // Happy path: user-key-encrypted login.
    do {
        let (user, password) = try await reader.passwordCredential(for: "login-1")
        r.expect(user, "octocat", "passwordCredential user")
        r.expect(password, "s3cr3t!", "passwordCredential password")
    } catch {
        r.expectTrue(false, "passwordCredential(login-1) threw: \(error)")
    }

    // Per-cipher-key path: fields encrypted under a wrapped per-cipher key.
    do {
        let (user, password) = try await reader.passwordCredential(for: "login-2")
        r.expect(user, "tanuki", "passwordCredential (per-cipher key) user")
        r.expect(password, "p@ss", "passwordCredential (per-cipher key) password")
    } catch {
        r.expectTrue(false, "passwordCredential(login-2) threw: \(error)")
    }

    // Not found → .notFound.
    await r.expectThrowsErrorAsync(VaultReaderError.notFound, "passwordCredential missing → notFound") {
        _ = try await reader.passwordCredential(for: "does-not-exist")
    }

    // Non-login (secure note) → .noPasswordField.
    await r.expectThrowsErrorAsync(VaultReaderError.noPasswordField,
                                   "passwordCredential on non-login → noPasswordField") {
        _ = try await reader.passwordCredential(for: "note-1")
    }
}

/// A locked vault rejects all password decryption with `.locked`.
func checkPasswordLocked(_ r: inout TestRunner) async {
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

    let reader = VaultReader(store: store,
                             keyVault: Fixtures.lockedVault(),
                             keychain: makeFakeKeychain())

    await r.expectThrowsErrorAsync(VaultReaderError.locked, "passwordCredential locked → locked") {
        _ = try await reader.passwordCredential(for: "login-1")
    }
}
