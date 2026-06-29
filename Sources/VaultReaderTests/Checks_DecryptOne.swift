import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import VaultReader

/// `decryptOneCipher` returns the decrypted name + login fields for ONE cipher.
func checkDecryptOneCipher(_ r: inout TestRunner) async {
    let (store, dir): (VaultStore, URL)
    do { (store, dir) = try await Fixtures.freshStore() }
    catch { r.expectTrue(false, "freshStore threw: \(error)"); return }
    defer { Fixtures.cleanup(dir) }

    do {
        try await store.upsertCiphers([
            Fixtures.loginRow(id: "login-1", name: "GitHub", username: "octocat",
                              password: "s3cr3t!", totp: "JBSWY3DPEHPK3PXP",
                              uris: ["https://github.com", "https://gist.github.com"]),
            Fixtures.secureNoteRow(id: "note-1", name: "My note"),
        ])
    } catch {
        r.expectTrue(false, "seed upsert threw: \(error)"); return
    }

    let keyVault = await Fixtures.unlockedVault()
    let reader = VaultReader(store: store, keyVault: keyVault, keychain: makeFakeKeychain())

    do {
        let cipher = try await reader.decryptOneCipher(id: "login-1")
        r.expect(cipher.id, "login-1", "decryptOne id")
        r.expect(cipher.type, CipherType.login.rawValue, "decryptOne type")
        r.expect(cipher.name, "GitHub", "decryptOne name")
        r.expect(cipher.username, "octocat", "decryptOne username")
        r.expect(cipher.password, "s3cr3t!", "decryptOne password")
        r.expect(cipher.totp, "JBSWY3DPEHPK3PXP", "decryptOne totp")
        r.expect(cipher.uris, ["https://github.com", "https://gist.github.com"], "decryptOne uris")
    } catch {
        r.expectTrue(false, "decryptOneCipher(login-1) threw: \(error)")
    }

    // A non-login decrypts name only (no login fields).
    do {
        let cipher = try await reader.decryptOneCipher(id: "note-1")
        r.expect(cipher.name, "My note", "decryptOne note name")
        r.expect(cipher.username, nil, "decryptOne note username nil")
        r.expect(cipher.password, nil, "decryptOne note password nil")
        r.expect(cipher.uris, [], "decryptOne note uris empty")
    } catch {
        r.expectTrue(false, "decryptOneCipher(note-1) threw: \(error)")
    }

    // Missing → .notFound.
    await r.expectThrowsErrorAsync(VaultReaderError.notFound, "decryptOne missing → notFound") {
        _ = try await reader.decryptOneCipher(id: "nope")
    }

    // Locked → .locked.
    let lockedReader = VaultReader(store: store, keyVault: Fixtures.lockedVault(),
                                   keychain: makeFakeKeychain())
    await r.expectThrowsErrorAsync(VaultReaderError.locked, "decryptOne locked → locked") {
        _ = try await lockedReader.decryptOneCipher(id: "login-1")
    }
}
