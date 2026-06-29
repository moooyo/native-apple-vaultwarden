import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import Networking
import VaultRepository

/// createCipher: encrypts via the encryptor, pushes to the (fake) API, and persists the
/// returned row locally. Assert the fake recorded the create request (with a non-empty
/// encrypted name wire string), and that the stored row is retrievable and decrypts back
/// to the original plaintext.
func checkCreateCipher(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    // Log in so the vault is unlocked and an accountID exists.
    do {
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
    } catch { r.expectTrue(false, "createCipher: login threw: \(error)"); return }

    let plaintext = PlaintextCipher(
        type: CipherType.login.rawValue, name: "Example Site", notes: "a note",
        login: PlaintextCipher.Login(username: "bob", password: "hunter2",
                                     uris: [PlaintextCipher.Uri(uri: "https://example.test")])
    )

    var createdID = ""
    do {
        createdID = try await h.vault.createCipher(plaintext)
        r.expectTrue(!createdID.isEmpty, "createCipher: returns a non-empty id")
    } catch {
        r.expectTrue(false, "createCipher threw: \(error)"); return
    }

    // The fake API recorded exactly one create request, and the encrypted name is a real
    // type-2 EncString wire string (NOT the plaintext).
    let created = await h.api.createdRequests
    r.expect(created.count, 1, "createCipher: fake recorded one create")
    if let req = created.first {
        let nameWire = req.name.stringValue
        r.expectTrue(nameWire.hasPrefix("2."), "createCipher: name encrypted as type-2 EncString")
        r.expectTrue(!nameWire.contains("Example Site"), "createCipher: plaintext name NOT in request")
        r.expect(req.type, CipherType.login.rawValue, "createCipher: request type")
        r.expectTrue(req.login?.username != nil, "createCipher: request carries encrypted username")
    }

    // The stored row is retrievable and decrypts back to the original plaintext.
    do {
        let row = try await h.store.cipher(id: createdID)
        r.expectTrue(row != nil, "createCipher: row persisted in store")

        let cipher = try await h.vault.cipher(id: createdID)
        r.expect(cipher.name, "Example Site", "createCipher: round-trip name")
        r.expect(cipher.notes, "a note", "createCipher: round-trip notes")
        r.expect(cipher.login?.username, "bob", "createCipher: round-trip username")
        r.expect(cipher.login?.password, "hunter2", "createCipher: round-trip password")
        r.expect(cipher.login?.uris.first?.uri, "https://example.test", "createCipher: round-trip uri")
    } catch {
        r.expectTrue(false, "createCipher: retrieve/decrypt threw: \(error)")
    }
}

/// createCipher while locked throws `.locked` and does NOT call the API.
func checkCreateCipherLockedFails(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    // Log in (to get an accountID) then lock.
    do {
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
    } catch { r.expectTrue(false, "createCipherLocked: login threw: \(error)"); return }
    await h.vault.lock()

    let plaintext = PlaintextCipher(type: CipherType.login.rawValue, name: "Nope")
    await r.expectThrowsErrorAsync(RepositoryError.locked, "createCipherLocked: throws .locked") {
        _ = try await h.vault.createCipher(plaintext)
    }
    let created = await h.api.createdRequests
    r.expect(created.count, 0, "createCipherLocked: API not called when locked")
}

/// lock(): clears the key — KeyVault.isUnlocked becomes false, the encryptor loses its key,
/// and a subsequent decrypt (cipher read) and createCipher both fail as locked.
func checkLock(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
    } catch { r.expectTrue(false, "lock: login threw: \(error)"); return }

    // Seed a cipher we can read while unlocked.
    let session = await h.auth.session
    guard let accountID = session?.accountID else {
        r.expectTrue(false, "lock: missing accountID"); return
    }
    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "lk-1", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: Fixtures.enc("Locked Test"), searchText: "locked test")
        ])
        // Sanity: readable while unlocked.
        let before = try await h.vault.cipher(id: "lk-1")
        r.expect(before.name, "Locked Test", "lock: readable before lock")
    } catch { r.expectTrue(false, "lock: seed/read threw: \(error)"); return }

    // Lock via the repository.
    await h.vault.lock()

    let unlocked = await h.keyVault.isUnlocked
    r.expectTrue(!unlocked, "lock: KeyVault.isUnlocked false after lock")
    let authUnlocked = await h.auth.isUnlocked()
    r.expectTrue(!authUnlocked, "lock: auth.isUnlocked() false after lock")

    // A subsequent decrypt (cipher read) fails as locked.
    await r.expectThrowsErrorAsync(RepositoryError.locked, "lock: cipher read throws .locked") {
        _ = try await h.vault.cipher(id: "lk-1")
    }

    // A subsequent createCipher fails as locked.
    await r.expectThrowsErrorAsync(RepositoryError.locked, "lock: createCipher throws .locked") {
        _ = try await h.vault.createCipher(PlaintextCipher(type: CipherType.login.rawValue, name: "X"))
    }

    // auth.lock() is the same effect (idempotent + symmetric with vault.lock()).
    await h.auth.lock()
    let stillLocked = await h.keyVault.isUnlocked
    r.expectTrue(!stillLocked, "lock: auth.lock() keeps it locked")
}
