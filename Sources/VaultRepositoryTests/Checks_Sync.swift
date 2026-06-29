import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import KeychainBridge
import Networking
import SyncEngine
import VaultRepository

// MARK: - Shared setup

/// Make a harness and log in (vault unlocked, accountID available). Returns the harness +
/// the resolved accountID, or `nil` after recording a failure on `r`.
private func loggedInHarness(_ r: inout TestRunner) async -> (Fixtures.Harness, String)? {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "makeHarness threw: \(error)"); return nil }
    do {
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
    } catch { r.expectTrue(false, "login threw: \(error)"); Fixtures.cleanup(h.dir); return nil }
    guard let id = await h.auth.session?.accountID else {
        r.expectTrue(false, "missing accountID after login"); Fixtures.cleanup(h.dir); return nil
    }
    return (h, id)
}

// MARK: - Offline outbox paths

/// createCipher offline (`.serverUnreachable`): enqueues an OutboxOp.create row in the REAL
/// VaultStore AND persists an optimistic local cipher row that decrypts back to plaintext.
func checkCreateCipherOffline(_ r: inout TestRunner) async {
    guard let (h, _) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    await h.api.setCreateError(NetworkingError.serverUnreachable)

    let plaintext = PlaintextCipher(
        type: CipherType.login.rawValue, name: "Offline Item", notes: "offline note",
        login: PlaintextCipher.Login(username: "carol", password: "p@ss",
                                     uris: [PlaintextCipher.Uri(uri: "https://offline.test")])
    )

    var localID = ""
    do {
        localID = try await h.vault.createCipher(plaintext)
        r.expectTrue(!localID.isEmpty, "createOffline: returns a local id")
    } catch {
        r.expectTrue(false, "createOffline: createCipher threw: \(error)"); return
    }

    // (a) An OutboxRow was enqueued (op=create, entity=cipher, entityID=localID).
    do {
        let outbox = try await h.store.outbox()
        r.expect(outbox.count, 1, "createOffline: one outbox row enqueued")
        if let row = outbox.first {
            r.expect(row.opType, OutboxOp.create.rawValue, "createOffline: outbox op=create")
            r.expect(row.entityType, OutboxEntity.cipher.rawValue, "createOffline: outbox entity=cipher")
            r.expect(row.entityID, localID, "createOffline: outbox entityID=localID")
            r.expectTrue(!row.payloadJSON.isEmpty && row.payloadJSON != "{}",
                         "createOffline: outbox payload non-trivial")
        }
    } catch { r.expectTrue(false, "createOffline: outbox() threw: \(error)") }

    // (b) The optimistic local row is retrievable and decrypts to the plaintext.
    do {
        let row = try await h.store.cipher(id: localID)
        r.expectTrue(row != nil, "createOffline: local row persisted")
        let cipher = try await h.vault.cipher(id: localID)
        r.expect(cipher.name, "Offline Item", "createOffline: local row name decrypts")
        r.expect(cipher.notes, "offline note", "createOffline: local row notes decrypt")
        r.expect(cipher.login?.username, "carol", "createOffline: local row username decrypts")
        r.expect(cipher.login?.password, "p@ss", "createOffline: local row password decrypts")
        r.expect(cipher.login?.uris.first?.uri, "https://offline.test", "createOffline: local row uri decrypts")
    } catch { r.expectTrue(false, "createOffline: local row retrieve/decrypt threw: \(error)") }
}

/// updateCipher offline: enqueues an OutboxOp.update row and persists the optimistic local row.
func checkUpdateCipherOffline(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    // Seed an existing row to update.
    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "upd-1", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: Fixtures.enc("Before"), searchText: "before")
        ])
    } catch { r.expectTrue(false, "updateOffline: seed threw: \(error)"); return }

    await h.api.setUpdateError(NetworkingError.serverUnreachable)

    let updated = PlaintextCipher(id: "upd-1", type: CipherType.login.rawValue, name: "After Offline",
                                  login: PlaintextCipher.Login(username: "dave"))
    do {
        try await h.vault.updateCipher(id: "upd-1", updated)
    } catch { r.expectTrue(false, "updateOffline: updateCipher threw: \(error)"); return }

    // Outbox enqueued with op=update, entityID=upd-1.
    do {
        let outbox = try await h.store.outbox()
        r.expect(outbox.count, 1, "updateOffline: one outbox row enqueued")
        if let row = outbox.first {
            r.expect(row.opType, OutboxOp.update.rawValue, "updateOffline: outbox op=update")
            r.expect(row.entityID, "upd-1", "updateOffline: outbox entityID")
        }
    } catch { r.expectTrue(false, "updateOffline: outbox() threw: \(error)") }

    // Optimistic local row reflects the new plaintext.
    do {
        let cipher = try await h.vault.cipher(id: "upd-1")
        r.expect(cipher.name, "After Offline", "updateOffline: local row updated name decrypts")
        r.expect(cipher.login?.username, "dave", "updateOffline: local row updated username decrypts")
    } catch { r.expectTrue(false, "updateOffline: local row decrypt threw: \(error)") }
}

/// deleteCipher offline: enqueues an OutboxOp.delete row and removes the local row.
func checkDeleteCipherOffline(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "del-1", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: Fixtures.enc("Doomed"), searchText: "doomed")
        ])
    } catch { r.expectTrue(false, "deleteOffline: seed threw: \(error)"); return }

    await h.api.setDeleteError(NetworkingError.serverUnreachable)

    do {
        try await h.vault.deleteCipher(id: "del-1")
    } catch { r.expectTrue(false, "deleteOffline: deleteCipher threw: \(error)"); return }

    // Outbox enqueued with op=delete, entityID=del-1.
    do {
        let outbox = try await h.store.outbox()
        r.expect(outbox.count, 1, "deleteOffline: one outbox row enqueued")
        if let row = outbox.first {
            r.expect(row.opType, OutboxOp.delete.rawValue, "deleteOffline: outbox op=delete")
            r.expect(row.entityID, "del-1", "deleteOffline: outbox entityID")
        }
    } catch { r.expectTrue(false, "deleteOffline: outbox() threw: \(error)") }

    // The local row is removed (best-effort delete after enqueue).
    do {
        let row = try await h.store.cipher(id: "del-1")
        r.expectTrue(row == nil, "deleteOffline: local row removed")
    } catch { r.expectTrue(false, "deleteOffline: cipher() threw: \(error)") }
}

// MARK: - Online update / delete round-trips

/// updateCipher online: encrypts + calls the fake API update + updates the store; the stored
/// row reflects the new plaintext and NO outbox row is enqueued.
func checkUpdateCipherOnline(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "u-1", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: Fixtures.enc("Old Name"), searchText: "old name")
        ])
    } catch { r.expectTrue(false, "updateOnline: seed threw: \(error)"); return }

    let updated = PlaintextCipher(id: "u-1", type: CipherType.login.rawValue, name: "New Name",
                                  login: PlaintextCipher.Login(username: "erin", password: "newpw"))
    do {
        try await h.vault.updateCipher(id: "u-1", updated)
    } catch { r.expectTrue(false, "updateOnline: updateCipher threw: \(error)"); return }

    // Fake API recorded the update with an encrypted (type-2) name.
    let updates = await h.api.updatedRequests
    r.expect(updates.count, 1, "updateOnline: fake recorded one update")
    if let u = updates.first {
        r.expect(u.id, "u-1", "updateOnline: update id forwarded")
        r.expectTrue(u.req.name.stringValue.hasPrefix("2."), "updateOnline: name encrypted as type-2")
        r.expectTrue(!u.req.name.stringValue.contains("New Name"), "updateOnline: plaintext name NOT in request")
    }

    // Store updated; no outbox row.
    do {
        let cipher = try await h.vault.cipher(id: "u-1")
        r.expect(cipher.name, "New Name", "updateOnline: store reflects new name")
        r.expect(cipher.login?.username, "erin", "updateOnline: store reflects new username")
        let outbox = try await h.store.outbox()
        r.expect(outbox.count, 0, "updateOnline: no outbox row enqueued")
    } catch { r.expectTrue(false, "updateOnline: verify threw: \(error)") }
}

/// deleteCipher online: calls the fake API delete + removes the local row; no outbox row.
func checkDeleteCipherOnline(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "d-1", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: Fixtures.enc("Gone Soon"), searchText: "gone soon")
        ])
    } catch { r.expectTrue(false, "deleteOnline: seed threw: \(error)"); return }

    do {
        try await h.vault.deleteCipher(id: "d-1")
    } catch { r.expectTrue(false, "deleteOnline: deleteCipher threw: \(error)"); return }

    // Fake API recorded the delete.
    let deleted = await h.api.deletedIDs
    r.expect(deleted, ["d-1"], "deleteOnline: fake recorded the delete id")

    // Local row removed; no outbox row.
    do {
        let row = try await h.store.cipher(id: "d-1")
        r.expectTrue(row == nil, "deleteOnline: local row removed")
        let outbox = try await h.store.outbox()
        r.expect(outbox.count, 0, "deleteOnline: no outbox row enqueued")
    } catch { r.expectTrue(false, "deleteOnline: verify threw: \(error)") }
}

// MARK: - refresh()

/// refresh(): a queued refresh response → the new access token is set and refresh() returns true.
func checkRefreshSuccess(_ r: inout TestRunner) async {
    guard let (h, _) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    // login persisted refresh token "refresh-1" in the keychain. Queue a new token response.
    let newToken = Fixtures.tokenResponse(accessToken: "access-2", refreshToken: "refresh-2")
    await h.api.setRefreshResponse(newToken)

    do {
        let ok = try await h.auth.refresh()
        r.expectTrue(ok, "refresh: returns true on success")
    } catch { r.expectTrue(false, "refresh: threw: \(error)"); return }

    let tokens = await h.api.accessTokensSet
    r.expectTrue(tokens.contains("access-2"), "refresh: new access token set on API client")
}

/// refresh() with a failing API (no refresh response queued → fake throws .unauthorized):
/// the source wraps it as RepositoryError.network and THROWS (it does not return false).
func checkRefreshFailureThrows(_ r: inout TestRunner) async {
    guard let (h, _) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    // No refreshResponse queued → FakeAPI.refresh throws NetworkingError.unauthorized,
    // which AuthRepository.refresh() wraps as RepositoryError.network(...). The `network`
    // factory is internal, so reconstruct the equivalent public `.underlying` value (kind
    // .network, description = String(describing: the wrapped error)).
    let expected = RepositoryError.underlying(kind: .network,
                                              description: String(describing: NetworkingError.unauthorized))
    await r.expectThrowsErrorAsync(expected, "refresh: failing API throws RepositoryError.network") {
        _ = try await h.auth.refresh()
    }
}

/// refresh() with no stored refresh token throws .notAuthenticated (logout cleared it).
func checkRefreshNoTokenThrows(_ r: inout TestRunner) async {
    guard let (h, _) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    await h.auth.logout()  // deletes the stored refresh token

    await r.expectThrowsErrorAsync(RepositoryError.notAuthenticated,
                                   "refresh: no stored token throws .notAuthenticated") {
        _ = try await h.auth.refresh()
    }
}

// MARK: - logout()

/// logout(): locks the KeyVault + encryptor, clears the session, drops the bearer token, and
/// deletes the stored secrets — so a subsequent master-password unlock cannot run (no session)
/// and the vault stays locked.
func checkLogout(_ r: inout TestRunner) async {
    guard let (h, _) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    // Sanity: unlocked + has session before logout.
    let unlockedBefore = await h.keyVault.isUnlocked
    r.expectTrue(unlockedBefore, "logout: unlocked before")

    await h.auth.logout()

    // KeyVault + encryptor cleared.
    let unlockedAfter = await h.keyVault.isUnlocked
    r.expectTrue(!unlockedAfter, "logout: KeyVault locked after logout")
    let authUnlocked = await h.auth.isUnlocked()
    r.expectTrue(!authUnlocked, "logout: auth.isUnlocked() false after logout")

    // Session cleared.
    let session = await h.auth.session
    r.expectTrue(session == nil, "logout: session cleared")

    // Bearer token dropped (nil pushed to the API client).
    let tokens = await h.api.accessTokensSet
    r.expectTrue(tokens.last == .some(nil), "logout: bearer token cleared (nil set)")

    // Stored secrets deleted: the refresh token is gone (refresh now fails as notAuthenticated),
    // and master-password unlock can't run because the session is gone.
    await r.expectThrowsErrorAsync(RepositoryError.notAuthenticated,
                                   "logout: refresh after logout throws .notAuthenticated (token deleted)") {
        _ = try await h.auth.refresh()
    }
    await r.expectThrowsErrorAsync(RepositoryError.notAuthenticated,
                                   "logout: unlockWithMasterPassword after logout throws .notAuthenticated") {
        try await h.auth.unlockWithMasterPassword(Fixtures.password)
    }
}
