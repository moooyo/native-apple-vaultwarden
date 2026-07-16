import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import KeychainBridge
import Networking
import SyncEngine
import VaultRepository
import AppShared

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
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
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
            r.expect(row.accountID, accountID, "createOffline: outbox account scoped")
            r.expect(row.opType, OutboxOp.create.rawValue, "createOffline: outbox op=create")
            r.expect(row.entityType, OutboxEntity.cipher.rawValue, "createOffline: outbox entity=cipher")
            r.expect(row.entityID, localID, "createOffline: outbox entityID=localID")
            r.expectTrue(!row.payloadJSON.isEmpty && row.payloadJSON != "{}",
                         "createOffline: outbox payload non-trivial")
            let payload = try OutboxCipherPayload.decode(row.payloadJSON)
            r.expect(try EncString(parsing: payload.name).type,
                     EncryptionType.aesCbc256_HmacSha256_B64,
                     "createOffline: queued payload uses decryptable type-2 encryption")
        }
    } catch { r.expectTrue(false, "createOffline: outbox() threw: \(error)") }

    // (b) The optimistic local row is retrievable and decrypts to the plaintext.
    do {
        let row = try await h.store.cipher(id: localID, accountID: accountID)
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
            r.expect(row.accountID, accountID, "updateOffline: outbox account scoped")
            r.expect(row.opType, OutboxOp.update.rawValue, "updateOffline: outbox op=update")
            r.expect(row.entityID, "upd-1", "updateOffline: outbox entityID")
            let payload = try OutboxCipherPayload.decode(row.payloadJSON)
            r.expect(try EncString(parsing: payload.name).type,
                     EncryptionType.aesCbc256_HmacSha256_B64,
                     "updateOffline: queued payload uses decryptable type-2 encryption")
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
            r.expect(row.accountID, accountID, "deleteOffline: outbox account scoped")
            r.expect(row.opType, OutboxOp.delete.rawValue, "deleteOffline: outbox op=delete")
            r.expect(row.entityID, "del-1", "deleteOffline: outbox entityID")
        }
    } catch { r.expectTrue(false, "deleteOffline: outbox() threw: \(error)") }

    // The local row is removed (best-effort delete after enqueue).
    do {
        let row = try await h.store.cipher(id: "del-1", accountID: accountID)
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

/// A personal item with a protected per-cipher key must keep that key and encrypt edited
/// fields with the unwrapped cipher key on the online request + server echo round-trip.
func checkPersonalCipherKeyUpdateOnline(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    let protectedKey = Fixtures.protectedCipherKey()

    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "key-online", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: Fixtures.cipherEnc("Before"),
                      encBlob: blobJSON(username: Fixtures.cipherEnc("alice"),
                                        password: Fixtures.cipherEnc("old")),
                      encCipherKey: protectedKey.stringValue, searchText: "before")
        ])
        var edited = try await h.vault.cipher(id: "key-online")
        r.expect(edited.protectedCipherKey, protectedKey,
                 "itemKey online: read exposes protected key metadata")
        edited.name = "After"
        edited.login?.password = "new"
        try await h.vault.updateCipher(id: "key-online", edited)

        guard let request = await h.api.updatedRequests.first?.req else {
            r.expectTrue(false, "itemKey online: update request recorded"); return
        }
        r.expect(request.key, protectedKey, "itemKey online: request preserves protected key")
        let requestName = try SymmetricCrypto.decrypt(request.name, using: Fixtures.cipherKey())
        r.expect(String(data: requestName, encoding: .utf8), "After",
                 "itemKey online: request fields use cipher key")

        let stored = try await h.store.cipher(id: "key-online", accountID: accountID)
        r.expect(stored?.encCipherKey, protectedKey.stringValue,
                 "itemKey online: server echo row preserves protected key")
        let roundTrip = try await h.vault.cipher(id: "key-online")
        r.expect(roundTrip.name, "After", "itemKey online: updated name decrypts")
        r.expect(roundTrip.login?.password, "new", "itemKey online: updated password decrypts")
    } catch {
        r.expectTrue(false, "itemKey online: round-trip threw: \(error)")
    }
}

/// The optimistic offline row and serialized outbox payload must preserve the same protected
/// key, so the local edit remains readable and a later flush sends correctly keyed ciphertext.
func checkPersonalCipherKeyUpdateOffline(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    let protectedKey = Fixtures.protectedCipherKey()

    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "key-offline", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: Fixtures.cipherEnc("Before"),
                      encBlob: blobJSON(username: Fixtures.cipherEnc("bob")),
                      encCipherKey: protectedKey.stringValue, searchText: "before")
        ])
        await h.api.setUpdateError(NetworkingError.serverUnreachable)
        var edited = try await h.vault.cipher(id: "key-offline")
        edited.name = "After Offline"
        edited.login?.username = "robert"
        try await h.vault.updateCipher(id: "key-offline", edited)

        let stored = try await h.store.cipher(id: "key-offline", accountID: accountID)
        r.expect(stored?.encCipherKey, protectedKey.stringValue,
                 "itemKey offline: optimistic row preserves protected key")
        let roundTrip = try await h.vault.cipher(id: "key-offline")
        r.expect(roundTrip.name, "After Offline", "itemKey offline: updated name decrypts")
        r.expect(roundTrip.login?.username, "robert",
                 "itemKey offline: updated username decrypts")

        guard let outbox = try await h.store.outbox().first else {
            r.expectTrue(false, "itemKey offline: outbox row exists"); return
        }
        let payload = try JSONDecoder().decode(OutboxCipherPayload.self,
                                               from: Data(outbox.payloadJSON.utf8))
        r.expect(payload.key, protectedKey.stringValue,
                 "itemKey offline: outbox preserves protected key")
        let queuedName = try EncString(parsing: payload.name)
        let queuedPlaintext = try SymmetricCrypto.decrypt(queuedName, using: Fixtures.cipherKey())
        r.expect(String(data: queuedPlaintext, encoding: .utf8), "After Offline",
                 "itemKey offline: queued fields use cipher key")
    } catch {
        r.expectTrue(false, "itemKey offline: round-trip threw: \(error)")
    }
}

/// Until organization keys are represented in `KeyVault`, never fall back to the personal
/// user key for an organization item: reject before the API or local row can be changed.
func checkOrganizationUpdateWithoutKeyIsRejected(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    let originalNameWire = Fixtures.enc("Organization Item")
    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "org-no-key", accountID: accountID,
                      type: CipherType.login.rawValue, organizationID: "org-1",
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: originalNameWire, searchText: "organization item")
        ])
    } catch {
        r.expectTrue(false, "organization key guard: seed threw: \(error)"); return
    }

    let edited = PlaintextCipher(id: "org-no-key", type: CipherType.login.rawValue,
                                 name: "Must Not Write", organizationID: "org-1",
                                 login: .init(username: "alice"))
    await r.expectThrowsErrorAsync(
        RepositoryError.organizationCipherKeyUnavailable,
        "organization key guard: missing key is rejected"
    ) {
        try await h.vault.updateCipher(id: "org-no-key", edited)
    }
    r.expect((await h.api.updatedRequests).count, 0,
             "organization key guard: API update not called")
    do {
        r.expect((try await h.store.cipher(id: "org-no-key", accountID: accountID))?.encName,
                 originalNameWire,
                 "organization key guard: local row unchanged")
    } catch {
        r.expectTrue(false, "organization key guard: verify row threw: \(error)")
    }
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
        let row = try await h.store.cipher(id: "d-1", accountID: accountID)
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

/// Refresh tokens are namespaced by canonical account id. Switching servers must never send
/// the previous account's token to the newly selected environment.
func checkRefreshTokenIsAccountScoped(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            .success(Fixtures.tokenResponse(accessToken: "access-a", refreshToken: "refresh-a")),
            .success(Fixtures.tokenResponse(accessToken: "access-b", refreshToken: "refresh-b")),
        ])
    } catch { r.expectTrue(false, "scoped refresh: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    let serverB = ServerEnvironment(string: "https://other.example.test")!
    do {
        _ = try await h.auth.login(
            email: Fixtures.email,
            password: Fixtures.password,
            server: Fixtures.server
        )
        let accountA = await h.auth.session!.accountID
        _ = try await h.auth.login(
            email: Fixtures.email,
            password: Fixtures.password,
            server: serverB
        )
        let accountB = await h.auth.session!.accountID

        let storedA = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.refreshToken(accountID: accountA)
        )
        let storedB = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.refreshToken(accountID: accountB)
        )
        r.expect(String(data: storedA ?? Data(), encoding: .utf8), "refresh-a",
                 "scoped refresh: account A token remains in A namespace")
        r.expect(String(data: storedB ?? Data(), encoding: .utf8), "refresh-b",
                 "scoped refresh: account B token is in B namespace")

        await h.api.setRefreshResponse(
            Fixtures.tokenResponse(accessToken: "access-b2", refreshToken: "refresh-b2")
        )
        _ = try await h.auth.refresh()
        r.expect(await h.api.refreshTokensUsed.last, "refresh-b",
                 "scoped refresh: active B environment receives only B token")
        r.expect(await h.api.refreshServers.last, serverB,
                 "scoped refresh: request is explicitly bound to B server")
    } catch {
        r.expectTrue(false, "scoped refresh flow threw: \(error)")
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
    let activeSessionMarker = try? await h.keychain.getSecret(
        account: AppShared.KeychainAccount.activeSessionID
    )
    r.expectTrue(activeSessionMarker == nil,
                 "logout: shared extension session nonce deleted")

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

/// Offline create followed by edits must remain one create payload; after the server assigns
/// an id, the local placeholder alias resolves to the final row without a PUT to the placeholder.
func checkOfflineCreateUpdateCoalesces(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    await h.api.setCreateError(NetworkingError.serverUnreachable)

    do {
        let localID = try await h.vault.createCipher(PlaintextCipher(
            type: CipherType.login.rawValue,
            name: "Draft",
            login: .init(username: "alice", password: "one")
        ))
        let createAttemptsBeforeFlush = await h.api.createdRequests.count
        await h.api.setCreateError(nil)
        try await h.vault.updateCipher(id: localID, PlaintextCipher(
            id: localID,
            type: CipherType.login.rawValue,
            name: "Final",
            login: .init(username: "alice", password: "two")
        ))

        let queued = try await h.store.outbox(accountID: accountID)
        r.expect(queued.count, 1, "offline create+update: one outbox row")
        r.expect(queued.first?.opType, "create",
                 "offline create+update: operation remains create")
        let outcome = try await h.syncEngine.flushOutbox(accountID: accountID)
        r.expect(outcome.flushed, 1, "offline create+update: latest create flushes")
        r.expect(await h.api.createdRequests.count, createAttemptsBeforeFlush + 1,
                 "offline create+update: flush makes one additional POST")
        r.expect(await h.api.updatedRequests.count, 0,
                 "offline create+update: no PUT to placeholder")
        let final = try await h.vault.cipher(id: localID)
        r.expect(final.name, "Final",
                 "offline create+update: placeholder alias resolves latest payload")
    } catch {
        r.expectTrue(false, "offline create+update threw: \(error)")
    }
}

/// Deleting an unsent create cancels it atomically; no server item may later resurrect.
func checkOfflineCreateDeleteCancels(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    await h.api.setCreateError(NetworkingError.serverUnreachable)

    do {
        let localID = try await h.vault.createCipher(PlaintextCipher(
            type: CipherType.login.rawValue,
            name: "Discard me"
        ))
        let createAttemptsBeforeDelete = await h.api.createdRequests.count
        await h.api.setCreateError(nil)
        try await h.vault.deleteCipher(id: localID)
        r.expect(try await h.store.outbox(accountID: accountID).count, 0,
                 "offline create+delete: create and delete cancel")
        r.expectTrue(try await h.store.cipher(
            id: localID,
            accountID: accountID
        ) == nil, "offline create+delete: optimistic row deleted")
        _ = try await h.syncEngine.flushOutbox(accountID: accountID)
        r.expect(await h.api.createdRequests.count, createAttemptsBeforeDelete,
                 "offline create+delete: no later POST")
        r.expect(await h.api.deletedIDs.count, 0,
                 "offline create+delete: no DELETE to placeholder")
    } catch {
        r.expectTrue(false, "offline create+delete threw: \(error)")
    }
}

/// A user edit that begins while create POST is paused waits for finalization, resolves the
/// server id alias, then updates the real server row. It cannot mutate the in-flight outbox row.
func checkMutationWaitsForInFlightCreate(_ r: inout TestRunner) async {
    guard let (h, _) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    await h.api.setCreateError(NetworkingError.serverUnreachable)

    do {
        let localID = try await h.vault.createCipher(PlaintextCipher(
            type: CipherType.login.rawValue,
            name: "Before"
        ))
        let createAttemptsBeforeFlush = await h.api.createdRequests.count
        await h.api.setCreateError(nil)
        await h.api.pauseNextCreate()
        let flush = Task { try await h.syncEngine.flushOutbox(
            accountID: (await h.auth.session)!.accountID
        ) }
        await h.api.waitUntilCreateIsPaused()
        let update = Task {
            try await h.vault.updateCipher(id: localID, PlaintextCipher(
                id: localID,
                type: CipherType.login.rawValue,
                name: "After"
            ))
        }
        await Task.yield()
        r.expect(await h.api.updatedRequests.count, 0,
                 "in-flight create: update waits behind coordinator")
        await h.api.resumePausedCreate()
        _ = try await flush.value
        try await update.value

        r.expect(await h.api.createdRequests.count, createAttemptsBeforeFlush + 1,
                 "in-flight create: one additional POST")
        r.expect(await h.api.updatedRequests.first?.id,
                 "server-id-\(createAttemptsBeforeFlush + 1)",
                 "in-flight create: queued UI edit targets server id")
        r.expect(try await h.vault.cipher(id: localID).name, "After",
                 "in-flight create: alias returns final edit")
    } catch {
        r.expectTrue(false, "in-flight create race threw: \(error)")
    }
}

/// Refresh grants are serialized because rotating refresh tokens cannot safely be raced.
func checkConcurrentRefreshesAreSerialized(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    await h.api.setRefreshResponse(Fixtures.tokenResponse(
        accessToken: "access-refreshed",
        refreshToken: "refresh-2"
    ))
    await h.api.pauseNextRefresh()

    let first = Task { try await h.auth.refresh() }
    await h.api.waitUntilRefreshIsPaused()
    let second = Task { try await h.auth.refresh() }
    await Task.yield()
    r.expect(await h.api.refreshTokensUsed, ["refresh-1"],
             "concurrent refresh: second grant waits")
    await h.api.resumePausedRefresh()
    do {
        _ = try await first.value
        _ = try await second.value
        r.expect(await h.api.refreshTokensUsed, ["refresh-1", "refresh-2"],
                 "concurrent refresh: second grant uses rotated token")
        let stored = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.refreshToken(accountID: accountID)
        )
        r.expect(String(data: stored ?? Data(), encoding: .utf8), "refresh-2",
                 "concurrent refresh: latest valid token remains durable")
    } catch {
        r.expectTrue(false, "concurrent refresh threw: \(error)")
    }
}

/// A server pull and CRUD share the same coordinator. Delete cannot complete and then be
/// resurrected by a stale sync response that was already in flight.
func checkDeleteWaitsForInFlightFullSync(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    let response = Fixtures.syncResponse(
        cipherID: "sync-delete-race",
        name: "Race",
        username: "alice",
        uri: "https://race.example"
    )
    await h.api.setSyncResponse(response)
    do {
        _ = try await h.vault.sync()
        await h.api.pauseNextSync()
        let sync = Task { try await h.vault.sync() }
        await h.api.waitUntilSyncIsPaused()
        let delete = Task { try await h.vault.deleteCipher(id: "sync-delete-race") }
        await Task.yield()
        r.expect(await h.api.deletedIDs.count, 0,
                 "sync/delete race: delete waits for pull")
        await h.api.resumePausedSync()
        _ = try await sync.value
        try await delete.value
        r.expectTrue(try await h.store.cipher(
            id: "sync-delete-race",
            accountID: accountID
        ) == nil, "sync/delete race: final local state is deleted")
        r.expect(await h.api.deletedIDs, ["sync-delete-race"],
                 "sync/delete race: real server id deleted once")
    } catch {
        r.expectTrue(false, "sync/delete race threw: \(error)")
    }
}

func checkLockWaitsForRefreshRotation(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    await h.api.setRefreshResponse(Fixtures.tokenResponse(
        accessToken: "access-after-lock-race",
        refreshToken: "refresh-after-lock-race"
    ))
    await h.api.pauseNextRefresh()
    let refresh = Task { try await h.auth.refresh() }
    await h.api.waitUntilRefreshIsPaused()
    let lock = Task { await h.auth.lock() }
    await Task.yield()
    r.expectTrue(await h.keyVault.isUnlocked,
                 "refresh/lock: lock waits while token rotation is in flight")
    await h.api.resumePausedRefresh()
    do {
        _ = try await refresh.value
        await lock.value
        let token = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.refreshToken(accountID: accountID)
        )
        r.expect(String(data: token ?? Data(), encoding: .utf8),
                 "refresh-after-lock-race",
                 "refresh/lock: rotated token is durable before lock completes")
        r.expectTrue(!(await h.keyVault.isUnlocked),
                     "refresh/lock: vault ends locked")
    } catch {
        r.expectTrue(false, "refresh/lock race threw: \(error)")
    }
}
