import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import SyncEngine

/// fullSync: upserts ciphers + folders, builds search_text, and respects the
/// incremental revision rule (older server revision does NOT overwrite a
/// locally-newer row; a newer server revision DOES).
func checkFullSyncUpsert(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "fullSync: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false) // disable to isolate the upsert assertions
    let base = Date(timeIntervalSince1970: 1_750_000_000)

    let cipherJSON = Fixtures.loginCipherJSON(
        id: "cipher-1", name: "GitHub", username: "octocat",
        uri: "https://github.com", revision: base)
    let folderJSON = Fixtures.folderJSON(id: "folder-1", name: "Work", revision: base)
    let response = Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [cipherJSON], folders: [folderJSON]))

    let api = FakeVaultAPI(syncResponse: response)
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(outcome.upserted, 1, "fullSync upserts 1 cipher")
        r.expect(outcome.dropped, 0, "fullSync no dropped ciphers")
        r.expect(outcome.deletedLocally, 0, "fullSync no local deletes on first sync")

        // The store actually has the cipher + folder.
        let rows = try await store.allCiphers(accountID: Fixtures.accountID)
        r.expect(rows.count, 1, "store has 1 cipher after sync")
        r.expect(rows.first?.id, "cipher-1", "stored cipher id")

        // search_text was built from decrypted name + username + uri (lowercased).
        let search = rows.first?.searchText ?? ""
        r.expectTrue(search.contains("github"), "search_text contains decrypted name")
        r.expectTrue(search.contains("octocat"), "search_text contains decrypted username")

        let folders = try await store.allFolders(accountID: Fixtures.accountID)
        r.expect(folders.count, 1, "store has 1 folder after sync")
        r.expect(folders.first?.id, "folder-1", "stored folder id")

        await api.setSyncResponse(
            Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [cipherJSON], folders: []))
        )
        _ = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(try await store.allFolders(accountID: Fixtures.accountID).count, 0,
                 "clean server omission removes stale local folder")
    } catch {
        r.expectTrue(false, "fullSync threw: \(error)")
    }
}

/// Incremental rule: a second sync with an OLDER server revision must NOT overwrite a
/// locally-newer row; with a NEWER revision it DOES.
func checkIncrementalRevisionRule(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "incremental: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let base = Date(timeIntervalSince1970: 1_750_000_000)
    let older = base.addingTimeInterval(-3600)
    let newer = base.addingTimeInterval(3600)

    // First sync establishes cipher-1 at `base` with name "Original".
    let firstJSON = Fixtures.loginCipherJSON(
        id: "cipher-1", name: "Original", username: "octocat",
        uri: "https://github.com", revision: base)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [firstJSON])))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        _ = try await engine.fullSync(accountID: Fixtures.accountID)

        // --- OLDER server revision: must be skipped (local stays "Original"). ---
        let olderJSON = Fixtures.loginCipherJSON(
            id: "cipher-1", name: "StaleName", username: "octocat",
            uri: "https://github.com", revision: older)
        await api.setSyncResponse(Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [olderJSON])))
        let outcome2 = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(outcome2.upserted, 0, "older server revision does NOT upsert (skip-write)")
        let afterOlder = try await store.cipher(id: "cipher-1", accountID: Fixtures.accountID)
        r.expectTrue(afterOlder?.searchText?.contains("original") ?? false,
                     "row unchanged after older revision (still 'Original')")
        r.expectTrue(!(afterOlder?.searchText?.contains("stalename") ?? true),
                     "stale name NOT written")

        // --- NEWER server revision: must overwrite. ---
        let newerJSON = Fixtures.loginCipherJSON(
            id: "cipher-1", name: "FreshName", username: "octocat",
            uri: "https://github.com", revision: newer)
        await api.setSyncResponse(Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [newerJSON])))
        let outcome3 = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(outcome3.upserted, 1, "newer server revision DOES upsert")
        let afterNewer = try await store.cipher(id: "cipher-1", accountID: Fixtures.accountID)
        r.expectTrue(afterNewer?.searchText?.contains("freshname") ?? false,
                     "row overwritten after newer revision ('FreshName')")
    } catch {
        r.expectTrue(false, "incremental rule threw: \(error)")
    }
}

/// fullSync deletes a local cipher the server no longer has (and that isn't pending
/// in the outbox).
func checkFullSyncDeletesMissing(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "delete-missing: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let base = Date(timeIntervalSince1970: 1_750_000_000)

    let a = Fixtures.loginCipherJSON(id: "cipher-a", name: "A", username: "ua",
                                     uri: "https://a.test", revision: base)
    let b = Fixtures.loginCipherJSON(id: "cipher-b", name: "B", username: "ub",
                                     uri: "https://b.test", revision: base)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [a, b])))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        _ = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(try await store.allCiphers(accountID: Fixtures.accountID).count, 2,
                 "two ciphers after first sync")

        // Second sync omits cipher-b → it should be deleted locally.
        await api.setSyncResponse(Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [a])))
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(outcome.deletedLocally, 1, "missing server cipher deleted locally")
        let remaining = try await store.allCiphers(accountID: Fixtures.accountID)
        r.expect(remaining.count, 1, "one cipher remains")
        r.expect(remaining.first?.id, "cipher-a", "the kept cipher is cipher-a")
    } catch {
        r.expectTrue(false, "delete-missing threw: \(error)")
    }
}

func checkServerTrashRowRemovesLiveCipher(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "trash row: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }
    let base = Date(timeIntervalSince1970: 1_750_000_000)
    let live = Fixtures.loginCipherJSON(
        id: "trashed", name: "Soon deleted", username: "alice",
        uri: "https://trash.example", revision: base
    )
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(
        Fixtures.syncJSON(ciphers: [live])
    ))
    let engine = SyncEngine(
        api: api, store: store, keyVault: await Fixtures.unlockedVault(),
        identityStore: FakeIdentityStore(enabled: false)
    )
    do {
        _ = try await engine.fullSync(accountID: Fixtures.accountID)
        let trashed = live.replacingOccurrences(
            of: "\"deletedDate\":null",
            with: "\"deletedDate\":\"2026-07-16T00:00:00.000Z\""
        )
        await api.setSyncResponse(Fixtures.decodeSync(
            Fixtures.syncJSON(ciphers: [trashed])
        ))
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(outcome.deletedLocally, 1,
                 "trash row: live cache row removed")
        r.expect(try await store.allCiphers(accountID: Fixtures.accountID).count, 0,
                 "trash row: absent from live listing")
    } catch {
        r.expectTrue(false, "trash row sync threw: \(error)")
    }
}

/// Pending-outbox guard on UPSERT: a cipher with a queued (unflushed) local write must
/// NOT be overwritten by a pull, even when the server re-sends it with an EQUAL/OLDER
/// revisionDate. The local row's enc must stay as the local edit.
func checkFullSyncSkipsPendingUpsert(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "pending-upsert guard: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let base = Date(timeIntervalSince1970: 1_750_000_000)

    // First sync establishes cipher-1 at `base` named "ServerName".
    let firstJSON = Fixtures.loginCipherJSON(
        id: "cipher-1", name: "ServerName", username: "octocat",
        uri: "https://github.com", revision: base)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [firstJSON])))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        _ = try await engine.fullSync(accountID: Fixtures.accountID)

        // Simulate a local edit: rewrite the row's search_text to a local-only value and
        // enqueue an unflushed outbox write for cipher-1.
        guard let current = try await store.cipher(
            id: "cipher-1",
            accountID: Fixtures.accountID
        ) else {
            r.expectTrue(false, "pending-upsert guard: cipher exists after first sync"); return
        }
        let locallyEdited = CipherRow(
            id: current.id, accountID: current.accountID, type: current.type,
            revisionDate: current.revisionDate, creationDate: current.creationDate,
            encName: current.encName, searchText: "localedit-marker")
        try await store.upsertCiphers([locallyEdited])
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "update",
            entityType: "cipher", entityID: "cipher-1",
            payloadJSON: "{}", lastKnownRevisionDate: current.revisionDate))

        // Server re-sends cipher-1 with EQUAL revision and a different name — must be skipped.
        let equalRev = Fixtures.loginCipherJSON(
            id: "cipher-1", name: "ServerNameChanged", username: "octocat",
            uri: "https://github.com", revision: base)
        await api.setSyncResponse(Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [equalRev])))
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(outcome.upserted, 0, "pending row with equal-revision server copy is NOT upserted")

        let after = try await store.cipher(id: "cipher-1", accountID: Fixtures.accountID)
        r.expect(after?.searchText, "localedit-marker", "pending local edit preserved (not clobbered)")
    } catch {
        r.expectTrue(false, "pending-upsert guard threw: \(error)")
    }
}

/// Delete guard: a pending-outbox cipher the server OMITS from sync must NOT be deleted
/// locally (its create/edit hasn't round-tripped yet).
func checkFullSyncKeepsPendingOmitted(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "pending-omit guard: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let base = Date(timeIntervalSince1970: 1_750_000_000)

    // Establish two ciphers, then enqueue a pending write for cipher-b.
    let a = Fixtures.loginCipherJSON(id: "cipher-a", name: "A", username: "ua",
                                     uri: "https://a.test", revision: base)
    let b = Fixtures.loginCipherJSON(id: "cipher-b", name: "B", username: "ub",
                                     uri: "https://b.test", revision: base)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [a, b])))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        _ = try await engine.fullSync(accountID: Fixtures.accountID)
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "update",
            entityType: "cipher", entityID: "cipher-b",
            payloadJSON: "{}", lastKnownRevisionDate: nil))

        // Second sync OMITS cipher-b. Normally it'd be deleted, but it's pending → kept.
        await api.setSyncResponse(Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [a])))
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(outcome.deletedLocally, 0, "pending-but-omitted cipher is NOT deleted")
        let bRow = try await store.cipher(id: "cipher-b", accountID: Fixtures.accountID)
        r.expectTrue(bRow != nil, "pending-but-omitted cipher remains in the store")
    } catch {
        r.expectTrue(false, "pending-omit guard threw: \(error)")
    }
}

/// Account B may coincidentally have an outbox entity id matching a server cipher for
/// account A. That must not suppress A's pull/merge.
func checkFullSyncScopesPendingOutbox(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "pending account isolation: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let accountB = "user-2"
    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let serverCipher = Fixtures.loginCipherJSON(
        id: "shared-entity-id",
        name: "Account A server item",
        username: "alice",
        uri: "https://account-a.test",
        revision: Date(timeIntervalSince1970: 1_750_000_000)
    )
    let api = FakeVaultAPI(
        syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [serverCipher]))
    )
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        try await Fixtures.seedAccounts([accountB], in: store)
        try await store.enqueueOutbox(OutboxRow(
            accountID: accountB, opType: "update", entityType: "cipher",
            entityID: "shared-entity-id", payloadJSON: "{}"))

        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(outcome.upserted, 1, "account B pending id does not suppress A merge")
        let row = try await store.cipher(
            id: "shared-entity-id",
            accountID: Fixtures.accountID
        )
        r.expect(row?.accountID, Fixtures.accountID, "server cipher is stored under account A")
        r.expect(try await store.outbox(accountID: accountB).count, 1,
                 "account B pending row remains queued")
    } catch {
        r.expectTrue(false, "pending account isolation threw: \(error)")
    }
}
