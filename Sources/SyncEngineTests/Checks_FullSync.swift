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
        let afterOlder = try await store.cipher(id: "cipher-1")
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
        let afterNewer = try await store.cipher(id: "cipher-1")
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
