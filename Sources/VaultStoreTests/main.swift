import Foundation
import VaultStore

func makeRow(id: String, account: String = "acct1", name: String, search: String,
             revision: String) -> CipherRow {
    CipherRow(
        id: id,
        accountID: account,
        type: 1,
        favorite: false,
        revisionDate: revision,
        creationDate: "2026-06-01T00:00:00Z",
        encName: "2.\(name)Enc",
        encBlob: "2.\(name)Blob",
        searchText: search
    )
}

func runAllTests() async -> Int {
    var r = TestRunner()

    r.expect(VaultStoreError.notFound, VaultStoreError.notFound, "error equatable smoke")

    // A fresh temp-file DB path; clean up at the end.
    let dbURL = FileManager.default.temporaryDirectory
        .appendingPathComponent("vaultstore-test-\(UUID().uuidString).sqlite")
    let passphrase = Data((0..<32).map { UInt8($0) })

    defer {
        // Remove the db and WAL/SHM sidecars.
        for suffix in ["", "-wal", "-shm"] {
            try? FileManager.default.removeItem(
                at: dbURL.deletingPathExtension()
                    .appendingPathExtension("sqlite\(suffix.isEmpty ? "" : suffix)"))
        }
        try? FileManager.default.removeItem(at: dbURL)
        try? FileManager.default.removeItem(at: URL(fileURLWithPath: dbURL.path + "-wal"))
        try? FileManager.default.removeItem(at: URL(fileURLWithPath: dbURL.path + "-shm"))
    }

    do {
        let store = try VaultStore(databaseURL: dbURL, passphrase: passphrase)

        // --- Ciphers: upsert + read back equal ---
        let a = makeRow(id: "c1", name: "Alpha", search: "Alpha alice@example.com github.com",
                        revision: "2026-06-10T00:00:00Z")
        let b = makeRow(id: "c2", name: "Bravo", search: "Bravo bob@example.com gitlab.com",
                        revision: "2026-06-11T00:00:00Z")
        try await store.upsertCiphers([a, b])

        let all = try await store.allCiphers(accountID: "acct1")
        r.expect(all.count, 2, "upsert two ciphers -> two rows")
        // Ordered by revision_date DESC -> b (newer) first.
        r.expect(all.first?.id, "c2", "allCiphers ordered by revision DESC")

        let fetchedA = try await store.cipher(id: "c1")
        r.expectTrue(fetchedA != nil, "cipher(id:) finds c1")
        r.expect(fetchedA, a, "cipher(id:) round-trips equal")

        r.expectTrue((try await store.cipher(id: "nope")) == nil, "cipher(id:) missing -> nil")

        // --- Update (upsert same id) ---
        let aUpdated = makeRow(id: "c1", name: "AlphaV2", search: "AlphaV2 alice@example.com",
                               revision: "2026-06-12T00:00:00Z")
        try await store.upsertCiphers([aUpdated])
        let countAfterUpdate = try await store.allCiphers(accountID: "acct1").count
        r.expect(countAfterUpdate, 2, "upsert same id updates not inserts")
        let reFetched = try await store.cipher(id: "c1")
        r.expect(reFetched?.encName, "2.AlphaV2Enc", "upsert overwrites enc_name")
        r.expect(reFetched?.revisionDate, "2026-06-12T00:00:00Z", "upsert overwrites revision")

        // --- Search over search_text ---
        let searchAlice = try await store.search("alice", accountID: "acct1")
        r.expect(searchAlice.count, 1, "search 'alice' matches one")
        r.expect(searchAlice.first?.id, "c1", "search 'alice' -> c1")

        let searchExample = try await store.search("example.com", accountID: "acct1")
        r.expect(searchExample.count, 2, "search 'example.com' matches both")

        let searchNone = try await store.search("zzzzz", accountID: "acct1")
        r.expect(searchNone.count, 0, "search no match -> empty")

        // LIKE wildcards in the query are escaped (treated literally).
        let searchWildcard = try await store.search("%", accountID: "acct1")
        r.expect(searchWildcard.count, 0, "search literal '%' matches nothing")

        // Account scoping.
        let otherAccount = try await store.allCiphers(accountID: "other")
        r.expect(otherAccount.count, 0, "allCiphers scoped by account")

        // --- Delete ---
        try await store.deleteCipher(id: "c2")
        r.expect(try await store.allCiphers(accountID: "acct1").count, 1, "deleteCipher removes row")
        do {
            try await store.deleteCipher(id: "c2")
            r.expectTrue(false, "deleting missing cipher should throw")
        } catch let e as VaultStoreError {
            r.expect(e, .notFound, "deleteCipher missing -> notFound")
        }

        // --- Folders ---
        let f1 = FolderRow(id: "f1", accountID: "acct1", encName: "2.WorkEnc",
                           revisionDate: "2026-06-05T00:00:00Z")
        try await store.upsertFolders([f1])
        let folders = try await store.allFolders(accountID: "acct1")
        r.expect(folders.count, 1, "upsert one folder")
        r.expect(folders.first, f1, "folder round-trips equal")
        // Update folder.
        let f1v2 = FolderRow(id: "f1", accountID: "acct1", encName: "2.PersonalEnc",
                             revisionDate: "2026-06-06T00:00:00Z")
        try await store.upsertFolders([f1v2])
        r.expect((try await store.allFolders(accountID: "acct1")).first?.encName, "2.PersonalEnc",
                 "upsert folder updates")

        // --- Sync state round-trip ---
        r.expectTrue((try await store.syncState(accountID: "acct1")) == nil, "syncState absent -> nil")
        let ss = SyncStateRow(accountID: "acct1", lastAccountRevision: "2026-06-12T00:00:00Z",
                              lastFullSyncAt: "2026-06-12T01:00:00Z")
        try await store.setSyncState(ss)
        r.expect(try await store.syncState(accountID: "acct1"), ss, "syncState round-trips")
        // Update.
        let ss2 = SyncStateRow(accountID: "acct1", lastAccountRevision: "2026-06-13T00:00:00Z",
                               lastFullSyncAt: "2026-06-13T01:00:00Z")
        try await store.setSyncState(ss2)
        r.expect((try await store.syncState(accountID: "acct1"))?.lastAccountRevision,
                 "2026-06-13T00:00:00Z", "setSyncState upserts")

        // --- Outbox enqueue/read/clear ---
        let id1 = try await store.enqueueOutbox(OutboxRow(
            opType: "update", entityType: "cipher", entityID: "c1",
            payloadJSON: "{\"a\":1}", lastKnownRevisionDate: "2026-06-12T00:00:00Z"))
        let id2 = try await store.enqueueOutbox(OutboxRow(
            opType: "create", entityType: "folder", entityID: "f9",
            payloadJSON: "{\"b\":2}"))
        r.expectTrue(id2 > id1, "outbox ids autoincrement")

        let outbox = try await store.outbox()
        r.expect(outbox.count, 2, "outbox has two pending ops")
        r.expect(outbox.first?.id, id1, "outbox ordered by id ASC")
        r.expect(outbox.first?.entityID, "c1", "outbox first op entity")
        r.expect(outbox.first?.payloadJSON, "{\"a\":1}", "outbox payload round-trips")
        r.expectTrue(outbox[1].lastKnownRevisionDate == nil, "outbox null revision round-trips")

        try await store.clearOutbox(id: id1)
        let outboxAfter = try await store.outbox()
        r.expect(outboxAfter.count, 1, "clearOutbox removes one")
        r.expect(outboxAfter.first?.id, id2, "remaining outbox op")
        do {
            try await store.clearOutbox(id: 99999)
            r.expectTrue(false, "clearing missing outbox should throw")
        } catch let e as VaultStoreError {
            r.expect(e, .notFound, "clearOutbox missing -> notFound")
        }
    } catch {
        r.expectTrue(false, "VaultStore session threw: \(error)")
    }

    // --- Persistence: reopen the same file, rows survive ---
    do {
        let store2 = try VaultStore(databaseURL: dbURL, passphrase: passphrase)
        let persisted = try await store2.allCiphers(accountID: "acct1")
        r.expect(persisted.count, 1, "reopen DB -> cipher persists")
        r.expect(persisted.first?.id, "c1", "persisted cipher is c1")
        r.expect(persisted.first?.encName, "2.AlphaV2Enc", "persisted cipher keeps updated enc_name")
        let ss = try await store2.syncState(accountID: "acct1")
        r.expect(ss?.lastAccountRevision, "2026-06-13T00:00:00Z", "reopen -> sync_state persists")
        let outbox = try await store2.outbox()
        r.expect(outbox.count, 1, "reopen -> outbox persists")
    } catch {
        r.expectTrue(false, "VaultStore reopen threw: \(error)")
    }

    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
