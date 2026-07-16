import Foundation
import Darwin
import SQLCipher
import VaultStore

func holdMigrationLock(at lockPath: String, microseconds: useconds_t) -> Int32 {
    let descriptor = Darwin.open(
        lockPath,
        O_CREAT | O_RDWR,
        S_IRUSR | S_IWUSR
    )
    guard descriptor >= 0 else { return 20 }
    defer { Darwin.close(descriptor) }

    // This fixture uses a non-blocking acquisition too: a broken test setup exits
    // promptly rather than hanging before it can signal readiness to its parent.
    guard Darwin.lockf(descriptor, F_TLOCK, 0) == 0 else { return 21 }
    defer { Darwin.lockf(descriptor, F_ULOCK, 0) }

    FileHandle.standardOutput.write(Data([0x52]))
    _ = Darwin.usleep(microseconds)
    return 0
}

/// Creates the legacy system-SQLite shape without applying a SQLCipher key.
func createLegacyPlaintextDatabase(
    at databasePath: String,
    sentinel: String,
    closeOnSuccess: Bool
) -> Int32 {
    var db: OpaquePointer?
    let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
    guard sqlite3_open_v2(databasePath, &db, flags, nil) == SQLITE_OK, let db else {
        if let db { sqlite3_close(db) }
        return 10
    }

    let schema = """
    PRAGMA journal_mode=WAL;
    PRAGMA wal_autocheckpoint=0;
    PRAGMA user_version=7;
    CREATE TABLE account (
        id TEXT PRIMARY KEY, email TEXT, server_url TEXT, kdf_type INTEGER,
        kdf_iters INTEGER, revision_date TEXT, security_stamp TEXT,
        enc_user_key TEXT, enc_private_key TEXT
    );
    CREATE TABLE cipher (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL, type INTEGER NOT NULL,
        folder_id TEXT, organization_id TEXT, favorite INTEGER NOT NULL DEFAULT 0,
        reprompt INTEGER NOT NULL DEFAULT 0, edit INTEGER NOT NULL DEFAULT 1,
        view_password INTEGER NOT NULL DEFAULT 1, revision_date TEXT NOT NULL,
        creation_date TEXT NOT NULL, deleted_date TEXT, enc_name TEXT, enc_notes TEXT,
        enc_blob TEXT, enc_cipher_key TEXT, search_text TEXT,
        FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
    );
    -- Deliberately omit the legacy child index: createSchema must migrate the table
    -- before attempting an account_id-based replacement index.
    CREATE TABLE cipher_uri (
        id TEXT PRIMARY KEY,
        cipher_id TEXT NOT NULL,
        enc_uri TEXT,
        match_type INTEGER,
        FOREIGN KEY(cipher_id) REFERENCES cipher(id) ON DELETE CASCADE
    );
    CREATE TABLE outbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        op_type TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        last_known_revision_date TEXT
    );
    CREATE TABLE passkey_import_receipt (
        id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        outbox_id INTEGER,
        completed INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(account_id, id),
        UNIQUE(outbox_id),
        FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE,
        FOREIGN KEY(outbox_id) REFERENCES outbox(id) ON DELETE SET NULL
    );
    INSERT INTO account (id, email) VALUES ('legacy-acct', 'legacy@example.com');
    """
    guard sqlite3_exec(db, schema, nil, nil, nil) == SQLITE_OK else {
        sqlite3_close(db)
        return 11
    }

    var statement: OpaquePointer?
    let insert = """
    INSERT INTO cipher
      (id, account_id, type, favorite, reprompt, edit, view_password,
       revision_date, creation_date, enc_name, enc_blob, search_text)
    VALUES
      ('legacy-cipher', 'legacy-acct', 1, 0, 0, 1, 1,
       '2026-07-15T00:00:00Z', '2026-07-01T00:00:00Z',
       '2.LegacyEnc', '2.LegacyBlob', ?1);
    """
    guard sqlite3_prepare_v2(db, insert, -1, &statement, nil) == SQLITE_OK,
          let statement else {
        sqlite3_close(db)
        return 12
    }
    let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
    let bindResult = sqlite3_bind_text(statement, 1, sentinel, -1, transient)
    let stepResult = bindResult == SQLITE_OK ? sqlite3_step(statement) : bindResult
    sqlite3_finalize(statement)
    guard bindResult == SQLITE_OK, stepResult == SQLITE_DONE else {
        sqlite3_close(db)
        return 13
    }

    guard sqlite3_exec(db, """
    INSERT INTO cipher_uri (id, cipher_id, enc_uri, match_type)
    VALUES ('legacy-uri', 'legacy-cipher', '2.LegacyURI', 0);
    """, nil, nil, nil) == SQLITE_OK else {
        sqlite3_close(db)
        return 16
    }

    let legacyOutbox = """
    INSERT INTO cipher
      (id, account_id, type, favorite, reprompt, edit, view_password,
       revision_date, creation_date, enc_name, enc_blob, search_text)
    VALUES
      ('orphan-cipher', 'missing-account', 1, 0, 0, 1, 1,
       '2026-07-15T00:00:00Z', '2026-07-01T00:00:00Z',
       '2.OrphanEnc', '2.OrphanBlob', 'orphan-quarantine-secret');
    INSERT INTO outbox
      (op_type, entity_type, entity_id, payload_json, last_known_revision_date)
    VALUES
      ('update', 'cipher', 'legacy-cipher', '{}', '2026-07-15T00:00:00Z');
    INSERT INTO outbox
      (op_type, entity_type, entity_id, payload_json, last_known_revision_date)
    VALUES
      ('delete', 'cipher', 'missing-legacy-cipher', '{}', NULL);
    INSERT INTO outbox
      (op_type, entity_type, entity_id, payload_json, last_known_revision_date)
    VALUES
      ('update', 'cipher', 'orphan-cipher', '{}', NULL);
    INSERT INTO passkey_import_receipt
      (id, account_id, outbox_id, completed)
    VALUES ('legacy-receipt', 'legacy-acct', 1, 0);
    """
    guard sqlite3_exec(db, legacyOutbox, nil, nil, nil) == SQLITE_OK else {
        sqlite3_close(db)
        return 14
    }

    if closeOnSuccess {
        return sqlite3_close(db) == SQLITE_OK ? 0 : 15
    }
    // The crash-fixture child deliberately leaves db open and immediately invokes _exit.
    return 0
}

func encryptedScalarInt(
    at databasePath: String,
    passphrase: Data,
    sql: String
) -> Int32? {
    var db: OpaquePointer?
    let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
    guard sqlite3_open_v2(databasePath, &db, flags, nil) == SQLITE_OK, let db else {
        if let db { sqlite3_close(db) }
        return nil
    }
    defer { sqlite3_close(db) }

    let keyResult = passphrase.withUnsafeBytes { bytes in
        sqlite3_key(db, bytes.baseAddress, Int32(bytes.count))
    }
    guard keyResult == SQLITE_OK else { return nil }

    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK,
          let statement else { return nil }
    defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
    return sqlite3_column_int(statement, 0)
}

func encryptedUserVersion(at databasePath: String, passphrase: Data) -> Int32? {
    encryptedScalarInt(at: databasePath, passphrase: passphrase, sql: "PRAGMA user_version;")
}

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

    // --- Cross-process migration lock: bounded wait, explicit failure, recovery ---
    let contentionURL = FileManager.default.temporaryDirectory
        .appendingPathComponent("vaultstore-lock-\(UUID().uuidString).sqlite")
    let contentionLockURL = contentionURL.deletingLastPathComponent().appendingPathComponent(
        ".\(contentionURL.lastPathComponent).migration.lock"
    )
    defer {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(
                at: URL(fileURLWithPath: contentionURL.path + suffix)
            )
        }
        try? FileManager.default.removeItem(at: contentionLockURL)
    }

    r.expectTrue(VaultStore.migrationLockTimeout > 0
                 && VaultStore.migrationLockTimeout <= 2,
                 "production migration lock wait is positive and extension-safe")
    do {
        let readyPipe = Pipe()
        let holder = Process()
        holder.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        // A long safety release keeps this regression test finite even if the
        // production code accidentally returns to a blocking F_LOCK call.
        holder.arguments = [
            "--hold-migration-lock", contentionLockURL.path, "10000000",
        ]
        holder.standardOutput = readyPipe
        try holder.run()

        let ready = readyPipe.fileHandleForReading.readData(ofLength: 1)
        r.expect(ready, Data([0x52]), "lock-holder child acquired migration lock")

        var bodyRan = false
        do {
            try VaultStore.withMigrationLock(at: contentionURL, timeout: 0.2) {
                bodyRan = true
            }
            r.expectTrue(false, "contended migration lock must not enter protected body")
        } catch let error as VaultStoreError {
            r.expect(error, .migrationLockTimedOut,
                     "contended migration lock returns explicit timeout")
        } catch {
            r.expectTrue(false, "contended migration lock returned unexpected error: \(error)")
        }
        r.expectTrue(!bodyRan, "timed-out migration lock leaves protected body untouched")
        r.expectTrue(holder.isRunning,
                     "migration lock returns before the owning process releases it")

        if holder.isRunning { holder.terminate() }
        holder.waitUntilExit()

        _ = try VaultStore(
            databaseURL: contentionURL,
            passphrase: Data(repeating: 0x6B, count: 32)
        )
        r.expectTrue(true, "normal store open succeeds after migration lock release")
    } catch {
        r.expectTrue(false, "migration lock contention fixture threw: \(error)")
    }

    // A fresh temp-file DB path; clean up at the end.
    let dbURL = FileManager.default.temporaryDirectory
        .appendingPathComponent("vaultstore-test-\(UUID().uuidString).sqlite")
    let passphrase = Data((0..<32).map { UInt8($0) })
    let plaintextSentinel = "vaultstore-search-\(UUID().uuidString)"

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
        try? FileManager.default.removeItem(
            at: dbURL.deletingLastPathComponent().appendingPathComponent(
                ".\(dbURL.lastPathComponent).migration.lock"
            )
        )
    }

    do {
        let store = try VaultStore(databaseURL: dbURL, passphrase: passphrase)

        // Parent account row — children FK-reference account(id) ON DELETE CASCADE.
        let account = AccountRow(
            id: "acct1",
            email: "owner@example.com",
            serverURL: "https://vault.example.com/team",
            kdfType: 0,
            kdfIters: 600000,
            revisionDate: "2026-06-09T00:00:00Z",
            securityStamp: "stamp",
            encUserKey: "2.user-key",
            encPrivateKey: "2.private-key"
        )
        try await store.upsertAccounts([account])
        r.expect(try await store.account(id: "acct1"), account,
                 "account lookup returns the complete row")
        r.expectTrue(try await store.account(id: "missing-account") == nil,
                     "account lookup returns nil for a missing id")
        try await store.upsertAccounts([
            AccountRow(id: "acct1", securityStamp: "new-stamp")
        ])
        let partiallyUpdatedAccount = try await store.account(id: "acct1")
        r.expect(partiallyUpdatedAccount?.serverURL, account.serverURL,
                 "partial account upsert preserves server URL")
        r.expect(partiallyUpdatedAccount?.kdfIters, account.kdfIters,
                 "partial account upsert preserves KDF metadata")
        r.expect(partiallyUpdatedAccount?.encUserKey, account.encUserKey,
                 "partial account upsert preserves protected user key")
        r.expect(partiallyUpdatedAccount?.securityStamp, "new-stamp",
                 "partial account upsert updates supplied fields")

        // --- Ciphers: upsert + read back equal ---
        let a = makeRow(id: "c1", name: "Alpha",
                        search: "Alpha alice@example.com github.com \(plaintextSentinel)",
                        revision: "2026-06-10T00:00:00Z")
        let b = makeRow(id: "c2", name: "Bravo", search: "Bravo bob@example.com gitlab.com",
                        revision: "2026-06-11T00:00:00Z")
        try await store.upsertCiphers([a, b])

        // `search_text` is intentionally plaintext inside SQLite so it can be queried.
        // SQLCipher must keep that unique value out of every on-disk database artifact.
        let sentinelBytes = Data(plaintextSentinel.utf8)
        for (url, label) in [
            (dbURL, "database"),
            (URL(fileURLWithPath: dbURL.path + "-wal"), "WAL"),
            (URL(fileURLWithPath: dbURL.path + "-shm"), "SHM"),
        ] {
            r.expectTrue(FileManager.default.fileExists(atPath: url.path),
                         "\(label) exists for encryption inspection")
            if let bytes = try? Data(contentsOf: url) {
                r.expectTrue(bytes.range(of: sentinelBytes) == nil,
                             "unique search_text absent from \(label)")
            } else {
                r.expectTrue(false, "read \(label) for encryption inspection")
            }
        }

        let all = try await store.allCiphers(accountID: "acct1")
        r.expect(all.count, 2, "upsert two ciphers -> two rows")
        // Ordered by revision_date DESC -> b (newer) first.
        r.expect(all.first?.id, "c2", "allCiphers ordered by revision DESC")

        let fetchedA = try await store.cipher(id: "c1", accountID: "acct1")
        r.expectTrue(fetchedA != nil, "cipher(id:) finds c1")
        r.expect(fetchedA, a, "cipher(id:) round-trips equal")

        r.expectTrue((try await store.cipher(id: "nope", accountID: "acct1")) == nil,
                     "cipher(id:accountID:) missing -> nil")

        // --- Update (upsert same id) ---
        let aUpdated = makeRow(id: "c1", name: "AlphaV2", search: "AlphaV2 alice@example.com",
                               revision: "2026-06-12T00:00:00Z")
        try await store.upsertCiphers([aUpdated])
        let countAfterUpdate = try await store.allCiphers(accountID: "acct1").count
        r.expect(countAfterUpdate, 2, "upsert same id updates not inserts")
        let reFetched = try await store.cipher(id: "c1", accountID: "acct1")
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

        // Identical server UUIDs can occur on cloned Vaultwarden instances. Composite
        // entity keys must preserve both rows and scope children/deletes to their account.
        try await store.upsertAccounts([AccountRow(id: "acct2", email: "two@example.com")])
        let sharedA = makeRow(id: "shared-id", account: "acct1", name: "SharedA",
                              search: "account a", revision: "2026-06-12T00:00:00Z")
        let sharedB = makeRow(id: "shared-id", account: "acct2", name: "SharedB",
                              search: "account b", revision: "2026-06-13T00:00:00Z")
        try await store.upsertCiphers([sharedA, sharedB])
        r.expect((try await store.cipher(id: "shared-id", accountID: "acct1"))?.encName,
                 sharedA.encName, "composite cipher key preserves account A")
        r.expect((try await store.cipher(id: "shared-id", accountID: "acct2"))?.encName,
                 sharedB.encName, "composite cipher key preserves account B")
        try await store.upsertCipherURIs([
            CipherURIRow(id: "shared-uri", accountID: "acct1", cipherID: "shared-id",
                         encURI: "2.AccountAURI"),
            CipherURIRow(id: "shared-uri", accountID: "acct2", cipherID: "shared-id",
                         encURI: "2.AccountBURI"),
        ])
        r.expect((try await store.cipherURIs(
            cipherID: "shared-id", accountID: "acct1"
        )).first?.encURI, "2.AccountAURI", "composite child key preserves account A")
        r.expect((try await store.cipherURIs(
            cipherID: "shared-id", accountID: "acct2"
        )).first?.encURI, "2.AccountBURI", "composite child key preserves account B")
        let sharedFolderA = FolderRow(
            id: "shared-folder", accountID: "acct1", encName: "2.FolderA",
            revisionDate: "2026-06-12T00:00:00Z"
        )
        let sharedFolderB = FolderRow(
            id: "shared-folder", accountID: "acct2", encName: "2.FolderB",
            revisionDate: "2026-06-13T00:00:00Z"
        )
        try await store.upsertFolders([sharedFolderA, sharedFolderB])
        r.expect((try await store.folder(id: "shared-folder", accountID: "acct1"))?.encName,
                 "2.FolderA", "composite folder key preserves account A")
        r.expect((try await store.folder(id: "shared-folder", accountID: "acct2"))?.encName,
                 "2.FolderB", "composite folder key preserves account B")
        try await store.deleteCipher(id: "shared-id", accountID: "acct1")
        r.expectTrue(try await store.cipher(id: "shared-id", accountID: "acct1") == nil,
                     "account A delete removes only its cipher")
        r.expectTrue(try await store.cipher(id: "shared-id", accountID: "acct2") != nil,
                     "account A delete cannot remove account B cipher")
        r.expect(try await store.cipherURIs(
            cipherID: "shared-id", accountID: "acct1"
        ).count, 0, "account A child cascades within its composite parent")
        r.expect(try await store.cipherURIs(
            cipherID: "shared-id", accountID: "acct2"
        ).count, 1, "account B child survives account A cascade")
        try await store.deleteCipher(id: "shared-id", accountID: "acct2")
        try await store.deleteFolder(id: "shared-folder", accountID: "acct1")
        r.expectTrue(try await store.folder(
            id: "shared-folder", accountID: "acct2"
        ) != nil, "folder delete is account scoped")
        try await store.deleteFolder(id: "shared-folder", accountID: "acct2")

        // --- Delete ---
        try await store.deleteCipher(id: "c2", accountID: "acct1")
        r.expect(try await store.allCiphers(accountID: "acct1").count, 1, "deleteCipher removes row")
        do {
            try await store.deleteCipher(id: "c2", accountID: "acct1")
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
            accountID: "acct1", opType: "update", entityType: "cipher", entityID: "c1",
            payloadJSON: "{\"a\":1}", lastKnownRevisionDate: "2026-06-12T00:00:00Z"))
        let id2 = try await store.enqueueOutbox(OutboxRow(
            accountID: "acct1", opType: "create", entityType: "folder", entityID: "f9",
            payloadJSON: "{\"b\":2}"))
        try await store.upsertAccounts([AccountRow(id: "acct2", email: "two@example.com")])
        let id3 = try await store.enqueueOutbox(OutboxRow(
            accountID: "acct2", opType: "delete", entityType: "cipher", entityID: "other-c",
            payloadJSON: "{}"))
        r.expectTrue(id2 > id1, "outbox ids autoincrement")
        r.expectTrue(id3 > id2, "outbox ids continue across accounts")

        let outbox = try await store.outbox()
        r.expect(outbox.count, 3, "outbox has pending ops across accounts")
        r.expect(outbox.first?.id, id1, "outbox ordered by id ASC")
        r.expect(outbox.first?.accountID, "acct1", "outbox account id round-trips")
        r.expect(outbox.first?.entityID, "c1", "outbox first op entity")
        r.expect(outbox.first?.payloadJSON, "{\"a\":1}", "outbox payload round-trips")
        r.expectTrue(outbox[1].lastKnownRevisionDate == nil, "outbox null revision round-trips")
        r.expect(try await store.outbox(accountID: "acct1").count, 2,
                 "account-scoped outbox returns only account 1")
        r.expect(try await store.outbox(accountID: "acct2").count, 1,
                 "account-scoped outbox returns only account 2")
        do {
            try await store.clearOutbox(id: id3, accountID: "acct1")
            r.expectTrue(false, "wrong account must not clear another account's row")
        } catch let e as VaultStoreError {
            r.expect(e, .notFound, "wrong-account clear is rejected")
        }
        r.expect(try await store.outbox(accountID: "acct2").count, 1,
                 "wrong-account clear leaves row queued")
        try await store.clearOutbox(id: id3, accountID: "acct2")

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

        // --- ON DELETE CASCADE: account + cipher + cipher_uri; delete cipher -> uri gone ---
        let parent = makeRow(id: "cascade1", name: "Cascade",
                             search: "Cascade cascade.example.com",
                             revision: "2026-06-14T00:00:00Z")
        try await store.upsertCiphers([parent])
        try await store.upsertCipherURIs([
            CipherURIRow(id: "u1", accountID: "acct1", cipherID: "cascade1",
                         encURI: "2.uriEnc", matchType: 0),
            CipherURIRow(id: "u2", accountID: "acct1", cipherID: "cascade1",
                         encURI: "2.uri2Enc", matchType: nil),
        ])
        r.expect((try await store.cipherURIs(cipherID: "cascade1", accountID: "acct1")).count, 2,
                 "cipher_uri rows inserted")
        r.expect((try await store.cipherURIs(cipherID: "cascade1", accountID: "acct1")).first?.matchType, 0,
                 "cipher_uri matchType round-trips")
        r.expectTrue((try await store.cipherURIs(cipherID: "cascade1", accountID: "acct1"))[1].matchType == nil,
                     "cipher_uri null matchType round-trips")

        try await store.deleteCipher(id: "cascade1", accountID: "acct1")
        r.expect((try await store.cipherURIs(cipherID: "cascade1", accountID: "acct1")).count, 0,
                 "ON DELETE CASCADE: cipher_uri removed with parent cipher")
    } catch {
        r.expectTrue(false, "VaultStore session threw: \(error)")
    }

    // sqlite3_key installs a candidate key lazily. VaultStore forces a sqlite_master
    // page read during init so a wrong key is rejected immediately on reopen.
    do {
        _ = try VaultStore(databaseURL: dbURL, passphrase: Data(repeating: 0xA5, count: 32))
        r.expectTrue(false, "reopen DB with wrong key should fail")
    } catch let error as VaultStoreError {
        if case .keyValidationFailed = error {
            r.expectTrue(true, "reopen DB with wrong key fails validation")
        } else {
            r.expectTrue(false, "wrong key returned unexpected error: \(error)")
        }
    } catch {
        r.expectTrue(false, "wrong key returned non-VaultStoreError: \(error)")
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

    // --- One-time migration: legacy plaintext SQLite + uncheckpointed WAL ---
    let legacyURL = FileManager.default.temporaryDirectory
        .appendingPathComponent("vaultstore-legacy-\(UUID().uuidString).sqlite")
    let legacyPassphrase = Data((32..<64).map { UInt8($0) })
    let legacySentinel = "legacy-search-\(UUID().uuidString)"
    defer {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(
                at: URL(fileURLWithPath: legacyURL.path + suffix)
            )
        }
        try? FileManager.default.removeItem(
            at: legacyURL.deletingLastPathComponent().appendingPathComponent(
                ".\(legacyURL.lastPathComponent).migration.lock"
            )
        )
    }

    do {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        child.arguments = ["--create-plaintext-wal", legacyURL.path, legacySentinel]
        try child.run()
        child.waitUntilExit()
        r.expect(child.terminationStatus, 0, "create crashed legacy plaintext WAL fixture")

        let plaintextHeader = try Data(contentsOf: legacyURL).prefix(16)
        r.expect(Data(plaintextHeader), Data("SQLite format 3\0".utf8),
                 "legacy fixture starts with plaintext SQLite header")
        let legacyWALURL = URL(fileURLWithPath: legacyURL.path + "-wal")
        r.expectTrue(FileManager.default.fileExists(atPath: legacyWALURL.path),
                     "crashed legacy fixture leaves WAL")
        let legacyNeedle = Data(legacySentinel.utf8)
        let plaintextArtifacts = [legacyURL, legacyWALURL]
        r.expectTrue(plaintextArtifacts.contains { url in
            (try? Data(contentsOf: url).range(of: legacyNeedle)) != nil
        }, "legacy search_text is demonstrably plaintext before migration")

        do {
            let migrated = try VaultStore(
                databaseURL: legacyURL,
                passphrase: legacyPassphrase
            )
            let row = try await migrated.cipher(id: "legacy-cipher", accountID: "legacy-acct")
            r.expect(row?.searchText, legacySentinel,
                     "plaintext WAL row survives SQLCipher migration")
            r.expect(try await migrated.cipherURIs(
                cipherID: "legacy-cipher",
                accountID: "legacy-acct"
            ).count, 1, "legacy child table without index migrates before index creation")
            r.expectTrue(try await migrated.cipher(
                id: "orphan-cipher", accountID: "missing-account"
            ) == nil, "orphan legacy cipher is excluded from live account data")

            try await migrated.upsertAccounts([
                AccountRow(id: "cloned-account", email: "clone@example.com")
            ])
            try await migrated.upsertCiphers([
                makeRow(id: "legacy-cipher", account: "cloned-account", name: "Clone",
                        search: "clone", revision: "2026-07-16T00:00:00Z")
            ])
            r.expectTrue(try await migrated.cipher(
                id: "legacy-cipher", accountID: "legacy-acct"
            ) != nil, "migrated global row remains under its persisted account")
            r.expectTrue(try await migrated.cipher(
                id: "legacy-cipher", accountID: "cloned-account"
            ) != nil, "migrated schema accepts same UUID under another account")
            let migratedOutbox = try await migrated.outbox(accountID: "legacy-acct")
            r.expect(migratedOutbox.count, 1,
                     "legacy outbox row with existing cipher is backfilled")
            r.expect(migratedOutbox.first?.accountID, "legacy-acct",
                     "legacy outbox row inherits cipher account")
            r.expect(migratedOutbox.first?.entityID, "legacy-cipher",
                     "backfilled legacy outbox keeps entity")
            r.expectTrue(!(try await migrated.isPasskeyImportCompleted(
                id: "legacy-receipt",
                accountID: "legacy-acct"
            )), "legacy outbox migration preserves pending receipt state")
            let linkedOperation = OutboxRow(
                accountID: "legacy-acct",
                opType: "update",
                entityType: "cipher",
                entityID: "legacy-cipher",
                payloadJSON: "{}",
                lastKnownRevisionDate: "2026-07-15T00:00:00Z"
            )
            r.expectTrue(try await migrated.enqueueOutboxForPasskeyImport(
                receiptID: "legacy-receipt",
                accountID: "legacy-acct",
                operation: linkedOperation
            ), "legacy receipt remains linked to its migrated outbox row")
            r.expect(try await migrated.outbox(accountID: "legacy-acct").count, 1,
                     "replaying linked receipt does not enqueue a duplicate")
            r.expect(try await migrated.outbox().count, 1,
                     "unattributable legacy outbox row is not sendable")
            let postMigrationID = try await migrated.enqueueOutbox(OutboxRow(
                accountID: "legacy-acct", opType: "update", entityType: "cipher",
                entityID: "legacy-cipher", payloadJSON: "{}"))
            r.expectTrue(postMigrationID > (migratedOutbox.first?.id ?? 0),
                         "outbox autoincrement continues after schema migration")
            try await migrated.clearOutbox(id: postMigrationID, accountID: "legacy-acct")

            for (url, label) in [
                (legacyURL, "migrated database"),
                (URL(fileURLWithPath: legacyURL.path + "-wal"), "migrated WAL"),
                (URL(fileURLWithPath: legacyURL.path + "-shm"), "migrated SHM"),
            ] {
                r.expectTrue(FileManager.default.fileExists(atPath: url.path),
                             "\(label) exists for encryption inspection")
                let bytes = try Data(contentsOf: url)
                r.expectTrue(bytes.range(of: legacyNeedle) == nil,
                             "legacy search_text absent from \(label)")
            }
        }

        do {
            _ = try VaultStore(
                databaseURL: legacyURL,
                passphrase: Data(repeating: 0x5A, count: 32)
            )
            r.expectTrue(false, "migrated database rejects wrong key")
        } catch let error as VaultStoreError {
            if case .keyValidationFailed = error {
                r.expectTrue(true, "migrated database rejects wrong key")
            } else {
                r.expectTrue(false, "migrated database wrong-key error: \(error)")
            }
        }

        r.expect(encryptedUserVersion(
            at: legacyURL.path,
            passphrase: legacyPassphrase
        ), 7, "plaintext migration preserves PRAGMA user_version")
        r.expect(encryptedScalarInt(
            at: legacyURL.path,
            passphrase: legacyPassphrase,
            sql: "SELECT count(*) FROM outbox_quarantine;"
        ), 2, "unattributable/orphan legacy outbox rows are quarantined")
        r.expect(encryptedScalarInt(
            at: legacyURL.path,
            passphrase: legacyPassphrase,
            sql: "SELECT count(*) FROM pragma_table_info('cipher') WHERE pk > 0;"
        ), 2, "legacy cipher table migrates to a two-column primary key")
        r.expect(encryptedScalarInt(
            at: legacyURL.path,
            passphrase: legacyPassphrase,
            sql: "SELECT count(*) FROM sqlite_master "
                + "WHERE type='table' AND name='cipher_migration_quarantine';"
        ), 1, "orphan migration creates a durable payload quarantine table")
        r.expect(encryptedScalarInt(
            at: legacyURL.path,
            passphrase: legacyPassphrase,
            sql: "SELECT count(*) FROM cipher_migration_quarantine;"
        ), 1, "orphan migration copies one complete cipher row")
        r.expect(encryptedScalarInt(
            at: legacyURL.path,
            passphrase: legacyPassphrase,
            sql: "SELECT count(*) FROM cipher_migration_quarantine "
                + "WHERE id='orphan-cipher' AND enc_blob='2.OrphanBlob' "
                + "AND search_text='orphan-quarantine-secret';"
        ), 1, "orphan migration quarantine preserves the complete encrypted payload")
        r.expect(encryptedScalarInt(
            at: legacyURL.path,
            passphrase: legacyPassphrase,
            sql: "SELECT count(*) FROM pragma_foreign_key_list('outbox') "
                + "WHERE \"table\"='account' AND \"from\"='account_id' "
                + "AND on_delete='CASCADE';"
        ), 1, "migrated outbox has account cascade foreign key")
        r.expect(encryptedScalarInt(
            at: legacyURL.path,
            passphrase: legacyPassphrase,
            sql: "SELECT count(*) FROM pragma_foreign_key_list('passkey_import_receipt') "
                + "WHERE \"table\"='outbox' AND \"from\"='outbox_id';"
        ), 1, "receipt foreign key still targets rebuilt outbox")
        r.expect(encryptedScalarInt(
            at: legacyURL.path,
            passphrase: legacyPassphrase,
            sql: "SELECT count(*) FROM pragma_index_list('outbox') "
                + "WHERE name='idx_outbox_account';"
        ), 1, "migrated outbox has account index")

        do {
            let reopened = try VaultStore(
                databaseURL: legacyURL,
                passphrase: legacyPassphrase
            )
            r.expect((try await reopened.cipher(id: "legacy-cipher", accountID: "legacy-acct"))?.searchText,
                     legacySentinel,
                     "migrated database reopens with correct key")
        }
    } catch {
        r.expectTrue(false, "plaintext migration test threw: \(error)")
    }

    // --- Migration crash recovery: missing live file + retained plaintext backup ---
    let recoveryURL = FileManager.default.temporaryDirectory
        .appendingPathComponent("vaultstore-recovery-\(UUID().uuidString).sqlite")
    let recoveryKey = Data((64..<96).map { UInt8($0) })
    let recoverySentinel = "recovery-search-\(UUID().uuidString)"
    let recoveryBackupURL = recoveryURL.deletingLastPathComponent().appendingPathComponent(
        ".\(recoveryURL.lastPathComponent).plaintext-backup-fixture"
    )
    defer {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(
                at: URL(fileURLWithPath: recoveryURL.path + suffix)
            )
            try? FileManager.default.removeItem(
                at: URL(fileURLWithPath: recoveryBackupURL.path + suffix)
            )
        }
        let prefix = ".\(recoveryURL.lastPathComponent).plaintext-backup-"
        if let files = try? FileManager.default.contentsOfDirectory(
            at: recoveryURL.deletingLastPathComponent(),
            includingPropertiesForKeys: nil
        ) {
            for file in files where file.lastPathComponent.hasPrefix(prefix) {
                try? FileManager.default.removeItem(at: file)
            }
        }
        try? FileManager.default.removeItem(
            at: recoveryURL.deletingLastPathComponent().appendingPathComponent(
                ".\(recoveryURL.lastPathComponent).migration.lock"
            )
        )
    }

    do {
        r.expect(createLegacyPlaintextDatabase(
            at: recoveryBackupURL.path,
            sentinel: recoverySentinel,
            closeOnSuccess: true
        ), 0, "create retained plaintext backup fixture")
        r.expectTrue(!FileManager.default.fileExists(atPath: recoveryURL.path),
                     "crash-recovery fixture has no live database")

        do {
            let recovered = try VaultStore(
                databaseURL: recoveryURL,
                passphrase: recoveryKey
            )
            r.expect((try await recovered.cipher(id: "legacy-cipher", accountID: "legacy-acct"))?.searchText,
                     recoverySentinel,
                     "missing live database restores and migrates plaintext backup")
        }
        r.expectTrue(!FileManager.default.fileExists(atPath: recoveryBackupURL.path),
                     "restored plaintext backup removed after encrypted validation")

        // Simulate termination after atomic replacement but before backup cleanup.
        let staleBackupURL = recoveryURL.deletingLastPathComponent().appendingPathComponent(
            ".\(recoveryURL.lastPathComponent).plaintext-backup-stale"
        )
        var stalePlaintext = Data("SQLite format 3\0".utf8)
        stalePlaintext.append(Data(recoverySentinel.utf8))
        try stalePlaintext.write(to: staleBackupURL, options: .atomic)

        do {
            let reopened = try VaultStore(
                databaseURL: recoveryURL,
                passphrase: recoveryKey
            )
            r.expect((try await reopened.cipher(id: "legacy-cipher", accountID: "legacy-acct"))?.searchText,
                     recoverySentinel,
                     "valid encrypted live database wins over stale plaintext backup")
        }
        r.expectTrue(!FileManager.default.fileExists(atPath: staleBackupURL.path),
                     "stale plaintext backup removed only after encrypted validation")
    } catch {
        r.expectTrue(false, "migration backup recovery test threw: \(error)")
    }

    return r.summary()
}

if CommandLine.arguments.count == 4,
   CommandLine.arguments[1] == "--create-plaintext-wal" {
    let status = createLegacyPlaintextDatabase(
        at: CommandLine.arguments[2],
        sentinel: CommandLine.arguments[3],
        closeOnSuccess: false
    )
    _exit(status)
}

if CommandLine.arguments.count == 4,
   CommandLine.arguments[1] == "--hold-migration-lock" {
    if let microseconds = useconds_t(CommandLine.arguments[3]) {
        _exit(holdMigrationLock(
            at: CommandLine.arguments[2],
            microseconds: microseconds
        ))
    }
    _exit(22)
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
