import Foundation
import SQLCipher
import VaultStore

func checkOutboxRecovery(_ runner: inout TestRunner) async {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "vaultstore-outbox-\(UUID().uuidString)", directoryHint: .isDirectory)
    defer { try? FileManager.default.removeItem(at: directory) }
    let database = directory.appending(path: "vault.sqlite")
    let passphrase = Data(repeating: 0x5B, count: 32)
    let original = makeRow(id: "conflicted", name: "Local", revision: "2026-11-24T00:00:00Z")
    let server = makeRow(id: original.id, name: "Server", revision: "2026-11-23T00:00:00Z")
    let copy = makeRow(id: "new-copy", name: "Local", revision: original.revisionDate)
    let foreign = makeRow(id: original.id, account: "acct2", name: "Other", revision: original.revisionDate)
    let update = OutboxRow(accountID: original.accountID, opType: "update", entityType: "cipher",
                           entityID: original.id, payloadJSON: "{}", lastKnownRevisionDate: server.revisionDate)
    let createCopy = OutboxRow(accountID: copy.accountID, opType: "create", entityType: "cipher",
                               entityID: copy.id, payloadJSON: "{}")

    do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let store = try VaultStore(databaseURL: database, passphrase: passphrase)
        try await store.upsertAccounts([AccountRow(id: original.accountID), AccountRow(id: foreign.accountID)])
        try await store.upsertCiphers([original, foreign])
        runner.expectTrue(try await store.enqueueOutboxForPasskeyImport(receiptID: "keep-receipt",
                                                                        accountID: original.accountID, operation: update),
                          "interrupted receipt points to the conflicting update")
        let otherID = try await store.enqueueOutbox(OutboxRow(accountID: foreign.accountID, opType: "update",
                                                              entityType: "cipher", entityID: original.id, payloadJSON: "{}"))
        guard let initial = try await store.outbox(accountID: original.accountID).first, let initialID = initial.id else {
            runner.expectTrue(false, "conflict fixture has a queued update")
            return
        }

        do {
            try await store.setOutboxIssue(id: otherID, accountID: original.accountID, issue: .deleteConflict)
            runner.expectTrue(false, "issue cannot be set for a different account")
        } catch VaultStoreError.notFound {
            runner.expectTrue(true, "issue updates enforce the owning account")
        }

        runner.expectTrue(try await store.setOutboxIssue(expected: initial, issue: .updateConflict),
                          "current operation accepts a conflict issue")
        let reopened = try VaultStore(databaseURL: database, passphrase: passphrase)
        runner.expectTrue(!(try await reopened.setOutboxIssue(expected: initial, issue: .updateConflict)),
                          "stale operation cannot acquire the same issue on a second connection")
        guard let blocked = try await reopened.outbox(accountID: original.accountID).first else {
            runner.expectTrue(false, "conflicting update survives database reopen")
            return
        }
        runner.expect(blocked.issue, .updateConflict, "issue persists across database connections")

        do {
            try await store.resolveCipherOutbox(expected: initial, serverCipher: server)
            runner.expectTrue(false, "stale recovery must not discard the local edit")
        } catch VaultStoreError.notFound {
            runner.expect(try await store.cipher(id: original.id, accountID: original.accountID), original,
                          "stale recovery leaves the optimistic version intact")
        }

        do {
            try await store.resolveCipherOutbox(expected: blocked, serverCipher: foreign)
            runner.expectTrue(false, "recovery must not install another account's cipher")
        } catch VaultStoreError.stepFailed {
            runner.expect(try await store.cipher(id: foreign.id, accountID: foreign.accountID), foreign,
                          "recovery leaves the other account's cipher intact")
        }

        try executeOutboxFixtureSQL(database, passphrase: passphrase, sql: """
        CREATE TRIGGER fail_recovery BEFORE DELETE ON outbox
        WHEN OLD.account_id='acct1' AND OLD.entity_id='conflicted'
        BEGIN SELECT RAISE(ABORT, 'Outbox recovery test failure'); END;
        """)
        do {
            try await store.resolveCipherOutbox(expected: blocked, serverCipher: server, copy: copy, copyOperation: createCopy)
            runner.expectTrue(false, "injected failure must abort recovery")
        } catch VaultStoreError.stepFailed {
            runner.expect(try await store.outbox(accountID: original.accountID), [blocked],
                          "failed recovery rolls back the new create and retains the original issue")
            runner.expect(try await store.cipher(id: original.id, accountID: original.accountID), original,
                          "failed recovery rolls back server replacement")
            runner.expect(try await store.cipher(id: copy.id, accountID: copy.accountID), nil,
                          "failed recovery rolls back the local copy")
            runner.expectTrue(!(try await store.isPasskeyImportCompleted(id: "keep-receipt", accountID: original.accountID)),
                              "failed recovery rolls back receipt completion")
        }
        try executeOutboxFixtureSQL(database, passphrase: passphrase, sql: "DROP TRIGGER fail_recovery;")

        try await reopened.resolveCipherOutbox(expected: blocked, serverCipher: server, copy: copy, copyOperation: createCopy)
        runner.expect(try await store.cipher(id: original.id, accountID: original.accountID), server,
                      "explicit server choice replaces a newer optimistic timestamp")
        runner.expect(try await store.cipher(id: copy.id, accountID: copy.accountID), copy,
                      "keep a copy preserves the local version under an independent id")
        let pendingCopies = try await store.outbox(accountID: original.accountID)
        runner.expect(pendingCopies.map(\.entityID), [copy.id], "only the independent create remains queued")
        runner.expect(pendingCopies.first?.issue, nil, "independent create starts as a normal pending write")
        runner.expect(encryptedScalarInt(at: database.path, passphrase: passphrase, sql: """
        SELECT count(*) FROM passkey_import_receipt AS r JOIN outbox AS o ON o.id=r.outbox_id
        WHERE r.account_id='acct1' AND r.id='keep-receipt' AND r.completed=1 AND o.entity_id='new-copy';
        """), 1, "receipt is reattached to the staged copy and will not replay")
        runner.expectTrue(!(try await store.enqueueOutboxForPasskeyImport(receiptID: "keep-receipt",
                                                                         accountID: original.accountID, operation: update)),
                          "replaying the original handoff cannot alter the staged copy")
        runner.expect((try await store.outbox(accountID: foreign.accountID)).compactMap(\.id), [otherID],
                      "recovery preserves the other account's outbox")
        runner.expect((try await store.outbox(accountID: foreign.accountID)).first?.issue, nil,
                      "marking an issue never changes another account's outbox")

        if let pendingCopy = pendingCopies.first, let copyID = pendingCopy.id {
            let otherPending = try await store.enqueueOutbox(update)
            do {
                try await store.finalizeOutboxWrite(id: copyID, accountID: copy.accountID,
                                                    localEntityID: copy.id, serverCipher: server)
                runner.expectTrue(false, "reconciling a create cannot overwrite another locally pending identity")
            } catch VaultStoreError.stepFailed {
                runner.expect(try await store.cipher(id: copy.id, accountID: copy.accountID), copy,
                              "failed reconciliation retains the optimistic copy")
                runner.expect((try await store.outbox(accountID: copy.accountID)).compactMap(\.id), [copyID, otherPending],
                              "failed reconciliation retains both outbox operations")
            }
            try await store.clearOutbox(id: otherPending, accountID: copy.accountID)
            try await store.clearOutbox(id: copyID, accountID: copy.accountID)
        }

        runner.expectTrue(try await store.enqueueOutboxForPasskeyImport(receiptID: "discard-receipt",
                                                                        accountID: original.accountID, operation: update),
                          "discard fixture starts with a pending passkey receipt")
        guard let discard = try await store.outbox(accountID: original.accountID).first, let discardID = discard.id else {
            runner.expectTrue(false, "discard fixture has a queued operation")
            return
        }
        runner.expectTrue(discardID > initialID, "replaced operations never reuse the original id")
        try await store.resolveCipherOutbox(expected: discard, serverCipher: nil)
        runner.expect(try await store.cipher(id: original.id, accountID: original.accountID), nil,
                      "accepting server absence drops the local version")
        runner.expect(try await store.outbox(accountID: original.accountID), [],
                      "accepting server absence removes only its queued operation")
        runner.expectTrue(try await store.isPasskeyImportCompleted(id: "discard-receipt", accountID: original.accountID),
                          "discard completes the linked receipt instead of re-enqueueing the handoff")

        let unconfirmed = OutboxRow(accountID: copy.accountID, opType: "create", entityType: "cipher",
                                    entityID: copy.id, payloadJSON: "{\"submitted\":true}", issue: .unconfirmedCreate)
        try await store.persistOfflineCipherMutation(operation: unconfirmed, localCipher: copy)
        let blockedCreate = try await reopened.outbox(accountID: copy.accountID)
        runner.expect(blockedCreate.map(\.issue), [.unconfirmedCreate],
                      "staging a create durably records its dispatch issue")
        let queuedUpdate = OutboxRow(accountID: copy.accountID, opType: "update", entityType: "cipher",
                                     entityID: copy.id, payloadJSON: "{\"modified\":true}")
        let editedCopy = makeRow(id: copy.id, name: "Edited", revision: copy.revisionDate)
        do {
            try await store.persistOfflineCipherMutation(operation: queuedUpdate, localCipher: editedCopy)
            runner.expectTrue(false, "a normal edit must not change a submitted create payload")
        } catch VaultStoreError.stepFailed {
            runner.expect(try await store.cipher(id: copy.id, accountID: copy.accountID), copy,
                          "blocked local edit leaves the original ciphertext intact")
        }
        do {
            try await store.enqueueOutboxForPasskeyImport(receiptID: "blocked-passkey", accountID: copy.accountID,
                                                          operation: queuedUpdate, localCipher: editedCopy)
            runner.expectTrue(false, "a passkey import must not change a submitted create payload")
        } catch VaultStoreError.stepFailed {
            runner.expect(try await store.outbox(accountID: copy.accountID), blockedCreate,
                          "both mutation paths preserve the exact blocked outbox row")
        }
    } catch {
        runner.expectTrue(false, "outbox recovery fixture threw: \(error)")
    }
}

private func executeOutboxFixtureSQL(_ database: URL, passphrase: Data, sql: String) throws {
    var handle: OpaquePointer?
    let status = sqlite3_open_v2(database.path, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil)
    defer { if let handle { sqlite3_close(handle) } }
    guard status == SQLITE_OK, let handle else { throw VaultStoreError.openFailed }
    guard passphrase.withUnsafeBytes({ sqlite3_key(handle, $0.baseAddress, Int32($0.count)) }) == SQLITE_OK,
          sqlite3_exec(handle, sql, nil, nil, nil) == SQLITE_OK else {
        throw VaultStoreError.stepFailed("could not configure outbox recovery fixture")
    }
}
