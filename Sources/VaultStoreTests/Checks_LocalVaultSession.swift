import Foundation
import SQLCipher
import VaultStore

func checkLocalVaultSessionPersistence(_ runner: inout TestRunner) async {
    let nonce = UUID().uuidString
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "vaultstore-session-\(nonce)", directoryHint: .isDirectory)
    defer { try? FileManager.default.removeItem(at: directory) }
    let database = directory.appending(path: "vault.sqlite")
    let passphrase = Data(repeating: 0x6A, count: 32)
    let firstAccountID = "https://vault.example.test/caf\u{00E9}|owner@example.test"
    let secondAccountID = "https://vault.example.test/second|owner@example.test"
    let firstAccount = AccountRow(id: firstAccountID, kdfIters: 600_000, encUserKey: "test-protected-key-a")
    let secondAccount = AccountRow(id: secondAccountID, kdfIters: 650_000, encUserKey: "test-protected-key-b")
    let firstVerifier = "test-verifier-\(nonce)"
    let firstRefreshToken = "test-refresh-\(nonce)"
    let rotatedRefresh = "test-rotated-\(nonce)\u{0}with-suffix"
    let firstRememberedDevice = "test-remembered-\(nonce)"
    let secondRememberedDevice = "test-other-remembered-\(nonce)"
    let biometricEnvelope = Data("test-envelope-\(nonce)\u{0}with-suffix".utf8)
    let first = LocalVaultSession(accountID: firstAccountID, id: UUID(), localAuthHash: firstVerifier,
                                  refreshToken: firstRefreshToken)
    let refreshedFirst = LocalVaultSession(accountID: firstAccountID, id: first.id, localAuthHash: firstVerifier,
                                           refreshToken: rotatedRefresh)
    let second = LocalVaultSession(accountID: secondAccountID, id: UUID(), localAuthHash: "other-verifier",
                                   refreshToken: nil)
    let fixtureSecrets = [firstVerifier, firstRefreshToken, firstRememberedDevice, rotatedRefresh].map { Data($0.utf8) }
        + [biometricEnvelope]
    let cachedItem = makeRow(id: "pending-item", account: firstAccountID, name: "Cached",
                             revision: "2026-11-23T00:00:00Z")

    do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        do {
            let store = try VaultStore(databaseURL: database, passphrase: passphrase)
            try await store.upsertAccounts([secondAccount])
            runner.expect(try await store.localVaultSession(), nil, "account rows do not imply a standalone session")
            runner.expect(try await store.setLocalBiometricEnvelope(biometricEnvelope, accountID: secondAccountID, sessionID: second.id),
                          false, "biometric enrollment does not create a standalone session")
            try await store.installLocalVaultSession(first, rememberedDevice: firstRememberedDevice, account: firstAccount)
            runner.expect(try await store.account(id: firstAccountID), firstAccount, "login can publish new account metadata with the session")
            runner.expect(try await store.setLocalBiometricEnvelope(biometricEnvelope, accountID: firstAccountID, sessionID: first.id),
                          true, "biometric enrollment updates the current session")
            try await store.upsertCiphers([cachedItem])
            let pendingID = try await store.enqueueOutbox(OutboxRow(accountID: firstAccountID, opType: "update",
                                                                    entityType: "cipher", entityID: cachedItem.id,
                                                                    payloadJSON: "{}"))

            let orphan = LocalVaultSession(accountID: "missing-account", id: UUID(), localAuthHash: firstVerifier,
                                           refreshToken: nil)
            do {
                try await store.installLocalVaultSession(orphan, rememberedDevice: secondRememberedDevice)
                runner.expectTrue(false, "a standalone session requires an existing account")
            } catch VaultStoreError.stepFailed {
                runner.expect(try await store.localVaultSession(), first, "invalid account leaves the active session intact")
            }

            do {
                let updatedFirst = AccountRow(id: firstAccountID, kdfIters: 700_000, encUserKey: "test-new-first-key")
                try await store.installLocalVaultSession(second, rememberedDevice: nil, account: updatedFirst)
                runner.expectTrue(false, "a matching account row is required for atomic publication")
            } catch VaultStoreError.stepFailed {
                runner.expect(try await store.localVaultSession(), first, "mismatched account cannot publish a session")
                runner.expect(try await store.account(id: firstAccountID), firstAccount, "mismatch cannot overwrite account metadata")
                runner.expect(try await store.cipher(id: cachedItem.id, accountID: firstAccountID), cachedItem,
                              "mismatch preserves the cached item")
                runner.expect((try await store.outbox(accountID: firstAccountID)).compactMap(\.id), [pendingID],
                              "mismatch preserves the pending write")
            }

            let differentBytes = "https://vault.example.test/cafe\u{0301}|owner@example.test"
            let differentRow = AccountRow(id: differentBytes, kdfIters: 700_000, encUserKey: "test-ambiguous-key")
            do {
                try await store.installLocalVaultSession(first, rememberedDevice: nil, account: differentRow)
                runner.expectTrue(false, "the account id must match the exact database key")
            } catch VaultStoreError.stepFailed {
                runner.expect(try await store.account(id: differentBytes), nil, "Unicode-equivalent text cannot create a different account")
            }

            let malformedID = firstAccountID + "\u{0}extra"
            let malformedSession = LocalVaultSession(accountID: malformedID, id: UUID(), localAuthHash: firstVerifier,
                                                       refreshToken: nil)
            do {
                let malformedAccount = AccountRow(id: malformedID, kdfIters: 700_000)
                try await store.installLocalVaultSession(malformedSession, rememberedDevice: nil, account: malformedAccount)
                runner.expectTrue(false, "an account id cannot contain a null byte")
            } catch VaultStoreError.stepFailed {
                runner.expect(try await store.account(id: firstAccountID), firstAccount,
                              "a malformed account id cannot overwrite another account")
            }

            try executeLocalSessionFixtureSQL(database, passphrase: passphrase, sql: """
            CREATE TRIGGER fail_remembered_device BEFORE INSERT ON local_vault_remembered_device
            BEGIN SELECT RAISE(ABORT, 'Remembered device test failure'); END;
            """)
            do {
                let modifiedMetadata = AccountRow(id: secondAccountID, kdfIters: 700_000, encUserKey: "test-new-protected-key")
                try await store.installLocalVaultSession(second, rememberedDevice: secondRememberedDevice, account: modifiedMetadata)
                runner.expectTrue(false, "a failed remembered-device write must abort session publication")
            } catch VaultStoreError.stepFailed {
                runner.expect(try await store.localVaultSession(), first, "failed batch keeps the previous active session")
                runner.expect(try await store.localBiometricEnvelope(accountID: firstAccountID, sessionID: first.id), biometricEnvelope,
                              "failed batch keeps the previous biometric envelope")
                runner.expect(try await store.account(id: secondAccountID), secondAccount, "failed batch rolls back account metadata")
                runner.expect(try await store.localVaultRememberedDevice(accountID: secondAccountID), nil,
                              "failed batch publishes no remembered device")
            }
            try executeLocalSessionFixtureSQL(database, passphrase: passphrase, sql: "DROP TRIGGER fail_remembered_device;")
            let parallelConnection = try VaultStore(databaseURL: database, passphrase: passphrase)
            let staleSession = try await parallelConnection.localVaultSession()
            runner.expect(staleSession, first, "the second connection reads the same session and original token")
            runner.expect(try await store.updateLocalVaultRefreshToken(rotatedRefresh, accountID: firstAccountID,
                                                                       sessionID: first.id, expectedToken: firstRefreshToken),
                          true, "the current session can rotate its refresh token")
            runner.expect(try await parallelConnection.updateLocalVaultRefreshToken("stale-refresh", accountID: firstAccountID,
                                                                                    sessionID: first.id, expectedToken: staleSession?.refreshToken),
                          false, "a stale refresh of the same account and session cannot overwrite the rotated token")
            runner.expect(try await parallelConnection.updateLocalVaultRefreshToken("partial-refresh", accountID: firstAccountID,
                                                                                    sessionID: first.id, expectedToken: String(rotatedRefresh.prefix { $0 != "\u{0}" })),
                          false, "a truncated refresh token cannot match the stored token")
            runner.expect(try await parallelConnection.localVaultSession(), refreshedFirst,
                          "failed conditional updates leave the rotated token unchanged")
            runner.expect(try await parallelConnection.localBiometricEnvelope(accountID: firstAccountID, sessionID: first.id), biometricEnvelope,
                          "refresh rotation preserves the current biometric envelope across connections")
            runner.expect(try await parallelConnection.localBiometricEnvelope(accountID: secondAccountID, sessionID: first.id), nil,
                          "biometric envelope reads require the exact account")
            runner.expect(try await parallelConnection.setLocalBiometricEnvelope(nil, accountID: differentBytes, sessionID: first.id),
                          false, "biometric revocation cannot match a canonically equivalent account with different bytes")

            for suffix in ["", "-wal", "-shm"] {
                let bytes = try Data(contentsOf: URL(fileURLWithPath: database.path + suffix))
                runner.expectTrue(!bytes.isEmpty && fixtureSecrets.allSatisfy { bytes.range(of: $0) == nil },
                                  "standalone credentials are absent from raw database\(suffix) bytes")
            }
        }

        let checkpointed = try Data(contentsOf: database)
        runner.expectTrue(fixtureSecrets.allSatisfy { checkpointed.range(of: $0) == nil },
                          "standalone credentials remain sealed after the WAL is checkpointed")

        do {
            let reopened = try VaultStore(databaseURL: database, passphrase: passphrase)
            runner.expect(try await reopened.localVaultSession(), refreshedFirst, "a new connection restores the exact rotated session")
            runner.expect(try await reopened.localBiometricEnvelope(accountID: firstAccountID, sessionID: first.id), biometricEnvelope,
                          "the biometric envelope survives reopening")
            runner.expect(try await reopened.localVaultRememberedDevice(accountID: firstAccountID), firstRememberedDevice,
                          "the remembered device survives reopening")
            runner.expect(try await reopened.localVaultRememberedDevice(accountID: secondAccountID), nil,
                          "the same email at another server path does not share the remembered device")

            let replacement = LocalVaultSession(accountID: firstAccountID, id: UUID(), localAuthHash: firstVerifier,
                                                refreshToken: nil)
            try await reopened.installLocalVaultSession(replacement, rememberedDevice: nil)
            runner.expect(try await reopened.localVaultSession(), replacement, "a nil refresh does not inherit the previous token")
            runner.expect(try await reopened.localBiometricEnvelope(accountID: firstAccountID, sessionID: replacement.id), nil,
                          "a new session for the same account does not inherit biometric enrollment")
            runner.expect(try await reopened.localBiometricEnvelope(accountID: firstAccountID, sessionID: first.id), nil,
                          "a retired session cannot read a biometric envelope")
            runner.expect(try await reopened.setLocalBiometricEnvelope(biometricEnvelope, accountID: firstAccountID, sessionID: first.id),
                          false, "late biometric enrollment cannot update a replaced session")
            runner.expect(try await reopened.localVaultRememberedDevice(accountID: firstAccountID), firstRememberedDevice,
                          "a login without a new remembered device preserves the prior one")
            runner.expect(try await reopened.updateLocalVaultRefreshToken("stale", accountID: firstAccountID,
                                                                          sessionID: first.id, expectedToken: nil),
                          false, "refresh cannot update a replaced session for the same account")
            runner.expect(try await reopened.removeLocalVaultSession(accountID: firstAccountID, sessionID: first.id),
                          false, "logout cannot remove a newer session for the same account")
            runner.expect(try await reopened.updateLocalVaultRefreshToken("wrong", accountID: secondAccountID,
                                                                          sessionID: replacement.id, expectedToken: nil),
                          false, "refresh requires both the session UUID and the exact account")
            runner.expect(try await reopened.removeLocalVaultSession(accountID: secondAccountID, sessionID: replacement.id),
                          false, "logout requires both the session UUID and the exact account")
            runner.expect(try await reopened.updateLocalVaultRefreshToken("from-nil", accountID: firstAccountID,
                                                                          sessionID: replacement.id, expectedToken: nil),
                          true, "a nil expected value matches a session with no previous token")
            runner.expect(try await reopened.updateLocalVaultRefreshToken("stale-nil", accountID: firstAccountID,
                                                                          sessionID: replacement.id, expectedToken: nil),
                          false, "a nil expected value does not match an existing token")
            runner.expect(try await reopened.localVaultSession()?.refreshToken, "from-nil", "the new token remains stored")
            try await reopened.installLocalVaultSession(second, rememberedDevice: secondRememberedDevice)
            runner.expect(try await reopened.localVaultSession(), second, "switching accounts replaces the singleton session")
            try await reopened.removeLocalVaultRememberedDevice(accountID: firstAccountID)
            runner.expect(try await reopened.localVaultRememberedDevice(accountID: firstAccountID), nil,
                          "a rejected remembered device can be removed independently")
            runner.expect(try await reopened.localVaultRememberedDevice(accountID: secondAccountID), secondRememberedDevice,
                          "removing one remembered device preserves the other account's device")
            runner.expect(try await reopened.setLocalBiometricEnvelope(biometricEnvelope, accountID: secondAccountID, sessionID: second.id),
                          true, "the new account can enroll separately")
            runner.expect(try await reopened.setLocalBiometricEnvelope(nil, accountID: secondAccountID, sessionID: second.id),
                          true, "biometric revocation updates the current session")
            runner.expect(try await reopened.localBiometricEnvelope(accountID: secondAccountID, sessionID: second.id), nil,
                          "revocation removes the biometric envelope without ending the session")
            for invalidEnvelope in [Data(), Data(repeating: 0x20, count: 8_193)] {
                do {
                    _ = try await reopened.setLocalBiometricEnvelope(invalidEnvelope, accountID: secondAccountID, sessionID: second.id)
                    runner.expectTrue(false, "an invalid biometric envelope cannot be stored")
                } catch VaultStoreError.stepFailed {
                    runner.expect(try await reopened.localBiometricEnvelope(accountID: secondAccountID, sessionID: second.id), nil,
                                  "a rejected biometric envelope is not published")
                }
            }
            for invalidValue in ["zeroblob(0)", "zeroblob(8193)", "'not-a-blob'"] {
                try executeLocalSessionFixtureSQL(database, passphrase: passphrase,
                                                  sql: "UPDATE local_vault_session SET biometric_envelope=\(invalidValue);")
                runner.expect(try await reopened.localBiometricEnvelope(accountID: secondAccountID, sessionID: second.id), nil,
                              "malformed database values are not returned as biometric envelopes")
                runner.expect(try await reopened.localVaultSession(), second, "malformed biometric data leaves ordinary session access intact")
            }
            runner.expect(try await reopened.setLocalBiometricEnvelope(biometricEnvelope, accountID: secondAccountID, sessionID: second.id),
                          true, "a fresh enrollment replaces malformed data")
            runner.expect(try await reopened.removeLocalVaultSession(accountID: secondAccountID, sessionID: second.id),
                          true, "logout removes the active session")
            runner.expect(try await reopened.localBiometricEnvelope(accountID: secondAccountID, sessionID: second.id), nil,
                          "logout removes the biometric envelope with the session")
            runner.expect(try await reopened.updateLocalVaultRefreshToken("after-logout", accountID: secondAccountID,
                                                                          sessionID: second.id, expectedToken: nil),
                          false, "a late refresh cannot republish a logged-out session")
        }

        do {
            let afterLogout = try VaultStore(databaseURL: database, passphrase: passphrase)
            runner.expect(try await afterLogout.localVaultSession(), nil, "logout survives reopening")
            runner.expect(try await afterLogout.account(id: secondAccountID)?.id, secondAccountID,
                          "logout does not remove the cached account")
            runner.expect(try await afterLogout.localVaultRememberedDevice(accountID: secondAccountID), secondRememberedDevice,
                          "logout preserves the opt-in remembered device")
            try await afterLogout.installLocalVaultSession(first, rememberedDevice: nil)
        }
        try executeLocalSessionFixtureSQL(database, passphrase: passphrase,
                                          sql: "ALTER TABLE local_vault_session DROP COLUMN biometric_envelope;")
        let migrated = try VaultStore(databaseURL: database, passphrase: passphrase)
        runner.expect(try await migrated.localVaultSession(), first, "the biometric schema migration preserves an existing local session")
        runner.expect(try await migrated.localBiometricEnvelope(accountID: firstAccountID, sessionID: first.id), nil,
                      "the biometric schema migration does not enroll an existing session")
        runner.expect(try await migrated.setLocalBiometricEnvelope(biometricEnvelope, accountID: firstAccountID, sessionID: first.id),
                      true, "an existing session can enroll after the schema migration")
    } catch {
        runner.expectTrue(false, "standalone session persistence test threw: \(error)")
    }
}

private func executeLocalSessionFixtureSQL(_ database: URL, passphrase: Data, sql: String) throws {
    var handle: OpaquePointer?
    let status = sqlite3_open_v2(database.path, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil)
    defer { if let handle { sqlite3_close(handle) } }
    guard status == SQLITE_OK, let handle else { throw VaultStoreError.openFailed }
    guard passphrase.withUnsafeBytes({ sqlite3_key(handle, $0.baseAddress, Int32($0.count)) }) == SQLITE_OK,
          sqlite3_exec(handle, sql, nil, nil, nil) == SQLITE_OK else {
        throw VaultStoreError.stepFailed("could not configure standalone session fixture")
    }
}
