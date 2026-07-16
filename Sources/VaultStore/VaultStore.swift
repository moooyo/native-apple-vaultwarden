// VaultStore — SQLCipher-encrypted offline cache for the Tessera vault.
//
// Design refs: blueprint §C; design spec §7.3 (schema) / §5.4 (VaultStore).

import Foundation
import Darwin
import SQLCipher
import CryptoCore
import VaultModels

// SQLITE_TRANSIENT tells SQLite to copy bound bytes (safe for Swift String/Data
// whose storage may move). The C macro casts -1 to a destructor function pointer.
private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

/// Serialized (actor) access to the on-disk encrypted vault cache.
///
/// All values are bound via prepared statements — SQL strings never interpolate
/// caller-supplied values, so the store is not susceptible to SQL injection.
public actor VaultStore {
    private static let migrationProcessLock = NSLock()
    /// A contender (normally the AutoFill extension) must fail predictably instead
    /// of waiting forever while another process owns the migration lock. The process
    /// that acquired the lock may still run a long migration to completion.
    package static let migrationLockTimeout: TimeInterval = 1
    private static let migrationLockInitialBackoffMicroseconds: useconds_t = 10_000
    private static let migrationLockMaximumBackoffMicroseconds: useconds_t = 50_000
    private let db: OpaquePointer

    /// Opens (creating if needed) the database at `databaseURL`, applies its SQLCipher
    /// key, verifies that the key can read the database, enables WAL, and creates the
    /// schema if absent. The `passphrase` is the random DB key from the Keychain — not
    /// the master password.
    public init(databaseURL: URL, passphrase: Data) throws {
        try VaultStore.withMigrationLock(at: databaseURL) {
            try VaultStore.reconcileStalePlaintextBackups(
                at: databaseURL,
                passphrase: passphrase
            )
            try VaultStore.migratePlaintextDatabaseIfNeeded(
                at: databaseURL,
                passphrase: passphrase
            )
            try VaultStore.reconcileStalePlaintextBackups(
                at: databaseURL,
                passphrase: passphrase
            )
        }

        var handle: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(databaseURL.path, &handle, flags, nil) == SQLITE_OK,
              let handle else {
            if let handle { sqlite3_close(handle) }
            throw VaultStoreError.openFailed
        }
        self.db = handle

        do {
            try VaultStore.applyEncryption(db: handle, passphrase: passphrase)
            try VaultStore.exec(handle, "PRAGMA journal_mode=WAL;")
            // Wait up to 5s on a locked DB instead of failing immediately with
            // SQLITE_BUSY — concurrent app + AutoFill-extension access under WAL.
            try VaultStore.exec(handle, "PRAGMA busy_timeout=5000;")
            try VaultStore.exec(handle, "PRAGMA foreign_keys=ON;")
            try VaultStore.withMigrationLock(at: databaseURL) {
                try VaultStore.createSchema(handle)
            }
        } catch {
            sqlite3_close(handle)
            throw error
        }
    }

    /// Serializes migration and stale-backup recovery across the app and AutoFill
    /// extension. The lock file is intentionally persistent: unlinking a locked file
    /// would let another process lock a different inode and enter concurrently.
    package static func withMigrationLock<T>(
        at databaseURL: URL,
        timeout: TimeInterval = migrationLockTimeout,
        _ body: () throws -> T
    ) throws -> T {
        // Use one monotonic deadline for both the in-process mutex and the
        // cross-process advisory lock, so their combined wait is bounded.
        let waitBudget = timeout.isFinite
            ? min(max(0, timeout), migrationLockTimeout)
            : migrationLockTimeout
        let deadline = ProcessInfo.processInfo.systemUptime + waitBudget
        var backoff = migrationLockInitialBackoffMicroseconds

        while !migrationProcessLock.try() {
            try waitForMigrationLockRetry(deadline: deadline, backoff: &backoff)
        }
        defer { migrationProcessLock.unlock() }

        let lockURL = databaseURL.deletingLastPathComponent().appendingPathComponent(
            ".\(databaseURL.lastPathComponent).migration.lock"
        )
        let descriptor = Darwin.open(
            lockURL.path,
            O_CREAT | O_RDWR,
            S_IRUSR | S_IWUSR
        )
        guard descriptor >= 0 else {
            throw VaultStoreError.plaintextMigrationFailed(
                "could not open database migration lock"
            )
        }
        defer { Darwin.close(descriptor) }

        backoff = migrationLockInitialBackoffMicroseconds
        while Darwin.lockf(descriptor, F_TLOCK, 0) != 0 {
            let lockError = errno
            guard lockError == EACCES || lockError == EAGAIN || lockError == EINTR else {
                throw VaultStoreError.plaintextMigrationFailed(
                    "could not acquire database migration lock (errno \(lockError))"
                )
            }
            try waitForMigrationLockRetry(deadline: deadline, backoff: &backoff)
        }
        defer { Darwin.lockf(descriptor, F_ULOCK, 0) }
        return try body()
    }

    /// Sleeps only until the shared deadline, with a short capped exponential
    /// backoff to avoid spinning while keeping extension startup responsive.
    private static func waitForMigrationLockRetry(
        deadline: TimeInterval,
        backoff: inout useconds_t
    ) throws {
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0 else {
            throw VaultStoreError.migrationLockTimedOut
        }

        let remainingMicroseconds = remaining * 1_000_000
        let delay = useconds_t(min(Double(backoff), remainingMicroseconds))
        if delay > 0 {
            _ = Darwin.usleep(delay)
        }
        guard ProcessInfo.processInfo.systemUptime < deadline else {
            throw VaultStoreError.migrationLockTimedOut
        }
        backoff = min(backoff * 2, migrationLockMaximumBackoffMicroseconds)
    }

    /// Resolves the only crash window in the atomic replacement: the encrypted live
    /// file may already be valid while its retained plaintext rollback link remains.
    /// A valid encrypted live file wins and the protected backup is removed. If the
    /// live path is missing, one unambiguous plaintext backup is restored and then
    /// migrated by the caller. Ambiguous or invalid state is preserved and reported.
    private static func reconcileStalePlaintextBackups(
        at databaseURL: URL,
        passphrase: Data
    ) throws {
        let backups: [URL]
        do {
            backups = try plaintextBackupURLs(for: databaseURL)
        } catch {
            throw VaultStoreError.plaintextMigrationFailed(
                "could not inspect plaintext migration backups: \(error)"
            )
        }
        guard !backups.isEmpty else { return }

        for backup in backups {
            try protectPlaintextFile(at: backup)
        }

        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: databaseURL.path) else {
            guard backups.count == 1,
                  try hasPlaintextSQLiteHeader(at: backups[0]) else {
                throw VaultStoreError.plaintextMigrationFailed(
                    "live database is missing; plaintext backups were preserved: "
                        + backups.map(\.path).joined(separator: ", ")
                )
            }
            do {
                try fileManager.moveItem(at: backups[0], to: databaseURL)
            } catch {
                throw VaultStoreError.plaintextMigrationFailed(
                    "could not restore plaintext migration backup \(backups[0].path): \(error)"
                )
            }
            return
        }

        if try hasPlaintextSQLiteHeader(at: databaseURL) {
            // The previous attempt did not install the encrypted replacement. Keep
            // every rollback copy until this live plaintext database is migrated.
            return
        }

        do {
            try validateEncryptedDatabase(at: databaseURL, passphrase: passphrase)
        } catch {
            throw VaultStoreError.plaintextMigrationFailed(
                "live database could not be validated; plaintext backups were preserved at: "
                    + backups.map(\.path).joined(separator: ", ")
            )
        }

        for backup in backups {
            do {
                try fileManager.removeItem(at: backup)
            } catch {
                throw VaultStoreError.plaintextMigrationFailed(
                    "validated encrypted database, but could not remove plaintext backup "
                        + "\(backup.path): \(error)"
                )
            }
        }
    }

    private static func plaintextBackupURLs(for databaseURL: URL) throws -> [URL] {
        let prefix = ".\(databaseURL.lastPathComponent).plaintext-backup-"
        return try FileManager.default.contentsOfDirectory(
            at: databaseURL.deletingLastPathComponent(),
            includingPropertiesForKeys: nil,
            options: [.skipsSubdirectoryDescendants]
        )
        .filter { $0.lastPathComponent.hasPrefix(prefix) }
        .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private static func protectPlaintextFile(at fileURL: URL) throws {
#if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        do {
            try FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.complete],
                ofItemAtPath: fileURL.path
            )
        } catch {
            throw VaultStoreError.plaintextMigrationFailed(
                "could not apply complete file protection to \(fileURL.path): \(error)"
            )
        }
#else
        // NSFileProtectionComplete is an iOS-family data-protection facility.
        _ = fileURL
#endif
    }

    // Isolated so the actor-protected, non-Sendable `db` handle can be closed safely.
    isolated deinit {
        sqlite3_close(db)
    }

    /// Applies the raw Keychain-supplied key and forces a page read so an incorrect key
    /// fails during initialization rather than on the first later query.
    private static func applyEncryption(db: OpaquePointer, passphrase: Data) throws {
        guard !passphrase.isEmpty, passphrase.count <= Int(Int32.max) else {
            throw VaultStoreError.invalidPassphrase
        }

        let keyResult = passphrase.withUnsafeBytes { bytes in
            sqlite3_key(db, bytes.baseAddress, Int32(bytes.count))
        }
        guard keyResult == SQLITE_OK else {
            throw VaultStoreError.keyFailed(errorMessage(db))
        }

        // An unknown PRAGMA returns no row under stock SQLite. Requiring a non-empty
        // value proves that this process linked and loaded SQLCipher, not libsqlite3.
        guard let cipherVersion = try scalarText(db, sql: "PRAGMA cipher_version;"),
              !cipherVersion.isEmpty else {
            throw VaultStoreError.encryptionUnavailable
        }

        // sqlite3_key only installs the key; it does not read an encrypted page. This
        // query forces validation now and reliably rejects a wrong key on reopen.
        do {
            _ = try scalarInt64(db, sql: "SELECT count(*) FROM sqlite_master;")
        } catch {
            throw VaultStoreError.keyValidationFailed(errorMessage(db))
        }
    }

    /// Converts a legacy system-SQLite database in place without ever exposing a
    /// partially encrypted file at the live path. SQLCipher explicitly requires
    /// ATTACH + sqlcipher_export for plaintext-to-encrypted conversion; rekey is only
    /// supported for databases that are already encrypted.
    private static func migratePlaintextDatabaseIfNeeded(
        at databaseURL: URL,
        passphrase: Data
    ) throws {
        guard try hasPlaintextSQLiteHeader(at: databaseURL) else { return }
        guard !passphrase.isEmpty, passphrase.count <= Int(Int32.max) else {
            throw VaultStoreError.invalidPassphrase
        }

        let fileManager = FileManager.default
        let migrationID = UUID().uuidString
        let directory = databaseURL.deletingLastPathComponent()
        let encryptedURL = directory.appendingPathComponent(
            ".\(databaseURL.lastPathComponent).sqlcipher-migration-\(migrationID)"
        )
        let backupName = ".\(databaseURL.lastPathComponent).plaintext-backup-\(migrationID)"
        let backupURL = directory.appendingPathComponent(backupName)

        removeDatabaseArtifacts(at: encryptedURL)
        defer { removeDatabaseArtifacts(at: encryptedURL) }

        var plaintextDB: OpaquePointer?
        // SQLITE_OPEN_CREATE also permits ATTACH to create the encrypted export file.
        // The plaintext source itself was already verified to exist by its header.
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(databaseURL.path, &plaintextDB, flags, nil) == SQLITE_OK,
              let openedPlaintextDB = plaintextDB else {
            if let plaintextDB { sqlite3_close(plaintextDB) }
            throw VaultStoreError.plaintextMigrationFailed("could not open plaintext database")
        }
        plaintextDB = openedPlaintextDB
        defer {
            if let plaintextDB { sqlite3_close(plaintextDB) }
        }

        do {
            sqlite3_busy_timeout(openedPlaintextDB, 5_000)

            // Recover and consolidate any committed pages left by a previous WAL-mode
            // process. A busy result means another process may still own live state;
            // abort and preserve the plaintext database instead of racing it.
            try checkpointPlaintextWAL(openedPlaintextDB)

            let journalMode = try scalarText(
                openedPlaintextDB,
                sql: "PRAGMA journal_mode=DELETE;"
            )
            guard journalMode?.lowercased() == "delete" else {
                throw VaultStoreError.plaintextMigrationFailed(
                    "could not acquire plaintext database for WAL migration"
                )
            }

            let lockingMode = try scalarText(
                openedPlaintextDB,
                sql: "PRAGMA locking_mode=EXCLUSIVE;"
            )
            guard lockingMode?.lowercased() == "exclusive" else {
                throw VaultStoreError.plaintextMigrationFailed(
                    "could not lock plaintext database exclusively"
                )
            }

            try attachEncryptedDatabase(
                encryptedURL,
                to: openedPlaintextDB,
                passphrase: passphrase
            )
            var isAttached = true
            defer {
                if isAttached {
                    try? exec(openedPlaintextDB, "DETACH DATABASE encrypted;")
                }
            }

            try exec(openedPlaintextDB, "BEGIN EXCLUSIVE TRANSACTION;")
            do {
                let userVersion = try scalarInt64(
                    openedPlaintextDB,
                    sql: "PRAGMA main.user_version;"
                ) ?? 0
                try exec(openedPlaintextDB, "SELECT sqlcipher_export('encrypted');")
                try exec(
                    openedPlaintextDB,
                    "PRAGMA encrypted.user_version=\(userVersion);"
                )
                try exec(openedPlaintextDB, "COMMIT;")
            } catch {
                try? exec(openedPlaintextDB, "ROLLBACK;")
                throw error
            }

            try exec(openedPlaintextDB, "DETACH DATABASE encrypted;")
            isAttached = false

            // Validate the completed encrypted copy before touching the live path.
            try validateEncryptedDatabase(at: encryptedURL, passphrase: passphrase)

            // DELETE journal mode plus a successful TRUNCATE checkpoint makes these
            // legacy sidecars redundant. Removing them prevents a plaintext WAL from
            // being associated with the newly encrypted main database after replace.
            try deleteSidecars(at: databaseURL)
            try protectPlaintextFile(at: databaseURL)

            _ = try fileManager.replaceItemAt(
                databaseURL,
                withItemAt: encryptedURL,
                backupItemName: backupName,
                options: [.withoutDeletingBackupItem]
            )
            try protectPlaintextFile(at: backupURL)

            do {
                // Validate the file at its final URL before discarding the rollback copy.
                try validateEncryptedDatabase(at: databaseURL, passphrase: passphrase)
            } catch {
                sqlite3_close(openedPlaintextDB)
                plaintextDB = nil
                do {
                    _ = try fileManager.replaceItemAt(
                        databaseURL,
                        withItemAt: backupURL,
                        backupItemName: nil
                    )
                } catch let restoreError {
                    throw VaultStoreError.plaintextMigrationFailed(
                        "encrypted replacement validation failed; plaintext backup remains at "
                            + "\(backupURL.path): \(restoreError)"
                    )
                }
                throw error
            }

            sqlite3_close(openedPlaintextDB)
            plaintextDB = nil
            try fileManager.removeItem(at: backupURL)
        } catch let error as VaultStoreError {
            switch error {
            case .invalidPassphrase, .plaintextMigrationFailed:
                throw error
            default:
                throw VaultStoreError.plaintextMigrationFailed(String(describing: error))
            }
        } catch {
            throw VaultStoreError.plaintextMigrationFailed(String(describing: error))
        }
    }

    private static func hasPlaintextSQLiteHeader(at databaseURL: URL) throws -> Bool {
        guard FileManager.default.fileExists(atPath: databaseURL.path) else { return false }
        do {
            let handle = try FileHandle(forReadingFrom: databaseURL)
            defer { try? handle.close() }
            let header = try handle.read(upToCount: 16) ?? Data()
            return header == Data("SQLite format 3\0".utf8)
        } catch {
            throw VaultStoreError.plaintextMigrationFailed(
                "could not inspect existing database header: \(error)"
            )
        }
    }

    private static func checkpointPlaintextWAL(_ db: OpaquePointer) throws {
        let statement = try prepare(db, sql: "PRAGMA wal_checkpoint(TRUNCATE);")
        defer { sqlite3_finalize(statement) }

        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw VaultStoreError.plaintextMigrationFailed(errorMessage(db))
        }
        guard sqlite3_column_int(statement, 0) == 0 else {
            throw VaultStoreError.plaintextMigrationFailed(
                "plaintext WAL is busy; close other app or extension processes and retry"
            )
        }
    }

    private static func attachEncryptedDatabase(
        _ encryptedURL: URL,
        to db: OpaquePointer,
        passphrase: Data
    ) throws {
        let statement = try prepare(
            db,
            sql: "ATTACH DATABASE ?1 AS encrypted KEY ?2;"
        )
        defer { sqlite3_finalize(statement) }

        guard sqlite3_bind_text(
            statement,
            1,
            encryptedURL.path,
            -1,
            SQLITE_TRANSIENT
        ) == SQLITE_OK else {
            throw VaultStoreError.plaintextMigrationFailed(errorMessage(db))
        }
        let bindResult = passphrase.withUnsafeBytes { bytes in
            sqlite3_bind_blob(statement, 2, bytes.baseAddress, Int32(bytes.count), SQLITE_TRANSIENT)
        }
        guard bindResult == SQLITE_OK, sqlite3_step(statement) == SQLITE_DONE else {
            throw VaultStoreError.plaintextMigrationFailed(errorMessage(db))
        }
    }

    private static func validateEncryptedDatabase(
        at databaseURL: URL,
        passphrase: Data
    ) throws {
        var validationDB: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(databaseURL.path, &validationDB, flags, nil) == SQLITE_OK,
              let validationDB else {
            if let validationDB { sqlite3_close(validationDB) }
            throw VaultStoreError.plaintextMigrationFailed(
                "could not open encrypted migration result"
            )
        }
        defer { sqlite3_close(validationDB) }

        try applyEncryption(db: validationDB, passphrase: passphrase)
        guard try scalarText(validationDB, sql: "PRAGMA integrity_check;") == "ok" else {
            throw VaultStoreError.plaintextMigrationFailed(
                "encrypted migration result failed integrity_check"
            )
        }
    }

    private static func deleteSidecars(at databaseURL: URL) throws {
        let fileManager = FileManager.default
        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecarURL = URL(fileURLWithPath: databaseURL.path + suffix)
            guard fileManager.fileExists(atPath: sidecarURL.path) else { continue }
            try fileManager.removeItem(at: sidecarURL)
        }
    }

    private static func removeDatabaseArtifacts(at databaseURL: URL) {
        try? FileManager.default.removeItem(at: databaseURL)
        try? deleteSidecars(at: databaseURL)
    }

    // MARK: - Accounts

    public func upsertAccounts(_ rows: [AccountRow]) throws {
        guard !rows.isEmpty else { return }
        let sql = """
        INSERT INTO account
          (id, email, server_url, kdf_type, kdf_iters, revision_date,
           security_stamp, enc_user_key, enc_private_key)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
        ON CONFLICT(id) DO UPDATE SET
          email=COALESCE(excluded.email, account.email),
          server_url=COALESCE(excluded.server_url, account.server_url),
          kdf_type=COALESCE(excluded.kdf_type, account.kdf_type),
          kdf_iters=COALESCE(excluded.kdf_iters, account.kdf_iters),
          revision_date=COALESCE(excluded.revision_date, account.revision_date),
          security_stamp=COALESCE(excluded.security_stamp, account.security_stamp),
          enc_user_key=COALESCE(excluded.enc_user_key, account.enc_user_key),
          enc_private_key=COALESCE(excluded.enc_private_key, account.enc_private_key);
        """
        try transaction {
            let stmt = try prepare(sql)
            defer { sqlite3_finalize(stmt) }
            for row in rows {
                bindText(stmt, 1, row.id)
                bindText(stmt, 2, row.email)
                bindText(stmt, 3, row.serverURL)
                bindOptionalInt(stmt, 4, row.kdfType)
                bindOptionalInt(stmt, 5, row.kdfIters)
                bindText(stmt, 6, row.revisionDate)
                bindText(stmt, 7, row.securityStamp)
                bindText(stmt, 8, row.encUserKey)
                bindText(stmt, 9, row.encPrivateKey)
                try step(stmt)
                sqlite3_reset(stmt)
                sqlite3_clear_bindings(stmt)
            }
        }
    }

    /// Fetch one account row by its stable id. Cold-start session restoration uses this
    /// scoped lookup so a Keychain marker can never select metadata from another account.
    public func account(id: String) throws -> AccountRow? {
        let sql = """
        SELECT id, email, server_url, kdf_type, kdf_iters, revision_date,
               security_stamp, enc_user_key, enc_private_key
        FROM account WHERE id=?1 LIMIT 1;
        """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, id)

        let rc = sqlite3_step(stmt)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW else { throw VaultStoreError.stepFailed(lastErrorMessage()) }
        return AccountRow(
            id: textColumn(stmt, 0) ?? "",
            email: textColumn(stmt, 1),
            serverURL: textColumn(stmt, 2),
            kdfType: sqlite3_column_type(stmt, 3) == SQLITE_NULL
                ? nil : Int(sqlite3_column_int64(stmt, 3)),
            kdfIters: sqlite3_column_type(stmt, 4) == SQLITE_NULL
                ? nil : Int(sqlite3_column_int64(stmt, 4)),
            revisionDate: textColumn(stmt, 5),
            securityStamp: textColumn(stmt, 6),
            encUserKey: textColumn(stmt, 7),
            encPrivateKey: textColumn(stmt, 8)
        )
    }

    // MARK: - Ciphers

    public func upsertCiphers(_ rows: [CipherRow]) throws {
        guard !rows.isEmpty else { return }
        try transaction {
            try upsertCiphersInCurrentTransaction(rows)
        }
    }

    /// Inserts/updates cipher rows without opening a transaction. Callers must already
    /// hold this actor and, when combining the write with other state transitions, wrap
    /// it in `transaction` so no partially-visible state can escape.
    private func upsertCiphersInCurrentTransaction(_ rows: [CipherRow]) throws {
        guard !rows.isEmpty else { return }
        let sql = """
        INSERT INTO cipher
          (id, account_id, type, folder_id, organization_id, favorite, reprompt, edit,
           view_password, revision_date, creation_date, deleted_date,
           enc_name, enc_notes, enc_blob, enc_cipher_key, search_text)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)
        ON CONFLICT(account_id, id) DO UPDATE SET
          type=excluded.type, folder_id=excluded.folder_id,
          organization_id=excluded.organization_id, favorite=excluded.favorite,
          reprompt=excluded.reprompt, edit=excluded.edit, view_password=excluded.view_password,
          revision_date=excluded.revision_date, creation_date=excluded.creation_date,
          deleted_date=excluded.deleted_date, enc_name=excluded.enc_name,
          enc_notes=excluded.enc_notes, enc_blob=excluded.enc_blob,
          enc_cipher_key=excluded.enc_cipher_key, search_text=excluded.search_text;
        """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        for row in rows {
            bindText(stmt, 1, row.id)
            bindText(stmt, 2, row.accountID)
            bindInt(stmt, 3, Int64(row.type))
            bindText(stmt, 4, row.folderID)
            bindText(stmt, 5, row.organizationID)
            bindInt(stmt, 6, row.favorite ? 1 : 0)
            bindInt(stmt, 7, Int64(row.reprompt))
            bindInt(stmt, 8, row.edit ? 1 : 0)
            bindInt(stmt, 9, row.viewPassword ? 1 : 0)
            bindText(stmt, 10, row.revisionDate)
            bindText(stmt, 11, row.creationDate)
            bindText(stmt, 12, row.deletedDate)
            bindText(stmt, 13, row.encName)
            bindText(stmt, 14, row.encNotes)
            bindText(stmt, 15, row.encBlob)
            bindText(stmt, 16, row.encCipherKey)
            bindText(stmt, 17, row.searchText)
            try step(stmt)
            sqlite3_reset(stmt)
            sqlite3_clear_bindings(stmt)
        }
    }

    public func allCiphers(accountID: String) throws -> [CipherRow] {
        let sql = "\(cipherSelectColumns) WHERE account_id=?1 AND deleted_date IS NULL ORDER BY revision_date DESC;"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, accountID)
        return try collectCiphers(stmt)
    }

    /// Returns a bounded slice of live login rows for memory-constrained consumers such
    /// as the AutoFill extension. The SQL `LIMIT` is applied before rows/blobs cross the
    /// actor boundary; callers never need to materialize the account's full vault.
    public func recentLoginCiphers(
        accountID: String,
        limit: Int,
        maximumBlobBytes: Int = 131_072
    ) throws -> [CipherRow] {
        let boundedLimit = min(max(limit, 0), 500)
        let boundedBlobBytes = min(max(maximumBlobBytes, 1), 1_048_576)
        guard boundedLimit > 0 else { return [] }
        let sql = """
        \(cipherSelectColumns)
        WHERE account_id=?1 AND type=?2 AND deleted_date IS NULL
          AND length(CAST(COALESCE(enc_blob, '') AS BLOB)) <= ?4
          AND length(CAST(COALESCE(enc_name, '') AS BLOB)) <= 16384
          AND length(CAST(COALESCE(enc_cipher_key, '') AS BLOB)) <= 16384
        ORDER BY revision_date DESC, id ASC
        LIMIT ?3;
        """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, accountID)
        bindInt(stmt, 2, Int64(CipherType.login.rawValue))
        bindInt(stmt, 3, Int64(boundedLimit))
        bindInt(stmt, 4, Int64(boundedBlobBytes))
        return try collectCiphers(stmt)
    }

    public func cipher(id: String, accountID: String) throws -> CipherRow? {
        let sql = "\(cipherSelectColumns) WHERE id=?1 AND account_id=?2;"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, id)
        bindText(stmt, 2, accountID)
        return try collectCiphers(stmt).first
    }

    public func deleteCipher(id: String, accountID: String) throws {
        let stmt = try prepare("DELETE FROM cipher WHERE id=?1 AND account_id=?2;")
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, id)
        bindText(stmt, 2, accountID)
        try step(stmt)
        if sqlite3_changes(db) == 0 { throw VaultStoreError.notFound }
    }

    /// Resolve an offline-create placeholder after the server assigns its real id.
    public func resolveCipherID(_ id: String, accountID: String) throws -> String {
        var current = id
        var visited = Set<String>()
        for _ in 0..<8 {
            guard visited.insert(current).inserted else {
                throw VaultStoreError.stepFailed("cipher id alias cycle")
            }
            let stmt = try prepare("""
            SELECT server_id FROM entity_id_alias
            WHERE account_id=?1 AND local_id=?2;
            """)
            bindText(stmt, 1, accountID)
            bindText(stmt, 2, current)
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE {
                sqlite3_finalize(stmt)
                return current
            }
            guard rc == SQLITE_ROW, let next = textColumn(stmt, 0), !next.isEmpty else {
                sqlite3_finalize(stmt)
                throw VaultStoreError.stepFailed(lastErrorMessage())
            }
            sqlite3_finalize(stmt)
            current = next
        }
        throw VaultStoreError.stepFailed("cipher id alias chain too deep")
    }

    /// Case-insensitive substring search over the plaintext `search_text` column.
    public func search(_ query: String, accountID: String) throws -> [CipherRow] {
        let sql = """
        \(cipherSelectColumns)
        WHERE account_id=?1 AND deleted_date IS NULL
          AND search_text LIKE ?2 ESCAPE '\\'
        ORDER BY revision_date DESC;
        """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, accountID)
        // Escape LIKE wildcards in the user query, then wrap in %...% for substring match.
        bindText(stmt, 2, "%\(VaultStore.escapeLike(query))%")
        return try collectCiphers(stmt)
    }

    private let cipherSelectColumns = """
    SELECT id, account_id, type, folder_id, organization_id, favorite, reprompt, edit,
           view_password, revision_date, creation_date, deleted_date,
           enc_name, enc_notes, enc_blob, enc_cipher_key, search_text
    FROM cipher
    """

    private func collectCiphers(_ stmt: OpaquePointer) throws -> [CipherRow] {
        var rows: [CipherRow] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else { throw VaultStoreError.stepFailed(lastErrorMessage()) }
            rows.append(CipherRow(
                id: textColumn(stmt, 0) ?? "",
                accountID: textColumn(stmt, 1) ?? "",
                type: Int(sqlite3_column_int64(stmt, 2)),
                folderID: textColumn(stmt, 3),
                organizationID: textColumn(stmt, 4),
                favorite: sqlite3_column_int64(stmt, 5) != 0,
                reprompt: Int(sqlite3_column_int64(stmt, 6)),
                edit: sqlite3_column_int64(stmt, 7) != 0,
                viewPassword: sqlite3_column_int64(stmt, 8) != 0,
                revisionDate: textColumn(stmt, 9) ?? "",
                creationDate: textColumn(stmt, 10) ?? "",
                deletedDate: textColumn(stmt, 11),
                encName: textColumn(stmt, 12),
                encNotes: textColumn(stmt, 13),
                encBlob: textColumn(stmt, 14),
                encCipherKey: textColumn(stmt, 15),
                searchText: textColumn(stmt, 16)
            ))
        }
        return rows
    }

    // MARK: - Cipher URIs

    public func upsertCipherURIs(_ rows: [CipherURIRow]) throws {
        guard !rows.isEmpty else { return }
        let sql = """
        INSERT INTO cipher_uri (id, account_id, cipher_id, enc_uri, match_type)
        VALUES (?1,?2,?3,?4,?5)
        ON CONFLICT(account_id, id) DO UPDATE SET
          cipher_id=excluded.cipher_id, enc_uri=excluded.enc_uri, match_type=excluded.match_type;
        """
        try transaction {
            let stmt = try prepare(sql)
            defer { sqlite3_finalize(stmt) }
            for row in rows {
                bindText(stmt, 1, row.id)
                bindText(stmt, 2, row.accountID)
                bindText(stmt, 3, row.cipherID)
                bindText(stmt, 4, row.encURI)
                bindOptionalInt(stmt, 5, row.matchType)
                try step(stmt)
                sqlite3_reset(stmt)
                sqlite3_clear_bindings(stmt)
            }
        }
    }

    public func cipherURIs(cipherID: String, accountID: String) throws -> [CipherURIRow] {
        let sql = """
        SELECT id, account_id, cipher_id, enc_uri, match_type
        FROM cipher_uri WHERE cipher_id=?1 AND account_id=?2 ORDER BY id ASC;
        """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, cipherID)
        bindText(stmt, 2, accountID)
        var rows: [CipherURIRow] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else { throw VaultStoreError.stepFailed(lastErrorMessage()) }
            rows.append(CipherURIRow(
                id: textColumn(stmt, 0) ?? "",
                accountID: textColumn(stmt, 1) ?? "",
                cipherID: textColumn(stmt, 2) ?? "",
                encURI: textColumn(stmt, 3),
                matchType: sqlite3_column_type(stmt, 4) == SQLITE_NULL ? nil : Int(sqlite3_column_int64(stmt, 4))
            ))
        }
        return rows
    }

    // MARK: - Folders

    public func upsertFolders(_ rows: [FolderRow]) throws {
        guard !rows.isEmpty else { return }
        let sql = """
        INSERT INTO folder (id, account_id, enc_name, revision_date)
        VALUES (?1,?2,?3,?4)
        ON CONFLICT(account_id, id) DO UPDATE SET
          enc_name=excluded.enc_name,
          revision_date=excluded.revision_date;
        """
        try transaction {
            let stmt = try prepare(sql)
            defer { sqlite3_finalize(stmt) }
            for row in rows {
                bindText(stmt, 1, row.id)
                bindText(stmt, 2, row.accountID)
                bindText(stmt, 3, row.encName)
                bindText(stmt, 4, row.revisionDate)
                try step(stmt)
                sqlite3_reset(stmt)
                sqlite3_clear_bindings(stmt)
            }
        }
    }

    public func allFolders(accountID: String) throws -> [FolderRow] {
        let sql = "SELECT id, account_id, enc_name, revision_date FROM folder WHERE account_id=?1 ORDER BY revision_date DESC;"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, accountID)
        var rows: [FolderRow] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else { throw VaultStoreError.stepFailed(lastErrorMessage()) }
            rows.append(FolderRow(
                id: textColumn(stmt, 0) ?? "",
                accountID: textColumn(stmt, 1) ?? "",
                encName: textColumn(stmt, 2),
                revisionDate: textColumn(stmt, 3) ?? ""
            ))
        }
        return rows
    }

    public func folder(id: String, accountID: String) throws -> FolderRow? {
        let stmt = try prepare("""
        SELECT id, account_id, enc_name, revision_date
        FROM folder WHERE id=?1 AND account_id=?2;
        """)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, id)
        bindText(stmt, 2, accountID)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return FolderRow(
            id: textColumn(stmt, 0) ?? "",
            accountID: textColumn(stmt, 1) ?? "",
            encName: textColumn(stmt, 2),
            revisionDate: textColumn(stmt, 3) ?? ""
        )
    }

    public func deleteFolder(id: String, accountID: String) throws {
        let stmt = try prepare("DELETE FROM folder WHERE id=?1 AND account_id=?2;")
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, id)
        bindText(stmt, 2, accountID)
        try step(stmt)
        if sqlite3_changes(db) == 0 { throw VaultStoreError.notFound }
    }

    // MARK: - Sync state

    public func setSyncState(_ s: SyncStateRow) throws {
        let sql = """
        INSERT INTO sync_state (account_id, last_account_revision, last_full_sync_at)
        VALUES (?1,?2,?3)
        ON CONFLICT(account_id) DO UPDATE SET
          last_account_revision=excluded.last_account_revision,
          last_full_sync_at=excluded.last_full_sync_at;
        """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, s.accountID)
        bindText(stmt, 2, s.lastAccountRevision)
        bindText(stmt, 3, s.lastFullSyncAt)
        try step(stmt)
    }

    public func syncState(accountID: String) throws -> SyncStateRow? {
        let sql = "SELECT account_id, last_account_revision, last_full_sync_at FROM sync_state WHERE account_id=?1;"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, accountID)
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW else { throw VaultStoreError.stepFailed(lastErrorMessage()) }
        return SyncStateRow(
            accountID: textColumn(stmt, 0) ?? "",
            lastAccountRevision: textColumn(stmt, 1),
            lastFullSyncAt: textColumn(stmt, 2)
        )
    }

    // MARK: - Outbox

    @discardableResult
    public func enqueueOutbox(_ op: OutboxRow) throws -> Int64 {
        try insertOutboxInCurrentTransaction(op)
    }

    private func insertOutboxInCurrentTransaction(_ op: OutboxRow) throws -> Int64 {
        let sql = """
        INSERT INTO outbox
          (account_id, op_type, entity_type, entity_id, payload_json, last_known_revision_date)
        VALUES (?1,?2,?3,?4,?5,?6);
        """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, op.accountID)
        bindText(stmt, 2, op.opType)
        bindText(stmt, 3, op.entityType)
        bindText(stmt, 4, op.entityID)
        bindText(stmt, 5, op.payloadJSON)
        bindText(stmt, 6, op.lastKnownRevisionDate)
        try step(stmt)
        return sqlite3_last_insert_rowid(db)
    }

    /// Whether an entity already has durable work waiting. Repository mutations use this
    /// to append/coalesce locally instead of issuing PUT/DELETE against a create placeholder.
    public func hasPendingOutbox(
        accountID: String,
        entityType: String,
        entityID: String
    ) throws -> Bool {
        let stmt = try prepare("""
        SELECT 1 FROM outbox
        WHERE account_id=?1 AND entity_type=?2 AND entity_id=?3 LIMIT 1;
        """)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, accountID)
        bindText(stmt, 2, entityType)
        bindText(stmt, 3, entityID)
        switch sqlite3_step(stmt) {
        case SQLITE_ROW: return true
        case SQLITE_DONE: return false
        default: throw VaultStoreError.stepFailed(lastErrorMessage())
        }
    }

    /// Atomically persist an offline cipher mutation and its optimistic local result.
    /// Existing rows for the same entity are coalesced while the transaction is private:
    /// create+update replaces the create payload, create+delete cancels both, repeated updates
    /// retain the original server revision, and update+delete becomes one delete.
    public func persistOfflineCipherMutation(
        operation: OutboxRow,
        localCipher: CipherRow?
    ) throws {
        let hasLocalCipher = localCipher != nil
        guard operation.entityType == "cipher",
              operation.opType == "create"
                || operation.opType == "update"
                || operation.opType == "delete",
              ((operation.opType == "delete" && !hasLocalCipher)
                || (operation.opType != "delete" && hasLocalCipher)),
              localCipher == nil
                || (localCipher?.accountID == operation.accountID
                    && localCipher?.id == operation.entityID) else {
            throw VaultStoreError.stepFailed("offline cipher mutation mismatch")
        }

        try transaction {
            let pendingReceipt = try prepare("""
            SELECT 1 FROM passkey_import_receipt AS r
            JOIN outbox AS o ON o.id=r.outbox_id
            WHERE r.account_id=?1 AND r.completed=0
              AND o.entity_type=?2 AND o.entity_id=?3
            LIMIT 1;
            """)
            defer { sqlite3_finalize(pendingReceipt) }
            bindText(pendingReceipt, 1, operation.accountID)
            bindText(pendingReceipt, 2, operation.entityType)
            bindText(pendingReceipt, 3, operation.entityID)
            let receiptResult = sqlite3_step(pendingReceipt)
            guard receiptResult != SQLITE_ROW else {
                throw VaultStoreError.stepFailed(
                    "pending passkey import must recover before another mutation"
                )
            }
            guard receiptResult == SQLITE_DONE else {
                throw VaultStoreError.stepFailed(lastErrorMessage())
            }

            if operation.opType == "create" {
                let clearAlias = try prepare("""
                DELETE FROM entity_id_alias WHERE account_id=?1 AND local_id=?2;
                """)
                defer { sqlite3_finalize(clearAlias) }
                bindText(clearAlias, 1, operation.accountID)
                bindText(clearAlias, 2, operation.entityID)
                try step(clearAlias)
            }
            _ = try insertOutboxInCurrentTransaction(operation)
            if let localCipher {
                try upsertCiphersInCurrentTransaction([localCipher])
            } else {
                let remove = try prepare(
                    "DELETE FROM cipher WHERE account_id=?1 AND id=?2;"
                )
                defer { sqlite3_finalize(remove) }
                bindText(remove, 1, operation.accountID)
                bindText(remove, 2, operation.entityID)
                try step(remove)
            }
            try normalizeOutboxEntityInCurrentTransaction(
                accountID: operation.accountID,
                entityType: operation.entityType,
                entityID: operation.entityID
            )
        }
    }

    private struct OutboxEntityKey: Hashable {
        let entityType: String
        let entityID: String
    }

    /// Validates legacy/pre-fix queues before network work becomes visible to SyncEngine.
    public func outboxForFlush(accountID: String) throws -> [OutboxRow] {
        let rows = try outbox(accountID: accountID)
        let grouped = Dictionary(grouping: rows) {
            OutboxEntityKey(entityType: $0.entityType, entityID: $0.entityID)
        }
        for (key, group) in grouped where group.count > 1 {
            let linked = try prepare("""
            SELECT 1 FROM passkey_import_receipt AS r
            JOIN outbox AS o ON o.id=r.outbox_id
            WHERE r.account_id=?1 AND o.entity_type=?2 AND o.entity_id=?3
            LIMIT 1;
            """)
            defer { sqlite3_finalize(linked) }
            bindText(linked, 1, accountID)
            bindText(linked, 2, key.entityType)
            bindText(linked, 3, key.entityID)
            let linkResult = sqlite3_step(linked)
            if linkResult == SQLITE_ROW {
                // A pre-fix, partially imported passkey cannot be losslessly merged from
                // encrypted payloads here. Fail closed and let the drainer/manual recovery
                // resolve it instead of silently dropping either the passkey or later edit.
                throw VaultStoreError.stepFailed(
                    "ambiguous receipt-linked outbox sequence requires recovery"
                )
            }
            guard linkResult == SQLITE_DONE else {
                throw VaultStoreError.stepFailed(lastErrorMessage())
            }
        }
        return rows
    }

    private func outboxRowsInCurrentTransaction(accountID: String) throws -> [OutboxRow] {
        let stmt = try prepare("""
        SELECT id, account_id, op_type, entity_type, entity_id, payload_json,
               last_known_revision_date
        FROM outbox WHERE account_id=?1 ORDER BY id ASC;
        """)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, accountID)
        return try collectOutbox(stmt)
    }

    private func normalizeOutboxEntityInCurrentTransaction(
        accountID: String,
        entityType: String,
        entityID: String
    ) throws {
        let stmt = try prepare("""
        SELECT id, account_id, op_type, entity_type, entity_id, payload_json,
               last_known_revision_date
        FROM outbox
        WHERE account_id=?1 AND entity_type=?2 AND entity_id=?3
        ORDER BY id ASC;
        """)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, accountID)
        bindText(stmt, 2, entityType)
        bindText(stmt, 3, entityID)
        let rows = try collectOutbox(stmt)
        guard let first = rows.first, let firstID = first.id else { return }
        guard rows.allSatisfy({
            $0.opType == "create" || $0.opType == "update" || $0.opType == "delete"
        }) else {
            throw VaultStoreError.stepFailed("unknown outbox operation during coalescing")
        }

        let createRows = rows.filter { $0.opType == "create" }
        if !createRows.isEmpty {
            guard first.opType == "create", createRows.count == 1 else {
                throw VaultStoreError.stepFailed("ambiguous create sequence in outbox")
            }
            if rows.contains(where: { $0.opType == "delete" }) {
                try deleteOutboxEntityRowsInCurrentTransaction(
                    accountID: accountID,
                    entityType: entityType,
                    entityID: entityID,
                    keepingID: nil
                )
                if entityType == "cipher" {
                    let remove = try prepare(
                        "DELETE FROM cipher WHERE account_id=?1 AND id=?2;"
                    )
                    defer { sqlite3_finalize(remove) }
                    bindText(remove, 1, accountID)
                    bindText(remove, 2, entityID)
                    try step(remove)
                }
                return
            }
            guard let latest = rows.last else { return }
            try updateOutboxRowInCurrentTransaction(
                id: firstID,
                accountID: accountID,
                opType: "create",
                payloadJSON: latest.payloadJSON,
                lastKnownRevisionDate: nil
            )
        } else if rows.contains(where: { $0.opType == "delete" }) {
            try updateOutboxRowInCurrentTransaction(
                id: firstID,
                accountID: accountID,
                opType: "delete",
                payloadJSON: "{}",
                lastKnownRevisionDate: nil
            )
        } else if let latest = rows.last {
            try updateOutboxRowInCurrentTransaction(
                id: firstID,
                accountID: accountID,
                opType: "update",
                payloadJSON: latest.payloadJSON,
                lastKnownRevisionDate: first.lastKnownRevisionDate
            )
        }

        try deleteOutboxEntityRowsInCurrentTransaction(
            accountID: accountID,
            entityType: entityType,
            entityID: entityID,
            keepingID: firstID
        )
    }

    private func updateOutboxRowInCurrentTransaction(
        id: Int64,
        accountID: String,
        opType: String,
        payloadJSON: String,
        lastKnownRevisionDate: String?
    ) throws {
        let stmt = try prepare("""
        UPDATE outbox SET op_type=?1, payload_json=?2, last_known_revision_date=?3
        WHERE id=?4 AND account_id=?5;
        """)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, opType)
        bindText(stmt, 2, payloadJSON)
        bindText(stmt, 3, lastKnownRevisionDate)
        bindInt(stmt, 4, id)
        bindText(stmt, 5, accountID)
        try step(stmt)
    }

    private func deleteOutboxEntityRowsInCurrentTransaction(
        accountID: String,
        entityType: String,
        entityID: String,
        keepingID: Int64?
    ) throws {
        let sql: String
        if keepingID == nil {
            sql = """
            DELETE FROM outbox
            WHERE account_id=?1 AND entity_type=?2 AND entity_id=?3;
            """
        } else {
            sql = """
            DELETE FROM outbox
            WHERE account_id=?1 AND entity_type=?2 AND entity_id=?3 AND id<>?4;
            """
        }
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, accountID)
        bindText(stmt, 2, entityType)
        bindText(stmt, 3, entityID)
        if let keepingID { bindInt(stmt, 4, keepingID) }
        try step(stmt)
    }

    /// Package-only diagnostic/migration view. Production callers must use the
    /// account-scoped overload below.
    package func outbox() throws -> [OutboxRow] {
        let sql = """
        SELECT id, account_id, op_type, entity_type, entity_id, payload_json,
               last_known_revision_date
        FROM outbox ORDER BY id ASC;
        """
        return try collectOutbox(sql)
    }

    /// Pending writes for one authenticated account only. Production sync paths must
    /// always use this scoped query so another account's rows can never be sent with
    /// the current account's bearer token.
    public func outbox(accountID: String) throws -> [OutboxRow] {
        let sql = """
        SELECT id, account_id, op_type, entity_type, entity_id, payload_json,
               last_known_revision_date
        FROM outbox WHERE account_id=?1 ORDER BY id ASC;
        """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, accountID)
        return try collectOutbox(stmt)
    }

    private func collectOutbox(_ sql: String) throws -> [OutboxRow] {
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        return try collectOutbox(stmt)
    }

    private func collectOutbox(_ stmt: OpaquePointer) throws -> [OutboxRow] {
        var rows: [OutboxRow] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else { throw VaultStoreError.stepFailed(lastErrorMessage()) }
            rows.append(OutboxRow(
                id: sqlite3_column_int64(stmt, 0),
                accountID: textColumn(stmt, 1) ?? "",
                opType: textColumn(stmt, 2) ?? "",
                entityType: textColumn(stmt, 3) ?? "",
                entityID: textColumn(stmt, 4) ?? "",
                payloadJSON: textColumn(stmt, 5) ?? "",
                lastKnownRevisionDate: textColumn(stmt, 6)
            ))
        }
        return rows
    }

    /// Package-only test/migration seam; production clear operations require accountID.
    package func clearOutbox(id: Int64) throws {
        let stmt = try prepare("DELETE FROM outbox WHERE id=?1;")
        defer { sqlite3_finalize(stmt) }
        bindInt(stmt, 1, id)
        try step(stmt)
        if sqlite3_changes(db) == 0 { throw VaultStoreError.notFound }
    }

    public func clearOutbox(id: Int64, accountID: String) throws {
        let stmt = try prepare("DELETE FROM outbox WHERE id=?1 AND account_id=?2;")
        defer { sqlite3_finalize(stmt) }
        bindInt(stmt, 1, id)
        bindText(stmt, 2, accountID)
        try step(stmt)
        if sqlite3_changes(db) == 0 { throw VaultStoreError.notFound }
    }

    /// Atomically reconciles a successful create/update response with its queued write.
    ///
    /// A passkey handoff receipt may still be pending when `SyncEngine` wins the race to
    /// send its linked outbox row. Completing that receipt before deleting the outbox is
    /// load-bearing: the foreign key clears `outbox_id` on delete, and a pending receipt
    /// with a NULL link would otherwise enqueue the same server create again on replay.
    /// The local placeholder replacement is part of the same transaction so a drainer
    /// that observed stale receipt state cannot resurrect the placeholder afterwards.
    public func finalizeOutboxWrite(
        id: Int64,
        accountID: String,
        localEntityID: String,
        serverCipher: CipherRow
    ) throws {
        guard serverCipher.accountID == accountID else {
            throw VaultStoreError.stepFailed("outbox result account mismatch")
        }

        try transaction {
            let queued = try prepare("""
            SELECT op_type, entity_type, entity_id
            FROM outbox WHERE id=?1 AND account_id=?2;
            """)
            defer { sqlite3_finalize(queued) }
            bindInt(queued, 1, id)
            bindText(queued, 2, accountID)
            guard sqlite3_step(queued) == SQLITE_ROW else {
                throw VaultStoreError.notFound
            }
            let opType = textColumn(queued, 0)
            guard textColumn(queued, 1) == "cipher",
                  textColumn(queued, 2) == localEntityID,
                  opType == "create" || opType == "update" else {
                throw VaultStoreError.stepFailed("outbox result does not match queued write")
            }

            let later = try prepare("""
            SELECT 1 FROM outbox
            WHERE account_id=?1 AND entity_type='cipher' AND entity_id=?2 AND id<>?3
            LIMIT 1;
            """)
            defer { sqlite3_finalize(later) }
            bindText(later, 1, accountID)
            bindText(later, 2, localEntityID)
            bindInt(later, 3, id)
            let hasLaterMutation: Bool
            switch sqlite3_step(later) {
            case SQLITE_ROW: hasLaterMutation = true
            case SQLITE_DONE: hasLaterMutation = false
            default: throw VaultStoreError.stepFailed(lastErrorMessage())
            }

            let rowToPersist: CipherRow
            if hasLaterMutation,
               let optimistic = try cipher(id: localEntityID, accountID: accountID) {
                // Preserve the latest local payload while advancing its server concurrency
                // base. The following queued mutation will send that payload using the
                // server response's real id/revision.
                rowToPersist = CipherRow(
                    id: serverCipher.id,
                    accountID: accountID,
                    type: optimistic.type,
                    folderID: optimistic.folderID,
                    organizationID: optimistic.organizationID,
                    favorite: optimistic.favorite,
                    reprompt: optimistic.reprompt,
                    edit: optimistic.edit,
                    viewPassword: optimistic.viewPassword,
                    revisionDate: serverCipher.revisionDate,
                    creationDate: serverCipher.creationDate,
                    deletedDate: optimistic.deletedDate,
                    encName: optimistic.encName,
                    encNotes: optimistic.encNotes,
                    encBlob: optimistic.encBlob,
                    encCipherKey: optimistic.encCipherKey,
                    searchText: optimistic.searchText
                )
            } else {
                rowToPersist = serverCipher
            }

            if serverCipher.id != localEntityID {
                let alias = try prepare("""
                INSERT INTO entity_id_alias (account_id, local_id, server_id)
                VALUES (?1,?2,?3)
                ON CONFLICT(account_id, local_id) DO UPDATE SET
                  server_id=excluded.server_id, created_at=CURRENT_TIMESTAMP;
                """)
                defer { sqlite3_finalize(alias) }
                bindText(alias, 1, accountID)
                bindText(alias, 2, localEntityID)
                bindText(alias, 3, serverCipher.id)
                try step(alias)

                let removePlaceholder = try prepare(
                    "DELETE FROM cipher WHERE id=?1 AND account_id=?2;"
                )
                defer { sqlite3_finalize(removePlaceholder) }
                bindText(removePlaceholder, 1, localEntityID)
                bindText(removePlaceholder, 2, accountID)
                try step(removePlaceholder)
            }
            try upsertCiphersInCurrentTransaction([rowToPersist])

            // A pre-fix queue may contain operations after a create/update. Remap them
            // atomically to the server id and revision, then SyncEngine reloads the queue
            // before issuing the next request.
            let remap = try prepare("""
            UPDATE outbox
            SET entity_id=?1,
                last_known_revision_date=CASE
                    WHEN op_type='update' THEN ?2
                    ELSE last_known_revision_date
                END
            WHERE account_id=?3 AND entity_type='cipher' AND entity_id=?4 AND id<>?5;
            """)
            defer { sqlite3_finalize(remap) }
            bindText(remap, 1, serverCipher.id)
            bindText(remap, 2, serverCipher.revisionDate)
            bindText(remap, 3, accountID)
            bindText(remap, 4, localEntityID)
            bindInt(remap, 5, id)
            try step(remap)

            let completeReceipt = try prepare("""
            UPDATE passkey_import_receipt SET completed=1
            WHERE outbox_id=?1 AND account_id=?2;
            """)
            defer { sqlite3_finalize(completeReceipt) }
            bindInt(completeReceipt, 1, id)
            bindText(completeReceipt, 2, accountID)
            try step(completeReceipt)

            let clear = try prepare("DELETE FROM outbox WHERE id=?1 AND account_id=?2;")
            defer { sqlite3_finalize(clear) }
            bindInt(clear, 1, id)
            bindText(clear, 2, accountID)
            try step(clear)
            guard sqlite3_changes(db) > 0 else { throw VaultStoreError.notFound }
        }
    }

    // MARK: - Passkey import receipts

    public func isPasskeyImportCompleted(id: String, accountID: String) throws -> Bool {
        let stmt = try prepare(
            "SELECT completed FROM passkey_import_receipt WHERE id=?1 AND account_id=?2;"
        )
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, id)
        bindText(stmt, 2, accountID)
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_DONE { return false }
        guard rc == SQLITE_ROW else { throw VaultStoreError.stepFailed(lastErrorMessage()) }
        return sqlite3_column_int64(stmt, 0) != 0
    }

    /// Package-visible seam used to reconstruct an interrupted pre-fix import in tests.
    /// Production imports use the overload that also persists `localCipher` atomically.
    @discardableResult
    package func enqueueOutboxForPasskeyImport(
        receiptID: String,
        accountID: String,
        operation: OutboxRow
    ) throws -> Bool {
        guard operation.accountID == accountID else {
            throw VaultStoreError.stepFailed("passkey import outbox account mismatch")
        }
        var shouldContinue = false
        try transaction {
            shouldContinue = try ensurePasskeyImportOutbox(
                receiptID: receiptID,
                accountID: accountID,
                operation: operation,
                coalesceExistingEntity: false
            )
        }
        return shouldContinue
    }

    /// Crash-safe passkey-import commit. The receipt, unique linked outbox write,
    /// optimistic local row, and completion bit become visible together. A replay that
    /// raced with successful outbox finalization returns `false` and cannot recreate the
    /// local placeholder or enqueue a second create.
    @discardableResult
    public func enqueueOutboxForPasskeyImport(
        receiptID: String,
        accountID: String,
        operation: OutboxRow,
        localCipher: CipherRow
    ) throws -> Bool {
        guard operation.accountID == accountID,
              localCipher.accountID == accountID,
              localCipher.id == operation.entityID else {
            throw VaultStoreError.stepFailed("passkey import persistence mismatch")
        }

        var shouldContinue = false
        try transaction {
            shouldContinue = try ensurePasskeyImportOutbox(
                receiptID: receiptID,
                accountID: accountID,
                operation: operation,
                coalesceExistingEntity: true
            )
            guard shouldContinue else { return }

            try upsertCiphersInCurrentTransaction([localCipher])
            let complete = try prepare("""
            UPDATE passkey_import_receipt SET completed=1
            WHERE id=?1 AND account_id=?2;
            """)
            defer { sqlite3_finalize(complete) }
            bindText(complete, 1, receiptID)
            bindText(complete, 2, accountID)
            try step(complete)
            guard sqlite3_changes(db) > 0 else {
                throw VaultStoreError.stepFailed("passkey import receipt account mismatch")
            }
        }
        return shouldContinue
    }

    /// Ensures the receipt and its single outbox link while already inside a transaction.
    /// Existing links are validated against the stable account/op/entity tuple; payload
    /// ciphertext is intentionally not compared because a replay re-encrypts with a new IV.
    private func ensurePasskeyImportOutbox(
        receiptID: String,
        accountID: String,
        operation: OutboxRow,
        coalesceExistingEntity: Bool
    ) throws -> Bool {
        let insertReceipt = try prepare("""
        INSERT INTO passkey_import_receipt (id, account_id, completed)
        VALUES (?1, ?2, 0) ON CONFLICT(account_id, id) DO NOTHING;
        """)
        defer { sqlite3_finalize(insertReceipt) }
        bindText(insertReceipt, 1, receiptID)
        bindText(insertReceipt, 2, accountID)
        try step(insertReceipt)

        let receipt = try prepare("""
        SELECT outbox_id, completed
        FROM passkey_import_receipt WHERE id=?1 AND account_id=?2;
        """)
        defer { sqlite3_finalize(receipt) }
        bindText(receipt, 1, receiptID)
        bindText(receipt, 2, accountID)
        guard sqlite3_step(receipt) == SQLITE_ROW else {
            throw VaultStoreError.stepFailed("passkey import receipt account mismatch")
        }
        if sqlite3_column_int64(receipt, 1) != 0 { return false }

        if sqlite3_column_type(receipt, 0) != SQLITE_NULL {
            let outboxID = sqlite3_column_int64(receipt, 0)
            let linked = try prepare("""
            SELECT account_id, op_type, entity_type, entity_id
            FROM outbox WHERE id=?1;
            """)
            defer { sqlite3_finalize(linked) }
            bindInt(linked, 1, outboxID)
            guard sqlite3_step(linked) == SQLITE_ROW,
                  textColumn(linked, 0) == accountID else {
                throw VaultStoreError.stepFailed("passkey import outbox link mismatch")
            }
            let tupleMatches = textColumn(linked, 1) == operation.opType
                && textColumn(linked, 2) == operation.entityType
                && textColumn(linked, 3) == operation.entityID
            if !tupleMatches {
                guard coalesceExistingEntity else {
                    throw VaultStoreError.stepFailed("passkey import outbox link mismatch")
                }
                // Recover a pre-fix pending receipt whose selected target disappeared.
                // The still-pending linked row is rewritten to the deterministic fallback
                // create in the same transaction as its local row + completion bit.
                let rewrite = try prepare("""
                UPDATE outbox
                SET op_type=?1, entity_type=?2, entity_id=?3,
                    payload_json=?4, last_known_revision_date=?5
                WHERE id=?6 AND account_id=?7;
                """)
                defer { sqlite3_finalize(rewrite) }
                bindText(rewrite, 1, operation.opType)
                bindText(rewrite, 2, operation.entityType)
                bindText(rewrite, 3, operation.entityID)
                bindText(rewrite, 4, operation.payloadJSON)
                bindText(rewrite, 5, operation.lastKnownRevisionDate)
                bindInt(rewrite, 6, outboxID)
                bindText(rewrite, 7, accountID)
                try step(rewrite)
            }
            return true
        }

        if coalesceExistingEntity {
            let incompleteReceipt = try prepare("""
            SELECT 1 FROM passkey_import_receipt AS r
            JOIN outbox AS o ON o.id=r.outbox_id
            WHERE r.account_id=?1 AND r.completed=0
              AND o.entity_type=?2 AND o.entity_id=?3
            LIMIT 1;
            """)
            defer { sqlite3_finalize(incompleteReceipt) }
            bindText(incompleteReceipt, 1, accountID)
            bindText(incompleteReceipt, 2, operation.entityType)
            bindText(incompleteReceipt, 3, operation.entityID)
            let incompleteResult = sqlite3_step(incompleteReceipt)
            guard incompleteResult != SQLITE_ROW else {
                throw VaultStoreError.stepFailed(
                    "older passkey import must recover before coalescing"
                )
            }
            guard incompleteResult == SQLITE_DONE else {
                throw VaultStoreError.stepFailed(lastErrorMessage())
            }

            let existing = try prepare("""
            SELECT 1 FROM outbox
            WHERE account_id=?1 AND entity_type=?2 AND entity_id=?3 LIMIT 1;
            """)
            defer { sqlite3_finalize(existing) }
            bindText(existing, 1, accountID)
            bindText(existing, 2, operation.entityType)
            bindText(existing, 3, operation.entityID)
            let existingResult = sqlite3_step(existing)
            if existingResult == SQLITE_ROW {
                _ = try insertOutboxInCurrentTransaction(operation)
                try normalizeOutboxEntityInCurrentTransaction(
                    accountID: accountID,
                    entityType: operation.entityType,
                    entityID: operation.entityID
                )
                // This receipt is completed in the same transaction as the merged local
                // row below. It needs no unique outbox link; `completed=1` is sufficient
                // to make handoff replay a no-op while the retained entity row flushes.
                return true
            }
            guard existingResult == SQLITE_DONE else {
                throw VaultStoreError.stepFailed(lastErrorMessage())
            }
        }

        let insertOutbox = try prepare("""
        INSERT INTO outbox
          (account_id, op_type, entity_type, entity_id, payload_json,
           last_known_revision_date)
        VALUES (?1,?2,?3,?4,?5,?6);
        """)
        defer { sqlite3_finalize(insertOutbox) }
        bindText(insertOutbox, 1, operation.accountID)
        bindText(insertOutbox, 2, operation.opType)
        bindText(insertOutbox, 3, operation.entityType)
        bindText(insertOutbox, 4, operation.entityID)
        bindText(insertOutbox, 5, operation.payloadJSON)
        bindText(insertOutbox, 6, operation.lastKnownRevisionDate)
        try step(insertOutbox)
        let outboxID = sqlite3_last_insert_rowid(db)

        let link = try prepare("""
        UPDATE passkey_import_receipt SET outbox_id=?1
        WHERE id=?2 AND account_id=?3;
        """)
        defer { sqlite3_finalize(link) }
        bindInt(link, 1, outboxID)
        bindText(link, 2, receiptID)
        bindText(link, 3, accountID)
        try step(link)
        guard sqlite3_changes(db) > 0 else {
            throw VaultStoreError.stepFailed("passkey import receipt account mismatch")
        }
        return true
    }

    public func completePasskeyImport(id: String, accountID: String) throws {
        let stmt = try prepare("""
        INSERT INTO passkey_import_receipt (id, account_id, completed)
        VALUES (?1, ?2, 1)
        ON CONFLICT(account_id, id) DO UPDATE SET completed=1;
        """)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, id)
        bindText(stmt, 2, accountID)
        try step(stmt)
        guard sqlite3_changes(db) > 0 else {
            throw VaultStoreError.stepFailed("passkey import receipt account mismatch")
        }
    }

    // MARK: - Low-level helpers

    private func prepare(_ sql: String) throws -> OpaquePointer {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else {
            throw VaultStoreError.prepareFailed(lastErrorMessage())
        }
        return stmt
    }

    private func step(_ stmt: OpaquePointer) throws {
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE || rc == SQLITE_ROW else {
            throw VaultStoreError.stepFailed(lastErrorMessage())
        }
    }

    private func transaction(_ body: () throws -> Void) throws {
        try VaultStore.exec(db, "BEGIN IMMEDIATE TRANSACTION;")
        do {
            try body()
            try VaultStore.exec(db, "COMMIT;")
        } catch {
            try? VaultStore.exec(db, "ROLLBACK;")
            throw error
        }
    }

    private func bindText(_ stmt: OpaquePointer, _ index: Int32, _ value: String?) {
        if let value {
            sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT)
        } else {
            sqlite3_bind_null(stmt, index)
        }
    }

    private func bindInt(_ stmt: OpaquePointer, _ index: Int32, _ value: Int64) {
        sqlite3_bind_int64(stmt, index, value)
    }

    private func bindOptionalInt(_ stmt: OpaquePointer, _ index: Int32, _ value: Int?) {
        if let value {
            sqlite3_bind_int64(stmt, index, Int64(value))
        } else {
            sqlite3_bind_null(stmt, index)
        }
    }

    private func textColumn(_ stmt: OpaquePointer, _ index: Int32) -> String? {
        guard let c = sqlite3_column_text(stmt, index) else { return nil }
        return String(cString: c)
    }

    private func lastErrorMessage() -> String {
        guard let c = sqlite3_errmsg(db) else { return "unknown SQLite error" }
        return String(cString: c)
    }

    // MARK: - Static helpers (usable before `self.db` is assigned during init)

    private static func exec(_ db: OpaquePointer, _ sql: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        if sqlite3_exec(db, sql, nil, nil, &err) != SQLITE_OK {
            let message = err.map { String(cString: $0) } ?? "unknown SQLite error"
            sqlite3_free(err)
            throw VaultStoreError.stepFailed(message)
        }
    }

    private static func scalarText(_ db: OpaquePointer, sql: String) throws -> String? {
        let statement = try prepare(db, sql: sql)
        defer { sqlite3_finalize(statement) }

        switch sqlite3_step(statement) {
        case SQLITE_ROW:
            guard let value = sqlite3_column_text(statement, 0) else { return nil }
            return String(cString: value)
        case SQLITE_DONE:
            return nil
        default:
            throw VaultStoreError.stepFailed(errorMessage(db))
        }
    }

    private static func scalarInt64(_ db: OpaquePointer, sql: String) throws -> Int64? {
        let statement = try prepare(db, sql: sql)
        defer { sqlite3_finalize(statement) }

        switch sqlite3_step(statement) {
        case SQLITE_ROW:
            return sqlite3_column_int64(statement, 0)
        case SQLITE_DONE:
            return nil
        default:
            throw VaultStoreError.stepFailed(errorMessage(db))
        }
    }

    private static func prepare(_ db: OpaquePointer, sql: String) throws -> OpaquePointer {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK,
              let statement else {
            throw VaultStoreError.prepareFailed(errorMessage(db))
        }
        return statement
    }

    private static func errorMessage(_ db: OpaquePointer) -> String {
        guard let message = sqlite3_errmsg(db) else { return "unknown SQLCipher error" }
        return String(cString: message)
    }

    /// Escapes `%`, `_`, and `\` so they are treated literally in a LIKE pattern
    /// (paired with `ESCAPE '\'`).
    static func escapeLike(_ s: String) -> String {
        var out = ""
        out.reserveCapacity(s.count)
        for ch in s {
            switch ch {
            case "\\", "%", "_": out.append("\\"); out.append(ch)
            default: out.append(ch)
            }
        }
        return out
    }

    private static func createSchema(_ db: OpaquePointer) throws {
        // Schema from design spec §7.3. `enc_*` columns are EncString wire strings (TEXT);
        // plaintext metadata columns support local query/sort/sync/search.
        let schema = """
        CREATE TABLE IF NOT EXISTS account (
            id TEXT PRIMARY KEY,
            email TEXT,
            server_url TEXT,
            kdf_type INTEGER,
            kdf_iters INTEGER,
            revision_date TEXT,
            security_stamp TEXT,
            enc_user_key TEXT,
            enc_private_key TEXT
        );

        CREATE TABLE IF NOT EXISTS cipher (
            id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            type INTEGER NOT NULL,
            folder_id TEXT,
            organization_id TEXT,
            favorite INTEGER NOT NULL DEFAULT 0,
            reprompt INTEGER NOT NULL DEFAULT 0,
            edit INTEGER NOT NULL DEFAULT 1,
            view_password INTEGER NOT NULL DEFAULT 1,
            revision_date TEXT NOT NULL,
            creation_date TEXT NOT NULL,
            deleted_date TEXT,
            enc_name TEXT,
            enc_notes TEXT,
            enc_blob TEXT,
            enc_cipher_key TEXT,
            search_text TEXT,
            PRIMARY KEY(account_id, id),
            FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS cipher_uri (
            id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            cipher_id TEXT NOT NULL,
            enc_uri TEXT,
            match_type INTEGER,
            PRIMARY KEY(account_id, id),
            FOREIGN KEY(account_id, cipher_id)
                REFERENCES cipher(account_id, id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS fido2_credential (
            id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            cipher_id TEXT NOT NULL,
            enc_blob TEXT,
            creation_date TEXT,
            PRIMARY KEY(account_id, id),
            FOREIGN KEY(account_id, cipher_id)
                REFERENCES cipher(account_id, id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS folder (
            id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            enc_name TEXT,
            revision_date TEXT NOT NULL,
            PRIMARY KEY(account_id, id),
            FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS collection (
            id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            organization_id TEXT,
            enc_name TEXT,
            PRIMARY KEY(account_id, id),
            FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS organization (
            id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            enc_org_key TEXT,
            name TEXT,
            PRIMARY KEY(account_id, id),
            FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS send (
            id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            type INTEGER,
            enc_name TEXT,
            enc_blob TEXT,
            deletion_date TEXT,
            expiration_date TEXT,
            disabled INTEGER,
            max_access_count INTEGER,
            PRIMARY KEY(account_id, id),
            FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS attachment (
            id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            cipher_id TEXT NOT NULL,
            enc_key TEXT,
            enc_file_name TEXT,
            file_size INTEGER,
            url TEXT,
            PRIMARY KEY(account_id, id),
            FOREIGN KEY(account_id, cipher_id)
                REFERENCES cipher(account_id, id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sync_state (
            account_id TEXT PRIMARY KEY,
            last_account_revision TEXT,
            last_full_sync_at TEXT
        );

        CREATE TABLE IF NOT EXISTS entity_id_alias (
            account_id TEXT NOT NULL,
            local_id TEXT NOT NULL,
            server_id TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(account_id, local_id),
            FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id TEXT NOT NULL,
            op_type TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            last_known_revision_date TEXT,
            FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS outbox_quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            legacy_outbox_id INTEGER,
            op_type TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            last_known_revision_date TEXT,
            reason TEXT NOT NULL,
            quarantined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS entity_migration_quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_table TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            account_id TEXT,
            reason TEXT NOT NULL,
            quarantined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        """
        try exec(db, schema)
        try migrateLegacyOutboxIfNeeded(db)
        try exec(db, """
        CREATE TABLE IF NOT EXISTS passkey_import_receipt (
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
        """)
        try migratePasskeyReceiptKeysIfNeeded(db)
        try migrateAccountScopedEntityKeysIfNeeded(db)
        try exec(db, """
        CREATE INDEX IF NOT EXISTS idx_cipher_account ON cipher(account_id);
        CREATE INDEX IF NOT EXISTS idx_cipher_folder ON cipher(account_id, folder_id);
        CREATE INDEX IF NOT EXISTS idx_cipher_uri_cipher
            ON cipher_uri(account_id, cipher_id);
        CREATE INDEX IF NOT EXISTS idx_fido2_cipher
            ON fido2_credential(account_id, cipher_id);
        CREATE INDEX IF NOT EXISTS idx_folder_account ON folder(account_id);
        CREATE INDEX IF NOT EXISTS idx_attachment_cipher
            ON attachment(account_id, cipher_id);
        CREATE INDEX IF NOT EXISTS idx_outbox_account ON outbox(account_id, id);
        """)
        try validateCurrentSchema(db)
    }

    private static func validateCurrentSchema(_ db: OpaquePointer) throws {
        for tableName in [
            "cipher", "cipher_uri", "fido2_credential", "folder", "collection",
            "organization", "send", "attachment", "passkey_import_receipt",
        ] {
            guard try primaryKeyColumns(of: tableName, db: db) == ["account_id", "id"] else {
                throw VaultStoreError.stepFailed(
                    "unexpected account-scoped primary key for \(tableName)"
                )
            }
        }
        let receiptOutboxFK = try scalarInt64(db, sql: """
        SELECT count(*) FROM pragma_foreign_key_list('passkey_import_receipt')
        WHERE "table"='outbox' AND "from"='outbox_id';
        """) ?? 0
        guard receiptOutboxFK == 1 else {
            throw VaultStoreError.stepFailed("passkey receipt outbox foreign key is invalid")
        }
        let violations = try scalarInt64(
            db,
            sql: "SELECT count(*) FROM pragma_foreign_key_check;"
        ) ?? 0
        guard violations == 0 else {
            throw VaultStoreError.stepFailed("foreign key check failed after schema migration")
        }
    }

    /// Account-scopes registration receipts as well as their linked outbox writes. A
    /// malformed legacy link is marked complete and detached during migration: replaying
    /// an already-ambiguous registration could issue a duplicate server create, while a
    /// fresh registration remains available under a new receipt id.
    private static func migratePasskeyReceiptKeysIfNeeded(_ db: OpaquePointer) throws {
        guard try primaryKeyColumns(of: "passkey_import_receipt", db: db)
            != ["account_id", "id"] else { return }

        try exec(db, "BEGIN IMMEDIATE TRANSACTION;")
        do {
            try exec(db, """
            INSERT INTO entity_migration_quarantine
              (source_table, entity_id, account_id, reason)
            SELECT 'passkey_import_receipt', r.id, r.account_id,
                   'persisted account does not exist; ownership was not guessed'
            FROM passkey_import_receipt AS r
            LEFT JOIN account AS a ON a.id=r.account_id
            WHERE a.id IS NULL;

            INSERT INTO entity_migration_quarantine
              (source_table, entity_id, account_id, reason)
            SELECT 'passkey_import_receipt', r.id, r.account_id,
                   CASE
                     WHEN o.id IS NULL THEN 'linked outbox row is missing or belongs to another account'
                     ELSE 'multiple receipts linked the same outbox row'
                   END
            FROM passkey_import_receipt AS r
            JOIN account AS a ON a.id=r.account_id
            LEFT JOIN outbox AS o
              ON o.id=r.outbox_id AND o.account_id=r.account_id
            WHERE r.outbox_id IS NOT NULL
              AND (o.id IS NULL OR r.rowid != (
                    SELECT MIN(earlier.rowid)
                    FROM passkey_import_receipt AS earlier
                    WHERE earlier.outbox_id=r.outbox_id
                  ));

            CREATE TABLE passkey_import_receipt_account_scoped (
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

            INSERT INTO passkey_import_receipt_account_scoped
              (id, account_id, outbox_id, completed, created_at)
            SELECT r.id, r.account_id, r.outbox_id, r.completed, r.created_at
            FROM passkey_import_receipt AS r
            JOIN account AS a ON a.id=r.account_id
            LEFT JOIN outbox AS o
              ON o.id=r.outbox_id AND o.account_id=r.account_id
            WHERE r.outbox_id IS NULL
               OR (o.id IS NOT NULL AND r.rowid=(
                    SELECT MIN(earlier.rowid)
                    FROM passkey_import_receipt AS earlier
                    WHERE earlier.outbox_id=r.outbox_id
                  ));

            INSERT INTO passkey_import_receipt_account_scoped
              (id, account_id, outbox_id, completed, created_at)
            SELECT r.id, r.account_id, NULL, 1, r.created_at
            FROM passkey_import_receipt AS r
            JOIN account AS a ON a.id=r.account_id
            LEFT JOIN outbox AS o
              ON o.id=r.outbox_id AND o.account_id=r.account_id
            WHERE r.outbox_id IS NOT NULL
              AND (o.id IS NULL OR r.rowid != (
                    SELECT MIN(earlier.rowid)
                    FROM passkey_import_receipt AS earlier
                    WHERE earlier.outbox_id=r.outbox_id
                  ));

            DROP TABLE passkey_import_receipt;
            ALTER TABLE passkey_import_receipt_account_scoped
                RENAME TO passkey_import_receipt;
            """)
            try exec(db, "COMMIT;")
        } catch {
            try? exec(db, "ROLLBACK;")
            throw error
        }
    }

    /// Upgrades the original globally-keyed cache schema to account-scoped entity keys.
    ///
    /// Ownership is copied only from an entity's persisted `account_id` (or, for a
    /// cipher child, from its persisted parent cipher). In particular, this migration
    /// never rewrites legacy `host|email` account ids to a newer canonical server id:
    /// doing so would guess which deployment owns ciphertext. Orphans are recorded in
    /// the encrypted quarantine table and left out of the live, sendable schema.
    private static func migrateAccountScopedEntityKeysIfNeeded(
        _ db: OpaquePointer
    ) throws {
        guard try primaryKeyColumns(of: "cipher", db: db) != ["account_id", "id"] else {
            return
        }

        try exec(db, "BEGIN IMMEDIATE TRANSACTION;")
        do {
            try exec(db, """
            -- Preserve the complete encrypted legacy rows for explicit/manual recovery.
            -- The generic quarantine index below is useful for diagnostics, but ids alone
            -- would not be a quarantine: dropping the source tables would destroy payloads.
            CREATE TABLE cipher_migration_quarantine AS SELECT * FROM cipher WHERE 0;
            CREATE TABLE folder_migration_quarantine AS SELECT * FROM folder WHERE 0;
            CREATE TABLE collection_migration_quarantine AS SELECT * FROM collection WHERE 0;
            CREATE TABLE organization_migration_quarantine AS SELECT * FROM organization WHERE 0;
            CREATE TABLE send_migration_quarantine AS SELECT * FROM send WHERE 0;
            CREATE TABLE cipher_uri_migration_quarantine AS SELECT * FROM cipher_uri WHERE 0;
            CREATE TABLE fido2_credential_migration_quarantine
                AS SELECT * FROM fido2_credential WHERE 0;
            CREATE TABLE attachment_migration_quarantine AS SELECT * FROM attachment WHERE 0;

            INSERT INTO cipher_migration_quarantine
            SELECT c.* FROM cipher AS c
            LEFT JOIN account AS a ON a.id=c.account_id
            WHERE a.id IS NULL;

            INSERT INTO folder_migration_quarantine
            SELECT f.* FROM folder AS f
            LEFT JOIN account AS a ON a.id=f.account_id
            WHERE a.id IS NULL;

            INSERT INTO collection_migration_quarantine
            SELECT x.* FROM collection AS x
            LEFT JOIN account AS a ON a.id=x.account_id
            WHERE a.id IS NULL;

            INSERT INTO organization_migration_quarantine
            SELECT x.* FROM organization AS x
            LEFT JOIN account AS a ON a.id=x.account_id
            WHERE a.id IS NULL;

            INSERT INTO send_migration_quarantine
            SELECT x.* FROM send AS x
            LEFT JOIN account AS a ON a.id=x.account_id
            WHERE a.id IS NULL;

            INSERT INTO cipher_uri_migration_quarantine
            SELECT u.* FROM cipher_uri AS u
            LEFT JOIN cipher AS c ON c.id=u.cipher_id
            LEFT JOIN account AS a ON a.id=c.account_id
            WHERE c.id IS NULL OR a.id IS NULL;

            INSERT INTO fido2_credential_migration_quarantine
            SELECT x.* FROM fido2_credential AS x
            LEFT JOIN cipher AS c ON c.id=x.cipher_id
            LEFT JOIN account AS a ON a.id=c.account_id
            WHERE c.id IS NULL OR a.id IS NULL;

            INSERT INTO attachment_migration_quarantine
            SELECT x.* FROM attachment AS x
            LEFT JOIN cipher AS c ON c.id=x.cipher_id
            LEFT JOIN account AS a ON a.id=c.account_id
            WHERE c.id IS NULL OR a.id IS NULL;

            INSERT INTO entity_migration_quarantine
              (source_table, entity_id, account_id, reason)
            SELECT 'cipher', c.id, c.account_id,
                   'persisted account does not exist; ownership was not guessed'
            FROM cipher AS c
            LEFT JOIN account AS a ON a.id=c.account_id
            WHERE a.id IS NULL;

            INSERT INTO entity_migration_quarantine
              (source_table, entity_id, account_id, reason)
            SELECT 'folder', f.id, f.account_id,
                   'persisted account does not exist; ownership was not guessed'
            FROM folder AS f
            LEFT JOIN account AS a ON a.id=f.account_id
            WHERE a.id IS NULL;

            INSERT INTO entity_migration_quarantine
              (source_table, entity_id, account_id, reason)
            SELECT 'collection', x.id, x.account_id,
                   'persisted account does not exist; ownership was not guessed'
            FROM collection AS x
            LEFT JOIN account AS a ON a.id=x.account_id
            WHERE a.id IS NULL;

            INSERT INTO entity_migration_quarantine
              (source_table, entity_id, account_id, reason)
            SELECT 'organization', x.id, x.account_id,
                   'persisted account does not exist; ownership was not guessed'
            FROM organization AS x
            LEFT JOIN account AS a ON a.id=x.account_id
            WHERE a.id IS NULL;

            INSERT INTO entity_migration_quarantine
              (source_table, entity_id, account_id, reason)
            SELECT 'send', x.id, x.account_id,
                   'persisted account does not exist; ownership was not guessed'
            FROM send AS x
            LEFT JOIN account AS a ON a.id=x.account_id
            WHERE a.id IS NULL;

            INSERT INTO entity_migration_quarantine
              (source_table, entity_id, account_id, reason)
            SELECT 'cipher_uri', u.id, NULL,
                   'parent cipher does not exist; ownership was not guessed'
            FROM cipher_uri AS u
            LEFT JOIN cipher AS c ON c.id=u.cipher_id
            LEFT JOIN account AS a ON a.id=c.account_id
            WHERE c.id IS NULL OR a.id IS NULL;

            INSERT INTO entity_migration_quarantine
              (source_table, entity_id, account_id, reason)
            SELECT 'fido2_credential', x.id, NULL,
                   'parent cipher does not exist; ownership was not guessed'
            FROM fido2_credential AS x
            LEFT JOIN cipher AS c ON c.id=x.cipher_id
            LEFT JOIN account AS a ON a.id=c.account_id
            WHERE c.id IS NULL OR a.id IS NULL;

            INSERT INTO entity_migration_quarantine
              (source_table, entity_id, account_id, reason)
            SELECT 'attachment', x.id, NULL,
                   'parent cipher does not exist; ownership was not guessed'
            FROM attachment AS x
            LEFT JOIN cipher AS c ON c.id=x.cipher_id
            LEFT JOIN account AS a ON a.id=c.account_id
            WHERE c.id IS NULL OR a.id IS NULL;

            CREATE TABLE cipher_account_scoped (
                id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                type INTEGER NOT NULL,
                folder_id TEXT,
                organization_id TEXT,
                favorite INTEGER NOT NULL DEFAULT 0,
                reprompt INTEGER NOT NULL DEFAULT 0,
                edit INTEGER NOT NULL DEFAULT 1,
                view_password INTEGER NOT NULL DEFAULT 1,
                revision_date TEXT NOT NULL,
                creation_date TEXT NOT NULL,
                deleted_date TEXT,
                enc_name TEXT,
                enc_notes TEXT,
                enc_blob TEXT,
                enc_cipher_key TEXT,
                search_text TEXT,
                PRIMARY KEY(account_id, id),
                FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
            );

            CREATE TABLE folder_account_scoped (
                id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                enc_name TEXT,
                revision_date TEXT NOT NULL,
                PRIMARY KEY(account_id, id),
                FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
            );

            CREATE TABLE collection_account_scoped (
                id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                organization_id TEXT,
                enc_name TEXT,
                PRIMARY KEY(account_id, id),
                FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
            );

            CREATE TABLE organization_account_scoped (
                id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                enc_org_key TEXT,
                name TEXT,
                PRIMARY KEY(account_id, id),
                FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
            );

            CREATE TABLE send_account_scoped (
                id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                type INTEGER,
                enc_name TEXT,
                enc_blob TEXT,
                deletion_date TEXT,
                expiration_date TEXT,
                disabled INTEGER,
                max_access_count INTEGER,
                PRIMARY KEY(account_id, id),
                FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
            );

            CREATE TABLE cipher_uri_account_scoped (
                id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                cipher_id TEXT NOT NULL,
                enc_uri TEXT,
                match_type INTEGER,
                PRIMARY KEY(account_id, id),
                FOREIGN KEY(account_id, cipher_id)
                    REFERENCES cipher_account_scoped(account_id, id) ON DELETE CASCADE
            );

            CREATE TABLE fido2_credential_account_scoped (
                id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                cipher_id TEXT NOT NULL,
                enc_blob TEXT,
                creation_date TEXT,
                PRIMARY KEY(account_id, id),
                FOREIGN KEY(account_id, cipher_id)
                    REFERENCES cipher_account_scoped(account_id, id) ON DELETE CASCADE
            );

            CREATE TABLE attachment_account_scoped (
                id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                cipher_id TEXT NOT NULL,
                enc_key TEXT,
                enc_file_name TEXT,
                file_size INTEGER,
                url TEXT,
                PRIMARY KEY(account_id, id),
                FOREIGN KEY(account_id, cipher_id)
                    REFERENCES cipher_account_scoped(account_id, id) ON DELETE CASCADE
            );

            INSERT INTO cipher_account_scoped
            SELECT c.* FROM cipher AS c JOIN account AS a ON a.id=c.account_id;

            INSERT INTO folder_account_scoped
            SELECT f.* FROM folder AS f JOIN account AS a ON a.id=f.account_id;

            INSERT INTO collection_account_scoped
            SELECT x.* FROM collection AS x JOIN account AS a ON a.id=x.account_id;

            INSERT INTO organization_account_scoped
            SELECT x.* FROM organization AS x JOIN account AS a ON a.id=x.account_id;

            INSERT INTO send_account_scoped
            SELECT x.* FROM send AS x JOIN account AS a ON a.id=x.account_id;

            INSERT INTO cipher_uri_account_scoped
              (account_id, id, cipher_id, enc_uri, match_type)
            SELECT c.account_id, u.id, u.cipher_id, u.enc_uri, u.match_type
            FROM cipher_uri AS u
            JOIN cipher AS c ON c.id=u.cipher_id
            JOIN account AS a ON a.id=c.account_id;

            INSERT INTO fido2_credential_account_scoped
              (account_id, id, cipher_id, enc_blob, creation_date)
            SELECT c.account_id, x.id, x.cipher_id, x.enc_blob, x.creation_date
            FROM fido2_credential AS x
            JOIN cipher AS c ON c.id=x.cipher_id
            JOIN account AS a ON a.id=c.account_id;

            INSERT INTO attachment_account_scoped
              (account_id, id, cipher_id, enc_key, enc_file_name, file_size, url)
            SELECT c.account_id, x.id, x.cipher_id, x.enc_key, x.enc_file_name,
                   x.file_size, x.url
            FROM attachment AS x
            JOIN cipher AS c ON c.id=x.cipher_id
            JOIN account AS a ON a.id=c.account_id;

            DROP TABLE cipher_uri;
            DROP TABLE fido2_credential;
            DROP TABLE attachment;
            DROP TABLE cipher;
            DROP TABLE folder;
            DROP TABLE collection;
            DROP TABLE organization;
            DROP TABLE send;

            ALTER TABLE cipher_account_scoped RENAME TO cipher;
            ALTER TABLE folder_account_scoped RENAME TO folder;
            ALTER TABLE collection_account_scoped RENAME TO collection;
            ALTER TABLE organization_account_scoped RENAME TO organization;
            ALTER TABLE send_account_scoped RENAME TO send;
            ALTER TABLE cipher_uri_account_scoped RENAME TO cipher_uri;
            ALTER TABLE fido2_credential_account_scoped RENAME TO fido2_credential;
            ALTER TABLE attachment_account_scoped RENAME TO attachment;

            CREATE INDEX idx_cipher_account ON cipher(account_id);
            CREATE INDEX idx_cipher_folder ON cipher(account_id, folder_id);
            CREATE INDEX idx_cipher_uri_cipher ON cipher_uri(account_id, cipher_id);
            CREATE INDEX idx_fido2_cipher ON fido2_credential(account_id, cipher_id);
            CREATE INDEX idx_folder_account ON folder(account_id);
            CREATE INDEX idx_attachment_cipher ON attachment(account_id, cipher_id);
            """)
            try exec(db, "COMMIT;")
        } catch {
            try? exec(db, "ROLLBACK;")
            throw error
        }
    }

    private static func primaryKeyColumns(
        of tableName: String,
        db: OpaquePointer
    ) throws -> [String] {
        let statement = try prepare(db, sql: "PRAGMA table_info(\(tableName));")
        defer { sqlite3_finalize(statement) }
        var keyed: [(position: Int, name: String)] = []
        while true {
            switch sqlite3_step(statement) {
            case SQLITE_ROW:
                let position = Int(sqlite3_column_int64(statement, 5))
                guard position > 0, let name = sqlite3_column_text(statement, 1) else {
                    continue
                }
                keyed.append((position, String(cString: name)))
            case SQLITE_DONE:
                return keyed.sorted { $0.position < $1.position }.map(\.name)
            default:
                throw VaultStoreError.stepFailed(errorMessage(db))
            }
        }
    }

    /// Adds account ownership to pre-account-scoped outbox tables. Only rows whose
    /// cipher still exists can be attributed safely. Everything else is quarantined
    /// outside the sendable outbox so it can never be submitted under whichever account
    /// happens to be active after upgrade.
    private static func migrateLegacyOutboxIfNeeded(_ db: OpaquePointer) throws {
        guard try !table("outbox", hasColumn: "account_id", db: db) else { return }

        let hasReceipt = try table(
            "passkey_import_receipt",
            hasColumn: "outbox_id",
            db: db
        )
        if hasReceipt {
            guard try table("passkey_import_receipt", hasColumn: "account_id", db: db),
                  try table("passkey_import_receipt", hasColumn: "completed", db: db) else {
                throw VaultStoreError.stepFailed(
                    "legacy passkey receipt ownership cannot be established"
                )
            }
        }

        // Preserve an existing receipt FK target while the outbox table is rebuilt under
        // the same name. With modern SQLite, RENAME otherwise rewrites it to
        // `outbox_legacy`, and dropping that table nulls the durable link.
        try exec(db, "PRAGMA foreign_keys=OFF;")
        try exec(db, "PRAGMA legacy_alter_table=ON;")
        defer {
            try? exec(db, "PRAGMA legacy_alter_table=OFF;")
            try? exec(db, "PRAGMA foreign_keys=ON;")
        }

        try exec(db, "BEGIN IMMEDIATE TRANSACTION;")
        do {
            try exec(db, "ALTER TABLE outbox RENAME TO outbox_legacy;")
            try exec(db, """
            CREATE TABLE outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id TEXT NOT NULL,
                op_type TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                last_known_revision_date TEXT,
                FOREIGN KEY(account_id) REFERENCES account(id) ON DELETE CASCADE
            );

            INSERT INTO outbox
              (id, account_id, op_type, entity_type, entity_id, payload_json,
               last_known_revision_date)
            SELECT o.id, c.account_id, o.op_type, o.entity_type, o.entity_id,
                   o.payload_json, o.last_known_revision_date
            FROM outbox_legacy AS o
            JOIN cipher AS c
              ON o.entity_type = 'cipher' AND c.id = o.entity_id
            JOIN account AS a ON a.id=c.account_id;

            INSERT INTO outbox_quarantine
              (legacy_outbox_id, op_type, entity_type, entity_id, payload_json,
               last_known_revision_date, reason)
            SELECT o.id, o.op_type, o.entity_type, o.entity_id, o.payload_json,
                   o.last_known_revision_date, 'account ownership could not be established'
            FROM outbox_legacy AS o
            LEFT JOIN cipher AS c
              ON o.entity_type = 'cipher' AND c.id = o.entity_id
            LEFT JOIN account AS a ON a.id=c.account_id
            WHERE c.id IS NULL OR a.id IS NULL;
            """)

            if hasReceipt {
                // An invalid legacy link cannot be retried safely. Detach and mark it
                // complete; valid id/account links remain attached to the rebuilt row.
                try exec(db, """
                UPDATE passkey_import_receipt
                SET outbox_id=NULL, completed=1
                WHERE outbox_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM outbox AS o
                    WHERE o.id=passkey_import_receipt.outbox_id
                      AND o.account_id=passkey_import_receipt.account_id
                );
                """)
            }
            try exec(db, "DROP TABLE outbox_legacy;")
            try exec(db, "COMMIT;")
        } catch {
            try? exec(db, "ROLLBACK;")
            throw error
        }
    }

    private static func table(
        _ tableName: String,
        hasColumn columnName: String,
        db: OpaquePointer
    ) throws -> Bool {
        // Both names are compile-time constants at the only call site.
        let statement = try prepare(db, sql: "PRAGMA table_info(\(tableName));")
        defer { sqlite3_finalize(statement) }
        while true {
            switch sqlite3_step(statement) {
            case SQLITE_ROW:
                guard let name = sqlite3_column_text(statement, 1) else { continue }
                if String(cString: name) == columnName { return true }
            case SQLITE_DONE:
                return false
            default:
                throw VaultStoreError.stepFailed(errorMessage(db))
            }
        }
    }
}
