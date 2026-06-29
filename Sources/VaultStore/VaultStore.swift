// VaultStore — encrypted offline cache for the Tessera vault.
//
// ENVIRONMENT NOTE (CLT-only host, no Xcode):
// This implementation uses the **system `import SQLite3` C API**, which resolves on
// Apple platforms with no extra linker config in SPM (it's a system module). The
// schema, SQL, and CRUD logic are identical to what SQLCipher needs.
//
// PRODUCTION: swap the linked library to SQLCipher and turn `applyEncryption` into a
// real key-derivation step. The public API already takes the random `passphrase`
// (from the Keychain) so no signature changes are needed — only the body of
// `applyEncryption(passphrase:)` and the linked SQLite build change. See that method.
//
// Design refs: blueprint §C; design spec §7.3 (schema) / §5.4 (VaultStore).

import Foundation
import SQLite3
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
    private let db: OpaquePointer

    /// Opens (creating if needed) the database at `databaseURL`, applies encryption
    /// (NO-OP under system SQLite3; SQLCipher in production), enables WAL, and
    /// creates the schema if absent. The `passphrase` is the random DB key from the
    /// Keychain — not the master password.
    public init(databaseURL: URL, passphrase: Data) throws {
        var handle: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(databaseURL.path, &handle, flags, nil) == SQLITE_OK,
              let handle else {
            if let handle { sqlite3_close(handle) }
            throw VaultStoreError.openFailed
        }
        self.db = handle

        do {
            // PRODUCTION: with SQLCipher this is where PRAGMA key / cipher_plaintext_header_size run.
            try VaultStore.applyEncryption(db: handle, passphrase: passphrase)
            try VaultStore.exec(handle, "PRAGMA journal_mode=WAL;")
            try VaultStore.exec(handle, "PRAGMA foreign_keys=ON;")
            try VaultStore.createSchema(handle)
        } catch {
            sqlite3_close(handle)
            throw error
        }
    }

    // Isolated so the actor-protected, non-Sendable `db` handle can be closed safely.
    isolated deinit {
        sqlite3_close(db)
    }

    /// Encryption seam. Under the system SQLite3 build this is a NO-OP.
    ///
    /// PRODUCTION: with SQLCipher, run `PRAGMA key` / `cipher_plaintext_header_size=32`
    /// here, e.g.:
    /// ```
    /// passphrase.withUnsafeBytes { raw in
    ///     sqlite3_key(db, raw.baseAddress, Int32(raw.count))
    /// }
    /// try exec(db, "PRAGMA cipher_plaintext_header_size = 32;")
    /// ```
    /// The shared App Group container additionally needs a self-managed salt so the
    /// app and the AutoFill extension can both open the file.
    private static func applyEncryption(db: OpaquePointer, passphrase: Data) throws {
        // NO-OP under system SQLite3 (no PRAGMA key support). Passphrase intentionally
        // unused here so the production swap is a body-only change.
        _ = passphrase
    }

    // MARK: - Ciphers

    public func upsertCiphers(_ rows: [CipherRow]) throws {
        guard !rows.isEmpty else { return }
        let sql = """
        INSERT INTO cipher
          (id, account_id, type, folder_id, organization_id, favorite, reprompt, edit,
           view_password, revision_date, creation_date, deleted_date,
           enc_name, enc_notes, enc_blob, enc_cipher_key, search_text)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)
        ON CONFLICT(id) DO UPDATE SET
          account_id=excluded.account_id, type=excluded.type, folder_id=excluded.folder_id,
          organization_id=excluded.organization_id, favorite=excluded.favorite,
          reprompt=excluded.reprompt, edit=excluded.edit, view_password=excluded.view_password,
          revision_date=excluded.revision_date, creation_date=excluded.creation_date,
          deleted_date=excluded.deleted_date, enc_name=excluded.enc_name,
          enc_notes=excluded.enc_notes, enc_blob=excluded.enc_blob,
          enc_cipher_key=excluded.enc_cipher_key, search_text=excluded.search_text;
        """
        try transaction {
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
    }

    public func allCiphers(accountID: String) throws -> [CipherRow] {
        let sql = "\(cipherSelectColumns) WHERE account_id=?1 ORDER BY revision_date DESC;"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, accountID)
        return try collectCiphers(stmt)
    }

    public func cipher(id: String) throws -> CipherRow? {
        let sql = "\(cipherSelectColumns) WHERE id=?1;"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, id)
        return try collectCiphers(stmt).first
    }

    public func deleteCipher(id: String) throws {
        let stmt = try prepare("DELETE FROM cipher WHERE id=?1;")
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, id)
        try step(stmt)
        if sqlite3_changes(db) == 0 { throw VaultStoreError.notFound }
    }

    /// Case-insensitive substring search over the plaintext `search_text` column.
    public func search(_ query: String, accountID: String) throws -> [CipherRow] {
        let sql = """
        \(cipherSelectColumns)
        WHERE account_id=?1 AND search_text LIKE ?2 ESCAPE '\\'
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

    // MARK: - Folders

    public func upsertFolders(_ rows: [FolderRow]) throws {
        guard !rows.isEmpty else { return }
        let sql = """
        INSERT INTO folder (id, account_id, enc_name, revision_date)
        VALUES (?1,?2,?3,?4)
        ON CONFLICT(id) DO UPDATE SET
          account_id=excluded.account_id, enc_name=excluded.enc_name,
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
        let sql = """
        INSERT INTO outbox (op_type, entity_type, entity_id, payload_json, last_known_revision_date)
        VALUES (?1,?2,?3,?4,?5);
        """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, op.opType)
        bindText(stmt, 2, op.entityType)
        bindText(stmt, 3, op.entityID)
        bindText(stmt, 4, op.payloadJSON)
        bindText(stmt, 5, op.lastKnownRevisionDate)
        try step(stmt)
        return sqlite3_last_insert_rowid(db)
    }

    public func outbox() throws -> [OutboxRow] {
        let sql = """
        SELECT id, op_type, entity_type, entity_id, payload_json, last_known_revision_date
        FROM outbox ORDER BY id ASC;
        """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        var rows: [OutboxRow] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else { throw VaultStoreError.stepFailed(lastErrorMessage()) }
            rows.append(OutboxRow(
                id: sqlite3_column_int64(stmt, 0),
                opType: textColumn(stmt, 1) ?? "",
                entityType: textColumn(stmt, 2) ?? "",
                entityID: textColumn(stmt, 3) ?? "",
                payloadJSON: textColumn(stmt, 4) ?? "",
                lastKnownRevisionDate: textColumn(stmt, 5)
            ))
        }
        return rows
    }

    public func clearOutbox(id: Int64) throws {
        let stmt = try prepare("DELETE FROM outbox WHERE id=?1;")
        defer { sqlite3_finalize(stmt) }
        bindInt(stmt, 1, id)
        try step(stmt)
        if sqlite3_changes(db) == 0 { throw VaultStoreError.notFound }
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
            id TEXT PRIMARY KEY,
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
            search_text TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_cipher_account ON cipher(account_id);
        CREATE INDEX IF NOT EXISTS idx_cipher_folder ON cipher(folder_id);

        CREATE TABLE IF NOT EXISTS cipher_uri (
            id TEXT PRIMARY KEY,
            cipher_id TEXT NOT NULL,
            enc_uri TEXT,
            match_type INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_cipher_uri_cipher ON cipher_uri(cipher_id);

        CREATE TABLE IF NOT EXISTS fido2_credential (
            id TEXT PRIMARY KEY,
            cipher_id TEXT NOT NULL,
            enc_blob TEXT,
            creation_date TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_fido2_cipher ON fido2_credential(cipher_id);

        CREATE TABLE IF NOT EXISTS folder (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            enc_name TEXT,
            revision_date TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_folder_account ON folder(account_id);

        CREATE TABLE IF NOT EXISTS collection (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            organization_id TEXT,
            enc_name TEXT
        );

        CREATE TABLE IF NOT EXISTS organization (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            enc_org_key TEXT,
            name TEXT
        );

        CREATE TABLE IF NOT EXISTS send (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            type INTEGER,
            enc_name TEXT,
            enc_blob TEXT,
            deletion_date TEXT,
            expiration_date TEXT,
            disabled INTEGER,
            max_access_count INTEGER
        );

        CREATE TABLE IF NOT EXISTS attachment (
            id TEXT PRIMARY KEY,
            cipher_id TEXT NOT NULL,
            enc_key TEXT,
            enc_file_name TEXT,
            file_size INTEGER,
            url TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_attachment_cipher ON attachment(cipher_id);

        CREATE TABLE IF NOT EXISTS sync_state (
            account_id TEXT PRIMARY KEY,
            last_account_revision TEXT,
            last_full_sync_at TEXT
        );

        CREATE TABLE IF NOT EXISTS outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            op_type TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            last_known_revision_date TEXT
        );
        """
        try exec(db, schema)
    }
}
