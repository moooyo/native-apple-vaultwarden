import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import Networking

/// Revision-token incremental sync, outbox flush, and AutoFill identity rebuild.
///
/// An `actor` so all sync state (in-flight work, conflict accounting) is serialized.
/// All decryption goes through the injected `KeyVault`; raw key bytes never reach
/// this layer.
///
/// ## Conflict strategy (design D12)
/// - **Outbox-first:** local writes are flushed before / independently of pulls, each
///   carrying `lastKnownRevisionDate` for optimistic concurrency. A stale write (server
///   has a newer revision → HTTP 400) leaves the row queued and is recorded as a
///   conflict rather than crashing.
/// - **Skip-write-when-server-older:** on pull, a server cipher only overwrites the
///   local row when the server `revisionDate` is strictly newer, protecting
///   locally-newer / pending edits.
public actor SyncEngine {
    private let api: VaultAPI
    private let store: VaultStore
    private let keyVault: KeyVault
    private let identityStore: CredentialIdentityWriting

    /// A fresh ISO-8601 formatter (with fractional seconds, matching the precision the
    /// server sends). Built per call rather than cached in a static, because
    /// `ISO8601DateFormatter` is not `Sendable` and a stored static would be a
    /// concurrency hazard under Swift 6 strict checking.
    private static func makeISOFormatter() -> ISO8601DateFormatter {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }

    /// Render a `Date` to the ISO-8601 string stored in the DB.
    static func isoString(_ date: Date) -> String {
        makeISOFormatter().string(from: date)
    }

    public init(api: VaultAPI, store: VaultStore, keyVault: KeyVault,
                identityStore: CredentialIdentityWriting) {
        self.api = api
        self.store = store
        self.keyVault = keyVault
        self.identityStore = identityStore
    }

    // MARK: - Full sync

    /// Pull `GET /api/sync`, map + upsert account/folders/ciphers into the store, then
    /// rebuild the AutoFill identity index. Soft-fails (dropped ciphers) are surfaced
    /// in the returned `SyncOutcome`, never thrown.
    ///
    /// Incremental rule: a server cipher overwrites the local row only when its
    /// `revisionDate` is strictly newer than what's stored (so locally-newer / pending
    /// rows are preserved). Brand-new server ciphers are always inserted.
    @discardableResult
    public func fullSync(accountID: String) async throws -> SyncOutcome {
        let response = try await api.sync(excludeDomains: true)

        // 1. Account row (carries the protected user/private keys + revision).
        let accountRow = AccountRow(
            id: accountID,
            email: response.profile.email,
            kdfType: nil,
            kdfIters: nil,
            revisionDate: nil,
            securityStamp: response.profile.securityStamp,
            encUserKey: response.profile.key?.stringValue,
            encPrivateKey: response.profile.privateKey?.stringValue
        )
        try await store.upsertAccounts([accountRow])

        // 2. Folders (always overwritten — small, no local-edit story in M1).
        let folderRows = response.folders.map { folder in
            FolderRow(
                id: folder.id,
                accountID: accountID,
                encName: folder.name.stringValue,
                revisionDate: Self.isoString(folder.revisionDate)
            )
        }
        try await store.upsertFolders(folderRows)

        // 3. Ciphers — apply the incremental rule against the stored revision dates.
        let stored = try await store.allCiphers(accountID: accountID)
        var storedByID: [String: CipherRow] = [:]
        for row in stored { storedByID[row.id] = row }

        // Outbox entity ids are protected: never delete a row with a pending write,
        // even if the server omits it (the create may not have round-tripped yet).
        let pendingIDs = Set(try await store.outbox().map(\.entityID))

        var toUpsert: [CipherRow] = []
        var serverIDs = Set<String>()
        for cipher in response.ciphers {
            serverIDs.insert(cipher.id)
            if let existing = storedByID[cipher.id],
               !Self.serverIsNewer(serverDate: cipher.revisionDate, storedDate: existing.revisionDate) {
                // Local copy is same-or-newer → skip-write (protect local/pending edits).
                continue
            }
            toUpsert.append(try await makeCipherRow(cipher, accountID: accountID))
        }
        if !toUpsert.isEmpty {
            try await store.upsertCiphers(toUpsert)
        }

        // 4. Local ciphers the server no longer has (and not pending) → delete.
        var deletedLocally = 0
        for row in stored where !serverIDs.contains(row.id) && !pendingIDs.contains(row.id) {
            try await store.deleteCipher(id: row.id)
            deletedLocally += 1
        }

        // 5. Persist sync state.
        try await store.setSyncState(SyncStateRow(
            accountID: accountID,
            lastAccountRevision: response.profile.securityStamp,
            lastFullSyncAt: Self.isoString(Date())
        ))

        // 6. Rebuild AutoFill identities from the now-current store contents.
        let identitiesWritten = await rebuildIdentities(accountID: accountID)

        return SyncOutcome(
            upserted: toUpsert.count,
            deletedLocally: deletedLocally,
            dropped: response.droppedCipherErrors.count,
            droppedMessages: response.droppedCipherErrors,
            identitiesWritten: identitiesWritten
        )
    }

    // MARK: - Outbox flush

    /// Flush queued outbound writes (outbox-first). For each op:
    /// - create/update: call the API with `lastKnownRevisionDate` for optimistic
    ///   concurrency; on success clear the row.
    /// - delete: call `deleteCipher`; on success clear the row.
    /// A stale/conflict error (HTTP 400, or a 404 on update/delete of something the
    /// server already changed) leaves the row queued and is counted as a conflict —
    /// it never throws. Malformed payloads / unknown ops are hard errors (they can
    /// never succeed, so surfacing them is correct).
    @discardableResult
    public func flushOutbox(accountID: String) async throws -> FlushOutcome {
        let rows = try await store.outbox()
        var flushed = 0
        var conflicts = 0

        for row in rows {
            guard let op = OutboxOp(rawValue: row.opType) else {
                throw SyncError.unknownOutboxOp(row.opType)
            }
            // M1 only flushes ciphers; ignore (leave queued) any other entity type.
            guard OutboxEntity(rawValue: row.entityType) == .cipher else { continue }

            do {
                switch op {
                case .create:
                    let payload = try decodePayload(row)
                    let req = try payload.cipherRequest(lastKnownRevisionDate: nil)
                    let created = try await api.createCipher(req)
                    // The server assigns the real id; persist the round-tripped row so
                    // local state matches the server (best-effort — a store failure here
                    // shouldn't strand the outbox row).
                    try? await persistCreated(created, localID: row.entityID, accountID: accountID)
                    try await store.clearOutbox(id: row.id!)
                    flushed += 1

                case .update:
                    let payload = try decodePayload(row)
                    let last = row.lastKnownRevisionDate.flatMap(Self.parseDate)
                    let req = try payload.cipherRequest(lastKnownRevisionDate: last)
                    let updated = try await api.updateCipher(id: row.entityID, req)
                    try? await persistCreated(updated, localID: row.entityID, accountID: accountID)
                    try await store.clearOutbox(id: row.id!)
                    flushed += 1

                case .delete:
                    try await api.deleteCipher(id: row.entityID)
                    try? await store.deleteCipher(id: row.entityID)
                    try await store.clearOutbox(id: row.id!)
                    flushed += 1
                }
            } catch let NetworkingError.http(status, _) where Self.isConflict(status) {
                // Optimistic-concurrency conflict: leave the row queued for the next
                // pull+retry cycle. Do NOT crash, do NOT clear.
                conflicts += 1
            } catch NetworkingError.unauthorized {
                // Token expired mid-flush — stop; the auth layer will refresh and retry.
                throw NetworkingError.unauthorized
            }
            // SyncError (malformed payload / unknown op) intentionally propagates.
        }

        return FlushOutcome(flushed: flushed, conflicts: conflicts)
    }

    // MARK: - Background refresh registration

    /// Platform-gated registration of the background-refresh trigger. Compile-only:
    /// the real scheduling is wired by the app target (which owns the Info.plist
    /// `BGTaskSchedulerPermittedIdentifiers` / the run loop). Kept minimal so the
    /// call site is explicit and the platform branches are documented.
    public nonisolated func registerBackgroundRefresh() {
        #if os(iOS)
        // App target registers a `BGAppRefreshTaskRequest` for
        // `AppShared`'s background-refresh identifier and, in its handler, calls
        // `fullSync` then `flushOutbox`. Declared here only as the documented seam;
        // `BackgroundTasks` is not imported in this library to keep it host-buildable.
        #elseif os(macOS)
        // App target schedules an `NSBackgroundActivityScheduler` (repeating,
        // ~30 min interval, `.utility` QoS) whose block runs the same sync+flush.
        #endif
    }

    // MARK: - Mapping CipherResponse -> CipherRow

    /// Map a server cipher into a store row, decrypting (via `KeyVault`) just enough to
    /// build the plaintext `search_text` index. The encrypted blob (`enc_blob`) is the
    /// JSON of the type sub-payload so the repository can later rebuild the full item.
    func makeCipherRow(_ cipher: CipherResponse, accountID: String) async throws -> CipherRow {
        let searchText = await buildSearchText(cipher)
        let encBlob = try? Self.encodeBlob(cipher)

        return CipherRow(
            id: cipher.id,
            accountID: accountID,
            type: cipher.type.rawValue,
            folderID: cipher.folderId,
            organizationID: cipher.organizationId,
            favorite: cipher.favorite,
            reprompt: cipher.reprompt,
            edit: cipher.edit ?? true,
            viewPassword: cipher.viewPassword ?? true,
            revisionDate: Self.isoString(cipher.revisionDate),
            creationDate: cipher.creationDate.map(Self.isoString)
                ?? Self.isoString(cipher.revisionDate),
            deletedDate: cipher.deletedDate.map(Self.isoString),
            encName: cipher.name.stringValue,
            encNotes: cipher.notes?.stringValue,
            encBlob: encBlob,
            encCipherKey: cipher.key?.stringValue,
            searchText: searchText
        )
    }

    /// Decrypt name + login username + URIs into a single lowercased searchable string.
    /// Per-cipher key (if present) is unwrapped first; decryption uses it so item-keyed
    /// ciphers index correctly. Best-effort per field: a field that fails to decrypt is
    /// skipped rather than aborting the row (soft-fail).
    private func buildSearchText(_ cipher: CipherResponse) async -> String {
        let cipherKey: SymmetricCryptoKey?
        if let protected = cipher.key {
            cipherKey = try? await keyVault.cipherKey(fromProtected: protected)
        } else {
            cipherKey = nil
        }

        func dec(_ enc: EncString?) async -> String? {
            guard let enc else { return nil }
            guard let data = try? await keyVault.decrypt(enc, cipherKey: cipherKey),
                  let s = String(data: data, encoding: .utf8) else { return nil }
            return s
        }

        var parts: [String] = []
        if let name = await dec(cipher.name) { parts.append(name) }
        if let username = await dec(cipher.login?.username) { parts.append(username) }
        for uri in cipher.login?.uris ?? [] {
            if let u = await dec(uri.uri) { parts.append(u) }
        }
        if let card = cipher.card {
            if let holder = await dec(card.cardholderName) { parts.append(holder) }
            if let brand = await dec(card.brand) { parts.append(brand) }
        }
        if let identity = cipher.identity {
            if let first = await dec(identity.firstName) { parts.append(first) }
            if let last = await dec(identity.lastName) { parts.append(last) }
            if let email = await dec(identity.email) { parts.append(email) }
        }

        return parts.joined(separator: " ").lowercased()
    }

    // MARK: - Identity rebuild

    /// Rebuild the AutoFill credential identities from the decrypted store contents.
    /// Returns the number of identities written (0 if AutoFill is disabled, in which
    /// case nothing is touched).
    private func rebuildIdentities(accountID: String) async -> Int {
        guard await identityStore.isEnabled() else { return 0 }

        let rows = (try? await store.allCiphers(accountID: accountID)) ?? []
        var identities: [CredentialIdentity] = []
        for row in rows where row.type == CipherType.login.rawValue && row.deletedDate == nil {
            guard let built = await buildIdentities(for: row) else { continue }
            identities.append(contentsOf: built)
        }

        if await identityStore.supportsIncremental() {
            await identityStore.incremental(add: identities, remove: [])
        } else {
            await identityStore.replaceAll(identities)
        }
        return identities.count
    }

    /// Build the AutoFill identities for a single login row (one per URI), decrypting
    /// the username + URIs + TOTP. Returns `nil` if the row has no usable URI.
    private func buildIdentities(for row: CipherRow) async -> [CredentialIdentity]? {
        let cipherKey: SymmetricCryptoKey?
        if let enc = row.encCipherKey, let parsed = try? EncString(parsing: enc) {
            cipherKey = try? await keyVault.cipherKey(fromProtected: parsed)
        } else {
            cipherKey = nil
        }

        func dec(_ wire: String?) async -> String? {
            guard let wire, let enc = try? EncString(parsing: wire) else { return nil }
            guard let data = try? await keyVault.decrypt(enc, cipherKey: cipherKey),
                  let s = String(data: data, encoding: .utf8) else { return nil }
            return s
        }

        // The login sub-payload is stored in `enc_blob` as JSON of EncString wire
        // strings; decode it to find the URIs + username + totp.
        guard let blob = row.encBlob,
              let payload = try? JSONDecoder().decode(BlobPayload.self, from: Data(blob.utf8)),
              let login = payload.login else { return nil }

        let username = await dec(login.username) ?? ""
        var out: [CredentialIdentity] = []

        for uri in login.uris ?? [] {
            guard let serviceIdentifier = await dec(uri.uri), !serviceIdentifier.isEmpty else { continue }
            out.append(CredentialIdentity(
                recordID: row.id,
                serviceIdentifier: serviceIdentifier,
                user: username,
                kind: .password
            ))
            // A login with a TOTP secret also offers a one-time-code identity for the
            // same service.
            if login.totp != nil {
                out.append(CredentialIdentity(
                    recordID: row.id,
                    serviceIdentifier: serviceIdentifier,
                    user: username,
                    kind: .otp
                ))
            }
            // Passkeys present on the login map to passkey identities (rpId == service).
            for _ in login.fido2Credentials ?? [] {
                out.append(CredentialIdentity(
                    recordID: row.id,
                    serviceIdentifier: serviceIdentifier,
                    user: username,
                    kind: .passkey
                ))
            }
        }
        return out.isEmpty ? nil : out
    }

    // MARK: - Helpers

    /// Strictly-newer comparison of two ISO-8601 date strings. Returns `true` only when
    /// `serverDate` parses to a `Date` strictly after `storedDate`. If either string
    /// fails to parse, the server is treated as newer (conservatively re-pull) so a
    /// malformed local date can't permanently shadow a server update.
    public static func serverIsNewer(serverDate: Date, storedDate: String) -> Bool {
        guard let stored = parseDate(storedDate) else { return true }
        return serverDate > stored
    }

    /// Parse an ISO-8601 string with or without fractional seconds.
    public static func parseDate(_ s: String) -> Date? {
        if let d = makeISOFormatter().date(from: s) { return d }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: s)
    }

    /// HTTP statuses treated as an optimistic-concurrency conflict (leave queued).
    public static func isConflict(_ status: Int) -> Bool {
        status == 400 || status == 404 || status == 409
    }

    private func decodePayload(_ row: OutboxRow) throws -> OutboxCipherPayload {
        do { return try OutboxCipherPayload.decode(row.payloadJSON) }
        catch { throw SyncError.malformedOutboxPayload(id: row.id) }
    }

    /// Persist a server-returned cipher (after a create/update flush) so local state
    /// matches. For a create, the local placeholder id may differ from the server id;
    /// remove the placeholder then upsert under the server id.
    private func persistCreated(_ cipher: CipherResponse, localID: String, accountID: String) async throws {
        if cipher.id != localID {
            try? await store.deleteCipher(id: localID)
        }
        let row = try await makeCipherRow(cipher, accountID: accountID)
        try await store.upsertCiphers([row])
    }

    /// Encode the cipher's type sub-payloads as a JSON blob of EncString wire strings,
    /// for `enc_blob`. Decryption of the blob happens in the repository/`VaultReader`.
    static func encodeBlob(_ cipher: CipherResponse) throws -> String {
        let blob = BlobPayload(cipher)
        let data = try JSONEncoder().encode(blob)
        return String(decoding: data, as: UTF8.self)
    }
}

/// The result of a `flushOutbox`. `flushed` rows were sent + cleared; `conflicts`
/// rows hit optimistic-concurrency conflicts and remain queued for the next cycle.
public struct FlushOutcome: Sendable, Equatable {
    public let flushed: Int
    public let conflicts: Int
    public init(flushed: Int, conflicts: Int) {
        self.flushed = flushed
        self.conflicts = conflicts
    }
}
