import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import Networking
import Generators
import Fido2
import AppShared

/// Revision-token incremental sync, outbox flush, and AutoFill identity rebuild.
///
/// An `actor` so all sync state (in-flight work, conflict accounting) is serialized.
/// All decryption goes through the injected `KeyVault`; raw key bytes never reach
/// this layer.
///
/// ## Conflict strategy
/// - **Outbox-first:** local writes are flushed before / independently of pulls, each
///   carrying `lastKnownRevisionDate` for optimistic concurrency. A stale write (server
///   has a newer revision → HTTP 400) parks the queued write for explicit recovery.
/// - **Skip-write-when-server-older:** on pull, a server cipher only overwrites the
///   local row when the server `revisionDate` is strictly newer, protecting
///   locally-newer / pending edits.
public actor SyncEngine {
    private let api: VaultAPI
    private let store: VaultStore
    private let keyVault: KeyVault
    private let identityStore: CredentialIdentityWriting
    private let mutationCoordinator: VaultMutationCoordinator
    private let identityPublicationCoordinator = VaultMutationCoordinator()
    /// Revokes pending AutoFill publications when the app begins/finishes an account
    /// transition. Account-scoped DB reconciliation may safely finish, but stale identities
    /// must never overwrite the authoritative clear/new-account replacement.
    private var identityWriteGeneration: UInt64 = 0

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
                identityStore: CredentialIdentityWriting,
                mutationCoordinator: VaultMutationCoordinator = VaultMutationCoordinator()) {
        self.api = api
        self.store = store
        self.keyVault = keyVault
        self.identityStore = identityStore
        self.mutationCoordinator = mutationCoordinator
    }

    public func invalidateIdentityWrites() {
        identityWriteGeneration &+= 1
    }

    public func identityGenerationLease() -> UInt64 { identityWriteGeneration }

    public func clearCredentialIdentitiesForAccountTransition() async {
        identityWriteGeneration &+= 1
        let generation = identityWriteGeneration
        await identityPublicationCoordinator.withLock {
            guard await self.identityGenerationLease() == generation else { return }
            await self.identityStore.replaceAll([])
        }
    }

    /// Rebuild identities after a local CRUD/import transaction, without requiring a
    /// network sync. Callers already hold the shared mutation coordinator.
    @discardableResult
    public func refreshCredentialIdentities(
        accountID: String,
        expectedGeneration: UInt64
    ) async -> Int {
        return await rebuildIdentities(
            accountID: accountID,
            expectedGeneration: expectedGeneration
        )
    }

    // MARK: - Full sync

    /// Pull `GET /api/sync`, map + upsert account/folders/ciphers into the store, then
    /// rebuild the AutoFill identity index. Soft-fails (dropped ciphers) are surfaced
    /// in the returned `SyncOutcome`, never thrown.
    ///
    /// Incremental rule: a server cipher overwrites the local row only when its
    /// `revisionDate` is strictly newer than what's stored (so locally-newer rows are
    /// preserved). A cipher with a pending (unflushed) outbox write is never overwritten
    /// regardless of revisionDate, and a pending cipher the server omits is never
    /// deleted — `flushOutbox` owns those rows. Brand-new server ciphers are inserted.
    @discardableResult
    public func fullSync(accountID: String) async throws -> SyncOutcome {
        try await mutationCoordinator.withLock {
            try await self.performFullSync(accountID: accountID)
        }
    }

    private func performFullSync(accountID: String) async throws -> SyncOutcome {
        let identityLease = identityWriteGeneration
        let sendGeneration = try await store.sendCacheGeneration(accountID: accountID)
        let response: SyncResponse
        do {
            response = try await api.sync(accountID: accountID, excludeDomains: true)
        } catch let error as NetworkingError where error.deniesVaultListingAccess {
            try await store.clearSendCache(accountID: accountID)
            throw error
        }

        // 1. Account row. Login-owned server/KDF/protected-user-key metadata is required
        // for cold unlock and must survive the profile's partial sync representation.
        let storedAccount = try await store.account(id: accountID)
        if let cached = storedAccount?.encUserKey, let current = response.profile.key,
           current.type == .aesCbc256_HmacSha256_B64, current.ciphertext.count == 80, current.stringValue != cached {
            throw SyncError.accountUnlockChanged
        }
        let accountRow = AccountRow(
            id: accountID,
            email: response.profile.email,
            serverURL: storedAccount?.serverURL,
            kdfType: storedAccount?.kdfType,
            kdfIters: storedAccount?.kdfIters,
            revisionDate: storedAccount?.revisionDate,
            securityStamp: response.profile.securityStamp,
            encUserKey: storedAccount?.encUserKey ?? response.profile.key?.stringValue,
            encPrivateKey: response.profile.privateKey?.stringValue
                ?? storedAccount?.encPrivateKey
        )
        try await store.upsertAccounts([accountRow])
        let sends = response.sends
        let completeSendListing = sends != nil && response.droppedSendCount == 0
        let appliedSendGeneration = try await store.cacheSends(sends ?? [], accountID: accountID,
                                                               update: completeSendListing ? .completeListing : .partialListing,
                                                               ifUnchangedSince: sendGeneration)

        // 2. Reconcile the account's server-authoritative folder set.
        let storedFolders = try await store.allFolders(accountID: accountID)
        var folderRows: [FolderRow] = []
        var folderMappingDrops: [String] = []
        let serverFolderIDs = Set(response.folders.map(\.id))
        for folder in response.folders {
            guard Self.isSupportedCipherField(folder.name) else {
                folderMappingDrops.append(
                    "Folder \(folder.id): unsupported encryption type \(folder.name.type.rawValue)"
                )
                continue
            }
            folderRows.append(FolderRow(
                id: folder.id,
                accountID: accountID,
                encName: folder.name.stringValue,
                revisionDate: Self.isoString(folder.revisionDate)
            ))
        }
        try await store.upsertFolders(folderRows)
        // A malformed folder is soft-dropped without exposing its id, so omission cannot
        // be distinguished from deletion in that response. Preserve stale rows until the
        // next clean sync instead of risking irreversible local data loss.
        if response.droppedFolderErrors.isEmpty {
            for folder in storedFolders where !serverFolderIDs.contains(folder.id) {
                try await store.deleteFolder(id: folder.id, accountID: accountID)
            }
        }

        if response.droppedCipherErrors.isEmpty {
            try await reconcileUnconfirmedCreates(response.ciphers, accountID: accountID)
        }

        // 3. Ciphers — apply the incremental rule against the stored revision dates.
        let stored = try await store.allCiphers(accountID: accountID, scope: .all)
        var storedByID: [String: CipherRow] = [:]
        for row in stored { storedByID[row.id] = row }

        // Outbox entity ids are protected: never delete a row with a pending write,
        // even if the server omits it (the create may not have round-tripped yet).
        let pendingIDs = Set(try await store.outbox(accountID: accountID).map(\.entityID))

        var toUpsert: [CipherRow] = []
        var serverIDs = Set<String>()
        var deletedLocally = 0
        var cipherMappingDrops: [String] = []
        for cipher in response.ciphers {
            serverIDs.insert(cipher.id)
            // A cipher with a queued (unflushed) local write must never be clobbered by
            // a pull — its local edit hasn't reached the server yet, so the server copy
            // is by definition stale regardless of revisionDate. flushOutbox owns that
            // row's reconciliation.
            let existing = storedByID[cipher.id]
            let deleted = cipher.deletedDate.map(Self.isoString)
            let archived = cipher.archivedDate.map(Self.isoString)
            let localDate = existing.flatMap { Self.parseDate($0.revisionDate) }
            let deletionToKeep = deleted ?? ((localDate ?? .distantPast) > cipher.revisionDate ? existing?.deletedDate : nil)
            if let existing, existing.deletedDate != deletionToKeep || existing.archivedDate != archived {
                try await store.setCipherVisibility(id: existing.id, accountID: accountID,
                                                    deletedDate: deletionToKeep, archivedDate: archived)
            }
            if pendingIDs.contains(cipher.id) { continue }
            guard Self.usesSupportedEncryption(cipher) else {
                cipherMappingDrops.append(
                    "Cipher \(cipher.id): unsupported encryption type"
                )
                continue
            }
            if let existing, let localDate, cipher.revisionDate <= localDate {
                if cipher.revisionDate == localDate,
                   cipher.favorite != existing.favorite || cipher.folderId != existing.folderID {
                    try await store.setCipherClassification(id: cipher.id, accountID: accountID,
                                                           folderID: cipher.folderId, favorite: cipher.favorite)
                }
                continue
            }
            toUpsert.append(try Self.makeCipherRow(cipher, accountID: accountID))
        }
        if !toUpsert.isEmpty {
            try await store.upsertCiphers(toUpsert)
        }

        // 4. Local ciphers the server no longer has (and not pending) → delete.
        // As with folders, a dropped cipher's id is unavailable. Defer all omission-based
        // deletion until a clean response so a malformed server element cannot erase the
        // last locally readable copy.
        if response.droppedCipherErrors.isEmpty {
            for row in stored where !serverIDs.contains(row.id) && !pendingIDs.contains(row.id) {
                try await store.deleteCipher(id: row.id, accountID: accountID)
                deletedLocally += 1
            }
        }

        // 5. Persist sync state.
        try await store.setSyncState(SyncStateRow(
            accountID: accountID,
            lastAccountRevision: response.profile.securityStamp,
            lastFullSyncAt: Self.isoString(Date())
        ))

        // 6. Rebuild AutoFill identities from the now-current store contents.
        let identitiesWritten = await rebuildIdentities(
            accountID: accountID,
            expectedGeneration: identityLease
        )

        let droppedMessages = response.droppedCipherErrors.map { "Cipher: \($0)" }
            + cipherMappingDrops
            + response.droppedFolderErrors.map { "Folder: \($0)" }
            + folderMappingDrops
            + response.droppedCollectionErrors.map { "Collection: \($0)" }
            + Array(repeating: "Send: unreadable encrypted record", count: response.droppedSendCount)
        let sendCount: Int?
        if let sends, completeSendListing, let appliedSendGeneration,
           try await store.sendCacheGeneration(accountID: accountID) == appliedSendGeneration {
            let now = Date.now
            sendCount = sends.count { ($0.type == .text || $0.type == .file) && $0.deletionDate > now }
        } else {
            sendCount = nil
        }
        return SyncOutcome(
            upserted: toUpsert.count,
            deletedLocally: deletedLocally,
            dropped: droppedMessages.count,
            droppedMessages: droppedMessages,
            identitiesWritten: identitiesWritten,
            profile: SyncedAccountProfile(email: response.profile.email, name: response.profile.name,
                                          serverURL: storedAccount?.serverURL),
            sendCount: sendCount
        )
    }

    // MARK: - Outbox flush

    /// Flush queued outbound writes (outbox-first). For each op:
    /// - create/update: call the API with `lastKnownRevisionDate` for optimistic
    ///   concurrency; on success clear the row.
    /// - delete: call `deleteCipher`; on success clear the row.
    ///
    /// Conflict handling is op-specific:
    /// - **create:** claim the row before dispatch, so an interruption cannot replay a POST
    ///   whose outcome is unknown. Only a confirmed pre-connect failure permits retry.
    /// - **update/delete:** park conflicts for explicit recovery. A DELETE 404 is already
    ///   the desired end state; a 409 is not proof of deletion.
    ///
    /// Transport / `serverUnreachable` errors are re-thrown so the row stays queued and
    /// the caller can retry once connectivity returns. Malformed payloads / unknown ops
    /// / missing row ids are hard errors (they can never succeed) and propagate.
    @discardableResult
    public func flushOutbox(accountID: String) async throws -> FlushOutcome {
        try await mutationCoordinator.withLock {
            try await self.performFlushOutbox(accountID: accountID)
        }
    }

    private func performFlushOutbox(accountID: String) async throws -> FlushOutcome {
        var flushed = 0
        var conflicts = 0
        var deferredRowIDs = Set<Int64>()

        while true {
            let rows = try await store.outboxForFlush(accountID: accountID)
            let blocked = Set(rows.filter { $0.issue != nil && $0.entityType == OutboxEntity.cipher.rawValue }.map(\.entityID))
            guard let row = rows.first(where: {
                if $0.entityType == OutboxEntity.cipher.rawValue, blocked.contains($0.entityID) { return false }
                guard let id = $0.id else { return true }
                return !deferredRowIDs.contains(id)
            }) else { break }
            guard let op = OutboxOp(rawValue: row.opType) else {
                throw SyncError.unknownOutboxOp(row.opType)
            }
            // M1 only flushes ciphers; ignore (leave queued) any other entity type.
            guard OutboxEntity(rawValue: row.entityType) == .cipher else {
                if let id = row.id { deferredRowIDs.insert(id) }
                continue
            }
            guard let rowID = row.id else { throw SyncError.malformedOutboxPayload(id: nil) }

            if op == .create {
                let payload = try decodePayload(row)
                let request = try payload.cipherRequest(lastKnownRevisionDate: nil)
                guard try await store.setOutboxIssue(expected: row, issue: .unconfirmedCreate) else { continue }
                switch try await dispatchClaimedCreate(row, request: request) {
                case .created: flushed += 1
                case .pending: throw NetworkingError.serverUnreachable
                case .issue: conflicts += 1
                }
                continue
            }

            do {
                switch op {
                case .create: break
                case .update:
                    let payload = try decodePayload(row)
                    if let existing = try await store.cipher(id: row.entityID, accountID: accountID),
                       existing.deletedDate != nil || existing.archivedDate != nil {
                        _ = try await store.setOutboxIssue(expected: row, issue: .updateConflict)
                        conflicts += 1
                        continue
                    }
                    guard let last = row.lastKnownRevisionDate.flatMap(Self.parseDate) else {
                        _ = try await store.setOutboxIssue(expected: row, issue: .updateConflict)
                        conflicts += 1
                        continue
                    }
                    let req = try payload.cipherRequest(lastKnownRevisionDate: last)
                    let updated = try await api.updateCipher(
                        accountID: accountID,
                        id: row.entityID,
                        req
                    )
                    let updatedRow = try Self.makeCipherRow(updated, accountID: accountID)
                    try await store.finalizeOutboxWrite(
                        id: rowID,
                        accountID: accountID,
                        localEntityID: row.entityID,
                        serverCipher: updatedRow
                    )
                    flushed += 1

                case .delete:
                    try await api.deleteCipher(accountID: accountID, id: row.entityID)
                    try? await store.deleteCipher(id: row.entityID, accountID: accountID)
                    try await store.clearOutbox(id: rowID, accountID: accountID)
                    flushed += 1
                }
            } catch let NetworkingError.http(status, body) {
                if op == .delete && Self.isAlreadyDeleted(status) {
                    // Server already removed it → desired end state. Clear locally too.
                    try? await store.deleteCipher(id: row.entityID, accountID: accountID)
                    try await store.clearOutbox(id: rowID, accountID: accountID)
                    flushed += 1
                } else if Self.isConflict(status) {
                    _ = try await store.setOutboxIssue(expected: row, issue: op == .delete ? .deleteConflict : .updateConflict)
                    conflicts += 1
                } else {
                    // A non-conflict HTTP error (e.g. 500) is a genuine failure; re-throw
                    // so the caller can surface it and the row stays queued.
                    throw NetworkingError.http(status: status, body: body)
                }
            } catch NetworkingError.unauthorized {
                // Token expired mid-flush — stop; the auth layer will refresh and retry.
                throw NetworkingError.unauthorized
            }
            // Transport / serverUnreachable / SyncError (malformed payload, unknown op,
            // missing row id) intentionally propagate: the row stays queued for retry.
        }

        return FlushOutcome(flushed: flushed, conflicts: conflicts)
    }

    package enum ClaimedCreateResult {
        case created(String), pending, issue(OutboxRow.Issue)
    }

    package func dispatchClaimedCreate(_ row: OutboxRow, request: CipherRequest) async throws -> ClaimedCreateResult {
        guard let id = row.id else { throw SyncError.malformedOutboxPayload(id: nil) }
        let accountID = row.accountID
        let created: CipherResponse
        do {
            created = try await api.createCipher(accountID: accountID, request)
        } catch NetworkingError.serverUnreachable, NetworkingError.accessTokenUnavailable {
            try await store.setOutboxIssue(id: id, accountID: accountID, issue: nil)
            return .pending
        } catch NetworkingError.unauthorized {
            try await store.setOutboxIssue(id: id, accountID: accountID, issue: nil)
            throw NetworkingError.unauthorized
        } catch let error as NetworkingError {
            switch error {
            case .http(let status, _) where (400..<500).contains(status) && status != 400 && status != 408:
                try await store.setOutboxIssue(id: id, accountID: accountID, issue: .rejectedCreate)
                return .issue(.rejectedCreate)
            case .accountContextChanged: throw error
            default: break
            }
            return .issue(.unconfirmedCreate)
        }

        let createdRow = try Self.makeCipherRow(created, accountID: accountID)
        try await store.finalizeOutboxWrite(id: id, accountID: accountID, localEntityID: row.entityID, serverCipher: createdRow)
        return .created(created.id)
    }

    package func confirmedCreate(in ciphers: [CipherResponse], for row: OutboxRow) throws -> CipherResponse? {
        let payload = try decodePayload(row)
        guard payload.organizationID == nil else { return nil }
        let candidates = ciphers.filter {
            $0.organizationId == nil && $0.type.rawValue == payload.type &&
                $0.name.stringValue == payload.name && $0.key?.stringValue == payload.key
        }
        guard candidates.count == 1, let match = candidates.first,
              match.deletedDate == nil, match.archivedDate == nil,
              match.folderId == payload.folderID, match.favorite == payload.favorite,
              match.reprompt == payload.reprompt, match.notes?.stringValue == payload.notes,
              Self.usesSupportedEncryption(match) else { return nil }

        let sent = try JSONDecoder().decode(BlobPayload.self, from: Data(row.payloadJSON.utf8))
        var actual = BlobPayload(match)
        if sent.login?.passwordRevisionDate == nil { actual.login?.passwordRevisionDate = nil }
        guard sent.normalizedForCreateConfirmation() == actual.normalizedForCreateConfirmation() else { return nil }
        return match
    }

    private func reconcileUnconfirmedCreates(_ ciphers: [CipherResponse], accountID: String) async throws {
        let rows = try await store.outbox(accountID: accountID)
        let entityCounts = Dictionary(grouping: rows, by: \.entityID).mapValues(\.count)
        for row in rows where row.issue == .unconfirmedCreate && row.opType == OutboxOp.create.rawValue {
            guard let id = row.id, entityCounts[row.entityID] == 1,
                  let matched = try? confirmedCreate(in: ciphers, for: row),
                  matched.id == row.entityID || entityCounts[matched.id] == nil else { continue }
            let cipher = try Self.makeCipherRow(matched, accountID: accountID)
            try await store.finalizeOutboxWrite(id: id, accountID: accountID, localEntityID: row.entityID, serverCipher: cipher)
        }
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

    private static func isSupportedCipherField(_ value: EncString) -> Bool {
        // `SymmetricCrypto.decrypt` intentionally implements only Bitwarden's current
        // type-2 AES-256-CBC + HMAC format. A structurally valid legacy type-1 value is
        // still not decryptable by this client and must be soft-dropped like type 7.
        value.type == .aesCbc256_HmacSha256_B64
    }

    /// Type-7/legacy/asymmetric field payloads are well-formed EncStrings but this client
    /// cannot decrypt them. Keep the last readable local row and surface a soft drop rather
    /// than overwriting it with an item the repository will silently hide.
    package static func usesSupportedEncryption(_ cipher: CipherResponse) -> Bool {
        var values: [EncString] = [cipher.name]
        func append(_ value: EncString?) { if let value { values.append(value) } }
        append(cipher.notes)
        append(cipher.key)
        if let login = cipher.login {
            append(login.username); append(login.password); append(login.totp)
            for uri in login.uris ?? [] { append(uri.uri); append(uri.uriChecksum) }
            for credential in login.fido2Credentials ?? [] {
                append(credential.credentialId); append(credential.keyType)
                append(credential.keyAlgorithm); append(credential.keyCurve)
                append(credential.keyValue); append(credential.rpId); append(credential.rpName)
                append(credential.userHandle); append(credential.userName)
                append(credential.userDisplayName); append(credential.counter)
                append(credential.discoverable)
            }
        }
        if let card = cipher.card {
            append(card.cardholderName); append(card.brand); append(card.number)
            append(card.expMonth); append(card.expYear); append(card.code)
        }
        if let identity = cipher.identity {
            append(identity.title); append(identity.firstName); append(identity.middleName)
            append(identity.lastName); append(identity.address1); append(identity.address2)
            append(identity.address3); append(identity.city); append(identity.state)
            append(identity.postalCode); append(identity.country); append(identity.company)
            append(identity.email); append(identity.phone); append(identity.ssn)
            append(identity.username); append(identity.passportNumber)
            append(identity.licenseNumber)
        }
        if let sshKey = cipher.sshKey {
            append(sshKey.privateKey); append(sshKey.publicKey); append(sshKey.keyFingerprint)
        }
        for field in cipher.fields ?? [] { append(field.name); append(field.value) }
        for attachment in cipher.attachments ?? [] {
            append(attachment.fileName); append(attachment.key)
        }
        return values.allSatisfy(isSupportedCipherField)
    }

    /// Maps server ciphertext directly into a store row without decrypting any fields.
    private static func makeCipherRow(_ cipher: CipherResponse, accountID: String) throws -> CipherRow {
        let encBlob = try Self.encodeBlob(cipher)

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
            archivedDate: cipher.archivedDate.map(Self.isoString),
            encName: cipher.name.stringValue,
            encNotes: cipher.notes?.stringValue,
            encBlob: encBlob,
            encCipherKey: cipher.key?.stringValue
        )
    }

    // MARK: - Identity rebuild

    /// Rebuild the AutoFill credential identities from the decrypted store contents.
    /// Returns the number of identities written (0 if AutoFill is disabled, in which
    /// case nothing is touched).
    private func rebuildIdentities(
        accountID: String,
        expectedGeneration: UInt64
    ) async -> Int {
        guard identityWriteGeneration == expectedGeneration, await keyVault.isUnlocked else { return 0 }
        guard await identityStore.isEnabled() else { return 0 }
        guard identityWriteGeneration == expectedGeneration else { return 0 }

        let rows = (try? await store.allCiphers(accountID: accountID)) ?? []
        var identities: [CredentialIdentity] = []
        for row in rows where row.type == CipherType.login.rawValue && row.deletedDate == nil && row.archivedDate == nil && row.organizationID == nil {
            guard let built = await buildIdentities(for: row) else { continue }
            identities.append(contentsOf: built)
        }

        // Add-only incremental writes cannot remove identities published by a previously
        // active account, so each account sync performs an authoritative replacement.
        guard identityWriteGeneration == expectedGeneration else { return 0 }
        let identitiesToPublish = identities
        return await identityPublicationCoordinator.withLock {
            guard await self.identityGenerationLease() == expectedGeneration else { return 0 }
            await self.identityStore.replaceAll(identitiesToPublish)
            return identitiesToPublish.count
        }
    }

    /// Build the AutoFill identities for a single login row. Password and OTP identities
    /// are emitted per URI; passkeys are emitted once per FIDO2 credential using that
    /// credential's real RP id, credential id, user handle, and username.
    private func buildIdentities(for row: CipherRow) async -> [CredentialIdentity]? {
        let cipherKey: SymmetricCryptoKey?
        if let wire = row.encCipherKey {
            // `VaultReader` treats a present but malformed/unwrappable item key as a hard
            // row failure. Do not fall back to the user key here and publish a promise that
            // the fulfillment path will correctly reject.
            guard let parsed = try? EncString(parsing: wire),
                  let resolved = try? await keyVault.cipherKey(fromProtected: parsed) else {
                return nil
            }
            cipherKey = resolved
        } else {
            cipherKey = nil
        }

        func decData(_ wire: String?) async -> Data? {
            guard let wire, let enc = try? EncString(parsing: wire) else { return nil }
            return try? await keyVault.decrypt(enc, cipherKey: cipherKey)
        }

        func dec(_ wire: String?) async -> String? {
            guard let data = await decData(wire) else { return nil }
            return String(data: data, encoding: .utf8)
        }

        // The login sub-payload is stored in `enc_blob` as JSON of EncString wire
        // strings; decode it to find the URIs + username + totp.
        guard let blob = row.encBlob,
              let payload = try? JSONDecoder().decode(BlobPayload.self, from: Data(blob.utf8)),
              let login = payload.login else { return nil }

        let username = await dec(login.username) ?? ""
        // Publishing an identity whose password cannot be decrypted only creates a
        // permanently failing system suggestion. Validate the secret while the vault is
        // already unlocked for the rebuild; the plaintext is neither retained nor indexed.
        let hasUsablePassword = await dec(login.password) != nil
        let hasValidOTP: Bool
        if let storedTOTP = await dec(login.totp) {
            hasValidOTP = (try? TOTP.configuration(from: storedTOTP)) != nil
        } else {
            hasValidOTP = false
        }
        var out: [CredentialIdentity] = []

        var publishedOrigins: Set<String> = []
        for uri in login.uris ?? [] {
            guard let raw = await dec(uri.uri), let serviceIdentifier = AutoFillWebsiteIdentity.value(for: raw, match: uri.match) else { continue }
            if let checksum = uri.uriChecksum, await dec(checksum) != LoginURIChecksum.encoded(raw) { continue }
            guard publishedOrigins.insert(serviceIdentifier).inserted else { continue }
            if hasUsablePassword {
                out.append(CredentialIdentity(
                    accountID: row.accountID,
                    recordID: row.id,
                    serviceIdentifier: serviceIdentifier,
                    user: username,
                    kind: .password
                ))
            }
            // A login with a TOTP secret also offers a one-time-code identity for the
            // same service.
            if hasValidOTP {
                out.append(CredentialIdentity(
                    accountID: row.accountID,
                    recordID: row.id,
                    serviceIdentifier: serviceIdentifier,
                    user: username,
                    kind: .otp
                ))
            }
        }

        for passkey in login.fido2Credentials ?? [] {
            guard let keyPlaintext = await decData(passkey.keyValue),
                  Self.isUsablePasskeyPrivateKey(keyPlaintext),
                  let relyingPartyIdentifier = await dec(passkey.rpId),
                  !relyingPartyIdentifier.isEmpty,
                  let encodedCredentialID = await dec(passkey.credentialId),
                  let credentialID = Self.decodeCredentialID(encodedCredentialID),
                  let encodedUserHandle = await dec(passkey.userHandle),
                  let userHandle = Self.decodeBase64URL(encodedUserHandle) else { continue }

            let passkeyUser = await dec(passkey.userName) ?? username
            out.append(CredentialIdentity(
                accountID: row.accountID,
                recordID: row.id,
                serviceIdentifier: relyingPartyIdentifier,
                user: passkeyUser,
                kind: .passkey,
                credentialID: credentialID,
                userHandle: userHandle
            ))
        }
        return out.isEmpty ? nil : out
    }

    /// Mirror `VaultReader`'s accepted passkey-key formats before publishing an identity:
    /// current Bitwarden rows contain unpadded-base64url PKCS#8 plaintext, while early
    /// Tessera rows encrypted the raw DER bytes. An identity is useful only if one form can
    /// be imported as the P-256 signing key needed to fulfill an assertion.
    private static func isUsablePasskeyPrivateKey(_ plaintext: Data) -> Bool {
        if let encoded = String(data: plaintext, encoding: .utf8),
           let pkcs8 = decodeBase64URL(encoded),
           (try? CredentialKey(pkcs8: pkcs8)) != nil {
            return true
        }
        return (try? CredentialKey(pkcs8: plaintext)) != nil
    }

    // MARK: - Helpers

    /// Decode Bitwarden's FIDO2 credential-id plaintext representation. UUID credentials
    /// are represented as their 16 RFC-4122 bytes; arbitrary credential ids use
    /// `b64.<unpadded base64url>`.
    private static func decodeCredentialID(_ value: String) -> Data? {
        if value.utf8.count == 36, let uuid = UUID(uuidString: value) {
            let bytes = uuid.uuid
            return Data([
                bytes.0, bytes.1, bytes.2, bytes.3,
                bytes.4, bytes.5, bytes.6, bytes.7,
                bytes.8, bytes.9, bytes.10, bytes.11,
                bytes.12, bytes.13, bytes.14, bytes.15,
            ])
        }
        guard value.hasPrefix("b64.") else { return nil }
        return decodeBase64URL(String(value.dropFirst(4)))
    }

    /// Decode an unpadded base64url value. Bitwarden stores FIDO2 user handles and
    /// non-UUID credential ids in this form.
    private static func decodeBase64URL(_ value: String) -> Data? {
        guard !value.isEmpty else { return nil }
        for byte in value.utf8 {
            let isAlphaNumeric = (byte >= 65 && byte <= 90)
                || (byte >= 97 && byte <= 122)
                || (byte >= 48 && byte <= 57)
            guard isAlphaNumeric || byte == 45 || byte == 95 else { return nil }
        }
        let remainder = value.utf8.count % 4
        guard remainder != 1 else { return nil }
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if remainder != 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: base64)
    }

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

    /// HTTP statuses that, for a DELETE, mean the server has already removed the entity
    /// — i.e. the delete's desired end state is reached, so the op is considered done.
    public static func isAlreadyDeleted(_ status: Int) -> Bool {
        status == 404
    }

    private func decodePayload(_ row: OutboxRow) throws -> OutboxCipherPayload {
        do { return try OutboxCipherPayload.decode(row.payloadJSON) }
        catch { throw SyncError.malformedOutboxPayload(id: row.id) }
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
