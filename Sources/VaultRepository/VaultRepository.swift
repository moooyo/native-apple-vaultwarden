import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import Networking
import SyncEngine

/// App-facing vault CRUD, read and sync orchestration.
///
/// Reads come from the local `VaultStore` (decrypted on demand via the `KeyVault`); writes
/// encrypt fields via the write-path `encryptor`, push through the API (or enqueue to the
/// store's outbox when offline), and update the local store. `sync()` delegates to the
/// injected `SyncEngine`.
///
/// An `actor` so all store/sync access from view models is serialized.
public actor VaultRepository {
    private let api: VaultAPI
    private let store: VaultStore
    private let keyVault: KeyVault
    private let encryptor: VaultEncrypting
    private let syncEngine: SyncEngine
    private let mutationCoordinator: VaultMutationCoordinator
    private let accountLease: @Sendable () async -> AccountSessionLease?
    private let lockHandler: @Sendable () async -> Void
    private var operationGeneration: UInt64 = 0

    private struct OperationLease: Sendable, Equatable {
        let session: AccountSessionLease
        let generation: UInt64
        var accountID: String { session.accountID }
    }

    public init(api: VaultAPI, store: VaultStore, keyVault: KeyVault, encryptor: VaultEncrypting,
                syncEngine: SyncEngine,
                mutationCoordinator: VaultMutationCoordinator,
                accountLease: @escaping @Sendable () async -> AccountSessionLease?,
                lockHandler: @escaping @Sendable () async -> Void) {
        self.api = api
        self.store = store
        self.keyVault = keyVault
        self.encryptor = encryptor
        self.syncEngine = syncEngine
        self.mutationCoordinator = mutationCoordinator
        self.accountLease = accountLease
        self.lockHandler = lockHandler
    }

    // MARK: - Reads

    /// All ciphers for the active account, decrypted into `PlaintextCipher` values.
    /// A row that fails to decrypt is skipped (soft-fail) rather than aborting the list.
    public func ciphers() async throws -> [PlaintextCipher] {
        try await ciphers(in: .active)
    }

    public func archivedCiphers() async throws -> [PlaintextCipher] {
        try await ciphers(in: .archived)
    }

    public func recentItemIDs(limit: Int) async throws -> [String] {
        let lease = try await requireOperationLease()
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let ids = try await store.recentItemIDs(accountID: lease.accountID, limit: limit)
        try await requireCurrentOperationLease(lease)
        return ids
    }

    public func recordUse(id: String) async {
        guard !Task.isCancelled, await keyVault.isUnlocked else { return }
        do {
            let lease = try await requireOperationLease()
            try await requireCurrentOperationLease(lease)
            try await store.recordUse(of: id, accountID: lease.accountID)
        } catch { return }
    }

    public func trashedCiphers() async throws -> [PlaintextCipher] {
        try await ciphers(in: .trash)
    }

    private func ciphers(in scope: CipherScope) async throws -> [PlaintextCipher] {
        let lease = try await requireOperationLease()
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let rows: [CipherRow]
        do { rows = try await store.allCiphers(accountID: lease.accountID, scope: scope) }
        catch { throw RepositoryError.store(error) }
        var out: [PlaintextCipher] = []
        for row in rows {
            if let decrypted = try? await decrypt(row) { out.append(decrypted) }
        }
        try await requireCurrentOperationLease(lease)
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        return out
    }

    public func folders() async throws -> [PlaintextFolder] {
        let lease = try await requireOperationLease()
        return try await folders(lease: lease)
    }

    private func folders(lease: OperationLease) async throws -> [PlaintextFolder] {
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let rows = try await store.allFolders(accountID: lease.accountID)
        var folders: [PlaintextFolder] = []
        for row in rows {
            if let name = await optionalDecrypt(row.encName, cipherKey: nil) {
                folders.append(PlaintextFolder(id: row.id, name: name))
            }
        }
        try await requireCurrentOperationLease(lease)
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        return folders.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    public func listing() async throws -> VaultListing {
        let lease = try await requireOperationLease()
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let rows = try await store.allCiphers(accountID: lease.accountID, scope: .all)
        var active: [PlaintextCipher] = []
        var archived: [PlaintextCipher] = []
        var trash: [PlaintextCipher] = []
        for row in rows {
            try Task.checkCancellation()
            guard let cipher = try? await decrypt(row) else { continue }
            if row.deletedDate != nil { trash.append(cipher) }
            else if row.archivedDate != nil { archived.append(cipher) }
            else { active.append(cipher) }
        }
        let visibleFolders = try await folders(lease: lease)
        return VaultListing(active: active, archived: archived, trash: trash, folders: visibleFolders)
    }

    /// The decrypted cipher for `id`, or throws `.cipherNotFound`.
    public func cipher(id: String) async throws -> PlaintextCipher {
        let lease = try await requireOperationLease()
        let (_, row) = try await requireCipherRow(id: id, accountID: lease.accountID)
        let result = try await decrypt(row)
        try await requireCurrentOperationLease(lease)
        return result
    }

    /// Search the local plaintext index, returning decrypted matches.
    public func search(_ query: String) async throws -> [PlaintextCipher] {
        let lease = try await requireOperationLease()
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let rows: [CipherRow]
        do { rows = try await store.search(query, accountID: lease.accountID) }
        catch { throw RepositoryError.store(error) }
        var out: [PlaintextCipher] = []
        for row in rows {
            if let decrypted = try? await decrypt(row) { out.append(decrypted) }
        }
        try await requireCurrentOperationLease(lease)
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        return out
    }

    // MARK: - Mutations

    /// Create a cipher: encrypt its fields, push to the API (or enqueue to the outbox when
    /// offline), and persist the resulting row locally. Returns the created cipher id.
    @discardableResult
    public func createCipher(_ plaintext: PlaintextCipher) async throws -> String {
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let lease = try await requireOperationLease()
        let identityGeneration = await syncEngine.identityGenerationLease()
        return try await mutationCoordinator.withLock {
            let id = try await self.createCipher(plaintext, lease: lease)
            _ = await self.syncEngine.refreshCredentialIdentities(
                accountID: lease.accountID,
                expectedGeneration: identityGeneration
            )
            return id
        }
    }

    public func importCiphers(_ items: [PlaintextCipher], expectedSession: AccountSessionLease) async throws {
        guard !items.isEmpty else { return }
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let lease = try await requireOperationLease()
        guard expectedSession == lease.session else { throw RepositoryError.notAuthenticated }
        try items.forEach(Self.validateSSHKey)
        let identityGeneration = await syncEngine.identityGenerationLease()
        try await mutationCoordinator.withLock {
            var saved = 0
            do {
                for item in items {
                    try Task.checkCancellation()
                    _ = try await self.createCipher(item, lease: lease)
                    saved += 1
                }
            } catch {
                guard saved > 0 else { throw error }
                if (try? await self.requireCurrentOperationLease(lease)) != nil {
                    await self.syncEngine.refreshCredentialIdentities(accountID: lease.accountID, expectedGeneration: identityGeneration)
                }
                throw PartialCipherImport(savedCount: saved)
            }
            try await self.requireCurrentOperationLease(lease)
            await self.syncEngine.refreshCredentialIdentities(accountID: lease.accountID, expectedGeneration: identityGeneration)
        }
    }

    private func createCipher(_ plaintext: PlaintextCipher,
                              lease: OperationLease) async throws -> String {
        try await requireCurrentOperationLease(lease)
        let encrypted = try await encryptCipher(
            plaintext,
            protectedCipherKey: plaintext.protectedCipherKey
        )
        try await requireCurrentOperationLease(lease)

        let localID = UUID().uuidString
        let row = encrypted.localRow(id: localID, accountID: lease.accountID)
        try await persistOfflineCipherMutation(
            accountID: lease.accountID, op: .create, entityID: localID, encrypted: encrypted,
            lastKnownRevisionDate: nil, localCipher: row, issue: .unconfirmedCreate
        )
        guard let queued = try await store.outbox(accountID: lease.accountID).first(where: { $0.entityID == localID }) else {
            throw RepositoryError.outboxIssueChanged
        }
        try await requireCurrentOperationLease(lease)
        let result: SyncEngine.ClaimedCreateResult
        do { result = try await syncEngine.dispatchClaimedCreate(queued, request: encrypted.request) }
        catch NetworkingError.unauthorized {
            try await requireCurrentOperationLease(lease)
            try await discardStagedCreate(queued)
            throw RepositoryError.network(NetworkingError.unauthorized)
        }
        catch { throw RepositoryError.network(error) }
        try await requireCurrentOperationLease(lease)
        switch result {
        case .created(let id): return id
        case .issue(.rejectedCreate):
            try await discardStagedCreate(queued)
            throw RepositoryError.underlying(kind: .network, description: "The server rejected the new cipher")
        case .pending, .issue: return localID
        }
    }

    private func discardStagedCreate(_ staged: OutboxRow) async throws {
        guard let current = try await store.outbox(accountID: staged.accountID).first(where: { $0.id == staged.id }),
              current.entityID == staged.entityID, current.payloadJSON == staged.payloadJSON else {
            throw RepositoryError.outboxIssueChanged
        }
        try await store.resolveCipherOutbox(expected: current, serverCipher: nil)
    }

    /// Update an existing cipher: encrypt, push (or enqueue), and persist.
    public func updateCipher(id: String, _ plaintext: PlaintextCipher) async throws {
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let lease = try await requireOperationLease()
        let identityGeneration = await syncEngine.identityGenerationLease()
        try await mutationCoordinator.withLock {
            try await self.updateCipher(id: id, plaintext, lease: lease)
            _ = await self.syncEngine.refreshCredentialIdentities(
                accountID: lease.accountID,
                expectedGeneration: identityGeneration
            )
        }
    }

    private func updateCipher(id: String, _ plaintext: PlaintextCipher,
                              lease: OperationLease) async throws {
        try await requireCurrentOperationLease(lease)
        let (resolvedID, existing) = try await requireCipherRow(
            id: id,
            accountID: lease.accountID
        )
        guard let storedRevision = SyncEngine.parseDate(existing.revisionDate) else {
            throw RepositoryError.cipherChanged
        }
        if let expectedRevision = plaintext.revisionDate, expectedRevision != storedRevision {
            throw RepositoryError.cipherChanged
        }
        let lastKnown = plaintext.revisionDate ?? storedRevision

        // The stored protected key is authoritative for an existing item. Keeping this
        // fallback also makes non-UI callers safe if they reconstructed a plaintext value
        // without copying the metadata field added for edit round-trips.
        let protectedCipherKey: EncString?
        if let wire = existing.encCipherKey {
            do { protectedCipherKey = try EncString(parsing: wire) }
            catch { throw RepositoryError.crypto(error) }
        } else {
            protectedCipherKey = plaintext.protectedCipherKey
        }
        let encrypted = try await encryptCipher(
            plaintext,
            protectedCipherKey: protectedCipherKey,
            lastKnownRevisionDate: lastKnown
        )
        try await requireCurrentOperationLease(lease)

        let hasPending: Bool
        do {
            hasPending = try await store.hasPendingOutbox(
                accountID: lease.accountID,
                entityType: OutboxEntity.cipher.rawValue,
                entityID: resolvedID
            )
        } catch { throw RepositoryError.store(error) }
        if hasPending {
            try await requireUnblockedOutbox(id: resolvedID, accountID: lease.accountID)
            let row = encrypted.localRow(id: resolvedID, accountID: lease.accountID,
                                         creationDate: existing.creationDate, after: storedRevision)
            try await persistOfflineCipherMutation(
                accountID: lease.accountID,
                op: .update,
                entityID: resolvedID,
                encrypted: encrypted,
                lastKnownRevisionDate: existing.revisionDate,
                localCipher: row
            )
            try await requireCurrentOperationLease(lease)
            return
        }

        let updated: CipherResponse
        do {
            updated = try await api.updateCipher(
                accountID: lease.accountID,
                id: resolvedID,
                encrypted.request
            )
        } catch NetworkingError.http(let status, let body) where status == 409 ||
                (status == 400 && body.localizedCaseInsensitiveContains("out of date")) {
            throw RepositoryError.cipherChanged
        } catch let error as NetworkingError where Self.isOffline(error) {
            try await requireCurrentOperationLease(lease)
            let row = encrypted.localRow(id: resolvedID, accountID: lease.accountID,
                                         creationDate: existing.creationDate, after: storedRevision)
            try await persistOfflineCipherMutation(
                accountID: lease.accountID,
                op: .update,
                entityID: resolvedID,
                encrypted: encrypted,
                lastKnownRevisionDate: existing.revisionDate,
                localCipher: row
            )
            try await requireCurrentOperationLease(lease)
            return
        } catch {
            throw RepositoryError.network(error)
        }

        let row = try await makeRow(from: updated, accountID: lease.accountID)
        do { try await store.upsertCiphers([row]) }
        catch { throw RepositoryError.store(error) }
        try await requireCurrentOperationLease(lease)
    }

    public func createFolder(name: String, expectedSession: AccountSessionLease? = nil) async throws -> String {
        let lease = try await requireOperationLease()
        guard expectedSession == nil || expectedSession == lease.session else {
            throw RepositoryError.notAuthenticated
        }
        return try await mutationCoordinator.withLock {
            try await self.writeFolder(id: nil, name: name, lease: lease)
        }
    }

    public func renameFolder(id: String, name: String) async throws {
        let lease = try await requireOperationLease()
        _ = try await mutationCoordinator.withLock {
            try await self.writeFolder(id: id, name: name, lease: lease)
        }
    }

    private func writeFolder(id: String?, name: String, lease: OperationLease) async throws -> String {
        try await requireCurrentOperationLease(lease)
        let title = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !title.isEmpty else { throw RepositoryError.invalidFolderName }
        let request = FolderRequest(name: try await encryptor.encryptString(title))
        try await requireCurrentOperationLease(lease)
        let result: FolderResponse
        if let id {
            result = try await api.updateFolder(accountID: lease.accountID, id: id, request)
            guard result.id == id else { throw RepositoryError.cipherNotFound }
        } else {
            result = try await api.createFolder(accountID: lease.accountID, request)
        }
        try await requireCurrentOperationLease(lease)
        try await store.upsertFolders([FolderRow(id: result.id, accountID: lease.accountID,
                                                 encName: result.name.stringValue, revisionDate: Self.iso(result.revisionDate))])
        try await requireCurrentOperationLease(lease)
        return result.id
    }

    public func deleteFolder(id: String) async throws {
        let lease = try await requireOperationLease()
        try await mutationCoordinator.withLock {
            try await self.requireCurrentOperationLease(lease)
            guard await self.keyVault.isUnlocked else { throw RepositoryError.locked }
            try await self.api.deleteFolder(accountID: lease.accountID, id: id)
            try await self.requireCurrentOperationLease(lease)
            try await self.store.deleteFolder(id: id, accountID: lease.accountID)
            try await self.requireCurrentOperationLease(lease)
        }
    }

    public func changeCipherVisibility(id: String, change: CipherVisibilityChange) async throws {
        let lease = try await requireOperationLease()
        let identityGeneration = await syncEngine.identityGenerationLease()
        try await mutationCoordinator.withLock {
            try await self.changeCipherVisibility(id: id, change: change, lease: lease)
            _ = await self.syncEngine.refreshCredentialIdentities(accountID: lease.accountID,
                                                                   expectedGeneration: identityGeneration)
        }
    }

    private func changeCipherVisibility(id: String, change: CipherVisibilityChange, lease: OperationLease) async throws {
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let (resolvedID, row) = try await requireCipherRow(id: id, accountID: lease.accountID, includeHidden: true)
        let allowed = switch change {
        case .trash: row.deletedDate == nil
        case .restore: row.deletedDate != nil
        case .archive: row.deletedDate == nil && row.archivedDate == nil
        case .unarchive: row.deletedDate == nil && row.archivedDate != nil
        }
        guard allowed else { throw RepositoryError.cipherNotFound }
        let pending = try await store.hasPendingOutbox(accountID: lease.accountID, entityType: OutboxEntity.cipher.rawValue,
                                                      entityID: resolvedID)
        guard !pending else { throw RepositoryError.pendingCipherChanges }
        try await requireCurrentOperationLease(lease)
        let response = try await api.changeCipherVisibility(accountID: lease.accountID, id: resolvedID, change: change)
        try await requireCurrentOperationLease(lease)
        if change == .trash {
            try await store.setCipherVisibility(id: resolvedID, accountID: lease.accountID,
                                                deletedDate: Self.iso(Date()), archivedDate: row.archivedDate)
        } else {
            guard let response, response.id == resolvedID else { throw RepositoryError.cipherNotFound }
            let updated = try await makeRow(from: response, accountID: lease.accountID)
            try await store.upsertCiphers([updated])
        }
        try await requireCurrentOperationLease(lease)
    }

    public func permanentlyDeleteCipher(id: String) async throws {
        let lease = try await requireOperationLease()
        let identityGeneration = await syncEngine.identityGenerationLease()
        try await mutationCoordinator.withLock {
            try await self.permanentlyDeleteCipher(id: id, lease: lease)
            _ = await self.syncEngine.refreshCredentialIdentities(
                accountID: lease.accountID,
                expectedGeneration: identityGeneration
            )
        }
    }

    private func permanentlyDeleteCipher(id: String, lease: OperationLease) async throws {
        try await requireCurrentOperationLease(lease)
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let (resolvedID, row) = try await requireCipherRow(
            id: id,
            accountID: lease.accountID,
            includeHidden: true
        )
        guard row.deletedDate != nil else { throw RepositoryError.cipherNotFound }
        try await requireCurrentOperationLease(lease)
        let preview = OutboxDeletePreview(name: row.encName, key: row.encCipherKey, organizationID: row.organizationID)
        let payload = String(decoding: try JSONEncoder().encode(preview), as: UTF8.self)
        let operation = OutboxRow(accountID: lease.accountID, opType: OutboxOp.delete.rawValue,
                                  entityType: OutboxEntity.cipher.rawValue, entityID: resolvedID, payloadJSON: payload)
        let pending: Bool
        do {
            pending = try await store.hasPendingOutbox(
                accountID: lease.accountID,
                entityType: OutboxEntity.cipher.rawValue,
                entityID: resolvedID
            )
        } catch { throw RepositoryError.store(error) }
        if pending {
            try await requireUnblockedOutbox(id: resolvedID, accountID: lease.accountID)
            do {
                try await store.persistOfflineCipherMutation(
                    operation: operation,
                    localCipher: nil
                )
            } catch { throw RepositoryError.store(error) }
            try await requireCurrentOperationLease(lease)
            return
        }
        do {
            try await api.deleteCipher(accountID: lease.accountID, id: resolvedID)
        } catch let error as NetworkingError where Self.isOffline(error) {
            try await requireCurrentOperationLease(lease)
            do {
                try await store.persistOfflineCipherMutation(
                    operation: operation,
                    localCipher: nil
                )
            } catch { throw RepositoryError.store(error) }
            try await requireCurrentOperationLease(lease)
            return
        } catch {
            throw RepositoryError.network(error)
        }
        do { try await store.deleteCipher(id: resolvedID, accountID: lease.accountID) }
        catch { throw RepositoryError.store(error) }
        try await requireCurrentOperationLease(lease)
    }

    // MARK: - Passkey registration import

    /// Add a credential-provider registration to an existing login, or create a new login
    /// when the system did not identify one. Replaying the same registration is a no-op,
    /// which makes extension -> app handoff acknowledgement crash-safe.
    public func importPasskeyRegistration(
        registrationID: String,
        expectedAccountID: String,
        cipherID: String?,
        relyingPartyID: String,
        userName: String,
        userDisplayName: String?,
        userHandle: Data,
        credentialID: Data,
        privateKeyPKCS8: Data,
        creationDate: Date
    ) async throws {
        let identityGeneration = await syncEngine.identityGenerationLease()
        try await mutationCoordinator.withLock {
            try await self.performPasskeyRegistrationImport(
                registrationID: registrationID,
                expectedAccountID: expectedAccountID,
                cipherID: cipherID,
                relyingPartyID: relyingPartyID,
                userName: userName,
                userDisplayName: userDisplayName,
                userHandle: userHandle,
                credentialID: credentialID,
                privateKeyPKCS8: privateKeyPKCS8,
                creationDate: creationDate
            )
            _ = await self.syncEngine.refreshCredentialIdentities(
                accountID: expectedAccountID,
                expectedGeneration: identityGeneration
            )
        }
    }

    private func performPasskeyRegistrationImport(
        registrationID: String,
        expectedAccountID: String,
        cipherID: String?,
        relyingPartyID: String,
        userName: String,
        userDisplayName: String?,
        userHandle: Data,
        credentialID: Data,
        privateKeyPKCS8: Data,
        creationDate: Date
    ) async throws {
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let lease = try await requireOperationLease()
        guard lease.accountID == expectedAccountID else {
            throw RepositoryError.notAuthenticated
        }
        let importCompleted: Bool
        do {
            importCompleted = try await store.isPasskeyImportCompleted(
                id: registrationID,
                accountID: expectedAccountID
            )
        } catch { throw RepositoryError.store(error) }
        if importCompleted {
            try await requireCurrentOperationLease(lease)
            return
        }
        guard !relyingPartyID.isEmpty, !userName.isEmpty,
              !userHandle.isEmpty, !credentialID.isEmpty, !privateKeyPKCS8.isEmpty else {
            throw RepositoryError.crypto(CryptoError.invalidKeyLength)
        }

        let credential = PlaintextCipher.Fido2Credential(
            credentialId: "b64.\(Self.base64URL(credentialID))",
            keyType: "public-key",
            keyAlgorithm: "ECDSA",
            keyCurve: "P-256",
            keyValue: Self.base64URL(privateKeyPKCS8),
            rpId: relyingPartyID,
            rpName: relyingPartyID,
            userHandle: Self.base64URL(userHandle),
            userName: userName,
            userDisplayName: userDisplayName ?? userName,
            counter: "0",
            discoverable: "true",
            creationDate: creationDate
        )

        if let cipherID {
            do {
                let (resolvedCipherID, row) = try await requireCipherRow(
                    id: cipherID,
                    accountID: expectedAccountID
                )
                var item = try await decrypt(row)
                try await requireCurrentOperationLease(lease)
                guard item.type == CipherType.login.rawValue else {
                    throw RepositoryError.cipherNotFound
                }
                var login = item.login ?? .init(username: userName)
                if Self.containsPasskey(
                    login.fido2Credentials,
                    relyingPartyID: relyingPartyID,
                    credentialID: credentialID
                ) {
                    try await requireCurrentOperationLease(lease)
                    do {
                        try await store.completePasskeyImport(
                            id: registrationID,
                            accountID: expectedAccountID
                        )
                    } catch { throw RepositoryError.store(error) }
                    try await requireCurrentOperationLease(lease)
                    return
                }
                login.fido2Credentials.append(credential)
                item.login = login
                let protectedKey = try parseProtectedCipherKey(row.encCipherKey)
                try await persistPasskeyImport(
                    registrationID: registrationID,
                    accountID: expectedAccountID,
                    operation: .update,
                    entityID: resolvedCipherID,
                    plaintext: item,
                    protectedCipherKey: protectedKey,
                    lastKnownRevisionDate: row.revisionDate,
                    lease: lease
                )
                try await requireCurrentOperationLease(lease)
                return
            } catch RepositoryError.cipherNotFound {
                // The RP already accepted this credential. If the selected target was
                // deleted or changed type before drain, preserve durability by falling
                // through to the deterministic new-login import below.
            }
        }

        // A replay after the first create may no longer have a local placeholder id, so scan
        // active-account logins for this exact RP + raw credential id before creating.
        let rows: [CipherRow]
        do { rows = try await store.allCiphers(accountID: expectedAccountID) }
        catch { throw RepositoryError.store(error) }
        var existing: [PlaintextCipher] = []
        for row in rows {
            if let item = try? await decrypt(row) { existing.append(item) }
        }
        try await requireCurrentOperationLease(lease)
        if existing.contains(where: {
            Self.containsPasskey(
                $0.login?.fido2Credentials ?? [],
                relyingPartyID: relyingPartyID,
                credentialID: credentialID
            )
        }) {
            try await requireCurrentOperationLease(lease)
            do {
                try await store.completePasskeyImport(
                    id: registrationID,
                    accountID: expectedAccountID
                )
            } catch { throw RepositoryError.store(error) }
            try await requireCurrentOperationLease(lease)
            return
        }

        let localID = "passkey-\(registrationID)"
        let item = PlaintextCipher(
            id: localID,
            type: CipherType.login.rawValue,
            name: relyingPartyID,
            login: .init(username: userName, fido2Credentials: [credential])
        )
        try await persistPasskeyImport(
            registrationID: registrationID,
            accountID: expectedAccountID,
            operation: .create,
            entityID: localID,
            plaintext: item,
            protectedCipherKey: nil,
            lastKnownRevisionDate: nil,
            lease: lease
        )
        try await requireCurrentOperationLease(lease)
    }

    public func generatorHistory() async throws -> GeneratorHistorySnapshot {
        let lease = try await requireOperationLease()
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let payloads = try await store.encryptedGenerationHistory(accountID: lease.accountID)
        var entries: [GeneratorHistoryEntry] = []
        let decoder = JSONDecoder()
        for payload in payloads {
            let data = try await keyVault.decrypt(EncString(parsing: payload))
            entries.append(try decoder.decode(GeneratorHistoryEntry.self, from: data))
        }
        try await requireCurrentOperationLease(lease)
        return GeneratorHistorySnapshot(session: lease.session, entries: entries)
    }

    public func addGeneration(_ entry: GeneratorHistoryEntry, session: AccountSessionLease) async throws {
        let lease = try await requireOperationLease()
        guard lease.session == session else { throw RepositoryError.notAuthenticated }
        let data = try JSONEncoder().encode(entry)
        let encrypted = try await encryptor.encrypt(data, cipherKey: nil)
        try await requireCurrentOperationLease(lease)
        try await store.insertGeneration(encrypted.stringValue, id: entry.id, accountID: session.accountID,
                                         limit: GeneratorHistoryEntry.limit)
        try await requireCurrentOperationLease(lease)
    }

    public func clearGeneratorHistory(session: AccountSessionLease) async throws {
        let lease = try await requireOperationLease()
        guard lease.session == session else { throw RepositoryError.notAuthenticated }
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        try await requireCurrentOperationLease(lease)
        try await store.clearGenerationHistory(accountID: session.accountID)
        try await requireCurrentOperationLease(lease)
    }

    // MARK: - Sync / lock

    public func outboxStatus(expectedSession: AccountSessionLease? = nil) async throws -> VaultOutboxStatus {
        let lease = try await requireOperationLease()
        if let expectedSession, lease.session != expectedSession { throw RepositoryError.notAuthenticated }
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let rows = try await store.outbox(accountID: lease.accountID).filter { $0.entityType == OutboxEntity.cipher.rawValue }
        let byEntity = Dictionary(grouping: rows, by: \.entityID)
        var issues: [VaultOutboxIssue] = []
        for operation in rows {
            guard let id = operation.id, let flag = operation.issue,
                  let kind = VaultOutboxIssue.Kind(rawValue: flag.rawValue) else { continue }
            let row = try await store.cipher(id: operation.entityID, accountID: lease.accountID)
            let itemName: String?
            if let row {
                itemName = await outboxItemName(row.encName, protectedKey: row.encCipherKey, organizationID: row.organizationID)
            } else if flag == .deleteConflict,
                      let preview = try? JSONDecoder().decode(OutboxDeletePreview.self, from: Data(operation.payloadJSON.utf8)) {
                itemName = await outboxItemName(preview.name, protectedKey: preview.key, organizationID: preview.organizationID)
            } else {
                itemName = nil
            }
            var canKeepLocalCopy = flag != .deleteConflict && itemName != nil && row?.organizationID == nil
                && byEntity[operation.entityID]?.count == 1
            if canKeepLocalCopy, let row, row.type == CipherType.sshKey.rawValue {
                canKeepLocalCopy = (try? await decrypt(row, strict: true))?.sshKey?.isComplete == true
            }
            issues.append(VaultOutboxIssue(id: id, kind: kind, itemName: itemName,
                                          canKeepLocalCopy: canKeepLocalCopy,
                                          localRevision: row?.revisionDate, session: lease.session))
        }
        try await requireCurrentOperationLease(lease)
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        return VaultOutboxStatus(pendingCount: byEntity.values.count { $0.allSatisfy { $0.issue == nil } }, issues: issues)
    }

    private struct OutboxDeletePreview: Codable {
        let name: String?
        let key: String?
        let organizationID: String?
    }

    private func outboxItemName(_ name: String?, protectedKey: String?, organizationID: String?) async -> String? {
        do {
            let protected = try parseProtectedCipherKey(protectedKey)
            let key = try await unwrapCipherKey(protected, organizationID: organizationID)
            return await optionalDecrypt(name, cipherKey: key)
        } catch { return nil }
    }

    public func resolveOutboxIssue(_ issue: VaultOutboxIssue, action: VaultOutboxAction,
                                   expectedSession: AccountSessionLease? = nil) async throws {
        let lease = try await requireOperationLease()
        if let expectedSession, lease.session != expectedSession { throw RepositoryError.notAuthenticated }
        guard issue.session == lease.session else { throw RepositoryError.outboxIssueChanged }
        let identityGeneration = await syncEngine.identityGenerationLease()
        try await mutationCoordinator.withLock {
            try await self.resolveOutboxIssue(issue, action: action, lease: lease)
            await self.syncEngine.refreshCredentialIdentities(accountID: lease.accountID, expectedGeneration: identityGeneration)
        }
        try await requireCurrentOperationLease(lease)
    }

    private func resolveOutboxIssue(_ issue: VaultOutboxIssue, action: VaultOutboxAction,
                                    lease: OperationLease) async throws {
        try await requireCurrentOperationLease(lease)
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let operations = try await store.outbox(accountID: lease.accountID)
        guard let queued = operations.first(where: { $0.id == issue.id && $0.entityType == OutboxEntity.cipher.rawValue }),
              queued.issue?.rawValue == issue.kind.rawValue,
              operations.count(where: { $0.entityType == queued.entityType && $0.entityID == queued.entityID }) == 1 else {
            throw RepositoryError.outboxIssueChanged
        }
        let local = try await store.cipher(id: queued.entityID, accountID: lease.accountID)
        guard local?.revisionDate == issue.localRevision else { throw RepositoryError.outboxIssueChanged }
        let sshCopy: PlaintextCipher?
        if action == .keepLocalCopy, let local, local.type == CipherType.sshKey.rawValue {
            let item = try await decrypt(local, strict: true)
            try Self.validateSSHKey(item)
            sshCopy = item
        } else {
            sshCopy = nil
        }
        try await requireCurrentOperationLease(lease)
        let response: SyncResponse
        do { response = try await api.sync(accountID: lease.accountID, excludeDomains: true) }
        catch let error as NetworkingError where error.deniesVaultListingAccess {
            try await requireCurrentOperationLease(lease)
            try await store.clearSendCache(accountID: lease.accountID)
            throw RepositoryError.vaultAccessDenied
        }
        catch { throw RepositoryError.network(error) }
        try await requireCurrentOperationLease(lease)

        let remote = response.ciphers.filter { $0.id == queued.entityID }
        guard remote.count <= 1, !remote.isEmpty || response.droppedCipherErrors.isEmpty else {
            throw RepositoryError.outboxRecoveryUnavailable
        }
        if queued.issue == .unconfirmedCreate,
           response.droppedCipherErrors.isEmpty,
           let matched = try? await syncEngine.confirmedCreate(in: response.ciphers, for: queued),
           matched.id == queued.entityID || !operations.contains(where: { $0.entityID == matched.id }) {
            let accepted = try await validatedServerRow(matched, accountID: lease.accountID)
            try Task.checkCancellation()
            try await requireCurrentOperationLease(lease)
            try await store.finalizeOutboxWrite(id: issue.id, accountID: lease.accountID,
                                                localEntityID: queued.entityID, serverCipher: accepted)
            return
        }
        let serverRow: CipherRow?
        if let source = remote.first {
            serverRow = try await validatedServerRow(source, accountID: lease.accountID)
        } else {
            serverRow = nil
        }

        var copy: CipherRow?
        var copyOperation: OutboxRow?
        if action == .keepLocalCopy {
            guard issue.canKeepLocalCopy, queued.opType != OutboxOp.delete.rawValue,
                  let local, local.organizationID == nil else { throw RepositoryError.outboxRecoveryUnavailable }
            var item = if let sshCopy { sshCopy } else { try await decrypt(local, strict: true) }
            if let folderID = item.folderID, !response.folders.contains(where: { $0.id == folderID }) {
                guard response.droppedFolderErrors.isEmpty else { throw RepositoryError.outboxRecoveryUnavailable }
                item.folderID = nil
            }
            if let credentials = item.login?.fido2Credentials, !credentials.isEmpty {
                let otherPendingIDs = Set(operations.lazy.filter {
                    $0.entityType == OutboxEntity.cipher.rawValue && $0.entityID != queued.entityID
                }.map(\.entityID))
                item.login?.fido2Credentials = try await passkeysForOutboxCopy(
                    credentials, response: response, accountID: lease.accountID, otherPendingIDs: otherPendingIDs
                )
            }
            let encrypted = try await encryptCipher(item, protectedCipherKey: item.protectedCipherKey)
            let copyID = UUID().uuidString
            copy = encrypted.localRow(id: copyID, accountID: lease.accountID)
            copyOperation = OutboxRow(accountID: lease.accountID, opType: OutboxOp.create.rawValue,
                                      entityType: OutboxEntity.cipher.rawValue, entityID: copyID,
                                      payloadJSON: try Self.outboxPayload(from: encrypted).encodedJSON())
        }
        try Task.checkCancellation()
        try await requireCurrentOperationLease(lease)
        try await store.resolveCipherOutbox(expected: queued, serverCipher: serverRow, copy: copy, copyOperation: copyOperation)
    }

    private func validatedServerRow(_ cipher: CipherResponse, accountID: String) async throws -> CipherRow {
        guard SyncEngine.usesSupportedEncryption(cipher) else { throw RepositoryError.outboxRecoveryUnavailable }
        let row = try await makeRow(from: cipher, accountID: accountID)
        guard (try? await decrypt(row, strict: true)) != nil else { throw RepositoryError.outboxRecoveryUnavailable }
        return row
    }

    private func passkeysForOutboxCopy(_ credentials: [PlaintextCipher.Fido2Credential], response: SyncResponse,
                                      accountID: String, otherPendingIDs: Set<String>) async throws -> [PlaintextCipher.Fido2Credential] {
        guard response.droppedCipherErrors.isEmpty else {
            throw RepositoryError.outboxRecoveryUnavailable
        }
        var duplicates: [Data: [PlaintextCipher.Fido2Credential]] = [:]
        for cipher in response.ciphers where cipher.organizationId == nil && cipher.login?.fido2Credentials?.isEmpty == false {
            let row = try await validatedServerRow(cipher, accountID: accountID)
            let item = try await decrypt(row, strict: true)
            for credential in item.login?.fido2Credentials ?? [] {
                guard let id = credential.credentialId.flatMap(Self.decodeCredentialID) else {
                    throw RepositoryError.outboxRecoveryUnavailable
                }
                duplicates[id, default: []].append(credential)
            }
        }
        var otherPendingCredentials = Set<Data>()
        for id in otherPendingIDs {
            guard let row = try await store.cipher(id: id, accountID: accountID),
                  row.type == CipherType.login.rawValue, row.organizationID == nil else { continue }
            let item = try await decrypt(row, strict: true)
            otherPendingCredentials.formUnion((item.login?.fido2Credentials ?? []).compactMap {
                $0.credentialId.flatMap(Self.decodeCredentialID)
            })
        }
        return try credentials.filter { credential in
            guard let id = credential.credentialId.flatMap(Self.decodeCredentialID),
                  !otherPendingCredentials.contains(id) else {
                throw RepositoryError.outboxRecoveryUnavailable
            }
            guard let matches = duplicates[id] else { return true }
            guard let key = credential.keyValue, matches.allSatisfy({
                $0.keyValue == key && $0.rpId == credential.rpId && $0.userHandle == credential.userHandle
            }) else {
                throw RepositoryError.outboxRecoveryUnavailable
            }
            return false
        }
    }

    private func requireUnblockedOutbox(id: String, accountID: String) async throws {
        if try await store.outbox(accountID: accountID).contains(where: {
            $0.entityType == OutboxEntity.cipher.rawValue && $0.entityID == id && $0.issue != nil
        }) {
            throw RepositoryError.pendingCipherChanges
        }
    }

    /// Full sync: flush the outbox first, then pull. Delegates to the injected `SyncEngine`.
    @discardableResult
    public func sync(expectedSession: AccountSessionLease? = nil) async throws -> SyncOutcome {
        let lease = try await requireOperationLease()
        if let expectedSession, lease.session != expectedSession { throw RepositoryError.notAuthenticated }
        do {
            try await syncEngine.flushOutbox(accountID: lease.accountID)
            try await requireCurrentOperationLease(lease)
            let outcome: SyncOutcome
            do {
                outcome = try await syncEngine.fullSync(accountID: lease.accountID)
            } catch let error as NetworkingError where error.deniesVaultListingAccess {
                try await requireCurrentOperationLease(lease)
                throw RepositoryError.vaultAccessDenied
            }
            try await requireCurrentOperationLease(lease)
            return outcome
        } catch let error as RepositoryError {
            throw error
        } catch {
            throw RepositoryError.sync(error)
        }
    }

    /// Lock the vault (zero the in-memory key material in the KeyVault + encryptor).
    public func lock() async {
        operationGeneration &+= 1
        await lockHandler()
    }

    // MARK: - Encryption / decryption

    /// The encrypted form of a cipher: a wire `CipherRequest` for the API plus the wire
    /// strings needed to build a local store row.
    private struct EncryptedCipher: Sendable {
        let request: CipherRequest
        let type: Int
        let folderID: String?
        let organizationID: String?
        let favorite: Bool
        let reprompt: Int
        let nameWire: String
        let notesWire: String?
        let blobJSON: String
        let searchText: String
        let protectedCipherKeyWire: String?

        /// Build a local `CipherRow` (used for the offline/optimistic path and as a fallback).
        func localRow(id: String, accountID: String, creationDate: String? = nil, after previous: Date? = nil) -> CipherRow {
            let now = VaultRepository.iso(max(Date(), previous?.addingTimeInterval(0.001) ?? .distantPast))
            return CipherRow(
                id: id, accountID: accountID, type: type, folderID: folderID,
                organizationID: organizationID,
                favorite: favorite, reprompt: reprompt,
                revisionDate: now, creationDate: creationDate ?? now,
                encName: nameWire, encNotes: notesWire, encBlob: blobJSON,
                encCipherKey: protectedCipherKeyWire, searchText: searchText
            )
        }
    }

    /// Encrypt an optional plaintext string under the item's per-cipher key when present,
    /// otherwise under the user key. Keeping this as a method avoids async closures crossing
    /// actor boundaries while the many field mappings remain straight-line.
    private func encOptional(_ s: String?, cipherKey: SymmetricCryptoKey?) async throws -> EncString? {
        guard let s else { return nil }
        return try await encryptor.encryptString(s, cipherKey: cipherKey)
    }

    private static func validateSSHKey(_ item: PlaintextCipher) throws {
        if item.type == CipherType.sshKey.rawValue, item.sshKey?.isComplete != true {
            throw RepositoryError.incompleteSSHKey
        }
    }

    /// Encrypt a plaintext cipher into a request + the bits needed for a local row.
    private func encryptCipher(_ p: PlaintextCipher,
                               protectedCipherKey: EncString?,
                               lastKnownRevisionDate: Date? = nil) async throws -> EncryptedCipher {
        try Self.validateSSHKey(p)
        let cipherKey = try await unwrapCipherKey(protectedCipherKey,
                                                  organizationID: p.organizationID)
        let nameEnc = try await encryptor.encryptString(p.name, cipherKey: cipherKey)
        let notesEnc = try await encOptional(p.notes, cipherKey: cipherKey)

        var loginReq: CipherLoginRequest?
        var blobLogin: BlobLogin?
        let plaintextLogin = p.login ?? (p.type == CipherType.login.rawValue ? .init() : nil)
        if let login = plaintextLogin {
            let userEnc = try await encOptional(login.username, cipherKey: cipherKey)
            let passEnc = try await encOptional(login.password, cipherKey: cipherKey)
            let totpEnc = try await encOptional(login.totp, cipherKey: cipherKey)
            var uriReqs: [CipherLoginUriRequest] = []
            var blobURIs: [BlobURI] = []
            for uri in login.uris {
                let uriEnc = try await encryptor.encryptString(uri.uri, cipherKey: cipherKey)
                uriReqs.append(CipherLoginUriRequest(uri: uriEnc, match: uri.match))
                blobURIs.append(BlobURI(uri: uriEnc.stringValue, match: uri.match))
            }
            var fidoReqs: [CipherFido2CredentialRequest] = []
            var blobFido: [BlobFido2] = []
            for fido in login.fido2Credentials {
                let credentialId = try await encOptional(fido.credentialId, cipherKey: cipherKey)
                let keyType = try await encOptional(fido.keyType, cipherKey: cipherKey)
                let keyAlgorithm = try await encOptional(fido.keyAlgorithm, cipherKey: cipherKey)
                let keyCurve = try await encOptional(fido.keyCurve, cipherKey: cipherKey)
                let keyValue = try await encOptional(fido.keyValue, cipherKey: cipherKey)
                let rpId = try await encOptional(fido.rpId, cipherKey: cipherKey)
                let rpName = try await encOptional(fido.rpName, cipherKey: cipherKey)
                let userHandle = try await encOptional(fido.userHandle, cipherKey: cipherKey)
                let userName = try await encOptional(fido.userName, cipherKey: cipherKey)
                let userDisplayName = try await encOptional(fido.userDisplayName, cipherKey: cipherKey)
                let counter = try await encOptional(fido.counter, cipherKey: cipherKey)
                let discoverable = try await encOptional(fido.discoverable, cipherKey: cipherKey)
                fidoReqs.append(CipherFido2CredentialRequest(
                    credentialId: credentialId, keyType: keyType, keyAlgorithm: keyAlgorithm,
                    keyCurve: keyCurve, keyValue: keyValue, rpId: rpId, rpName: rpName,
                    userHandle: userHandle, userName: userName,
                    userDisplayName: userDisplayName, counter: counter,
                    discoverable: discoverable, creationDate: fido.creationDate
                ))
                blobFido.append(BlobFido2(
                    credentialId: credentialId?.stringValue, keyType: keyType?.stringValue,
                    keyAlgorithm: keyAlgorithm?.stringValue, keyCurve: keyCurve?.stringValue,
                    keyValue: keyValue?.stringValue, rpId: rpId?.stringValue,
                    rpName: rpName?.stringValue, userHandle: userHandle?.stringValue,
                    userName: userName?.stringValue,
                    userDisplayName: userDisplayName?.stringValue,
                    counter: counter?.stringValue, discoverable: discoverable?.stringValue,
                    creationDate: fido.creationDate
                ))
            }
            loginReq = CipherLoginRequest(
                username: userEnc, password: passEnc, totp: totpEnc, uris: uriReqs,
                fido2Credentials: fidoReqs, passwordRevisionDate: login.passwordRevisionDate
            )
            blobLogin = BlobLogin(username: userEnc?.stringValue, password: passEnc?.stringValue,
                                  totp: totpEnc?.stringValue, uris: blobURIs,
                                  fido2Credentials: blobFido,
                                  passwordRevisionDate: login.passwordRevisionDate)
        }

        var cardReq: CipherCardRequest?
        var blobCard: BlobCard?
        let plaintextCard = p.card ?? (p.type == CipherType.card.rawValue ? .init() : nil)
        if let card = plaintextCard {
            let cardholderName = try await encOptional(card.cardholderName, cipherKey: cipherKey)
            let brand = try await encOptional(card.brand, cipherKey: cipherKey)
            let number = try await encOptional(card.number, cipherKey: cipherKey)
            let expMonth = try await encOptional(card.expMonth, cipherKey: cipherKey)
            let expYear = try await encOptional(card.expYear, cipherKey: cipherKey)
            let code = try await encOptional(card.code, cipherKey: cipherKey)
            cardReq = CipherCardRequest(cardholderName: cardholderName, brand: brand,
                                        number: number, expMonth: expMonth,
                                        expYear: expYear, code: code)
            blobCard = BlobCard(cardholderName: cardholderName?.stringValue,
                                brand: brand?.stringValue, number: number?.stringValue,
                                expMonth: expMonth?.stringValue, expYear: expYear?.stringValue,
                                code: code?.stringValue)
        }

        var identityReq: CipherIdentityRequest?
        var blobIdentity: BlobIdentity?
        let plaintextIdentity = p.identity ?? (p.type == CipherType.identity.rawValue ? .init() : nil)
        if let identity = plaintextIdentity {
            let title = try await encOptional(identity.title, cipherKey: cipherKey)
            let firstName = try await encOptional(identity.firstName, cipherKey: cipherKey)
            let middleName = try await encOptional(identity.middleName, cipherKey: cipherKey)
            let lastName = try await encOptional(identity.lastName, cipherKey: cipherKey)
            let address1 = try await encOptional(identity.address1, cipherKey: cipherKey)
            let address2 = try await encOptional(identity.address2, cipherKey: cipherKey)
            let address3 = try await encOptional(identity.address3, cipherKey: cipherKey)
            let city = try await encOptional(identity.city, cipherKey: cipherKey)
            let state = try await encOptional(identity.state, cipherKey: cipherKey)
            let postalCode = try await encOptional(identity.postalCode, cipherKey: cipherKey)
            let country = try await encOptional(identity.country, cipherKey: cipherKey)
            let company = try await encOptional(identity.company, cipherKey: cipherKey)
            let email = try await encOptional(identity.email, cipherKey: cipherKey)
            let phone = try await encOptional(identity.phone, cipherKey: cipherKey)
            let ssn = try await encOptional(identity.ssn, cipherKey: cipherKey)
            let username = try await encOptional(identity.username, cipherKey: cipherKey)
            let passportNumber = try await encOptional(identity.passportNumber, cipherKey: cipherKey)
            let licenseNumber = try await encOptional(identity.licenseNumber, cipherKey: cipherKey)
            identityReq = CipherIdentityRequest(
                title: title, firstName: firstName, middleName: middleName, lastName: lastName,
                address1: address1, address2: address2, address3: address3, city: city,
                state: state, postalCode: postalCode, country: country, company: company,
                email: email, phone: phone, ssn: ssn, username: username,
                passportNumber: passportNumber, licenseNumber: licenseNumber
            )
            blobIdentity = BlobIdentity(
                title: title?.stringValue, firstName: firstName?.stringValue,
                middleName: middleName?.stringValue, lastName: lastName?.stringValue,
                address1: address1?.stringValue, address2: address2?.stringValue,
                address3: address3?.stringValue, city: city?.stringValue,
                state: state?.stringValue, postalCode: postalCode?.stringValue,
                country: country?.stringValue, company: company?.stringValue,
                email: email?.stringValue, phone: phone?.stringValue, ssn: ssn?.stringValue,
                username: username?.stringValue, passportNumber: passportNumber?.stringValue,
                licenseNumber: licenseNumber?.stringValue
            )
        }

        let plaintextSecureNote = p.secureNote
            ?? (p.type == CipherType.secureNote.rawValue ? .init() : nil)
        let secureNoteReq = plaintextSecureNote.map { CipherSecureNoteRequest(type: $0.type) }
        let blobSecureNote = plaintextSecureNote.map { BlobSecureNote(type: $0.type) }

        var sshKeyReq: CipherSshKeyRequest?
        var blobSshKey: BlobSshKey?
        if let sshKey = p.sshKey {
            let privateKey = try await encOptional(sshKey.privateKey, cipherKey: cipherKey)
            let publicKey = try await encOptional(sshKey.publicKey, cipherKey: cipherKey)
            let keyFingerprint = try await encOptional(sshKey.keyFingerprint, cipherKey: cipherKey)
            sshKeyReq = CipherSshKeyRequest(privateKey: privateKey, publicKey: publicKey,
                                            keyFingerprint: keyFingerprint)
            blobSshKey = BlobSshKey(privateKey: privateKey?.stringValue,
                                    publicKey: publicKey?.stringValue,
                                    keyFingerprint: keyFingerprint?.stringValue)
        }

        var fieldReqs: [CipherFieldRequest] = []
        var blobFields: [BlobField] = []
        for field in p.fields {
            let fieldName = try await encOptional(field.name, cipherKey: cipherKey)
            let fieldValue = try await encOptional(field.value, cipherKey: cipherKey)
            fieldReqs.append(CipherFieldRequest(type: field.type, name: fieldName,
                                                value: fieldValue, linkedId: field.linkedId))
            blobFields.append(BlobField(type: field.type, name: fieldName?.stringValue,
                                        value: fieldValue?.stringValue, linkedId: field.linkedId))
        }

        let request = CipherRequest(
            type: p.type, name: nameEnc, notes: notesEnc, folderId: p.folderID,
            organizationId: p.organizationID, favorite: p.favorite, reprompt: p.reprompt,
            key: protectedCipherKey,
            login: loginReq, card: cardReq, identity: identityReq,
            secureNote: secureNoteReq, sshKey: sshKeyReq,
            fields: fieldReqs.isEmpty ? nil : fieldReqs,
            lastKnownRevisionDate: lastKnownRevisionDate
        )

        let blob = BlobRoot(login: blobLogin, card: blobCard, identity: blobIdentity,
                            secureNote: blobSecureNote, sshKey: blobSshKey,
                            fields: blobFields.isEmpty ? nil : blobFields)
        let blobJSON = (try? blob.json()) ?? "{}"

        // Plaintext search index: display/name-like fields only; secrets such as passwords,
        // card codes, private keys, SSNs, and hidden custom-field values are excluded.
        var parts: [String] = [p.name]
        parts.append(contentsOf: [p.login?.username].compactMap { $0 })
        parts.append(contentsOf: p.login?.uris.map(\.uri) ?? [])
        parts.append(contentsOf: [p.card?.cardholderName, p.card?.brand].compactMap { $0 })
        if let identity = p.identity {
            parts.append(contentsOf: [identity.firstName, identity.middleName, identity.lastName,
                                      identity.company, identity.email, identity.username,
                                      identity.city, identity.state, identity.country].compactMap { $0 })
        }
        parts.append(contentsOf: [p.sshKey?.keyFingerprint].compactMap { $0 })
        parts.append(contentsOf: p.fields.compactMap(\.name))
        let searchText = parts.joined(separator: " ").lowercased()

        return EncryptedCipher(
            request: request, type: p.type, folderID: p.folderID,
            organizationID: p.organizationID, favorite: p.favorite,
            reprompt: p.reprompt, nameWire: nameEnc.stringValue, notesWire: notesEnc?.stringValue,
            blobJSON: blobJSON, searchText: searchText,
            protectedCipherKeyWire: protectedCipherKey?.stringValue
        )
    }

    /// Decrypt a store row into a `PlaintextCipher`. Throws `.locked` if the vault is locked,
    /// `.crypto` on a parse/decrypt failure of a required field.
    private func decrypt(_ row: CipherRow, strict: Bool = false) async throws -> PlaintextCipher {
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let protectedCipherKey = try parseProtectedCipherKey(row.encCipherKey)
        let cipherKey = try await unwrapCipherKey(protectedCipherKey,
                                                  organizationID: row.organizationID)

        guard let nameWire = row.encName else { throw RepositoryError.crypto(CryptoError.invalidEncString) }
        let name = try await decryptWire(nameWire, cipherKey: cipherKey)
        func read(_ value: String?) async throws -> String? {
            guard let value else { return nil }
            if strict { return try await decryptWire(value, cipherKey: cipherKey) }
            return try? await decryptWire(value, cipherKey: cipherKey)
        }
        let notes = try await read(row.encNotes)
        let blobData = Data((row.encBlob ?? "{}").utf8)
        let blob: BlobRoot?
        if strict {
            blob = try JSONDecoder().decode(BlobRoot.self, from: blobData)
        } else {
            blob = try? JSONDecoder().decode(BlobRoot.self, from: blobData)
        }

        var login: PlaintextCipher.Login?
        if let l = blob?.login {
            let user = try await read(l.username)
            let pass = try await read(l.password)
            let totp = try await read(l.totp)
            var uris: [PlaintextCipher.Uri] = []
            for u in l.uris ?? [] {
                if let plain = try await read(u.uri) {
                    uris.append(PlaintextCipher.Uri(uri: plain, match: u.match))
                }
            }
            var fido2Credentials: [PlaintextCipher.Fido2Credential] = []
            for f in l.fido2Credentials ?? [] {
                fido2Credentials.append(PlaintextCipher.Fido2Credential(
                    credentialId: try await read(f.credentialId),
                    keyType: try await read(f.keyType),
                    keyAlgorithm: try await read(f.keyAlgorithm),
                    keyCurve: try await read(f.keyCurve),
                    keyValue: try await read(f.keyValue),
                    rpId: try await read(f.rpId),
                    rpName: try await read(f.rpName),
                    userHandle: try await read(f.userHandle),
                    userName: try await read(f.userName),
                    userDisplayName: try await read(f.userDisplayName),
                    counter: try await read(f.counter),
                    discoverable: try await read(f.discoverable),
                    creationDate: f.creationDate
                ))
            }
            login = PlaintextCipher.Login(username: user, password: pass, totp: totp,
                                          uris: uris, fido2Credentials: fido2Credentials,
                                          passwordRevisionDate: l.passwordRevisionDate)
        } else if row.type == CipherType.login.rawValue {
            login = .init()
        }

        var card: PlaintextCipher.Card?
        if let c = blob?.card {
            card = PlaintextCipher.Card(
                cardholderName: try await read(c.cardholderName),
                brand: try await read(c.brand),
                number: try await read(c.number),
                expMonth: try await read(c.expMonth),
                expYear: try await read(c.expYear),
                code: try await read(c.code)
            )
        } else if row.type == CipherType.card.rawValue {
            card = .init()
        }

        var identity: PlaintextCipher.Identity?
        if let i = blob?.identity {
            identity = PlaintextCipher.Identity(
                title: try await read(i.title),
                firstName: try await read(i.firstName),
                middleName: try await read(i.middleName),
                lastName: try await read(i.lastName),
                address1: try await read(i.address1),
                address2: try await read(i.address2),
                address3: try await read(i.address3),
                city: try await read(i.city),
                state: try await read(i.state),
                postalCode: try await read(i.postalCode),
                country: try await read(i.country),
                company: try await read(i.company),
                email: try await read(i.email),
                phone: try await read(i.phone),
                ssn: try await read(i.ssn),
                username: try await read(i.username),
                passportNumber: try await read(i.passportNumber),
                licenseNumber: try await read(i.licenseNumber)
            )
        } else if row.type == CipherType.identity.rawValue {
            identity = .init()
        }

        let secureNote: PlaintextCipher.SecureNote? = blob?.secureNote.map { .init(type: $0.type) }
            ?? (row.type == CipherType.secureNote.rawValue ? .init() : nil)

        var sshKey: PlaintextCipher.SshKey?
        if let s = blob?.sshKey {
            sshKey = PlaintextCipher.SshKey(
                privateKey: try await read(s.privateKey),
                publicKey: try await read(s.publicKey),
                keyFingerprint: try await read(s.keyFingerprint)
            )
        } else if row.type == CipherType.sshKey.rawValue {
            sshKey = .init()
        }

        var fields: [PlaintextCipher.Field] = []
        for f in blob?.fields ?? [] {
            fields.append(PlaintextCipher.Field(
                type: f.type ?? FieldType.text.rawValue,
                name: try await read(f.name),
                value: try await read(f.value),
                linkedId: f.linkedId
            ))
        }

        return PlaintextCipher(
            id: row.id, type: row.type, name: name, notes: notes,
            folderID: row.folderID, organizationID: row.organizationID,
            protectedCipherKey: protectedCipherKey,
            favorite: row.favorite, reprompt: row.reprompt, login: login, card: card,
            identity: identity, secureNote: secureNote, sshKey: sshKey, fields: fields,
            revisionDate: SyncEngine.parseDate(row.revisionDate), creationDate: SyncEngine.parseDate(row.creationDate),
            deletedDate: row.deletedDate.flatMap(SyncEngine.parseDate), archivedDate: row.archivedDate.flatMap(SyncEngine.parseDate)
        )
    }

    // MARK: - Private helpers

    private func requireOperationLease() async throws -> OperationLease {
        guard let session = await accountLease() else {
            throw RepositoryError.notAuthenticated
        }
        return OperationLease(session: session, generation: operationGeneration)
    }

    private func requireCurrentOperationLease(_ lease: OperationLease) async throws {
        guard operationGeneration == lease.generation,
              await accountLease() == lease.session else {
            throw RepositoryError.notAuthenticated
        }
    }

    /// Build a local store row from a server `CipherResponse` (reusing SyncEngine's blob /
    /// row mapping shape so reads stay consistent with sync).
    private func makeRow(from cipher: CipherResponse, accountID: String) async throws -> CipherRow {
        // A fallback empty blob would silently discard type-specific fields after a
        // successful online write. Encoding is deterministic; surface failure instead.
        let blobJSON = try Self.encodeBlob(cipher)
        let searchText = await buildSearchText(cipher)
        return CipherRow(
            id: cipher.id, accountID: accountID, type: cipher.type.rawValue,
            folderID: cipher.folderId, organizationID: cipher.organizationId,
            favorite: cipher.favorite, reprompt: cipher.reprompt,
            edit: cipher.edit ?? true, viewPassword: cipher.viewPassword ?? true,
            revisionDate: Self.iso(cipher.revisionDate),
            creationDate: cipher.creationDate.map(Self.iso) ?? Self.iso(cipher.revisionDate),
            deletedDate: cipher.deletedDate.map(Self.iso),
            archivedDate: cipher.archivedDate.map(Self.iso),
            encName: cipher.name.stringValue, encNotes: cipher.notes?.stringValue,
            encBlob: blobJSON, encCipherKey: cipher.key?.stringValue, searchText: searchText
        )
    }

    private func buildSearchText(_ cipher: CipherResponse) async -> String {
        var cipherKey: SymmetricCryptoKey?
        if let protected = cipher.key {
            cipherKey = try? await keyVault.cipherKey(fromProtected: protected)
        }
        var parts: [String] = []
        if let n = await decEncOptional(cipher.name, cipherKey: cipherKey) { parts.append(n) }
        if let u = await decEncOptional(cipher.login?.username, cipherKey: cipherKey) { parts.append(u) }
        for uri in cipher.login?.uris ?? [] {
            if let s = await decEncOptional(uri.uri, cipherKey: cipherKey) { parts.append(s) }
        }
        if let card = cipher.card {
            if let s = await decEncOptional(card.cardholderName, cipherKey: cipherKey) { parts.append(s) }
            if let s = await decEncOptional(card.brand, cipherKey: cipherKey) { parts.append(s) }
        }
        if let identity = cipher.identity {
            for enc in [identity.firstName, identity.middleName, identity.lastName,
                        identity.company, identity.email, identity.username,
                        identity.city, identity.state, identity.country] {
                if let s = await decEncOptional(enc, cipherKey: cipherKey) { parts.append(s) }
            }
        }
        if let sshKey = cipher.sshKey {
            if let s = await decEncOptional(sshKey.keyFingerprint, cipherKey: cipherKey) { parts.append(s) }
        }
        for field in cipher.fields ?? [] {
            if let s = await decEncOptional(field.name, cipherKey: cipherKey) { parts.append(s) }
        }
        return parts.joined(separator: " ").lowercased()
    }

    /// Best-effort decrypt of an optional `EncString` to UTF-8 (returns `nil` on any failure).
    private func decEncOptional(_ enc: EncString?, cipherKey: SymmetricCryptoKey?) async -> String? {
        guard let enc, let data = try? await keyVault.decrypt(enc, cipherKey: cipherKey),
              let s = String(data: data, encoding: .utf8) else { return nil }
        return s
    }

    private func persistOfflineCipherMutation(
        accountID: String,
        op: OutboxOp,
        entityID: String,
        encrypted: EncryptedCipher,
        lastKnownRevisionDate: String?,
        localCipher: CipherRow,
        issue: OutboxRow.Issue? = nil
    ) async throws {
        let payload = try Self.outboxPayload(from: encrypted)
        let json: String
        do { json = try payload.encodedJSON() } catch { throw RepositoryError.crypto(error) }
        let row = OutboxRow(accountID: accountID, opType: op.rawValue,
                            entityType: OutboxEntity.cipher.rawValue,
                            entityID: entityID, payloadJSON: json,
                            lastKnownRevisionDate: lastKnownRevisionDate, issue: issue)
        do {
            try await store.persistOfflineCipherMutation(
                operation: row,
                localCipher: localCipher
            )
        } catch { throw RepositoryError.store(error) }
    }

    /// Persist a registration as a deterministic local row + exactly one receipt-linked
    /// outbox operation before acknowledging the extension handoff. No network call occurs
    /// in this import transaction, so replay cannot create a second server item.
    private func persistPasskeyImport(
        registrationID: String,
        accountID: String,
        operation: OutboxOp,
        entityID: String,
        plaintext: PlaintextCipher,
        protectedCipherKey: EncString?,
        lastKnownRevisionDate: String?,
        lease: OperationLease
    ) async throws {
        let lastKnown = lastKnownRevisionDate.flatMap(SyncEngine.parseDate)
        let encrypted = try await encryptCipher(
            plaintext,
            protectedCipherKey: protectedCipherKey,
            lastKnownRevisionDate: lastKnown
        )
        try await requireCurrentOperationLease(lease)
        let payload: OutboxCipherPayload
        do { payload = try Self.outboxPayload(from: encrypted) }
        catch { throw RepositoryError.crypto(error) }
        let json: String
        do { json = try payload.encodedJSON() }
        catch { throw RepositoryError.crypto(error) }
        let outbox = OutboxRow(
            accountID: accountID,
            opType: operation.rawValue,
            entityType: OutboxEntity.cipher.rawValue,
            entityID: entityID,
            payloadJSON: json,
            lastKnownRevisionDate: lastKnownRevisionDate
        )

        let localRow = encrypted.localRow(id: entityID, accountID: accountID,
                                          creationDate: plaintext.creationDate.map(Self.iso), after: lastKnown)
        do {
            _ = try await store.enqueueOutboxForPasskeyImport(
                receiptID: registrationID,
                accountID: accountID,
                operation: outbox,
                localCipher: localRow
            )
        } catch { throw RepositoryError.store(error) }
    }

    private func requireCipherRow(
        id: String,
        accountID: String,
        includeHidden: Bool = false
    ) async throws -> (resolvedID: String, row: CipherRow) {
        let resolvedID: String
        do { resolvedID = try await store.resolveCipherID(id, accountID: accountID) }
        catch { throw RepositoryError.store(error) }
        let row: CipherRow?
        do { row = try await store.cipher(id: resolvedID, accountID: accountID) }
        catch { throw RepositoryError.store(error) }
        guard let row, includeHidden || (row.deletedDate == nil && row.archivedDate == nil) else {
            throw RepositoryError.cipherNotFound
        }
        return (resolvedID, row)
    }

    private func parseProtectedCipherKey(_ wire: String?) throws -> EncString? {
        guard let wire else { return nil }
        do { return try EncString(parsing: wire) }
        catch { throw RepositoryError.crypto(error) }
    }

    /// Unwrap a protected per-item key using the user key currently held by `KeyVault`.
    /// Organization keys are not loaded by this milestone; if such a key cannot be unwrapped,
    /// fail the edit explicitly before making an API call or replacing the local row.
    private func unwrapCipherKey(_ protected: EncString?,
                                 organizationID: String?) async throws -> SymmetricCryptoKey? {
        guard let protected else {
            if organizationID != nil { throw RepositoryError.organizationCipherKeyUnavailable }
            return nil
        }
        do { return try await keyVault.cipherKey(fromProtected: protected) }
        catch KeyVaultError.locked { throw RepositoryError.locked }
        catch where organizationID != nil {
            throw RepositoryError.organizationCipherKeyUnavailable
        }
        catch { throw RepositoryError.crypto(error) }
    }

    private func decryptWire(_ wire: String, cipherKey: SymmetricCryptoKey?) async throws -> String {
        let enc: EncString
        do { enc = try EncString(parsing: wire) } catch { throw RepositoryError.crypto(error) }
        do {
            let data = try await keyVault.decrypt(enc, cipherKey: cipherKey)
            guard let s = String(data: data, encoding: .utf8) else {
                throw RepositoryError.crypto(CryptoError.decryptionFailed)
            }
            return s
        } catch KeyVaultError.locked {
            throw RepositoryError.locked
        } catch let e as RepositoryError {
            throw e
        } catch {
            throw RepositoryError.crypto(error)
        }
    }

    private func optionalDecrypt(_ wire: String?, cipherKey: SymmetricCryptoKey?) async -> String? {
        guard let wire else { return nil }
        return try? await decryptWire(wire, cipherKey: cipherKey)
    }

    public func exportSnapshot(expectedSession: AccountSessionLease) async throws -> (items: [PlaintextCipher], folders: [PlaintextFolder]) {
        let lease = try await requireOperationLease()
        guard lease.session == expectedSession, await keyVault.isUnlocked else { throw RepositoryError.locked }
        try Task.checkCancellation()
        let snapshot = try await mutationCoordinator.withLock {
            try Task.checkCancellation()
            try await self.requireCurrentOperationLease(lease)
            return try await self.store.transferSnapshot(accountID: lease.accountID)
        }
        var folders: [PlaintextFolder] = []
        for row in snapshot.folders {
            try Task.checkCancellation()
            guard let encrypted = row.encName else { throw RepositoryError.crypto(CryptoError.invalidEncString) }
            let name = try await decryptWire(encrypted, cipherKey: nil)
            folders.append(.init(id: row.id, name: name))
        }
        var items: [PlaintextCipher] = []
        for row in snapshot.items where row.deletedDate == nil && row.organizationID == nil {
            try Task.checkCancellation()
            items.append(try await decrypt(row, strict: true))
        }
        try await requireCurrentOperationLease(lease)
        return (items, folders)
    }

    // MARK: - Static helpers

    /// HTTP transport/reachability failures that mean "queue this write for later".
    static func isOffline(_ error: NetworkingError) -> Bool {
        switch error {
        case .serverUnreachable, .transport: return true
        default: return false
        }
    }

    static func iso(_ date: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: date)
    }

    private static func containsPasskey(
        _ credentials: [PlaintextCipher.Fido2Credential],
        relyingPartyID: String,
        credentialID: Data
    ) -> Bool {
        credentials.contains {
            $0.rpId == relyingPartyID
                && $0.credentialId.flatMap(decodeCredentialID) == credentialID
        }
    }

    private static func decodeCredentialID(_ value: String) -> Data? {
        if let uuid = UUID(uuidString: value), value.utf8.count == 36 {
            let b = uuid.uuid
            return Data([
                b.0, b.1, b.2, b.3, b.4, b.5, b.6, b.7,
                b.8, b.9, b.10, b.11, b.12, b.13, b.14, b.15,
            ])
        }
        guard value.hasPrefix("b64.") else { return nil }
        return decodeBase64URL(String(value.dropFirst(4)))
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func decodeBase64URL(_ string: String) -> Data? {
        guard !string.isEmpty else { return nil }
        var base64 = string.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.utf8.count % 4
        guard remainder != 1 else { return nil }
        if remainder != 0 { base64 += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: base64)
    }

    /// Encode every server cipher sub-payload as JSON of EncString wire strings. This shape
    /// matches `SyncEngine.BlobPayload`, so a row written by either component is lossless.
    static func encodeBlob(_ cipher: CipherResponse) throws -> String {
        let login = cipher.login.map { l in
            BlobLogin(
                username: l.username?.stringValue, password: l.password?.stringValue,
                totp: l.totp?.stringValue,
                uris: l.uris?.map { BlobURI(uri: $0.uri?.stringValue, match: $0.match?.rawValue) },
                fido2Credentials: l.fido2Credentials?.map {
                    BlobFido2(
                        credentialId: $0.credentialId?.stringValue,
                        keyType: $0.keyType?.stringValue,
                        keyAlgorithm: $0.keyAlgorithm?.stringValue,
                        keyCurve: $0.keyCurve?.stringValue,
                        keyValue: $0.keyValue?.stringValue,
                        rpId: $0.rpId?.stringValue,
                        rpName: $0.rpName?.stringValue,
                        userHandle: $0.userHandle?.stringValue,
                        userName: $0.userName?.stringValue,
                        userDisplayName: $0.userDisplayName?.stringValue,
                        counter: $0.counter?.stringValue,
                        discoverable: $0.discoverable?.stringValue,
                        creationDate: $0.creationDate
                    )
                },
                passwordRevisionDate: l.passwordRevisionDate
            )
        }
        let card = cipher.card.map {
            BlobCard(cardholderName: $0.cardholderName?.stringValue,
                     brand: $0.brand?.stringValue, number: $0.number?.stringValue,
                     expMonth: $0.expMonth?.stringValue, expYear: $0.expYear?.stringValue,
                     code: $0.code?.stringValue)
        }
        let identity = cipher.identity.map {
            BlobIdentity(
                title: $0.title?.stringValue, firstName: $0.firstName?.stringValue,
                middleName: $0.middleName?.stringValue, lastName: $0.lastName?.stringValue,
                address1: $0.address1?.stringValue, address2: $0.address2?.stringValue,
                address3: $0.address3?.stringValue, city: $0.city?.stringValue,
                state: $0.state?.stringValue, postalCode: $0.postalCode?.stringValue,
                country: $0.country?.stringValue, company: $0.company?.stringValue,
                email: $0.email?.stringValue, phone: $0.phone?.stringValue,
                ssn: $0.ssn?.stringValue, username: $0.username?.stringValue,
                passportNumber: $0.passportNumber?.stringValue,
                licenseNumber: $0.licenseNumber?.stringValue
            )
        }
        let secureNote = cipher.secureNote.map { BlobSecureNote(type: $0.type.rawValue) }
        let sshKey = cipher.sshKey.map {
            BlobSshKey(privateKey: $0.privateKey?.stringValue,
                       publicKey: $0.publicKey?.stringValue,
                       keyFingerprint: $0.keyFingerprint?.stringValue)
        }
        let fields = cipher.fields?.map {
            BlobField(type: $0.type.rawValue, name: $0.name?.stringValue,
                      value: $0.value?.stringValue, linkedId: $0.linkedId)
        }
        let root = BlobRoot(login: login, card: card, identity: identity,
                            secureNote: secureNote, sshKey: sshKey, fields: fields)
        return try root.json()
    }

    /// Build an `OutboxCipherPayload` from an already-encrypted cipher request.
    private static func outboxPayload(from encrypted: EncryptedCipher) throws -> OutboxCipherPayload {
        let req = encrypted.request
        let login = req.login.map { l in
            OutboxCipherPayload.Login(
                username: l.username?.stringValue, password: l.password?.stringValue,
                totp: l.totp?.stringValue,
                uris: l.uris?.map { OutboxCipherPayload.Uri(uri: $0.uri?.stringValue, match: $0.match) },
                fido2Credentials: l.fido2Credentials?.map {
                    OutboxCipherPayload.Fido2(
                        credentialId: $0.credentialId?.stringValue,
                        keyType: $0.keyType?.stringValue,
                        keyAlgorithm: $0.keyAlgorithm?.stringValue,
                        keyCurve: $0.keyCurve?.stringValue,
                        keyValue: $0.keyValue?.stringValue,
                        rpId: $0.rpId?.stringValue,
                        rpName: $0.rpName?.stringValue,
                        userHandle: $0.userHandle?.stringValue,
                        userName: $0.userName?.stringValue,
                        userDisplayName: $0.userDisplayName?.stringValue,
                        counter: $0.counter?.stringValue,
                        discoverable: $0.discoverable?.stringValue,
                        creationDate: $0.creationDate
                    )
                },
                passwordRevisionDate: l.passwordRevisionDate
            )
        }
        let card = req.card.map {
            OutboxCipherPayload.Card(
                cardholderName: $0.cardholderName?.stringValue, brand: $0.brand?.stringValue,
                number: $0.number?.stringValue, expMonth: $0.expMonth?.stringValue,
                expYear: $0.expYear?.stringValue, code: $0.code?.stringValue
            )
        }
        let identity = req.identity.map {
            OutboxCipherPayload.Identity(
                title: $0.title?.stringValue, firstName: $0.firstName?.stringValue,
                middleName: $0.middleName?.stringValue, lastName: $0.lastName?.stringValue,
                address1: $0.address1?.stringValue, address2: $0.address2?.stringValue,
                address3: $0.address3?.stringValue, city: $0.city?.stringValue,
                state: $0.state?.stringValue, postalCode: $0.postalCode?.stringValue,
                country: $0.country?.stringValue, company: $0.company?.stringValue,
                email: $0.email?.stringValue, phone: $0.phone?.stringValue,
                ssn: $0.ssn?.stringValue, username: $0.username?.stringValue,
                passportNumber: $0.passportNumber?.stringValue,
                licenseNumber: $0.licenseNumber?.stringValue
            )
        }
        let secureNote = req.secureNote.map { OutboxCipherPayload.SecureNote(type: $0.type) }
        let sshKey = req.sshKey.map {
            OutboxCipherPayload.SshKey(privateKey: $0.privateKey?.stringValue,
                                       publicKey: $0.publicKey?.stringValue,
                                       keyFingerprint: $0.keyFingerprint?.stringValue)
        }
        let fields = req.fields?.map {
            OutboxCipherPayload.Field(type: $0.type, name: $0.name?.stringValue,
                                      value: $0.value?.stringValue, linkedId: $0.linkedId)
        }
        return OutboxCipherPayload(
            type: req.type, name: req.name.stringValue, notes: req.notes?.stringValue,
            folderID: req.folderId, organizationID: req.organizationId,
            favorite: req.favorite, reprompt: req.reprompt, key: req.key?.stringValue,
            login: login, card: card, identity: identity, secureNote: secureNote,
            sshKey: sshKey, fields: fields
        )
    }
}

// MARK: - Blob JSON (all cipher sub-payloads, EncString wire strings)

/// The `enc_blob` JSON shape the repository reads/writes. Optional properties keep it
/// backward-compatible with login-only rows created by earlier builds.
struct BlobRoot: Codable, Sendable {
    var login: BlobLogin?
    var card: BlobCard?
    var identity: BlobIdentity?
    var secureNote: BlobSecureNote?
    var sshKey: BlobSshKey?
    var fields: [BlobField]?
    func json() throws -> String {
        String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
    }
}

struct BlobLogin: Codable, Sendable {
    var username: String?
    var password: String?
    var totp: String?
    var uris: [BlobURI]?
    var fido2Credentials: [BlobFido2]?
    var passwordRevisionDate: Date?
}

struct BlobURI: Codable, Sendable {
    var uri: String?
    var match: Int?
}

struct BlobFido2: Codable, Sendable {
    var credentialId: String?
    var keyType: String?
    var keyAlgorithm: String?
    var keyCurve: String?
    var keyValue: String?
    var rpId: String?
    var rpName: String?
    var userHandle: String?
    var userName: String?
    var userDisplayName: String?
    var counter: String?
    var discoverable: String?
    var creationDate: Date?
}

struct BlobCard: Codable, Sendable {
    var cardholderName: String?
    var brand: String?
    var number: String?
    var expMonth: String?
    var expYear: String?
    var code: String?
}

struct BlobIdentity: Codable, Sendable {
    var title: String?
    var firstName: String?
    var middleName: String?
    var lastName: String?
    var address1: String?
    var address2: String?
    var address3: String?
    var city: String?
    var state: String?
    var postalCode: String?
    var country: String?
    var company: String?
    var email: String?
    var phone: String?
    var ssn: String?
    var username: String?
    var passportNumber: String?
    var licenseNumber: String?
}

struct BlobSecureNote: Codable, Sendable {
    var type: Int
}

struct BlobSshKey: Codable, Sendable {
    var privateKey: String?
    var publicKey: String?
    var keyFingerprint: String?
}

struct BlobField: Codable, Sendable {
    var type: Int?
    var name: String?
    var value: String?
    var linkedId: Int?
}
