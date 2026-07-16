import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import Networking
import SyncEngine

/// App-facing vault CRUD + read + sync orchestration (design spec §5.9).
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
        let lease = try await requireOperationLease()
        let rows: [CipherRow]
        do { rows = try await store.allCiphers(accountID: lease.accountID) }
        catch { throw RepositoryError.store(error) }
        var out: [PlaintextCipher] = []
        for row in rows {
            if let decrypted = try? await decrypt(row) { out.append(decrypted) }
        }
        try await requireCurrentOperationLease(lease)
        return out
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
        let rows: [CipherRow]
        do { rows = try await store.search(query, accountID: lease.accountID) }
        catch { throw RepositoryError.store(error) }
        var out: [PlaintextCipher] = []
        for row in rows {
            if let decrypted = try? await decrypt(row) { out.append(decrypted) }
        }
        try await requireCurrentOperationLease(lease)
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

    private func createCipher(_ plaintext: PlaintextCipher,
                              lease: OperationLease) async throws -> String {
        try await requireCurrentOperationLease(lease)
        let encrypted = try await encryptCipher(
            plaintext,
            protectedCipherKey: plaintext.protectedCipherKey
        )
        try await requireCurrentOperationLease(lease)

        let created: CipherResponse
        do {
            created = try await api.createCipher(
                accountID: lease.accountID,
                encrypted.request
            )
        } catch let error as NetworkingError where Self.isOffline(error) {
            // Offline: enqueue to the outbox under a local placeholder id and persist a
            // local row so the item shows immediately.
            let localID = plaintext.id ?? UUID().uuidString
            try await requireCurrentOperationLease(lease)
            let row = encrypted.localRow(id: localID, accountID: lease.accountID)
            try await persistOfflineCipherMutation(
                accountID: lease.accountID,
                op: .create,
                entityID: localID,
                encrypted: encrypted,
                lastKnownRevisionDate: nil,
                localCipher: row
            )
            try await requireCurrentOperationLease(lease)
            return localID
        } catch {
            throw RepositoryError.network(error)
        }

        let row = try await makeRow(from: created, accountID: lease.accountID)
        do { try await store.upsertCiphers([row]) }
        catch { throw RepositoryError.store(error) }
        try await requireCurrentOperationLease(lease)
        return created.id
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
        let lastKnown = SyncEngine.parseDate(existing.revisionDate)

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
            let row = encrypted.localRow(id: resolvedID, accountID: lease.accountID)
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
        } catch let error as NetworkingError where Self.isOffline(error) {
            try await requireCurrentOperationLease(lease)
            let row = encrypted.localRow(id: resolvedID, accountID: lease.accountID)
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

    /// Delete a cipher: call the API (or enqueue) and remove the local row.
    public func deleteCipher(id: String) async throws {
        let lease = try await requireOperationLease()
        let identityGeneration = await syncEngine.identityGenerationLease()
        try await mutationCoordinator.withLock {
            try await self.deleteCipher(id: id, lease: lease)
            _ = await self.syncEngine.refreshCredentialIdentities(
                accountID: lease.accountID,
                expectedGeneration: identityGeneration
            )
        }
    }

    private func deleteCipher(id: String, lease: OperationLease) async throws {
        try await requireCurrentOperationLease(lease)
        let (resolvedID, _) = try await requireCipherRow(
            id: id,
            accountID: lease.accountID
        )
        try await requireCurrentOperationLease(lease)
        let pending: Bool
        do {
            pending = try await store.hasPendingOutbox(
                accountID: lease.accountID,
                entityType: OutboxEntity.cipher.rawValue,
                entityID: resolvedID
            )
        } catch { throw RepositoryError.store(error) }
        if pending {
            let operation = OutboxRow(
                accountID: lease.accountID,
                opType: OutboxOp.delete.rawValue,
                entityType: OutboxEntity.cipher.rawValue,
                entityID: resolvedID,
                payloadJSON: "{}"
            )
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
            let row = OutboxRow(accountID: lease.accountID,
                                opType: OutboxOp.delete.rawValue,
                                entityType: OutboxEntity.cipher.rawValue,
                                entityID: resolvedID, payloadJSON: "{}", lastKnownRevisionDate: nil)
            do {
                try await store.persistOfflineCipherMutation(
                    operation: row,
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

    // MARK: - Sync / lock

    /// Full sync: flush the outbox first, then pull. Delegates to the injected `SyncEngine`.
    @discardableResult
    public func sync() async throws -> SyncOutcome {
        let lease = try await requireOperationLease()
        do {
            try await syncEngine.flushOutbox(accountID: lease.accountID)
            let outcome = try await syncEngine.fullSync(accountID: lease.accountID)
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
        func localRow(id: String, accountID: String) -> CipherRow {
            let now = ISO8601DateFormatter().string(from: Date())
            return CipherRow(
                id: id, accountID: accountID, type: type, folderID: folderID,
                organizationID: organizationID,
                favorite: favorite, reprompt: reprompt,
                revisionDate: now, creationDate: now,
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

    /// Encrypt a plaintext cipher into a request + the bits needed for a local row.
    private func encryptCipher(_ p: PlaintextCipher,
                               protectedCipherKey: EncString?,
                               lastKnownRevisionDate: Date? = nil) async throws -> EncryptedCipher {
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
        let plaintextSshKey = p.sshKey ?? (p.type == CipherType.sshKey.rawValue ? .init() : nil)
        if let sshKey = plaintextSshKey {
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
    private func decrypt(_ row: CipherRow) async throws -> PlaintextCipher {
        guard await keyVault.isUnlocked else { throw RepositoryError.locked }
        let protectedCipherKey = try parseProtectedCipherKey(row.encCipherKey)
        let cipherKey = try await unwrapCipherKey(protectedCipherKey,
                                                  organizationID: row.organizationID)

        guard let nameWire = row.encName else { throw RepositoryError.crypto(CryptoError.invalidEncString) }
        let name = try await decryptWire(nameWire, cipherKey: cipherKey)
        let notes = await optionalDecrypt(row.encNotes, cipherKey: cipherKey)

        let blob = try? JSONDecoder().decode(BlobRoot.self,
                                             from: Data((row.encBlob ?? "{}").utf8))

        var login: PlaintextCipher.Login?
        if let l = blob?.login {
            let user = await optionalDecrypt(l.username, cipherKey: cipherKey)
            let pass = await optionalDecrypt(l.password, cipherKey: cipherKey)
            let totp = await optionalDecrypt(l.totp, cipherKey: cipherKey)
            var uris: [PlaintextCipher.Uri] = []
            for u in l.uris ?? [] {
                if let plain = await optionalDecrypt(u.uri, cipherKey: cipherKey) {
                    uris.append(PlaintextCipher.Uri(uri: plain, match: u.match))
                }
            }
            var fido2Credentials: [PlaintextCipher.Fido2Credential] = []
            for f in l.fido2Credentials ?? [] {
                fido2Credentials.append(PlaintextCipher.Fido2Credential(
                    credentialId: await optionalDecrypt(f.credentialId, cipherKey: cipherKey),
                    keyType: await optionalDecrypt(f.keyType, cipherKey: cipherKey),
                    keyAlgorithm: await optionalDecrypt(f.keyAlgorithm, cipherKey: cipherKey),
                    keyCurve: await optionalDecrypt(f.keyCurve, cipherKey: cipherKey),
                    keyValue: await optionalDecrypt(f.keyValue, cipherKey: cipherKey),
                    rpId: await optionalDecrypt(f.rpId, cipherKey: cipherKey),
                    rpName: await optionalDecrypt(f.rpName, cipherKey: cipherKey),
                    userHandle: await optionalDecrypt(f.userHandle, cipherKey: cipherKey),
                    userName: await optionalDecrypt(f.userName, cipherKey: cipherKey),
                    userDisplayName: await optionalDecrypt(f.userDisplayName, cipherKey: cipherKey),
                    counter: await optionalDecrypt(f.counter, cipherKey: cipherKey),
                    discoverable: await optionalDecrypt(f.discoverable, cipherKey: cipherKey),
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
                cardholderName: await optionalDecrypt(c.cardholderName, cipherKey: cipherKey),
                brand: await optionalDecrypt(c.brand, cipherKey: cipherKey),
                number: await optionalDecrypt(c.number, cipherKey: cipherKey),
                expMonth: await optionalDecrypt(c.expMonth, cipherKey: cipherKey),
                expYear: await optionalDecrypt(c.expYear, cipherKey: cipherKey),
                code: await optionalDecrypt(c.code, cipherKey: cipherKey)
            )
        } else if row.type == CipherType.card.rawValue {
            card = .init()
        }

        var identity: PlaintextCipher.Identity?
        if let i = blob?.identity {
            identity = PlaintextCipher.Identity(
                title: await optionalDecrypt(i.title, cipherKey: cipherKey),
                firstName: await optionalDecrypt(i.firstName, cipherKey: cipherKey),
                middleName: await optionalDecrypt(i.middleName, cipherKey: cipherKey),
                lastName: await optionalDecrypt(i.lastName, cipherKey: cipherKey),
                address1: await optionalDecrypt(i.address1, cipherKey: cipherKey),
                address2: await optionalDecrypt(i.address2, cipherKey: cipherKey),
                address3: await optionalDecrypt(i.address3, cipherKey: cipherKey),
                city: await optionalDecrypt(i.city, cipherKey: cipherKey),
                state: await optionalDecrypt(i.state, cipherKey: cipherKey),
                postalCode: await optionalDecrypt(i.postalCode, cipherKey: cipherKey),
                country: await optionalDecrypt(i.country, cipherKey: cipherKey),
                company: await optionalDecrypt(i.company, cipherKey: cipherKey),
                email: await optionalDecrypt(i.email, cipherKey: cipherKey),
                phone: await optionalDecrypt(i.phone, cipherKey: cipherKey),
                ssn: await optionalDecrypt(i.ssn, cipherKey: cipherKey),
                username: await optionalDecrypt(i.username, cipherKey: cipherKey),
                passportNumber: await optionalDecrypt(i.passportNumber, cipherKey: cipherKey),
                licenseNumber: await optionalDecrypt(i.licenseNumber, cipherKey: cipherKey)
            )
        } else if row.type == CipherType.identity.rawValue {
            identity = .init()
        }

        let secureNote: PlaintextCipher.SecureNote? = blob?.secureNote.map { .init(type: $0.type) }
            ?? (row.type == CipherType.secureNote.rawValue ? .init() : nil)

        var sshKey: PlaintextCipher.SshKey?
        if let s = blob?.sshKey {
            sshKey = PlaintextCipher.SshKey(
                privateKey: await optionalDecrypt(s.privateKey, cipherKey: cipherKey),
                publicKey: await optionalDecrypt(s.publicKey, cipherKey: cipherKey),
                keyFingerprint: await optionalDecrypt(s.keyFingerprint, cipherKey: cipherKey)
            )
        } else if row.type == CipherType.sshKey.rawValue {
            sshKey = .init()
        }

        var fields: [PlaintextCipher.Field] = []
        for f in blob?.fields ?? [] {
            fields.append(PlaintextCipher.Field(
                type: f.type ?? FieldType.text.rawValue,
                name: await optionalDecrypt(f.name, cipherKey: cipherKey),
                value: await optionalDecrypt(f.value, cipherKey: cipherKey),
                linkedId: f.linkedId
            ))
        }

        return PlaintextCipher(
            id: row.id, type: row.type, name: name, notes: notes,
            folderID: row.folderID, organizationID: row.organizationID,
            protectedCipherKey: protectedCipherKey,
            favorite: row.favorite, reprompt: row.reprompt, login: login, card: card,
            identity: identity, secureNote: secureNote, sshKey: sshKey, fields: fields
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
        localCipher: CipherRow
    ) async throws {
        let payload = try Self.outboxPayload(from: encrypted)
        let json: String
        do { json = try payload.encodedJSON() } catch { throw RepositoryError.crypto(error) }
        let row = OutboxRow(accountID: accountID, opType: op.rawValue,
                            entityType: OutboxEntity.cipher.rawValue,
                            entityID: entityID, payloadJSON: json,
                            lastKnownRevisionDate: lastKnownRevisionDate)
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

        let localRow = encrypted.localRow(id: entityID, accountID: accountID)
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
        accountID: String
    ) async throws -> (resolvedID: String, row: CipherRow) {
        let resolvedID: String
        do { resolvedID = try await store.resolveCipherID(id, accountID: accountID) }
        catch { throw RepositoryError.store(error) }
        let row: CipherRow?
        do { row = try await store.cipher(id: resolvedID, accountID: accountID) }
        catch { throw RepositoryError.store(error) }
        guard let row, row.deletedDate == nil else {
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
